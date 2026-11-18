//! TLS: закрепление центра при установке (отпечаток УЦ) и mTLS к collector площадки с проверкой его личности —
//! как newHTTP/FetchPinnedCA в Go-агенте.

use crate::{claims, sign};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::{DigitallySignedStruct, SignatureScheme};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use sha2::{Digest, Sha256};
use std::sync::{Arc, Mutex};

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Цепочка до закреплённого УЦ (без проверки имени) с нужным назначением ключа.
pub fn verify_chain(ca: &[u8], chain: &[CertificateDer<'_>], client_auth: bool) -> Result<(), String> {
    let anchor_der = CertificateDer::from(ca.to_vec());
    let anchor = webpki::anchor_from_trusted_cert(&anchor_der).map_err(|e| format!("ca: {e}"))?;
    let leaf = webpki::EndEntityCert::try_from(&chain[0]).map_err(|e| format!("leaf: {e}"))?;
    let usage = if client_auth { webpki::KeyUsage::client_auth() } else { webpki::KeyUsage::server_auth() };
    leaf.verify_for_usage(&[webpki::ring::ED25519, webpki::ring::ECDSA_P256_SHA256, webpki::ring::ECDSA_P384_SHA384], &[anchor], &chain[1..], UnixTime::now(), usage, None, None)
        .map(|_| ())
        .map_err(|e| format!("chain: {e}"))
}

#[derive(Debug)]
struct Capture(Mutex<Vec<CertificateDer<'static>>>, Arc<rustls::crypto::CryptoProvider>);

impl ServerCertVerifier for Capture {
    fn verify_server_cert(&self, end: &CertificateDer<'_>, inter: &[CertificateDer<'_>], _: &ServerName<'_>, _: &[u8], _: UnixTime) -> Result<ServerCertVerified, rustls::Error> {
        let mut c = vec![end.clone().into_owned()];
        c.extend(inter.iter().map(|x| x.clone().into_owned()));
        *self.0.lock().unwrap() = c;
        Ok(ServerCertVerified::assertion()) // проверка — после получения УЦ по отпечатку
    }
    fn verify_tls12_signature(&self, m: &[u8], c: &CertificateDer<'_>, d: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(m, c, d, &self.1.signature_verification_algorithms)
    }
    fn verify_tls13_signature(&self, m: &[u8], c: &CertificateDer<'_>, d: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(m, c, d, &self.1.signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.1.signature_verification_algorithms.supported_schemes()
    }
}

pub fn normalize_fingerprint(v: &str) -> Option<String> {
    let v: String = v.trim().chars().filter(|c| !matches!(c, ':' | ' ' | '-')).collect::<String>().to_lowercase();
    (v.len() == 64 && v.bytes().all(|c| c.is_ascii_hexdigit())).then_some(v)
}

fn config(verifier: Arc<dyn ServerCertVerifier>, identity: Option<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)>) -> Result<Arc<rustls::ClientConfig>, String> {
    let b = rustls::ClientConfig::builder_with_provider(provider()).with_safe_default_protocol_versions().map_err(|e| e.to_string())?
        .dangerous().with_custom_certificate_verifier(verifier);
    Ok(Arc::new(match identity {
        Some((chain, key)) => b.with_client_auth_cert(chain, key).map_err(|e| e.to_string())?,
        None => b.with_no_client_auth(),
    }))
}

pub fn agent(cfg: Arc<rustls::ClientConfig>, timeout_s: u64) -> ureq::Agent {
    ureq::AgentBuilder::new().tls_config(cfg).timeout(std::time::Duration::from_secs(timeout_s)).redirects(0).build()
}

/// УЦ центра по адресу (collector или центр): SHA-256 совпадает с отпечатком из Web, а сертификат сервера этого же
/// соединения выпущен этим УЦ. Возвращает DER сертификата УЦ.
pub fn fetch_pinned_ca(base: &str, fingerprint: &str) -> Result<Vec<u8>, String> {
    let fp = normalize_fingerprint(fingerprint).ok_or("отпечаток центра: нужно 64 шестнадцатеричных символа из Web")?;
    let cap = Arc::new(Capture(Mutex::new(vec![]), provider()));
    let a = agent(config(cap.clone(), None)?, 20);
    let resp = a.get(&format!("{}/api/v1/registration/ca", base.trim_end_matches('/'))).call().map_err(|e| format!("нет связи: {e}"))?;
    let body: serde_json::Value = serde_json::from_reader(resp.into_reader().take_bytes(65536)).map_err(|_| "неверный ответ сервера")?;
    let p = pem::parse(body["ca_pem"].as_str().unwrap_or("")).map_err(|_| "неверный сертификат центра")?;
    if p.tag() != "CERTIFICATE" {
        return Err("неверный сертификат центра".into());
    }
    let ca = p.contents().to_vec();
    if sign::hex(&Sha256::digest(&ca)) != fp {
        return Err("отпечаток центра не совпадает: проверьте адрес и отпечаток из Web".into());
    }
    let chain = cap.0.lock().unwrap().clone();
    if chain.is_empty() {
        return Err("no server certificate".into());
    }
    verify_chain(&ca, &chain, false).map_err(|_| "сертификат сервера не выпущен центром с этим отпечатком".to_string())?;
    Ok(ca)
}

/// Проверка collector: цепочка до УЦ, имя `<source>.collector.invalid`, утверждения (вид collector, источник,
/// организация, при известном — номер collector). Пустой `source` — до регистрации: только цепочка.
#[derive(Debug)]
pub struct CollectorVerifier {
    pub ca: Vec<u8>,
    pub tenant: String,
    pub source: String,
    pub collector: String,
    provider: Arc<rustls::crypto::CryptoProvider>,
    /// Утверждения сертификата collector последнего проверенного соединения (ключ подписи кадров collector).
    pub peer: Mutex<Option<claims::Claims>>,
}

impl CollectorVerifier {
    pub fn new(ca: Vec<u8>, tenant: &str, source: &str, collector: &str) -> Self {
        Self { ca, tenant: tenant.into(), source: source.into(), collector: collector.into(), provider: provider(), peer: Mutex::new(None) }
    }
}

impl ServerCertVerifier for CollectorVerifier {
    fn verify_server_cert(&self, end: &CertificateDer<'_>, inter: &[CertificateDer<'_>], _: &ServerName<'_>, _: &[u8], _: UnixTime) -> Result<ServerCertVerified, rustls::Error> {
        let mut chain = vec![end.clone()];
        chain.extend_from_slice(inter);
        let bad = |m: String| rustls::Error::General(m);
        verify_chain(&self.ca, &chain, false).map_err(bad)?;
        if !self.source.is_empty() {
            let name = ServerName::try_from(format!("{}.collector.invalid", self.source)).map_err(|e| bad(e.to_string()))?;
            webpki::EndEntityCert::try_from(end).map_err(|e| bad(e.to_string()))?.verify_is_valid_for_subject_name(&name).map_err(|e| bad(e.to_string()))?;
            let c = claims::from_der(end).map_err(bad)?;
            if c.kind != "collector" || c.source != self.source || c.tenant != self.tenant || (!self.collector.is_empty() && c.collector != self.collector) {
                return Err(bad("collector identity mismatch".into()));
            }
            if let Ok(mut p) = self.peer.lock() {
                *p = Some(c);
            }
        }
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(&self, m: &[u8], c: &CertificateDer<'_>, d: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(m, c, d, &self.provider.signature_verification_algorithms)
    }
    fn verify_tls13_signature(&self, m: &[u8], c: &CertificateDer<'_>, d: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(m, c, d, &self.provider.signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

pub fn collector_agent(v: CollectorVerifier, identity: Option<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)>) -> Result<ureq::Agent, String> {
    Ok(agent(config(Arc::new(v), identity)?, 12))
}

/// Как collector_agent, но проверяющий доступен вызывающему (утверждения collector после соединения).
pub fn collector_agent_shared(v: Arc<CollectorVerifier>, identity: Option<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)>, timeout_s: u64) -> Result<ureq::Agent, String> {
    Ok(agent(config(v, identity)?, timeout_s))
}

pub trait TakeBytes: std::io::Read + Sized {
    fn take_bytes(self, n: u64) -> std::io::Take<Self> {
        self.take(n)
    }
}
impl<T: std::io::Read> TakeBytes for T {}
