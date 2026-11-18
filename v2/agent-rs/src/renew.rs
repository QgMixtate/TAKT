//! Продление сертификата TLS (C52.02) — как machinecred.Engine.Renew в Go: свежий challenge cert_renew, новый ключ
//! и CSR, запрос подписан ключом подписи агента; незавершённый запрос (renewal.pending.json) повторяется теми же
//! байтами; результат проверяется до УЦ и по неизменным утверждениям, затем tls-identity.json.

use crate::{canonical, client::{now_rfc3339, Client, RotatedIdentity}, der, enroll, sign, state};
use ed25519_dalek::SigningKey;
use serde_json::{json, Value};
use time::{format_description::well_known::Rfc3339, Duration, OffsetDateTime};

pub const RENEWAL_DOMAIN: &[u8] = b"SURVEYSCAN-RENEWAL-V1\n";
const PENDING: &str = "renewal.pending.json";

/// Пора ли продлевать: есть незавершённый запрос или до конца срока меньше часа.
pub fn due(c: &Client) -> bool {
    c.state_dir().join(PENDING).exists() || OffsetDateTime::now_utc() >= c.expires - Duration::hours(1)
}

impl Client {
    pub fn renew(&mut self) -> Result<(), String> {
        crate::client::verify_binding(&self.state_dir(), &self.claims.source, &self.key)?;
        let path = self.state_dir().join(PENDING);
        let pending: Value = if path.exists() {
            state::load_json(&path).map_err(|_| "invalid private credential state")?
        } else {
            let tls = SigningKey::generate(&mut rand_core::OsRng);
            let csr = der::csr_ed25519(&self.claims.source, &tls.verifying_key().to_bytes(), |m| ed25519_dalek::Signer::sign(&tls, m).to_bytes());
            let csr_pem = pem::encode_config(&pem::Pem::new("CERTIFICATE REQUEST", csr), pem::EncodeConfig::new().set_line_ending(pem::LineEnding::LF));
            let (code, resp) = self.post_raw("/api/v1/machine/heartbeat-challenges", &json!({"source_ids": [self.claims.source], "purpose": "cert_renew"}))?;
            let resp: Value = serde_json::from_slice(&resp).unwrap_or(Value::Null);
            let list = resp["challenges"].as_array().filter(|l| code == 200 && l.len() == 1).ok_or("renewal challenge unavailable")?;
            let ch = &list[0];
            let s = |k: &str| ch[k].as_str().unwrap_or_default().to_string();
            let expires = OffsetDateTime::parse(&s("expires_at"), &Rfc3339).map_err(|_| "renewal challenge binding invalid")?;
            if s("purpose") != "cert_renew" || s("tenant_id") != self.claims.tenant || s("source_id") != self.claims.source || s("generation_id") != self.claims.generation || OffsetDateTime::now_utc() >= expires {
                return Err("renewal challenge binding invalid".into());
            }
            let payload = json!({"schema_version": {"major": 1, "minor": 0}, "renewal_id": state::new_id(), "tenant_id": self.claims.tenant,
                "origin": {"source_id": self.claims.source, "source_kind": self.claims.kind, "generation_id": self.claims.generation},
                "challenge_id": s("challenge_id"), "nonce": s("nonce"), "csr_pem": csr_pem, "sent_at": now_rfc3339()});
            let canon = canonical::canonical_value(&payload)?;
            let p = json!({"request": {"payload": payload, "digest": sign::digest_hex(&canon), "key_id": self.claims.key_id, "signature": sign::sign(&self.key, RENEWAL_DOMAIN, &canon)},
                "private_key_pem": state::key_pem(&tls)});
            state::save_json(&path, &p)?;
            p
        };
        let (code, raw) = self.post_raw("/api/v1/machine/renewals", &pending["request"])?;
        if code == 409 {
            // истёкший challenge — не результат: следующий раз — новый challenge и новый ключ
            std::fs::remove_file(&path).map_err(|e| e.to_string())?;
            return Err("renewal challenge expired; retry with a fresh challenge".into());
        }
        if code != 200 {
            return Err("certificate renewal unavailable".into());
        }
        let result: enroll::EnrollmentResult = serde_json::from_slice(&raw).map_err(|_| "invalid renewal result")?;
        let ca = enroll::read_ca(&self.cfg)?;
        let c = enroll::verify_result(&result, &ca, &self.claims.source, &self.key.verifying_key().to_bytes()).map_err(|_| "renewal identity binding invalid")?;
        let m = &self.claims;
        if c.generation != m.generation || c.tenant != m.tenant || c.kind != m.kind || c.collector != m.collector || c.key_id != m.key_id || c.center_key_id != m.center_key_id || c.center_public != m.center_public {
            return Err("renewal identity binding invalid".into());
        }
        let private = pending["private_key_pem"].as_str().ok_or("invalid private credential state")?.to_string();
        let tls = SigningKey::from_pkcs8_pem_compat(&private)?;
        let leaf = pem::parse_many(&result.certificate_chain_pem).map_err(|_| "invalid chain")?.into_iter().next().ok_or("invalid chain")?;
        let (_, cert) = x509_parser::parse_x509_certificate(leaf.contents()).map_err(|_| "invalid chain")?;
        if cert.public_key().subject_public_key.data.as_ref() != tls.verifying_key().to_bytes() {
            return Err("renewal TLS key mismatch".into());
        }
        state::save_json(&self.state_dir().join("tls-identity.json"), &RotatedIdentity { result, private_key_pem: private })?;
        std::fs::remove_file(&path).map_err(|e| e.to_string())?;
        // новое соединение с новым сертификатом
        *self = Client::open(self.cfg.clone())?;
        Ok(())
    }
}

trait FromPem {
    fn from_pkcs8_pem_compat(pem: &str) -> Result<SigningKey, String>;
}

impl FromPem for SigningKey {
    fn from_pkcs8_pem_compat(pem: &str) -> Result<SigningKey, String> {
        use ed25519_dalek::pkcs8::DecodePrivateKey;
        SigningKey::from_pkcs8_pem(pem.trim()).map_err(|_| "invalid renewal key".into())
    }
}
