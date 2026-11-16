//! Конфигурация агента, enroll через collector и установка по коду — как agent.Enroll/agent.Register в Go.

use crate::{claims, machineid, state, tls};
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub tenant_id: String,
    pub site_id: String,
    pub network_scope_id: String,
    pub collector_url: String,
    pub collector_source_id: String,
    pub ca_certificate_file: String,
    pub state_directory: String,
    pub inventory_seconds: i64,
    pub heartbeat_seconds: i64,
    pub jitter_percent: i64,
    pub spool_limit_bytes: i64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub inventory_platform: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    pub grant_id: String,
    pub source_id: String,
    pub expires_at: String,
    pub enrollment_token: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentResult {
    pub source_id: String,
    pub generation_id: String,
    pub certificate_chain_pem: String,
    pub expires_at: String,
    pub signing_key_id: String,
    pub center_result_key_id: String,
    pub center_result_public_key: String,
}

#[derive(Deserialize, Debug)]
struct Registration {
    grant: Grant,
    tenant_id: String,
    site_id: String,
    network_scope_id: String,
    collector_source_id: Option<String>,
}

pub fn read_ca(c: &Config) -> Result<Vec<u8>, String> {
    let raw = std::fs::read_to_string(&c.ca_certificate_file).map_err(|_| "agent trusted CA unavailable")?;
    Ok(pem::parse(raw).map_err(|_| "agent trusted CA invalid")?.contents().to_vec())
}

fn chain_der(pem_chain: &str) -> Result<Vec<CertificateDer<'static>>, String> {
    let all = pem::parse_many(pem_chain).map_err(|_| "invalid chain")?;
    if all.is_empty() || all.iter().any(|p| p.tag() != "CERTIFICATE") {
        return Err("invalid chain".into());
    }
    Ok(all.into_iter().map(|p| CertificateDer::from(p.into_contents())).collect())
}

/// Проверка ответа enroll — как pki.VerifyEnrollmentResult: цепочка до УЦ (клиентское назначение), утверждения
/// совпадают с источником и ключом подписи, срок сертификата = expires_at.
pub fn verify_result(r: &EnrollmentResult, ca: &[u8], source: &str, signing_public: &[u8]) -> Result<claims::Claims, String> {
    if r.source_id != source || r.certificate_chain_pem.len() > 32768 {
        return Err("invalid".into());
    }
    let chain = chain_der(&r.certificate_chain_pem)?;
    tls::verify_chain(ca, &chain, true)?;
    let c = claims::from_der(&chain[0])?;
    let (_, cert) = x509_parser::parse_x509_certificate(&chain[0]).map_err(|_| "certificate")?;
    let expires = time::OffsetDateTime::parse(&r.expires_at, &time::format_description::well_known::Rfc3339).map_err(|_| "expires_at")?;
    use base64::Engine;
    if c.source != source || c.generation != r.generation_id || c.key_id != r.signing_key_id || c.center_key_id != r.center_result_key_id
        || c.signing_public != signing_public || base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&c.center_public) != r.center_result_public_key
        || cert.validity().not_after.timestamp() != expires.unix_timestamp()
    {
        return Err("enrollment identity not trusted".into());
    }
    Ok(c)
}

fn key_der(state: &Path, name: &str) -> Result<PrivateKeyDer<'static>, String> {
    let raw = std::fs::read_to_string(state.join(name)).map_err(|e| e.to_string())?;
    Ok(PrivateKeyDer::Pkcs8(pem::parse(raw).map_err(|_| "invalid agent key")?.into_contents().into()))
}

/// Enroll через collector (Bearer — токен grant): проверка ответа, привязка к назначенному collector, identity.json.
pub fn enroll(c: &Config, grant: &Grant) -> Result<(), String> {
    let st = PathBuf::from(&c.state_directory);
    let prep: state::Preparation = state::load_json(&st.join("preparation.json"))?;
    if prep.source_id != grant.source_id {
        return Err("enrollment grant source mismatch".into());
    }
    let signing = state::read_key(&st.join("signing.key"))?;
    let machine = machineid::local().ok_or("stable local machine identity unavailable")?;
    let b: state::HostBinding = state::load_json(&st.join("host-binding.json"))?;
    if b != state::binding(&prep.source_id, &machine, &signing) {
        return Err("agent host continuity mismatch".into());
    }
    let ca = read_ca(c)?;
    let client = tls::collector_agent(tls::CollectorVerifier::new(ca.clone(), &c.tenant_id, &c.collector_source_id, ""), None)?;
    let body = serde_json::json!({"grant_id": grant.grant_id, "source_id": prep.source_id, "csr_pem": prep.csr_pem, "signing_public_key": prep.signing_public_key});
    let resp = client.post(&format!("{}/api/v1/machine/enroll", c.collector_url)).set("Authorization", &format!("Bearer {}", grant.enrollment_token)).send_json(body);
    let resp = match resp {
        Ok(r) if r.status() == 201 => r,
        Ok(r) => return Err(format!("agent enrollment rejected: {}", r.status())),
        Err(ureq::Error::Status(code, _)) => return Err(format!("agent enrollment rejected: {code}")),
        Err(e) => return Err(format!("collector unavailable or identity rejected: {e}")),
    };
    let result: EnrollmentResult = serde_json::from_reader(std::io::Read::take(resp.into_reader(), 2 << 20)).map_err(|_| "agent enrollment rejected")?;
    let claims = verify_result(&result, &ca, &prep.source_id, &signing.verifying_key().to_bytes())?;
    if claims.kind != "agent" || claims.tenant != c.tenant_id {
        return Err("enrollment identity not trusted".into());
    }
    // ключ TLS соответствует выданному сертификату, collector — тот, за которым закреплён агент
    let bound = tls::collector_agent(tls::CollectorVerifier::new(ca, &c.tenant_id, &c.collector_source_id, &claims.collector), Some((chain_der(&result.certificate_chain_pem)?, key_der(&st, "tls.key")?)))?;
    match bound.get(&format!("{}/health/live", c.collector_url)).call() {
        Ok(r) if r.status() == 200 => {}
        _ => return Err("enrollment collector assignment mismatch".into()),
    }
    let identity = st.join("identity.json");
    if identity.exists() {
        let old: EnrollmentResult = state::load_json(&identity)?;
        return if serde_json::to_value(&old).ok() == serde_json::to_value(&result).ok() { Ok(()) } else { Err("existing identity cannot be replaced".into()) };
    }
    state::save_json(&identity, &result)
}

pub struct RegisterOptions {
    pub collector_url: String,
    pub code: String,
    pub fingerprint: String,
    pub config_path: PathBuf,
    pub state_dir: PathBuf,
    pub hostname: String,
}

/// Установка по коду: УЦ по отпечатку → prepare → регистрация (через collector) → конфигурация → enroll.
pub fn register(o: &RegisterOptions) -> Result<(), String> {
    let url = o.collector_url.trim_end_matches('/').to_string();
    if !url.starts_with("https://") || !o.state_dir.is_absolute() || !o.config_path.is_absolute() {
        return Err("адрес collector https://host:port, каталоги — абсолютные".into());
    }
    if o.config_path.exists() {
        return Err("конфигурация уже существует: агент зарегистрирован (удалите её только для переустановки)".into());
    }
    let ca = tls::fetch_pinned_ca(&url, &o.fingerprint)?;
    let machine = machineid::local().ok_or("stable local machine identity unavailable")?;
    let prep = state::prepare(&o.state_dir, &machine)?;
    let ca_path = o.state_dir.join("ca.pem");
    state::write_atomic(&ca_path, pem::encode_config(&pem::Pem::new("CERTIFICATE", ca.clone()), pem::EncodeConfig::new().set_line_ending(pem::LineEnding::LF)).as_bytes())?;
    let platform = if cfg!(windows) { "windows/amd64" } else { "linux/amd64" };
    let client = tls::collector_agent(tls::CollectorVerifier::new(ca, "", "", ""), None)?;
    let body = serde_json::json!({"registration_code": o.code, "source_id": prep.source_id, "csr_sha256": prep.csr_sha256, "signing_public_key": prep.signing_public_key, "hostname": o.hostname, "inventory_platform": platform});
    let reg: Registration = match client.post(&format!("{url}/api/v1/registration")).send_json(body) {
        Ok(r) if r.status() == 201 => serde_json::from_reader(std::io::Read::take(r.into_reader(), 65536)).map_err(|_| "неверный ответ центра")?,
        Err(ureq::Error::Status(401, _)) => return Err("код не принят: неверный, просрочен, отозван или исчерпан".into()),
        Err(ureq::Error::Status(409, r)) => {
            let body = r.into_string().unwrap_or_default();
            return Err(if body.contains("ALREADY_REGISTERED") { "эта машина уже зарегистрирована этим кодом".into() } else { format!("регистрация отклонена: 409 {body}") });
        }
        Err(ureq::Error::Status(code, _)) => return Err(format!("регистрация отклонена: {code}")),
        Ok(r) => return Err(format!("регистрация отклонена: {}", r.status())),
        Err(e) => return Err(format!("нет связи: {e}")),
    };
    let collector = reg.collector_source_id.filter(|x| claims::valid_id(x)).ok_or("код выдан не для агента")?;
    if reg.grant.source_id != prep.source_id {
        return Err("код выдан не для агента".into());
    }
    let cfg = Config {
        tenant_id: reg.tenant_id, site_id: reg.site_id, network_scope_id: reg.network_scope_id, collector_url: url, collector_source_id: collector,
        ca_certificate_file: ca_path.to_string_lossy().into(), state_directory: o.state_dir.to_string_lossy().into(), ..Default::default()
    };
    let grant_path = o.state_dir.join("registration-grant.json");
    state::save_json(&grant_path, &reg.grant)?; // при обрыве enroll можно повторить, регистрацию тем же CSR — нет
    state::save_json(&o.config_path, &cfg)?;
    enroll(&cfg, &reg.grant).map_err(|e| format!("регистрация прошла, enroll не завершён ({e}); повторите enroll --grant-file {}", grant_path.display()))?;
    let _ = std::fs::remove_file(grant_path);
    Ok(())
}
