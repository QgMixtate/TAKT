//! Каталог состояния агента — тот же формат, что у Go-агента (preparation.json, signing.key, tls.key,
//! sequences.json, host-binding.json): Rust-агент заменяет Go-агента на той же машине без перерегистрации.

use crate::{der, sign};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{pkcs8::DecodePrivateKey, SigningKey};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{fs, io::Write, path::Path};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Preparation {
    pub source_id: String,
    pub csr_pem: String,
    pub csr_sha256: String,
    pub signing_public_key: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct Counters {
    pub inventory: String,
    pub heartbeat: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct HostBinding {
    pub version: u32,
    pub digest: String,
}

/// Новый идентификатор (UUID v4, нижний регистр) — как identifier.New в Go.
pub fn new_id() -> String {
    let mut b = [0u8; 16];
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut b);
    b[6] = (b[6] & 15) | 64;
    b[8] = (b[8] & 63) | 128;
    let h = sign::hex(&b);
    format!("{}-{}-{}-{}-{}", &h[0..8], &h[8..12], &h[12..16], &h[16..20], &h[20..32])
}

pub fn binding(source: &str, machine: &str, key: &SigningKey) -> HostBinding {
    let mut m = Hmac::<Sha256>::new_from_slice(&key.to_bytes()).expect("hmac key");
    m.update(format!("SURVEYSCAN-HOST-BINDING-V1\n{source}\n{machine}").as_bytes());
    HostBinding { version: 1, digest: sign::hex(&m.finalize().into_bytes()) }
}

/// PKCS#8 v1 (без открытого ключа) — побайтно как x509.MarshalPKCS8PrivateKey в Go.
pub fn key_pem(key: &SigningKey) -> String {
    let mut der = vec![0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20];
    der.extend_from_slice(&key.to_bytes());
    pem::encode_config(&pem::Pem::new("PRIVATE KEY", der), pem::EncodeConfig::new().set_line_ending(pem::LineEnding::LF))
}

pub fn read_key(path: &Path) -> Result<SigningKey, String> {
    let raw = fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    SigningKey::from_pkcs8_pem(raw.trim()).map_err(|_| "invalid agent key".into())
}

/// Атомарная запись 0600 (временный файл в том же каталоге, fsync, rename).
pub fn write_atomic(path: &Path, raw: &[u8]) -> Result<(), String> {
    let dir = path.parent().ok_or("no parent")?;
    let tmp = dir.join(format!(".spool-{}", new_id()));
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
    let mut f = opts.open(&tmp).map_err(|e| e.to_string())?;
    let r = f.write_all(raw).and_then(|_| f.sync_all());
    drop(f);
    if let Err(e) = r.and_then(|_| fs::rename(&tmp, path)) {
        let _ = fs::remove_file(&tmp);
        return Err(e.to_string());
    }
    Ok(())
}

pub fn save_json<T: Serialize>(path: &Path, v: &T) -> Result<(), String> {
    write_atomic(path, &serde_json::to_vec(v).map_err(|e| e.to_string())?)
}

pub fn load_json<T: for<'a> Deserialize<'a>>(path: &Path) -> Result<T, String> {
    let raw = fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    serde_json::from_slice(&raw).map_err(|_| "invalid private agent state".into())
}

/// Подготовка личности по ключам (для тестов — детерминированно): CSR CN=untrusted-agent-request.
pub fn preparation_from(source: &str, tls: &SigningKey, signing: &SigningKey) -> Preparation {
    let csr = der::csr_ed25519("untrusted-agent-request", &tls.verifying_key().to_bytes(), |m| {
        ed25519_dalek::Signer::sign(tls, m).to_bytes()
    });
    let pem = pem::encode_config(&pem::Pem::new("CERTIFICATE REQUEST", csr.clone()), pem::EncodeConfig::new().set_line_ending(pem::LineEnding::LF));
    Preparation {
        source_id: source.to_string(),
        csr_pem: pem,
        csr_sha256: sign::hex(&Sha256::digest(&csr)),
        signing_public_key: URL_SAFE_NO_PAD.encode(signing.verifying_key().to_bytes()),
    }
}

const IDENTITY_FILES: [&str; 7] = ["tls.key", "signing.key", "identity.json", "sequences.json", "host-binding.json", "tls-identity.json", "renewal.pending.json"];

/// Prepare — как в Go: повторный вызов возвращает прежнюю подготовку (с проверкой привязки к машине).
pub fn prepare(state: &Path, machine: &str) -> Result<Preparation, String> {
    fs::create_dir_all(state).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    fs::set_permissions(state, std::os::unix::fs::PermissionsExt::from_mode(0o700)).map_err(|e| e.to_string())?;
    let path = state.join("preparation.json");
    if path.exists() {
        let prep: Preparation = load_json(&path)?;
        let key = read_key(&state.join("signing.key"))?;
        let b: HostBinding = load_json(&state.join("host-binding.json"))?;
        if b != binding(&prep.source_id, machine, &key) {
            return Err("agent host continuity mismatch; preserve state and enroll a new source on the replacement host".into());
        }
        return Ok(prep);
    }
    if IDENTITY_FILES.iter().any(|n| state.join(n).exists()) {
        return Err("agent state already contains identity material".into());
    }
    let tls = SigningKey::generate(&mut rand_core::OsRng);
    let signing = SigningKey::generate(&mut rand_core::OsRng);
    write_atomic(&state.join("tls.key"), key_pem(&tls).as_bytes())?;
    write_atomic(&state.join("signing.key"), key_pem(&signing).as_bytes())?;
    let prep = preparation_from(&new_id(), &tls, &signing);
    save_json(&state.join("sequences.json"), &Counters { inventory: "0".into(), heartbeat: "0".into() })?;
    save_json(&state.join("host-binding.json"), &binding(&prep.source_id, machine, &signing))?;
    save_json(&path, &prep)?;
    Ok(prep)
}
