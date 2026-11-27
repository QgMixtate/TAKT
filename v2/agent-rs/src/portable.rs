//! Portable-аудит (C52.03) — формат C23 как internal/portable и internal/portableaudit в Go: личность в каталоге
//! (identity.json, signing.key — seed base64, sequence, center.pub), подписанные наблюдения 1.2, ZIP с подписанным
//! каноническим манифестом, шифрование всего пакета HPKE (X25519/HKDF-SHA256/AES-256-GCM) ключом центра.

use crate::{canonical, client::now_rfc3339, sign, state};
use base64::{engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD}, Engine};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::Path;

pub const OBSERVATION_DOMAIN: &[u8] = b"SURVEYSCAN-OBSERVATION-V1\n";
pub const MANIFEST_DOMAIN: &[u8] = b"SURVEYSCAN-PORTABLE-MANIFEST-V1\n";
pub const ENC_MAGIC: &[u8] = b"SURVEYSCAN-PORTABLE-ENC-V1\n";

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Identity {
    pub tenant_id: String,
    pub site_id: String,
    pub network_scope_id: String,
    pub source_id: String,
    pub generation_id: String,
    pub key_id: String,
}

/// Идентификатор ключа: первые 16 байт SHA-256 открытого ключа в форме UUID.
pub fn key_id(public: &[u8]) -> String {
    let h = sign::hex(&Sha256::digest(public)[..16]);
    format!("{}-{}-{}-{}-{}", &h[..8], &h[8..12], &h[12..16], &h[16..20], &h[20..])
}

/// Идентификатор ключа шифрования центра: первые 16 байт SHA-256 (hex).
pub fn encryption_key_id(public: &[u8]) -> String {
    sign::hex(&Sha256::digest(public)[..16])
}

fn write_private(dir: &Path, name: &str, raw: &[u8]) -> Result<(), String> {
    state::write_atomic(&dir.join(name), raw)
}

/// №58: идентификатор, вставленный из Web/мессенджера, часто приходит с пробелами, кавычками, «ёлочками» или
/// невидимыми символами — оставляются только шестнадцатеричные цифры и дефисы.
pub fn clean_id(raw: &str) -> String {
    raw.chars().filter(|c| c.is_ascii_hexdigit() || *c == '-').collect::<String>().to_ascii_lowercase()
}

/// Строка подготовки носителя из Web (C52.04, мастер — шаг 1): `takt-portable:v1:` + base64url(JSON) с площадкой,
/// сегментом и (необязательно) ключом шифрования центра. Секретов в ней нет: это те же значения, что в командах Web.
#[derive(Debug, Deserialize, PartialEq)]
pub struct Prep {
    pub tenant: String,
    pub site: String,
    pub scope: String,
    #[serde(default)]
    pub center_key: Option<String>,
    #[serde(default)]
    pub site_name: Option<String>,
    #[serde(default)]
    pub scope_name: Option<String>,
}

pub const PREP_PREFIX: &str = "takt-portable:v1:";

pub fn parse_prep(text: &str) -> Result<Prep, String> {
    let body = text.trim().strip_prefix(PREP_PREFIX).ok_or("строка подготовки должна начинаться с takt-portable:v1: (скопируйте её из Web целиком)")?;
    let raw = URL_SAFE_NO_PAD.decode(body.trim_end_matches('=')).map_err(|_| "строка подготовки повреждена (скопируйте её из Web целиком)")?;
    if raw.len() > 4096 {
        return Err("строка подготовки слишком длинная".into());
    }
    let p: Prep = serde_json::from_slice(&raw).map_err(|_| "строка подготовки повреждена")?;
    if ![&p.tenant, &p.site, &p.scope].iter().all(|v| crate::claims::valid_id(v)) {
        return Err("строка подготовки: неверные идентификаторы".into());
    }
    if p.site_name.as_ref().is_some_and(|n| n.len() > 256) || p.scope_name.as_ref().is_some_and(|n| n.len() > 256) {
        return Err("строка подготовки: слишком длинное имя".into());
    }
    Ok(p)
}

pub fn init(dir: &Path, tenant: &str, site: &str, scope: &str) -> Result<(Identity, VerifyingKey), String> {
    let (tenant, site, scope) = (clean_id(tenant), clean_id(site), clean_id(scope));
    let (tenant, site, scope) = (tenant.as_str(), site.as_str(), scope.as_str());
    for (name, v) in [("tenant_id", tenant), ("site_id", site), ("scope_id", scope)] {
        if !crate::claims::valid_id(v) {
            return Err(format!("portable: {name} must be a UUID issued by the centre (xxxxxxxx-xxxx-4xxx-xxxx-xxxxxxxxxxxx), got {} characters after cleanup", v.len()));
        }
    }
    if dir.join("identity.json").exists() {
        return Err("portable: state directory already initialised".into());
    }
    state::ensure_dir(dir)?;
    let key = SigningKey::generate(&mut rand_core::OsRng);
    let id = Identity { tenant_id: tenant.into(), site_id: site.into(), network_scope_id: scope.into(), source_id: state::new_id(), generation_id: state::new_id(), key_id: key_id(&key.verifying_key().to_bytes()) };
    write_private(dir, "signing.key", STANDARD.encode(key.to_bytes()).as_bytes())?;
    write_private(dir, "identity.json", serde_json::to_string_pretty(&id).map_err(|e| e.to_string())?.as_bytes())?;
    Ok((id, key.verifying_key()))
}

pub fn load(dir: &Path) -> Result<(Identity, SigningKey), String> {
    let id: Identity = state::load_json(&dir.join("identity.json")).map_err(|_| "portable: identity unavailable (run init)")?;
    if !crate::claims::valid_id(&id.source_id) || !crate::claims::valid_id(&id.generation_id) {
        return Err("portable: identity invalid".into());
    }
    let seed = std::fs::read_to_string(dir.join("signing.key")).map_err(|_| "portable: signing key unavailable")?;
    let seed: [u8; 32] = STANDARD.decode(seed.trim()).ok().and_then(|b| b.try_into().ok()).ok_or("portable: signing key invalid")?;
    let key = SigningKey::from_bytes(&seed);
    if key_id(&key.verifying_key().to_bytes()) != id.key_id {
        return Err("portable: signing key does not match identity".into());
    }
    Ok((id, key))
}

/// Номер наблюдения сохраняется до экспорта: пропуски допустимы, повторы — нет.
fn next_sequence(dir: &Path) -> Result<u64, String> {
    let path = dir.join("sequence");
    let n: u64 = match std::fs::read_to_string(&path) {
        Ok(t) => t.trim().parse().map_err(|_| "portable: sequence file corrupt")?,
        Err(_) => 0,
    };
    write_private(dir, "sequence", (n + 1).to_string().as_bytes())?;
    Ok(n + 1)
}

pub fn set_center_key(dir: &Path, b64: &str) -> Result<String, String> {
    let public: [u8; 32] = STANDARD.decode(b64.trim()).ok().and_then(|b| b.try_into().ok()).ok_or("portable: centre encryption key must be base64 of 32 bytes")?;
    seal(&public, b"probe").map_err(|_| "portable: centre encryption key invalid")?;
    if let Some(existing) = center_key(dir)? {
        return if existing == public { Ok(encryption_key_id(&public)) } else { Err("portable: another centre encryption key is already set for this state directory".into()) };
    }
    write_private(dir, "center.pub", STANDARD.encode(public).as_bytes())?;
    Ok(encryption_key_id(&public))
}

pub fn center_key(dir: &Path) -> Result<Option<[u8; 32]>, String> {
    match std::fs::read_to_string(dir.join("center.pub")) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err("portable: centre key file unavailable".into()),
        Ok(t) => STANDARD.decode(t.trim()).ok().and_then(|b| b.try_into().ok()).map(Some).ok_or_else(|| "portable: centre key file corrupt".into()),
    }
}

/// Подписанное наблюдение: payload — каноническая форма как есть (как SignObservation в Go).
pub fn sign_observation(key: &SigningKey, payload: &Value) -> Result<(String, Vec<u8>), String> {
    let c = canonical::canonical_value(payload)?;
    let text = String::from_utf8(c.clone()).map_err(|_| "canonical form invalid")?;
    let raw = format!(r#"{{"payload":{},"digest":"{}","key_id":"{}","signature":"{}"}}"#, text, sign::digest_hex(&c), key_id(&key.verifying_key().to_bytes()), sign::sign(key, OBSERVATION_DOMAIN, &c));
    Ok((payload["observation_id"].as_str().unwrap_or_default().to_string(), raw.into_bytes()))
}

/// ZIP без сжатия (метод 0): manifest.json, manifest.sig, obs/<id>.json — читается archive/zip в центре.
fn zip_store(files: &[(String, Vec<u8>)]) -> Vec<u8> {
    let (mut out, mut central) = (Vec::new(), Vec::new());
    for (name, data) in files {
        let crc = crc32fast::hash(data);
        let offset = out.len() as u32;
        let header = |sig: u32, central_dir: bool| {
            let mut h = Vec::new();
            h.extend_from_slice(&sig.to_le_bytes());
            if central_dir {
                h.extend_from_slice(&20u16.to_le_bytes()); // version made by
            }
            h.extend_from_slice(&20u16.to_le_bytes()); // version needed
            h.extend_from_slice(&0x0800u16.to_le_bytes()); // UTF-8 names
            h.extend_from_slice(&0u16.to_le_bytes()); // stored
            h.extend_from_slice(&0u32.to_le_bytes()); // time/date
            h.extend_from_slice(&crc.to_le_bytes());
            h.extend_from_slice(&(data.len() as u32).to_le_bytes());
            h.extend_from_slice(&(data.len() as u32).to_le_bytes());
            h.extend_from_slice(&(name.len() as u16).to_le_bytes());
            h.extend_from_slice(&0u16.to_le_bytes()); // extra
            if central_dir {
                h.extend_from_slice(&[0u8; 6]); // comment length, disk start, internal attrs
                h.extend_from_slice(&0u32.to_le_bytes()); // external attrs
                h.extend_from_slice(&offset.to_le_bytes());
            }
            h.extend_from_slice(name.as_bytes());
            h
        };
        out.extend(header(0x04034b50, false));
        out.extend_from_slice(data);
        central.extend(header(0x02014b50, true));
    }
    let cd_offset = out.len() as u32;
    out.extend_from_slice(&central);
    out.extend_from_slice(&0x06054b50u32.to_le_bytes());
    out.extend_from_slice(&[0u8; 4]);
    out.extend_from_slice(&(files.len() as u16).to_le_bytes());
    out.extend_from_slice(&(files.len() as u16).to_le_bytes());
    out.extend_from_slice(&(central.len() as u32).to_le_bytes());
    out.extend_from_slice(&cd_offset.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

/// Пакет C23: канонический манифест, подпись манифеста (base64), наблюдения по id.
pub fn write_package(key: &SigningKey, id: &Identity, observations: &[(String, Vec<u8>)]) -> Result<Vec<u8>, String> {
    write_package_with(key, id, observations, None)
}

/// То же с discovery.json (C23.04): файл перечислен в манифесте (sha256, размер) и покрыт его подписью.
pub fn write_package_with(key: &SigningKey, id: &Identity, observations: &[(String, Vec<u8>)], discovery: Option<&[u8]>) -> Result<Vec<u8>, String> {
    let mut items: Vec<(String, Vec<u8>)> = observations.to_vec();
    items.sort_by(|a, b| a.0.cmp(&b.0));
    let manifest = json!({"format_version": 1, "tenant_id": id.tenant_id, "source_id": id.source_id, "key_id": id.key_id, "created_at": now_rfc3339(),
        "observations": items.iter().map(|(i, raw)| json!({"observation_id": i, "sha256": sign::hex(&Sha256::digest(raw)), "size": raw.len()})).collect::<Vec<_>>()});
    let mut manifest = manifest;
    if let Some(d) = discovery {
        manifest["discovery"] = json!({"sha256": sign::hex(&Sha256::digest(d)), "size": d.len()});
    }
    let canon = canonical::canonical_value(&manifest)?;
    let mut msg = MANIFEST_DOMAIN.to_vec();
    msg.extend_from_slice(&canon);
    let sig = STANDARD.encode(key.sign(&msg).to_bytes());
    let mut files = vec![("manifest.json".to_string(), canon), ("manifest.sig".to_string(), sig.into_bytes())];
    if let Some(d) = discovery {
        files.push(("discovery.json".to_string(), d.to_vec()));
    }
    files.extend(items.into_iter().map(|(i, raw)| (format!("obs/{i}.json"), raw)));
    Ok(zip_store(&files))
}

type Kem = hpke::kem::X25519HkdfSha256;

/// Конверт: EncMagic | key_id (16 байт) | HPKE enc || ciphertext; info = EncMagic | key_id.
pub fn seal(public: &[u8; 32], plain: &[u8]) -> Result<Vec<u8>, String> {
    use hpke::{Deserializable, Serializable};
    let pk = <Kem as hpke::Kem>::PublicKey::from_bytes(public).map_err(|_| "invalid centre key")?;
    let mut head = ENC_MAGIC.to_vec();
    head.extend_from_slice(&Sha256::digest(public)[..16]);
    let (enc, ct) = hpke::single_shot_seal::<hpke::aead::AesGcm256, hpke::kdf::HkdfSha256, Kem, _>(&hpke::OpModeS::Base, &pk, &head, plain, b"", &mut rand_core::OsRng).map_err(|_| "encryption failed")?;
    let mut out = head;
    out.extend_from_slice(&enc.to_bytes());
    out.extend_from_slice(&ct);
    Ok(out)
}

pub fn encrypted(data: &[u8]) -> bool {
    data.starts_with(ENC_MAGIC)
}

/// Наблюдение этого хоста или удалённой цели (record — kind:name, часы — estimated, как в Go).
pub fn observation(dir: &Path, id: &Identity, kind: &str, name: &str, candidates: &Value, mut sections: Vec<Value>) -> Result<Value, String> {
    let seq = next_sequence(dir)?;
    let collected = now_rfc3339();
    for s in sections.iter_mut() {
        if s["collected_at"].as_str().map(|t| t > collected.as_str()).unwrap_or(false) {
            s["collected_at"] = collected.clone().into();
        }
    }
    Ok(json!({"schema_version": {"major": 1, "minor": 2}, "observation_id": state::new_id(), "tenant_id": id.tenant_id,
        "origin": {"source_id": id.source_id, "source_kind": "portable", "generation_id": id.generation_id},
        "source_record": {"namespace": "host", "source_local_id": format!("{kind}:{name}")}, "scope": {"site_id": id.site_id, "network_scope_id": id.network_scope_id},
        "source_sequence": seq.to_string(), "collected_at": collected, "clock_quality": "estimated", "identity_candidates": candidates, "sections": sections}))
}

/// Публикация без перезаписи: временный файл, затем жёсткая ссылка (или переименование, если ФС без ссылок).
pub fn publish(out: &Path, data: &[u8]) -> Result<(), String> {
    if out.exists() {
        return Err(format!("portable: {} already exists (packages are never overwritten)", out.display()));
    }
    let tmp = out.with_extension("partial");
    let _ = std::fs::remove_file(&tmp);
    {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new().write(true).create_new(true).open(&tmp).map_err(|e| e.to_string())?;
        f.write_all(data).and_then(|_| f.sync_all()).map_err(|e| e.to_string())?;
    }
    let r = std::fs::hard_link(&tmp, out).or_else(|_| if out.exists() { Err(std::io::ErrorKind::AlreadyExists.into()) } else { std::fs::rename(&tmp, out) });
    let _ = std::fs::remove_file(&tmp);
    r.map_err(|e| e.to_string())
}

pub fn public_b64url(key: &VerifyingKey) -> String {
    URL_SAFE_NO_PAD.encode(key.to_bytes())
}

pub const DISCOVERY_FILE: &str = "discovery-last.json";

/// discovery.json для пакета (C23.04) из последнего обследования: исход по каждому узлу — из outcomes (ip → исход,
/// причина, профиль, наблюдение); узлы без записи — no_profile.
pub fn discovery_doc(last: &Value, outcomes: &std::collections::HashMap<String, Value>) -> Result<Vec<u8>, String> {
    let hosts: Vec<Value> = last["hosts"].as_array().ok_or("discovery invalid")?.iter().map(|h| {
        let mut row = serde_json::Map::new();
        for k in ["ip", "ports", "kind"] {
            row.insert(k.into(), h[k].clone());
        }
        match outcomes.get(h["ip"].as_str().unwrap_or_default()) {
            Some(Value::Object(o)) => {
                for (k, v) in o {
                    row.insert(k.clone(), v.clone());
                }
            }
            _ => {
                row.insert("outcome".into(), "no_profile".into());
            }
        }
        Value::Object(row)
    }).collect();
    let doc = json!({"schema_version": {"major": 1, "minor": 0}, "ranges": last["ranges"], "excluded": last["excluded"], "started_at": last["started_at"],
        "finished_at": last["finished_at"], "complete": last["complete"], "hosts": hosts});
    serde_json::to_vec(&doc).map_err(|e| e.to_string())
}

#[cfg(test)]
mod clean_id_tests {
    #[test]
    fn pasted_ids_are_cleaned() {
        let id = "00000000-0000-4000-8000-000000000001";
        for raw in [format!(" {id}\n"), format!("«{id}»"), format!("\"{id}\""), format!("\u{200b}{id}\u{feff}"), id.to_uppercase()] {
            assert_eq!(super::clean_id(&raw), id);
        }
        assert!(!crate::claims::valid_id(&super::clean_id("site 42")));
    }
}

#[cfg(test)]
mod prep_tests {
    use super::*;
    #[test]
    fn preparation_string_round_trip_and_rejections() {
        let j = r#"{"tenant":"00000000-0000-4000-8000-000000000001","site":"00000000-0000-4000-8000-000000000002","scope":"00000000-0000-4000-8000-000000000003","center_key":"MCowBQYDK2VuAyEA","site_name":"Москва"}"#;
        let s = format!("{PREP_PREFIX}{}", URL_SAFE_NO_PAD.encode(j));
        let p = parse_prep(&format!("  {s}\n")).unwrap();
        assert_eq!(p.site_name.as_deref(), Some("Москва"));
        assert_eq!(p.center_key.as_deref(), Some("MCowBQYDK2VuAyEA"));
        assert!(parse_prep("tenant=1").is_err());
        assert!(parse_prep(&format!("{PREP_PREFIX}!!!")).is_err());
        let bad = format!("{PREP_PREFIX}{}", URL_SAFE_NO_PAD.encode(r#"{"tenant":"x","site":"y","scope":"z"}"#));
        assert!(parse_prep(&bad).is_err());
    }
}
