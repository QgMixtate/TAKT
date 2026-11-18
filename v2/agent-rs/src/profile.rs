//! Профиль источника (C52.02) — как sourceprofile.Poll/Cached и agent.PollProfile в Go: подписанный запрос с nonce и
//! диагностикой, ответ подписан ключом центра из сертификата, откат ревизии и подмена конфигурации отвергаются,
//! принятый управляемый профиль кэшируется в profile.json (тот же файл, что у Go-агента).

use crate::{canonical, client::{now_rfc3339, Client}, sign, state};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::VerifyingKey;
use serde_json::{json, Value};
use std::time::SystemTime;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

pub const REQUEST_DOMAIN: &[u8] = b"SURVEYSCAN-PROFILE-REQUEST-V1\n";
pub const RESPONSE_DOMAIN: &[u8] = b"SURVEYSCAN-PROFILE-V1\n";

/// Диагностика для центра: очередь на диске (*.pending) и срок сертификата — как telemetry.Snapshot.
pub fn diagnostics(spool: &std::path::Path, cert_expires: OffsetDateTime) -> Result<Value, String> {
    let (mut files, mut bytes, mut oldest): (u64, u64, Option<SystemTime>) = (0, 0, None);
    if let Ok(dir) = std::fs::read_dir(spool) {
        for (i, entry) in dir.enumerate() {
            if i > 100_000 {
                return Err("spool diagnostic file bound exceeded".into());
            }
            let entry = entry.map_err(|e| e.to_string())?;
            if !entry.file_name().to_string_lossy().ends_with(".pending") {
                continue;
            }
            let meta = entry.metadata().map_err(|e| e.to_string())?;
            if !meta.is_file() {
                return Err("spool diagnostic requires regular records".into());
            }
            files += 1;
            bytes += meta.len();
            let at = meta.modified().map_err(|e| e.to_string())?;
            oldest = Some(oldest.map_or(at, |o| o.min(at)));
        }
    }
    let fmt = |t: OffsetDateTime| t.format(&Rfc3339).unwrap_or_default();
    Ok(json!({"collected_at": now_rfc3339(), "pending_files": files, "pending_bytes": bytes,
        "oldest_pending_at": oldest.map(|t| fmt(OffsetDateTime::from(t))), "disk_available_bytes": Value::Null,
        "certificate_expires_at": fmt(cert_expires)}))
}

fn str_of<'a>(v: &'a Value, path: &[&str]) -> &'a str {
    let mut cur = v;
    for k in path {
        cur = &cur[*k];
    }
    cur.as_str().unwrap_or_default()
}

/// Проверка подписанного профиля — как sourceprofile.VerifyResponse (fresh — ответ на только что отправленный запрос).
pub fn verify_response(c: &Client, raw: &[u8], nonce: &str, fresh: bool) -> Result<Value, String> {
    let frame: Value = serde_json::from_slice(raw).map_err(|_| "invalid profile")?;
    let payload = frame.get("payload").ok_or("invalid profile")?;
    let canon = canonical::canonical_value(payload)?;
    let public = VerifyingKey::from_bytes(c.claims.center_public.as_slice().try_into().map_err(|_| "invalid profile")?).map_err(|_| "invalid profile")?;
    if frame["key_id"].as_str() != Some(c.claims.center_key_id.as_str()) || frame["digest"].as_str() != Some(sign::digest_hex(&canon).as_str())
        || !sign::verify(&public, RESPONSE_DOMAIN, &canon, frame["signature"].as_str().unwrap_or_default())
    {
        return Err("profile signature invalid".into());
    }
    let p = payload;
    let cfg = &p["config"];
    let revision = str_of(cfg, &["profile_revision"]);
    let managed = p["managed"].as_bool().ok_or("invalid profile")?;
    if p["schema_version"]["major"] != 1 || p["schema_version"]["minor"] != 0 || str_of(p, &["tenant_id"]) != c.claims.tenant
        || str_of(p, &["origin", "source_id"]) != c.claims.source || str_of(p, &["origin", "source_kind"]) != c.claims.kind
        || str_of(p, &["origin", "generation_id"]) != c.claims.generation || str_of(p, &["nonce"]) != nonce
        || str_of(cfg, &["source_id"]) != c.claims.source || managed != (revision != "1") || revision.parse::<u64>().is_err()
    {
        return Err("profile binding invalid".into());
    }
    match cfg["collector_id"].as_str() {
        None if cfg["collector_id"].is_null() && c.claims.collector.is_empty() => {}
        Some(id) if id == c.claims.collector => {}
        _ => return Err("profile collector mismatch".into()),
    }
    let t = |k: &str| OffsetDateTime::parse(str_of(p, &[k]), &Rfc3339).map_err(|_| "invalid profile".to_string());
    let (issued, expires) = (t("issued_at")?, t("expires_at")?);
    let now = OffsetDateTime::now_utc();
    if expires <= issued || expires - issued > time::Duration::minutes(5) || (fresh && (now >= expires || issued > now + time::Duration::seconds(30))) {
        return Err("profile expired".into());
    }
    Ok(p.clone())
}

/// Последний принятый профиль из profile.json (если есть) — проверяется подпись и привязка, без требования свежести.
pub fn cached(c: &Client) -> Result<Option<Value>, String> {
    let path = c.state_dir().join("profile.json");
    let raw = match std::fs::read(&path) {
        Ok(r) if r.len() <= 65536 => r,
        Ok(_) => return Err("invalid cached profile".into()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.to_string()),
    };
    let frame: Value = serde_json::from_slice(&raw).map_err(|_| "invalid cached profile")?;
    let nonce = str_of(&frame["payload"], &["nonce"]).to_string();
    verify_response(c, &raw, &nonce, false).map(Some)
}

/// Запрос профиля. Возвращает (payload, изменилась ли управляемая ревизия). Управляемый профиль записывается
/// в profile.json; откат ревизии и другой конфиг под той же ревизией отвергаются.
pub fn poll(c: &mut Client, current: Option<&Value>) -> Result<(Value, bool), String> {
    crate::client::verify_binding(&c.state_dir(), &c.claims.source, &c.key)?;
    let diag = diagnostics(&c.state_dir().join("spool"), c.expires)?;
    state::save_json(&c.state_dir().join("diagnostics.json"), &diag)?;
    let applied = current.filter(|p| p["managed"] == true).map(|p| p["config"]["profile_revision"].clone()).unwrap_or(Value::Null);
    let mut random = [0u8; 32];
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut random);
    let nonce = URL_SAFE_NO_PAD.encode(random);
    let req = json!({"schema_version": {"major": 1, "minor": 1}, "tenant_id": c.claims.tenant,
        "origin": {"source_id": c.claims.source, "source_kind": c.claims.kind, "generation_id": c.claims.generation},
        "nonce": nonce, "sent_at": now_rfc3339(), "applied_revision": applied, "diagnostics": diag});
    let (code, raw) = c.post_raw("/api/v1/machine/profile", &c.signed(&req, REQUEST_DOMAIN)?)?;
    if code != 200 {
        return Err("profile center unavailable; last valid profile retained".into());
    }
    let next = verify_response(c, &raw, &nonce, true)?;
    if let Some(cur) = current {
        let rev = |p: &Value| p["config"]["profile_revision"].as_str().and_then(|s| s.parse::<u64>().ok()).unwrap_or(0);
        if rev(&next) < rev(cur) {
            return Err("profile rollback refused".into());
        }
        if rev(&next) == rev(cur) && next["config"] != cur["config"] {
            return Err("profile revision conflict".into());
        }
    }
    let managed = next["managed"] == true;
    let changed = managed && current.map_or(true, |cur| cur["config"]["profile_revision"] != next["config"]["profile_revision"]);
    if managed {
        state::write_atomic(&c.state_dir().join("profile.json"), &raw)?;
        apply(c, &next);
    }
    Ok((next, changed))
}

/// Интервалы из управляемого профиля — в действующую конфигурацию клиента (как applyProfile).
pub fn apply(c: &mut Client, p: &Value) {
    if p["managed"] != true {
        return;
    }
    let cfg = &p["config"];
    let n = |k: &str| cfg[k].as_i64();
    if let (Some(h), Some(i), Some(j), Some(s)) = (n("heartbeat_seconds"), n("inventory_seconds"), n("jitter_percent"), n("spool_limit_bytes")) {
        c.cfg.heartbeat_seconds = h;
        c.cfg.inventory_seconds = i;
        c.cfg.jitter_percent = j;
        c.cfg.spool_limit_bytes = s;
    }
}
