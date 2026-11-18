//! Очередь на диске и доставка (C52.02) — как queueSections12/flushProgress12 и diskspool в Go: подписанный batch 1.2
//! пишется атомарно как <delivery>.pending; удаляется только по подписанному ключом центра результату (receipt) с
//! spool_action=remove для всех записей. Повтор отправляет те же байты (тот же delivery_id и observation_id).

use crate::{canonical, client::{now_rfc3339, Client}, inventory12::Offer, sign, state};
use ed25519_dalek::VerifyingKey;
use serde_json::{json, Value};
use std::{fs, path::{Path, PathBuf}, time::{Duration, SystemTime}};

pub const MAX_FILES: usize = 4096;
pub const ACK_RESERVE: i64 = 65536;
pub const OBSERVATION_DOMAIN: &[u8] = b"SURVEYSCAN-OBSERVATION-V1\n";
pub const CENTER_RESULT_DOMAIN: &[u8] = b"SURVEYSCAN-CENTER-RESULT-V1\n";

fn valid_id(s: &str) -> bool {
    crate::claims::valid_id(s)
}

/// Место в очереди (как diskspool.capacity): старые подтверждения без пакета удаляются при нехватке места или
/// старше 7 суток; иначе — отказ «очередь полна».
pub fn capacity(dir: &Path, limit: i64, incoming: i64, max_files: usize) -> Result<(), String> {
    if limit < 0 || incoming < 0 || incoming > limit {
        return Err("spool full".into());
    }
    let mut used: i64 = 0;
    let mut count = 0usize;
    let mut eligible: Vec<(PathBuf, i64, SystemTime)> = vec![];
    for entry in fs::read_dir(dir).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let ft = entry.file_type().map_err(|e| e.to_string())?;
        if ft.is_symlink() {
            return Err("spool symlink is not permitted".into());
        }
        if ft.is_dir() {
            return Err("unexpected spool subdirectory".into());
        }
        let meta = entry.metadata().map_err(|e| e.to_string())?;
        used += meta.len() as i64;
        count += 1;
        let name = entry.file_name().to_string_lossy().to_string();
        let Some(id) = name.strip_suffix(".receipt") else { continue };
        if !valid_id(id) || dir.join(format!("{id}.pending")).exists() {
            continue;
        }
        eligible.push((entry.path(), meta.len() as i64, meta.modified().unwrap_or(SystemTime::UNIX_EPOCH)));
    }
    eligible.sort_by_key(|e| e.2);
    for (path, size, at) in eligible {
        let old = SystemTime::now().duration_since(at).unwrap_or_default() > Duration::from_secs(7 * 24 * 3600);
        if used + incoming <= limit && count < max_files && !old {
            continue;
        }
        fs::remove_file(&path).map_err(|e| e.to_string())?;
        used -= size;
        count -= 1;
    }
    if used + incoming > limit || count + 1 > max_files {
        return Err("spool full".into());
    }
    Ok(())
}

impl Client {
    pub fn spool(&self) -> PathBuf {
        self.state_dir().join("spool")
    }

    /// Проверки перед сбором: привязка к машине и место под новый пакет (128 КиБ) с резервом под подтверждения.
    pub fn preflight(&self) -> Result<(), String> {
        crate::client::verify_binding(&self.state_dir(), &self.claims.source, &self.key)?;
        state::ensure_dir(&self.spool())?;
        capacity(&self.spool(), self.cfg.spool_limit_bytes - ACK_RESERVE, 131072, MAX_FILES - 2)
    }

    /// Подписанный batch 1.2 из секций сбора → <delivery>.pending. Секции ok/complete в частичной политике — отказ.
    pub fn queue12(&mut self, limits: Offer, candidates: &Value, sections: &[Value], collected: &str) -> Result<String, String> {
        self.preflight()?;
        if sections.iter().any(|s| s["collection_complete"] == true || s["status"] == "ok") {
            return Err("inventory 1.2 batch rejected".into());
        }
        let sequence = self.next(false)?;
        let o = json!({"schema_version": {"major": 1, "minor": 2}, "observation_id": state::new_id(), "tenant_id": self.claims.tenant,
            "origin": {"source_id": self.claims.source, "source_kind": "agent", "generation_id": self.claims.generation},
            "source_record": {"namespace": "host", "source_local_id": "host"}, "scope": {"site_id": self.cfg.site_id, "network_scope_id": self.cfg.network_scope_id},
            "source_sequence": sequence, "collected_at": collected, "clock_quality": "trusted", "identity_candidates": candidates, "sections": sections});
        let canon = canonical::canonical_value(&o)?;
        let canon_text = String::from_utf8(canon.clone()).map_err(|_| "canonical form invalid")?;
        // payload — каноническая форма как есть (как в Go: подписанные байты не пересериализуются)
        let signed = format!(r#"{{"payload":{},"digest":"{}","key_id":{},"signature":"{}"}}"#, canon_text, sign::digest_hex(&canon), Value::from(self.claims.key_id.as_str()), sign::sign(&self.key, OBSERVATION_DOMAIN, &canon));
        if canon.len() as i64 > limits.canonical_bytes || signed.len() as i64 > limits.signed_bytes {
            return Err("inventory observation exceeds negotiated limits".into());
        }
        let delivery = state::new_id();
        let batch = format!(r#"{{"schema_version":{{"major":1,"minor":2}},"tenant_id":{},"delivery_id":"{}","records":[{}]}}"#, Value::from(self.claims.tenant.as_str()), delivery, signed);
        if batch.len() as i64 > limits.batch_bytes {
            return Err("inventory batch exceeds negotiated limits".into());
        }
        state::write_atomic(&self.spool().join(format!("{delivery}.pending")), batch.as_bytes())?;
        Ok(delivery)
    }

    /// Проверка результата центра для пакета — как wire.verifyCenterResult. Возвращает «можно удалить пакет».
    pub fn verify_center_result(&self, raw: &[u8], batch_raw: &[u8]) -> Result<bool, String> {
        let bad = || "center result invalid".to_string();
        let signed: Value = serde_json::from_slice(raw).map_err(|_| bad())?;
        let batch: Value = serde_json::from_slice(batch_raw).map_err(|_| bad())?;
        let p = signed.get("payload").filter(|p| p.is_object()).ok_or_else(bad)?;
        let canon = canonical::canonical_value(p)?;
        let key = VerifyingKey::from_bytes(self.claims.center_public.as_slice().try_into().map_err(|_| bad())?).map_err(|_| bad())?;
        if signed["key_id"].as_str() != Some(self.claims.center_key_id.as_str()) || signed["digest"].as_str() != Some(sign::digest_hex(&canon).as_str())
            || !sign::verify(&key, CENTER_RESULT_DOMAIN, &canon, signed["signature"].as_str().unwrap_or_default())
        {
            return Err(bad());
        }
        let batch_digest = sign::digest_hex(&canonical::canonical(batch_raw)?);
        let committed = time::OffsetDateTime::parse(p["committed_at"].as_str().unwrap_or_default(), &time::format_description::well_known::Rfc3339).map_err(|_| bad())?;
        let records = batch["records"].as_array().ok_or_else(bad)?;
        let results = p["results"].as_array().ok_or_else(bad)?;
        if p["schema_version"] != json!({"major": 1, "minor": 0}) || p["tenant_id"] != batch["tenant_id"] || p["delivery_id"] != batch["delivery_id"]
            || p["batch_digest"].as_str() != Some(batch_digest.as_str()) || committed > time::OffsetDateTime::now_utc() + time::Duration::minutes(5) || results.len() != records.len()
        {
            return Err(bad());
        }
        let mut expected: std::collections::HashMap<String, (String, String)> = Default::default();
        for r in records {
            let id = r["payload"]["observation_id"].as_str().ok_or_else(bad)?.to_string();
            let v = (r["payload"]["origin"]["source_id"].as_str().unwrap_or_default().to_string(), r["digest"].as_str().unwrap_or_default().to_string());
            if expected.insert(id, v).is_some() {
                return Err(bad());
            }
        }
        let mut remove = true;
        for r in results {
            let id = r["observation_id"].as_str().unwrap_or_default();
            let Some((src, dig)) = expected.remove(id) else { return Err(bad()) };
            if r["origin_source_id"].as_str() != Some(src.as_str()) || r["observation_digest"].as_str() != Some(dig.as_str()) {
                return Err(bad());
            }
            if r["spool_action"] != "remove" {
                remove = false;
            }
        }
        Ok(remove)
    }

    fn deliver(&self, method: &str, path: &str, body: Option<&[u8]>) -> Result<(u16, Vec<u8>), String> {
        let url = format!("{}{}", self.cfg.collector_url, path);
        let r = match body {
            Some(b) => self.http.request(method, &url).set("Content-Type", "application/json").send_bytes(b),
            None => self.http.request(method, &url).call(),
        };
        let resp = match r {
            Ok(r) => r,
            Err(ureq::Error::Status(_, r)) => r,
            Err(e) => return Err(format!("collector unavailable: {e}")),
        };
        let code = resp.status();
        let mut raw = vec![];
        std::io::Read::read_to_end(&mut std::io::Read::take(resp.into_reader(), 1 << 20), &mut raw).map_err(|e| e.to_string())?;
        Ok((code, raw))
    }

    /// Доставка очереди. Ok(true/false) — был ли продвинут хотя бы один пакет; Err — что-то ещё ждёт.
    pub fn flush(&self) -> Result<bool, String> {
        let dir = self.spool();
        state::ensure_dir(&dir)?;
        let mut names: Vec<String> = fs::read_dir(&dir).map_err(|e| e.to_string())?.filter_map(|e| e.ok()).map(|e| e.file_name().to_string_lossy().to_string()).filter(|n| n.ends_with(".pending")).collect();
        names.sort();
        let (mut progress, mut waiting) = (false, false);
        for name in names {
            let id = name.trim_end_matches(".pending").to_string();
            if !valid_id(&id) {
                return Err("invalid agent packet path".into());
            }
            let path = dir.join(&name);
            let raw = fs::read(&path).map_err(|e| e.to_string())?;
            let batch: Value = serde_json::from_slice(&raw).map_err(|_| "invalid agent pending packet")?;
            if batch["delivery_id"] != id.as_str() || batch["tenant_id"] != self.claims.tenant.as_str() {
                return Err("invalid agent pending packet".into());
            }
            let receipt = dir.join(format!("{id}.receipt"));
            if receipt.exists() {
                let cached = fs::read(&receipt).map_err(|e| e.to_string())?;
                if self.verify_center_result(&cached, &raw).map_err(|_| "cached source receipt verification failed")? {
                    fs::remove_file(&path).map_err(|e| e.to_string())?;
                    progress = true;
                }
                continue;
            }
            let (code, mut ack) = self.deliver("POST", "/api/v1/machine/observations", Some(&raw))?;
            if code != 202 {
                return Err(format!("collector batch rejected (HTTP {code})"));
            }
            let mut verdict = self.verify_center_result(&ack, &raw);
            if verdict.is_err() {
                let (code, status) = self.deliver("GET", &format!("/api/v1/machine/deliveries/{id}"), None)?;
                if code != 200 {
                    return Err(format!("collector status rejected (HTTP {code})"));
                }
                ack = status;
                verdict = self.verify_center_result(&ack, &raw);
            }
            let Ok(remove) = verdict else {
                waiting = true;
                continue;
            };
            capacity(&dir, self.cfg.spool_limit_bytes, ack.len() as i64, MAX_FILES)?;
            state::write_atomic(&receipt, &ack)?;
            if remove {
                fs::remove_file(&path).map_err(|e| e.to_string())?;
                progress = true;
            }
        }
        if waiting {
            return Err("center result pending; source packet retained".into());
        }
        Ok(progress)
    }
}

pub fn now() -> String {
    now_rfc3339()
}
