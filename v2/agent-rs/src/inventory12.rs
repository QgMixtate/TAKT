//! Инвентаризация профиля 1.2 (C15) — согласование лимитов и профиль сбора, как agent.NegotiateInventory12 и
//! SyncInventoryProfile12 в Go. Подписи collector и центра проверяются ключами из сертификатов (TLS/enroll),
//! никогда — ключами из тела. Кэш inventory-profile12.json — тот же формат, что у Go-агента.

use crate::{canonical, claims::Claims, client::{now_rfc3339, Client}, sign, state};
use base64::{engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD}, Engine};
use ed25519_dalek::VerifyingKey;
use serde_json::{json, Value};
use time::{format_description::well_known::Rfc3339, Duration, OffsetDateTime};

pub const CAPABILITIES_DOMAIN: &[u8] = b"SURVEYSCAN-INVENTORY-CAPABILITIES-V1\n";
pub const COLLECTOR_CAPABILITIES_DOMAIN: &[u8] = b"SURVEYSCAN-COLLECTOR-INVENTORY-CAPABILITIES-V1\n";
pub const PROFILE_REQUEST_DOMAIN: &[u8] = b"SURVEYSCAN-INVENTORY-PROFILE-REQUEST-V1-2\n";
pub const PROFILE_RESPONSE_DOMAIN: &[u8] = b"SURVEYSCAN-INVENTORY-PROFILE-RESPONSE-V1-2\n";
pub const PROFILE_CACHE: &str = "inventory-profile12.json";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Offer {
    pub canonical_bytes: i64,
    pub signed_bytes: i64,
    pub batch_bytes: i64,
    pub records: i64,
}

pub const MAXIMUM: Offer = Offer { canonical_bytes: 512 << 10, signed_bytes: 576 << 10, batch_bytes: 768 << 10, records: 100 };

/// Пересечение предложений; каждое должно быть самосогласованным (canonical < signed < batch).
/// ISSUES №122: SecurityCenter2 хранит несколько регистраций одного антивируса (одинаковый displayName, разный
/// productState); ключ записи protection в центре — kind+provider+name, дубль отклоняет всё наблюдение.
/// Оставляется первая запись каждого имени (порядок WMI).
pub fn unique_by_name(rows: Vec<Value>) -> Vec<Value> {
    let mut seen = std::collections::HashSet::new();
    rows.into_iter().filter(|r| seen.insert(r.get("name").and_then(Value::as_str).unwrap_or_default().to_string())).collect()
}

pub fn negotiate(offers: &[Offer]) -> Result<Offer, String> {
    let mut out = MAXIMUM;
    for o in offers {
        if o.canonical_bytes < 1 || o.signed_bytes < 1 || o.batch_bytes < 1 || o.records < 1 || o.canonical_bytes >= o.signed_bytes || o.signed_bytes >= o.batch_bytes {
            return Err("inventory limits invalid".into());
        }
        out = Offer { canonical_bytes: out.canonical_bytes.min(o.canonical_bytes), signed_bytes: out.signed_bytes.min(o.signed_bytes), batch_bytes: out.batch_bytes.min(o.batch_bytes), records: out.records.min(o.records) };
    }
    Ok(out)
}

fn limits_of(v: &Value) -> Result<Offer, String> {
    let n = |k: &str| v[k].as_i64().ok_or_else(|| "inventory limits invalid".to_string());
    Ok(Offer { canonical_bytes: n("canonical_bytes")?, signed_bytes: n("signed_bytes")?, batch_bytes: n("batch_bytes")?, records: n("max_records")? })
}

/// Предложение возможностей (центр или collector): версии 1.0 и 1.2, режим partial, лимиты — как wire.CapabilityOffer.
fn capability_offer(p: &Value) -> Result<Offer, String> {
    let v10 = json!({"major": 1, "minor": 0});
    let v12 = json!({"major": 1, "minor": 2});
    let two = |k: &str| p[k].as_array().map(|a| a.len() == 2 && a[0] == v10 && a[1] == v12).unwrap_or(false);
    if !two("observation_versions") || !two("batch_versions") || p["inventory12_snapshot_modes"] != json!(["partial"]) {
        return Err("inventory 1.2 not offered".into());
    }
    let o = limits_of(&p["inventory12_limits"])?;
    negotiate(&[o])?;
    Ok(o)
}

fn nonce() -> String {
    let mut b = [0u8; 32];
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut b);
    URL_SAFE_NO_PAD.encode(b)
}

fn time_of(p: &Value, k: &str) -> Result<OffsetDateTime, String> {
    OffsetDateTime::parse(p[k].as_str().unwrap_or_default(), &Rfc3339).map_err(|_| format!("{k} invalid"))
}

fn origin(source: &str, kind: &str, generation: &str) -> Value {
    json!({"source_id": source, "source_kind": kind, "generation_id": generation})
}

/// Подписанный кадр {payload, digest, key_id, signature}: ключ, дайджест канонической формы, подпись с доменом.
pub fn verify_frame(frame: &Value, domain: &[u8], key_id: &str, public: &[u8]) -> Result<Value, String> {
    let payload = frame.get("payload").filter(|p| p.is_object()).ok_or("signed frame invalid")?;
    let c = canonical::canonical_value(payload)?;
    let key = VerifyingKey::from_bytes(public.try_into().map_err(|_| "signed frame key invalid")?).map_err(|_| "signed frame key invalid")?;
    if frame["key_id"].as_str() != Some(key_id) || frame["digest"].as_str() != Some(sign::digest_hex(&c).as_str()) || !sign::verify(&key, domain, &c, frame["signature"].as_str().unwrap_or_default()) {
        return Err("signed frame invalid".into());
    }
    Ok(payload.clone())
}

fn fresh_window(p: &Value) -> Result<(OffsetDateTime, OffsetDateTime), String> {
    let (issued, expires) = (time_of(p, "issued_at")?, time_of(p, "expires_at")?);
    let now = OffsetDateTime::now_utc();
    if issued > now + Duration::seconds(30) || expires <= now || expires <= issued || expires - issued > Duration::minutes(5) {
        return Err("inventory capabilities expired".into());
    }
    Ok((issued, expires))
}

/// Свежее согласование: лимиты трёх участников, срок и сам подписанный кадр collector (доказательство).
#[derive(Clone, Debug)]
pub struct Negotiation {
    pub limits: Offer,
    pub expires: OffsetDateTime,
    pub collector: Value,
    pub proof: Value,
    pub nonce: String,
}

/// Проверка ответа inventory-capabilities: подпись collector (ключ из его сертификата) и вложенная подпись центра.
pub fn verify_capabilities(raw: &Value, me: &Claims, peer: &Claims, own: Offer, nonce: &str) -> Result<Negotiation, String> {
    let issuer = origin(&peer.source, "collector", &peer.generation);
    let audience = origin(&me.source, &me.kind, &me.generation);
    let p = verify_frame(raw, COLLECTOR_CAPABILITIES_DOMAIN, &peer.key_id, &peer.signing_public)?;
    let (issued, expires) = fresh_window(&p)?;
    if p["tenant_id"] != me.tenant.as_str() || p["issuer"] != issuer || p["audience"] != audience || p["nonce"] != nonce {
        return Err("collector capabilities binding invalid".into());
    }
    let center = verify_frame(&p["center"], CAPABILITIES_DOMAIN, &me.center_key_id, &me.center_public)?;
    let (c_issued, c_expires) = fresh_window(&center)?;
    if center["tenant_id"] != me.tenant.as_str() || center["audience"] != issuer || center["nonce"] != nonce || expires > c_expires || issued < c_issued {
        return Err("center capabilities binding invalid".into());
    }
    let limits = negotiate(&[own, capability_offer(&p)?, capability_offer(&center)?])?;
    Ok(Negotiation { limits, expires, collector: issuer, proof: raw.clone(), nonce: nonce.into() })
}

pub fn platform(c: &Client) -> String {
    if !c.cfg.inventory_platform.is_empty() {
        return c.cfg.inventory_platform.clone();
    }
    if cfg!(windows) { "windows/amd64".into() } else { "linux/amd64".into() }
}

impl Client {
    fn post_json(&self, path: &str, body: &Value, limit: u64) -> Result<(u16, Value), String> {
        let (code, raw) = self.post_raw(path, body)?;
        if raw.len() as u64 > limit {
            return Err("response exceeds bound".into());
        }
        Ok((code, serde_json::from_slice(&raw).unwrap_or(Value::Null)))
    }

    /// POST inventory-capabilities: свежее согласование лимитов агент ↔ collector ↔ центр.
    pub fn negotiate12(&self, own: Offer) -> Result<Negotiation, String> {
        let n = nonce();
        let (code, raw) = self.post_json("/api/v1/machine/inventory-capabilities", &json!({"nonce": n}), 65536)?;
        if code != 200 {
            return Err(format!("authenticated inventory capabilities unavailable: HTTP {code}"));
        }
        verify_capabilities(&raw, &self.claims, &self.peer()?, own, &n)
    }

    fn origin12(&self) -> Value {
        origin(&self.claims.source, "agent", &self.claims.generation)
    }

    /// Проверка профиля 1.2 — подпись центра, область, collector; fresh — ещё и nonce и срок.
    pub fn verify_profile12(&self, frame: &Value, fresh_nonce: Option<&str>) -> Result<Value, String> {
        let p = verify_frame(frame, PROFILE_RESPONSE_DOMAIN, &self.claims.center_key_id, &self.claims.center_public)?;
        let now = OffsetDateTime::now_utc();
        if p["tenant_id"] != self.claims.tenant.as_str() || p["origin"] != self.origin12() || p["config"]["collector_id"] != self.claims.collector.as_str() || time_of(&p, "issued_at")? > now + Duration::seconds(30) {
            return Err("inventory profile binding invalid".into());
        }
        if let Some(n) = fresh_nonce {
            if p["nonce"] != n || time_of(&p, "expires_at")? <= now {
                return Err("inventory profile not fresh".into());
            }
        }
        Ok(p)
    }

    /// Профиль из кэша (подпись и область проверяются заново). None — кэша нет; порча — ошибка.
    pub fn cached_profile12(&self) -> Result<Option<(Value, Value)>, String> {
        let path = self.state_dir().join(PROFILE_CACHE);
        if !path.exists() {
            return Ok(None);
        }
        let saved: Value = state::load_json(&path).map_err(|_| "inventory profile cache rejected")?;
        let raw = STANDARD.decode(saved["signed_response"].as_str().unwrap_or_default()).map_err(|_| "inventory profile cache rejected")?;
        if saved["version"] != 1 {
            return Err("inventory profile cache rejected".into());
        }
        let frame: Value = serde_json::from_slice(&raw).map_err(|_| "inventory profile cache rejected")?;
        let p = self.verify_profile12(&frame, None).map_err(|_| "inventory profile cache rejected")?;
        Ok(Some((p, frame)))
    }

    /// Один обмен: сообщить центру сохранённую ревизию, проверить свежий профиль, повторно проверить согласование и
    /// только затем заменить кэш (ревизия не убывает; та же ревизия с иной конфигурацией — отказ).
    pub fn sync_profile12(&self, n: &Negotiation, own: Offer) -> Result<(Value, Offer), String> {
        if n.expires <= OffsetDateTime::now_utc() {
            return Err("fresh inventory negotiation required".into());
        }
        let cached = self.cached_profile12()?;
        let applied = cached.as_ref().map(|(p, _)| json!({"common_revision": p["config"]["profile_revision"], "policy_id": p["config"]["policy_id"]})).unwrap_or(Value::Null);
        let req_nonce = nonce();
        let req = json!({"schema_version": {"major": 1, "minor": 2}, "tenant_id": self.claims.tenant, "origin": self.origin12(),
            "nonce": req_nonce, "sent_at": now_rfc3339(), "platform": platform(self), "applied": applied});
        let (code, raw) = self.post_raw("/api/v1/machine/inventory-profile", &self.signed(&req, PROFILE_REQUEST_DOMAIN)?)?;
        if code != 200 {
            return Err(format!("authenticated inventory profile unavailable: HTTP {code} {}", String::from_utf8_lossy(&raw[..raw.len().min(200)]).trim()));
        }
        if raw.len() > 65536 {
            return Err("inventory profile response exceeds bound".into());
        }
        // согласование, на которое опирается выбор, перепроверяется тем же collector
        let again = verify_capabilities(&n.proof, &self.claims, &self.peer()?, own, &n.nonce)?;
        if again.limits != n.limits || again.collector != n.collector || again.expires != n.expires {
            return Err("inventory selection changed".into());
        }
        let frame: Value = serde_json::from_slice(&raw).map_err(|_| "inventory profile invalid")?;
        let p = self.verify_profile12(&frame, Some(&req_nonce))?;
        let limits = negotiate(&[n.limits, limits_of(&p["config"]["inventory12_limits"])?, MAXIMUM])?;
        let rev = |v: &Value| v["config"]["profile_revision"].as_str().and_then(|s| s.parse::<u64>().ok());
        let new_rev = rev(&p).ok_or("inventory profile cache rejected")?;
        if let Some((old, _)) = &cached {
            let old_rev = rev(old).ok_or("inventory profile cache rejected")?;
            if new_rev < old_rev || (new_rev == old_rev && old["config"] != p["config"]) {
                return Err("inventory profile cache rejected".into());
            }
        }
        state::save_json(&self.state_dir().join(PROFILE_CACHE), &json!({"version": 1, "accepted_at": now_rfc3339(), "signed_response": STANDARD.encode(&raw)}))?;
        Ok((p, limits))
    }

    /// Работа без сети: последний принятый профиль; лимиты не шире своих и профильных.
    pub fn offline_profile12(&self, own: Offer) -> Result<(Value, Offer), String> {
        let (p, _) = self.cached_profile12()?.ok_or("no cached inventory profile")?;
        let limits = negotiate(&[own, limits_of(&p["config"]["inventory12_limits"])?, MAXIMUM])?;
        Ok((p, limits))
    }
}

#[cfg(test)]
mod unique_tests {
    use serde_json::json;
    #[test]
    fn duplicate_antivirus_registrations_keep_first() {
        let rows = vec![
            json!({"kind": "antivirus", "name": "Kaspersky", "state": "reported_product_state:266240"}),
            json!({"kind": "antivirus", "name": "Kaspersky", "state": "reported_product_state:262144"}),
            json!({"kind": "antivirus", "name": "Windows Defender"}),
        ];
        let out = super::unique_by_name(rows);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0]["state"], "reported_product_state:266240");
        assert_eq!(out[1]["name"], "Windows Defender");
    }
}
