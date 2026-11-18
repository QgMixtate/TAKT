//! Рабочий клиент агента (C52.02) — как agent.Open/Heartbeat в Go: проверенная личность из каталога состояния,
//! mTLS к закреплённому collector, счётчики последовательностей и подписанные сообщения C03.

use crate::{canonical, claims, enroll, machineid, sign, state, tls};
use ed25519_dalek::SigningKey;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::PathBuf;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

pub const HEARTBEAT_DOMAIN: &[u8] = b"SURVEYSCAN-HEARTBEAT-V1\n";

/// Ротированная личность (tls-identity.json) — как machinecred.Identity.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct RotatedIdentity {
    pub result: enroll::EnrollmentResult,
    pub private_key_pem: String,
}

pub struct Client {
    pub cfg: enroll::Config,
    pub claims: claims::Claims,
    pub key: SigningKey,
    pub http: ureq::Agent,
    pub expires: OffsetDateTime,
    pub verifier: std::sync::Arc<tls::CollectorVerifier>,
    state: PathBuf,
    sequence: state::Counters,
}

pub fn now_rfc3339() -> String {
    OffsetDateTime::now_utc().format(&Rfc3339).unwrap_or_default()
}

fn chain_der(pem_chain: &str) -> Result<Vec<CertificateDer<'static>>, String> {
    let all = pem::parse_many(pem_chain).map_err(|_| "invalid chain")?;
    if all.is_empty() || all.iter().any(|p| p.tag() != "CERTIFICATE") {
        return Err("invalid chain".into());
    }
    Ok(all.into_iter().map(|p| CertificateDer::from(p.into_contents())).collect())
}

fn private_der(raw: &str) -> Result<PrivateKeyDer<'static>, String> {
    Ok(PrivateKeyDer::Pkcs8(pem::parse(raw).map_err(|_| "invalid agent key")?.into_contents().into()))
}

impl Client {
    /// Открыть личность: привязка к машине, identity.json (или ротированная tls-identity.json), проверка до УЦ,
    /// утверждения agent/tenant, счётчики — те же файлы и правила, что у Go-агента.
    pub fn open(cfg: enroll::Config) -> Result<Client, String> {
        let st = PathBuf::from(&cfg.state_directory);
        let prep: state::Preparation = state::load_json(&st.join("preparation.json"))?;
        let key = state::read_key(&st.join("signing.key"))?;
        verify_binding(&st, &prep.source_id, &key)?;
        let rotated = st.join("tls-identity.json");
        let (result, private) = if rotated.exists() {
            let r: RotatedIdentity = state::load_json(&rotated)?;
            (r.result, r.private_key_pem)
        } else {
            let r: enroll::EnrollmentResult = state::load_json(&st.join("identity.json"))?;
            (r, std::fs::read_to_string(st.join("tls.key")).map_err(|_| "agent TLS key unavailable")?)
        };
        let ca = enroll::read_ca(&cfg)?;
        let claims = enroll::verify_result(&result, &ca, &prep.source_id, &key.verifying_key().to_bytes()).map_err(|_| "agent identity not trusted")?;
        if claims.kind != "agent" || claims.tenant != cfg.tenant_id {
            return Err("agent identity not trusted".into());
        }
        let expires = OffsetDateTime::parse(&result.expires_at, &Rfc3339).map_err(|_| "agent identity not trusted")?;
        let verifier = std::sync::Arc::new(tls::CollectorVerifier::new(ca, &cfg.tenant_id, &cfg.collector_source_id, &claims.collector));
        let http = tls::collector_agent_shared(verifier.clone(), Some((chain_der(&result.certificate_chain_pem)?, private_der(&private)?)), 30)?;
        let sequence: state::Counters = state::load_json(&st.join("sequences.json"))?;
        for s in [&sequence.inventory, &sequence.heartbeat] {
            s.parse::<u64>().map_err(|_| "invalid agent counters")?;
        }
        Ok(Client { cfg, claims, key, http, expires, verifier, state: st, sequence })
    }

    /// Следующий номер (inventory или heartbeat) — сохраняется на диск до отправки, как в Go (повтор не переиспользует номер).
    pub fn next(&mut self, heartbeat: bool) -> Result<String, String> {
        let slot = if heartbeat { &mut self.sequence.heartbeat } else { &mut self.sequence.inventory };
        let old: u64 = slot.parse().map_err(|_| "agent sequence exhausted")?;
        let next = old.checked_add(1).ok_or("agent sequence exhausted")?;
        *slot = next.to_string();
        state::save_json(&self.state.join("sequences.json"), &self.sequence)?;
        Ok(next.to_string())
    }

    /// Подписанная обёртка {payload, digest, key_id, signature}: дайджест и подпись — по канонической форме RFC 8785.
    pub fn signed(&self, payload: &Value, domain: &[u8]) -> Result<Value, String> {
        let c = canonical::canonical_value(payload)?;
        Ok(json!({"payload": payload, "digest": sign::digest_hex(&c), "key_id": self.claims.key_id, "signature": sign::sign(&self.key, domain, &c)}))
    }

    pub fn state_dir(&self) -> PathBuf {
        self.state.clone()
    }

    /// POST с телом ответа как есть (до 4 МиБ) — для подписанных кадров, где важны исходные байты.
    pub fn post_raw(&self, path: &str, body: &Value) -> Result<(u16, Vec<u8>), String> {
        let r = self.http.post(&format!("{}{}", self.cfg.collector_url, path)).set("Content-Type", "application/json").send_json(body);
        let resp = match r {
            Ok(r) => r,
            Err(ureq::Error::Status(_, r)) => r,
            Err(e) => return Err(format!("collector unavailable: {e}")),
        };
        let code = resp.status();
        let mut raw = Vec::new();
        std::io::Read::read_to_end(&mut std::io::Read::take(resp.into_reader(), 4 << 20), &mut raw).map_err(|e| e.to_string())?;
        Ok((code, raw))
    }

    fn post(&self, path: &str, body: &Value) -> Result<(u16, Value), String> {
        let r = self.http.post(&format!("{}{}", self.cfg.collector_url, path)).set("Content-Type", "application/json").send_json(body);
        let resp = match r {
            Ok(r) => r,
            Err(ureq::Error::Status(_, r)) => r,
            Err(e) => return Err(format!("collector unavailable: {e}")),
        };
        let code = resp.status();
        let v: Value = serde_json::from_reader(std::io::Read::take(resp.into_reader(), 4 << 20)).unwrap_or(Value::Null);
        Ok((code, v))
    }

    /// Утверждения collector из последнего TLS-соединения (обязательны для проверки его подписанных кадров).
    pub fn peer(&self) -> Result<claims::Claims, String> {
        let p = self.verifier.peer.lock().map_err(|_| "collector identity unavailable")?.clone().ok_or("collector identity unavailable")?;
        if p.kind != "collector" || p.tenant != self.claims.tenant || p.source != self.cfg.collector_source_id || p.collector != self.claims.collector {
            return Err("collector scope mismatch".into());
        }
        Ok(p)
    }

    /// Heartbeat: свежий вызов (challenge) от центра → подписанный heartbeat с nonce и следующим номером.
    pub fn heartbeat(&mut self) -> Result<(), String> {
        verify_binding(&self.state, &self.claims.source, &self.key)?;
        let (code, resp) = self.post("/api/v1/machine/heartbeat-challenges", &json!({"source_ids": [self.claims.source], "purpose": "heartbeat"}))?;
        let list = resp.get("challenges").and_then(Value::as_array).filter(|l| code == 200 && l.len() == 1).ok_or("fresh heartbeat challenge unavailable")?;
        let ch = &list[0];
        let s = |k: &str| ch.get(k).and_then(Value::as_str).unwrap_or_default().to_string();
        let expires = OffsetDateTime::parse(&s("expires_at"), &Rfc3339).map_err(|_| "heartbeat challenge binding invalid")?;
        if s("purpose") != "heartbeat" || s("tenant_id") != self.claims.tenant || s("source_id") != self.claims.source || s("generation_id") != self.claims.generation || OffsetDateTime::now_utc() >= expires {
            return Err("heartbeat challenge binding invalid".into());
        }
        let seq = self.next(true)?;
        let id = state::new_id();
        let h = json!({"schema_version": {"major": 1, "minor": 0}, "heartbeat_id": id, "tenant_id": self.claims.tenant,
            "origin": {"source_id": self.claims.source, "source_kind": "agent", "generation_id": self.claims.generation},
            "challenge_id": s("challenge_id"), "nonce": s("nonce"), "heartbeat_sequence": seq, "sent_at": now_rfc3339()});
        let (code, resp) = self.post("/api/v1/machine/heartbeats", &self.signed(&h, HEARTBEAT_DOMAIN)?)?;
        if code != 200 {
            return Err("heartbeat not accepted".into());
        }
        if resp.get("heartbeat_id").and_then(Value::as_str) != Some(id.as_str()) {
            return Err("heartbeat response mismatch".into());
        }
        Ok(())
    }
}

/// Привязка каталога состояния к машине (host-binding.json) — копия каталога на другой ПК не работает.
pub fn verify_binding(st: &std::path::Path, source: &str, key: &SigningKey) -> Result<(), String> {
    let machine = machineid::local().ok_or("stable local machine identity unavailable")?;
    let b: state::HostBinding = state::load_json(&st.join("host-binding.json"))?;
    if b != state::binding(source, &machine, key) {
        return Err("agent host continuity mismatch".into());
    }
    Ok(())
}
