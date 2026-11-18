//! Рабочий цикл Rust-агента (C52.02) — как runLoop12 в Go: heartbeat, профиль 1.0, профиль 1.2 (свежий или
//! последний принятый без сети), сбор по интервалу, очередь на диске, доставка с отступом при сбоях.
//! Состояние блокируется тем же agent.lock (flock), что у Go-агента: два агента на одном каталоге не работают.

use crate::{client::Client, enroll, inventory12::{self, Offer}, profile};
use serde_json::Value;
use std::time::{Duration, Instant};

fn report(code: &str) {
    println!("{code}");
}

fn detail(where_: &str, e: &str) {
    if std::env::var("SURVEYSCAN_AGENT_DEBUG").as_deref() == Ok("1") {
        let t: String = e.replace(['\n', '\r'], " ").chars().take(300).collect();
        println!("detail:{where_}: {t}");
    }
}

pub fn jitter(interval: i64, percent: i64) -> Duration {
    let base = Duration::from_secs(interval.max(1) as u64);
    if percent == 0 {
        return base;
    }
    let mut b = [0u8; 1];
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut b);
    let delta = (b[0] as f64 / 255.0 * 2.0 - 1.0) * percent as f64 / 100.0;
    base.mul_f64(1.0 + delta)
}

/// Лимиты, которые агент может принять с учётом размера очереди — как wire.InventorySpoolOffer12.
pub fn spool_offer(limit: i64) -> Result<Offer, String> {
    if !(524288..=1073741824).contains(&limit) {
        return Err("spool limit outside 512 KiB..1 GiB".into());
    }
    let m = inventory12::MAXIMUM;
    let batch = m.batch_bytes.min(limit - 65536 - 4096);
    let signed = m.signed_bytes.min(batch - (64 << 10));
    let canonical = m.canonical_bytes.min(signed - (64 << 10));
    inventory12::negotiate(&[Offer { canonical_bytes: canonical, signed_bytes: signed, batch_bytes: batch, records: m.records }])
}

#[cfg(unix)]
pub struct Lock(#[allow(dead_code)] std::fs::File);

#[cfg(unix)]
pub fn lock_state(dir: &std::path::Path) -> Result<Lock, String> {
    use std::os::unix::{fs::OpenOptionsExt, io::AsRawFd};
    let f = std::fs::OpenOptions::new().create(true).read(true).write(true).mode(0o600).open(dir.join("agent.lock")).map_err(|e| e.to_string())?;
    // SAFETY: дескриптор действителен, пока жив File; блокировка снимается при закрытии
    if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err("agent state already in use".into());
    }
    Ok(Lock(f))
}

#[cfg(not(unix))]
pub struct Lock;

#[cfg(not(unix))]
pub fn lock_state(_dir: &std::path::Path) -> Result<Lock, String> {
    Ok(Lock)
}

/// Удаление недописанных временных файлов (.spool-*, .agent-*) после сбоя — как diskspool.RecoverTemps.
pub fn recover_temps(dir: &std::path::Path) {
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let n = e.file_name().to_string_lossy().to_string();
            if (n.starts_with(".spool-") || n.starts_with(".agent-")) && e.file_type().map(|t| t.is_file()).unwrap_or(false) {
                let _ = std::fs::remove_file(e.path());
            }
        }
    }
}

fn collect() -> Result<(Value, Vec<Value>), String> {
    #[cfg(target_os = "linux")]
    {
        let s = crate::collect_linux::collect();
        Ok((s.candidates, s.sections))
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err("inventory collection for this OS is not implemented yet".into())
    }
}

/// Сетевой сбой (нет связи) против отказа протокола: только первый допускает работу по последнему профилю.
fn network_failure(e: &str) -> bool {
    e.starts_with("collector unavailable")
}

pub struct Agent {
    pub client: Client,
    own: Offer,
    limits: Option<Offer>,
    profile10: Option<Value>,
}

impl Agent {
    pub fn open(cfg: enroll::Config) -> Result<(Agent, Lock), String> {
        let st = std::path::PathBuf::from(&cfg.state_directory);
        let lock = lock_state(&st)?;
        recover_temps(&st);
        recover_temps(&st.join("spool"));
        let own = spool_offer(cfg.spool_limit_bytes)?;
        let mut client = Client::open(cfg)?;
        let profile10 = profile::cached(&client)?;
        if let Some(p) = &profile10 {
            profile::apply(&mut client, p);
        }
        Ok((Agent { client, own, limits: None, profile10 }, lock))
    }

    /// Свежий профиль 1.2; без сети — последний принятый; отказ протокола — сбор остановлен до свежего согласования.
    pub fn ensure_profile12(&mut self) -> bool {
        let r = self.client.negotiate12(self.own).and_then(|n| self.client.sync_profile12(&n, self.own));
        match r {
            Ok((_, limits)) => {
                self.limits = Some(limits);
                report("inventory_profile_synced");
                true
            }
            Err(e) if !network_failure(&e) => {
                self.limits = None;
                report("inventory_profile_rejected");
                detail("profile", &e);
                false
            }
            Err(_) if self.limits.is_some() => {
                report("inventory_profile_offline_using_last");
                true
            }
            Err(_) => match self.client.offline_profile12(self.own) {
                Ok((_, limits)) => {
                    self.limits = Some(limits);
                    report("inventory_profile_cached");
                    true
                }
                Err(_) => {
                    report("inventory_profile_unavailable");
                    false
                }
            },
        }
    }

    pub fn inventory(&mut self) -> Result<String, String> {
        let limits = self.limits.ok_or("inventory_waiting_profile")?;
        self.client.preflight()?;
        let (candidates, sections) = collect()?;
        // время наблюдения — по окончании сбора: секции не могут быть собраны позже наблюдения (как в Go)
        let at = crate::client::now_rfc3339();
        self.client.queue12(limits, &candidates, &sections, &at)
    }

    pub fn poll_profile10(&mut self) {
        match profile::poll(&mut self.client, self.profile10.as_ref()) {
            Ok((p, changed)) => {
                if p["managed"] == true {
                    self.profile10 = Some(p);
                }
                if changed {
                    report("profile_applied");
                }
            }
            Err(e) => {
                report("profile_unavailable_cached_or_local");
                detail("poll_profile_1_0", &e);
            }
        }
    }

    /// Постоянный цикл до сигнала остановки (stop возвращает true).
    pub fn run(&mut self, stop: &dyn Fn() -> bool) {
        let now = Instant::now;
        let (mut inventory_at, mut heartbeat_at, mut profile_at, mut profile12_at) = (now(), now(), now(), now());
        let (mut delivery_at, mut backoff) = (now(), Duration::from_secs(1));
        while !stop() {
            if now() >= profile_at {
                self.poll_profile10();
                profile_at = now() + Duration::from_secs(20);
            }
            if now() >= profile12_at {
                profile12_at = now() + if self.ensure_profile12() { Duration::from_secs(60) } else { Duration::from_secs(20) };
            }
            if now() >= heartbeat_at {
                match self.client.heartbeat() {
                    Ok(()) => report("heartbeat_accepted"),
                    Err(e) => {
                        report("heartbeat_failed");
                        detail("heartbeat", &e);
                    }
                }
                heartbeat_at = now() + jitter(self.client.cfg.heartbeat_seconds, self.client.cfg.jitter_percent);
            }
            if now() >= inventory_at {
                if self.limits.is_none() {
                    report("inventory_waiting_profile");
                    inventory_at = now() + Duration::from_secs(20);
                } else {
                    match self.inventory() {
                        Ok(_) => report("inventory_queued"),
                        Err(e) => {
                            report("inventory_failed");
                            detail("inventory", &e);
                        }
                    }
                    inventory_at = now() + jitter(self.client.cfg.inventory_seconds, self.client.cfg.jitter_percent);
                }
            }
            if now() >= delivery_at {
                match self.client.flush() {
                    Ok(_) => backoff = Duration::from_secs(1),
                    Err(e) => {
                        report("delivery_pending");
                        detail("flush", &e);
                        backoff = (backoff * 2).min(Duration::from_secs(300));
                        delivery_at = now() + backoff;
                    }
                }
            }
            std::thread::sleep(Duration::from_secs(1));
        }
    }
}
