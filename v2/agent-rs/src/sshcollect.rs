//! Сбор Linux по SSH (C52.06) — порт internal/remote/sshlinux: фиксированные read-only команды, разбор теми же
//! парсерами (linuxparse), один профиль на узел, без повторов входа при отказе (не блокировать учётку).
//! Ключ узла: первый контакт запоминается в каталоге аудита (known_hosts.json), смена ключа — отказ HOST_KEY_CHANGED.

use crate::linuxparse as p;
use russh::client::{self, Handle, KeyboardInteractiveAuthResponse};
use russh::client::AuthResult;
use russh::MethodKind;
use russh::keys::{HashAlg, PrivateKeyWithHashAlg};
use russh::ChannelMsg;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Фиксированная причина отказа (в пакет — только код, без текста ошибки).
#[derive(Debug, Clone, PartialEq)]
pub enum Failure {
    Unreachable,
    Timeout,
    HostKeyChanged,
    AuthFailed,
    SecondFactor,
    Unsupported(String),
    KeyInvalid,
}

impl Failure {
    pub fn code(&self) -> &'static str {
        match self {
            Failure::Unreachable => "HOST_UNREACHABLE",
            Failure::Timeout => "TIMEOUT",
            Failure::HostKeyChanged => "HOST_KEY_CHANGED",
            Failure::AuthFailed => "AUTH_FAILED",
            Failure::SecondFactor => "SECOND_FACTOR_REQUIRED",
            Failure::Unsupported(_) => "UNSUPPORTED_PLATFORM",
            Failure::KeyInvalid => "KEY_INVALID",
        }
    }
    /// no_access — вход/права; unreachable — сеть/срок.
    pub fn outcome(&self) -> &'static str {
        match self {
            Failure::Unreachable | Failure::Timeout => "unreachable",
            _ => "no_access",
        }
    }
}

/// Отпечатки ключей узлов аудита: адрес → «SHA256:…».
#[derive(Clone, Default)]
pub struct KnownHosts(pub Arc<Mutex<HashMap<String, String>>>);

impl KnownHosts {
    pub fn load(dir: &std::path::Path) -> KnownHosts {
        let m: HashMap<String, String> = std::fs::read(dir.join("known_hosts.json")).ok().and_then(|r| serde_json::from_slice(&r).ok()).unwrap_or_default();
        KnownHosts(Arc::new(Mutex::new(m)))
    }
    pub fn save(&self, dir: &std::path::Path) -> Result<(), String> {
        let m = self.0.lock().unwrap().clone();
        crate::state::save_json(&dir.join("known_hosts.json"), &m)
    }
}

struct Checker {
    addr: String,
    known: KnownHosts,
    changed: Arc<Mutex<bool>>,
}

impl client::Handler for Checker {
    type Error = russh::Error;
    async fn check_server_key(&mut self, key: &russh::keys::PublicKeyOrCertificate) -> Result<bool, Self::Error> {
        let russh::keys::PublicKeyOrCertificate::PublicKey { key, .. } = key else {
            return Ok(false); // сертификаты узлов не поддерживаются: только отпечаток ключа
        };
        let fp = key.fingerprint(HashAlg::Sha256).to_string();
        let mut m = self.known.0.lock().unwrap();
        match m.get(&self.addr) {
            Some(old) if *old != fp => {
                *self.changed.lock().unwrap() = true;
                Ok(false)
            }
            Some(_) => Ok(true),
            None => {
                m.insert(self.addr.clone(), fp);
                Ok(true)
            }
        }
    }
}

pub struct Target {
    pub ip: String,
    pub port: u16,
    pub user: String,
    /// пароль или парольная фраза ключа
    pub secret: String,
    pub key_file: Option<String>,
}

struct Session {
    handle: Handle<Checker>,
    limit: usize,
}

impl Session {
    /// Команда с лимитом вывода и времени; ненулевой код или превышение — «источник недоступен».
    async fn run(&self, cmd: &str) -> Option<String> {
        let fut = async {
            let mut ch = self.handle.channel_open_session().await.ok()?;
            ch.exec(true, cmd).await.ok()?;
            let (mut out, mut code) = (Vec::new(), None);
            while let Some(msg) = ch.wait().await {
                match msg {
                    ChannelMsg::Data { data } => {
                        if out.len() + data.len() > self.limit {
                            return None;
                        }
                        out.extend_from_slice(&data);
                    }
                    ChannelMsg::ExitStatus { exit_status } => code = Some(exit_status),
                    _ => {}
                }
            }
            (code == Some(0)).then(|| String::from_utf8_lossy(&out).into_owned())
        };
        tokio::time::timeout(Duration::from_secs(20), fut).await.ok().flatten()
    }
}

fn section(name: &str, rows: Vec<p::Row>) -> Value {
    let now = crate::client::now_rfc3339();
    if rows.is_empty() {
        return json!({"name": name, "collected_at": now, "status": "unavailable", "collection_complete": false, "reason_code": "SOURCE_UNAVAILABLE", "record_count": 0, "records": []});
    }
    json!({"name": name, "collected_at": now, "status": "partial", "collection_complete": false, "reason_code": "REMOTE_SSH_PARTIAL", "record_count": rows.len(), "records": rows})
}

fn failed(name: &str, status: &str, reason: &str) -> Value {
    json!({"name": name, "collected_at": crate::client::now_rfc3339(), "status": status, "collection_complete": false, "reason_code": reason, "record_count": 0, "records": []})
}

async fn connect(t: &Target, known: &KnownHosts) -> Result<Handle<Checker>, Failure> {
    let cfg = Arc::new(client::Config { inactivity_timeout: Some(Duration::from_secs(60)), ..Default::default() });
    let addr = format!("{}:{}", t.ip, t.port);
    let changed = Arc::new(Mutex::new(false));
    let checker = Checker { addr: addr.clone(), known: known.clone(), changed: changed.clone() };
    let mut h = match tokio::time::timeout(Duration::from_secs(10), client::connect(cfg, addr.as_str(), checker)).await {
        Err(_) => return Err(Failure::Timeout),
        Ok(Err(_)) if *changed.lock().unwrap() => return Err(Failure::HostKeyChanged),
        Ok(Err(_)) => return Err(Failure::Unreachable),
        Ok(Ok(h)) => h,
    };
    let ok = if let Some(kf) = &t.key_file {
        let phrase = (!t.secret.is_empty()).then_some(t.secret.as_str());
        let key = russh::keys::load_secret_key(kf, phrase).map_err(|_| Failure::KeyInvalid)?;
        let hash = h.best_supported_rsa_hash().await.ok().flatten().flatten();
        h.authenticate_publickey(&t.user, PrivateKeyWithHashAlg::new(Arc::new(key), hash)).await.map_err(|_| Failure::Unreachable)?.success()
    } else {
        let r = h.authenticate_password(&t.user, &t.secret).await.map_err(|_| Failure::Unreachable)?;
        // №142: пароль принят, но сервер требует ещё метод (AuthenticationMethods password,…) — это второй фактор;
        // если keyboard-interactive сервер не предлагает — пароль отклонён, второй попытки нет (риск блокировки)
        let ki = match &r {
            AuthResult::Success => None,
            AuthResult::Failure { partial_success: true, .. } => return Err(Failure::SecondFactor),
            AuthResult::Failure { remaining_methods, .. } => Some(remaining_methods.contains(&MethodKind::KeyboardInteractive)),
        };
        if ki.is_none() {
            true
        } else if ki == Some(false) {
            false
        } else {
            // PAM-вход: один вопрос о пароле — отвечаем один раз; любой иной вопрос — второй фактор
            match h.authenticate_keyboard_interactive_start(&t.user, None::<String>).await.map_err(|_| Failure::Unreachable)? {
                KeyboardInteractiveAuthResponse::Success => true,
                KeyboardInteractiveAuthResponse::InfoRequest { prompts, .. } => {
                    let pw = prompts.len() == 1 && prompts[0].prompt.to_lowercase().contains("password");
                    if !pw && !prompts.is_empty() {
                        return Err(Failure::SecondFactor);
                    }
                    let answers = if pw { vec![t.secret.clone()] } else { vec![] };
                    match h.authenticate_keyboard_interactive_respond(answers).await.map_err(|_| Failure::Unreachable)? {
                        KeyboardInteractiveAuthResponse::Success => true,
                        KeyboardInteractiveAuthResponse::InfoRequest { .. } => return Err(Failure::SecondFactor),
                        _ => false,
                    }
                }
                _ => false,
            }
        }
    };
    if !ok {
        return Err(Failure::AuthFailed); // без повторов: риск блокировки учётки
    }
    Ok(h)
}

/// Сбор узла: (кандидаты идентичности, 12 разделов) или причина отказа.
pub async fn collect(t: &Target, known: &KnownHosts) -> Result<(Value, Vec<Value>), Failure> {
    let handle = connect(t, known).await?;
    let s = Session { handle, limit: 16 << 20 };
    let fut = async {
        if let Some(k) = s.run("uname -s").await {
            let k = k.trim();
            if !k.is_empty() && k != "Linux" {
                return Err(Failure::Unsupported(k.to_lowercase()));
            }
        } else if s.run("cmd /c ver").await.is_some_and(|v| v.to_lowercase().contains("windows")) {
            return Err(Failure::Unsupported("windows".into()));
        }
        let mut by: HashMap<&str, Value> = HashMap::new();
        let host = s.run("LC_ALL=C hostname").await;
        let machine = s.run("LC_ALL=C cat /etc/machine-id").await.unwrap_or_default();
        by.insert("identity", match &host { Some(h) => section("identity", p::identity(h, &machine)), None => failed("identity", "unavailable", "SOURCE_UNAVAILABLE") });
        let osr = s.run("LC_ALL=C cat /etc/os-release || cat /usr/lib/os-release").await;
        let uname = s.run("LC_ALL=C uname -m").await.unwrap_or_default();
        by.insert("os", match &osr { Some(o) => section("os", p::os(o, &uname)), None => failed("os", "unavailable", "SOURCE_UNAVAILABLE") });
        let link = s.run("LC_ALL=C ip -o link show").await;
        let addr = s.run("LC_ALL=C ip -o addr show").await.unwrap_or_default();
        by.insert("network", match &link { Some(l) => section("network", p::network(l, &addr)), None => failed("network", "unavailable", "SOURCE_UNAVAILABLE") });
        let cpu = s.run("LC_ALL=C cat /proc/cpuinfo").await;
        let mem = s.run("LC_ALL=C cat /proc/meminfo").await;
        let mut hw = if cpu.is_some() || mem.is_some() { p::hardware(cpu.as_deref().unwrap_or(""), mem.as_deref().unwrap_or("")) } else { vec![] };
        let mut dmi = HashMap::new();
        for n in ["bios_vendor", "bios_version", "sys_vendor", "product_name", "product_serial", "product_uuid"] {
            if let Some(v) = s.run(&format!("cat /sys/class/dmi/id/{n} 2>/dev/null")).await {
                dmi.insert(n.to_string(), v);
            }
        }
        hw.extend(p::dmi(&dmi));
        by.insert("hardware", section("hardware", hw));
        let software = if let Some(d) = s.run("LC_ALL=C cat /var/lib/dpkg/status").await {
            section("software", p::packages(&d))
        } else if let Some(r) = s.run("LC_ALL=C rpm -qa --qf '%{NAME}\\t%{VERSION}-%{RELEASE}\\t%{ARCH}\\n'").await {
            section("software", p::rpm_packages(&r))
        } else if let Some(a) = s.run("LC_ALL=C cat /lib/apk/db/installed").await {
            section("software", p::apk_packages(&a))
        } else {
            failed("software", "unsupported", "PACKAGE_MANAGER_UNSUPPORTED")
        };
        by.insert("software", software);
        by.insert("services", match s.run("LC_ALL=C systemctl list-units --type=service --all --plain --no-legend --no-pager").await {
            Some(u) => section("services", p::systemd_services(&u, &s.run("LC_ALL=C systemctl list-unit-files --type=service --plain --no-legend --no-pager").await.unwrap_or_default())),
            None => failed("services", "unavailable", "SOURCE_UNAVAILABLE"),
        });
        by.insert("users_groups", match s.run("LC_ALL=C cat /etc/passwd").await {
            Some(pw) => section("users_groups", p::accounts(&pw, &s.run("LC_ALL=C cat /etc/group").await.unwrap_or_default())),
            None => failed("users_groups", "unavailable", "SOURCE_UNAVAILABLE"),
        });
        by.insert("resources", match s.run("LC_ALL=C cat /proc/self/mountinfo").await {
            Some(m) => section("resources", p::mounts(&m)),
            None => failed("resources", "unavailable", "SOURCE_UNAVAILABLE"),
        });
        let (mut ports, mut any) = (vec![], false);
        if let Some(r) = s.run("LC_ALL=C cat /proc/net/route").await {
            any = true;
            ports.extend(p::routes(&r));
        }
        for (cmd, proto, v6) in [("tcp", "tcp", false), ("tcp6", "tcp", true), ("udp", "udp", false), ("udp6", "udp", true)] {
            if let Some(t) = s.run(&format!("LC_ALL=C cat /proc/net/{cmd}")).await {
                any = true;
                ports.extend(p::sockets(proto, &t, v6));
            }
        }
        by.insert("routes_ports", if any { section("routes_ports", ports) } else { failed("routes_ports", "unavailable", "SOURCE_UNAVAILABLE") });
        let mut sections = vec![];
        for name in ["identity", "os", "network", "hardware", "software", "updates", "services", "users_groups", "routes_ports", "resources", "protection", "neighbors"] {
            sections.push(by.remove(name).unwrap_or_else(|| if ["updates", "protection", "neighbors"].contains(&name) { failed(name, "unsupported", "SECTION_UNSUPPORTED") } else { failed(name, "unavailable", "SOURCE_UNAVAILABLE") }));
        }
        let mut candidates = vec![];
        if let Some(r) = sections[0]["records"].get(0) {
            if let Some(h) = r["hostname"].as_str() {
                candidates.push(json!({"kind": "hostname", "namespace": "dns", "value": h}));
            }
            if let Some(m) = r["machine_uuid"].as_str() {
                candidates.push(json!({"kind": "machine_uuid", "namespace": "linux-machine-id", "value": m}));
            }
        }
        Ok((Value::Array(candidates), sections))
    };
    let r = tokio::time::timeout(Duration::from_secs(120), fut).await.map_err(|_| Failure::Timeout)?;
    let _ = s.handle.disconnect(russh::Disconnect::ByApplication, "", "").await;
    r
}
