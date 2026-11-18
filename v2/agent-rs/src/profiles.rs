//! Профили учёток и правила привязки portable-аудита (C52.06 п. 2–3). Файл profiles.json в каталоге аудита хранит
//! только имена, логины и пути к ключам — пароли и парольные фразы вводятся при запуске и на диск не пишутся.
//! Правило выбирает ОДИН профиль на узел (первое подходящее): учётки не перебираются, доменные не блокируются.

use crate::discover::Net;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub name: String,
    /// ssh | winrm
    pub kind: String,
    #[serde(default)]
    pub user: String,
    /// password | key (ssh) | current_user (winrm на Windows: Kerberos/NTLM текущего входа)
    pub auth: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_file: Option<String>,
    /// WinRM: http_kerberos (5985) | https (5986); SSH: порт (по умолчанию 22)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// WinRM Kerberos: адрес KDC (например, dc.domain.local); без него вход — NTLM
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kdc: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub profile: String,
    /// linux_ssh | windows_winrm | network_snmp (пусто — любой)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subnet: Option<String>,
    /// домен Windows (по сведениям NTLM узла) — для правил «Windows домена X»
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(deny_unknown_fields)]
pub struct Profiles {
    pub profiles: Vec<Profile>,
    pub rules: Vec<Rule>,
}

pub const FILE: &str = "profiles.json";

fn valid_name(n: &str) -> bool {
    !n.is_empty() && n.chars().count() <= 64 && n.chars().all(|c| c.is_alphanumeric() || " ._-".contains(c))
}

impl Profiles {
    pub fn validate(&self) -> Result<(), String> {
        let mut names = std::collections::HashSet::new();
        for p in &self.profiles {
            if !valid_name(&p.name) || !names.insert(p.name.as_str()) {
                return Err(format!("профиль «{}»: имя 1–64 символа (буквы, цифры, пробел . _ -), без повторов", p.name));
            }
            if p.user.is_empty() && p.auth != "current_user" {
                return Err(format!("профиль «{}»: нужен логин", p.name));
            }
            match (p.kind.as_str(), p.auth.as_str()) {
                ("ssh", "password") | ("winrm", "password") | ("winrm", "current_user") => {}
                ("ssh", "key") if p.key_file.as_deref().map(|f| std::path::Path::new(f).is_absolute()).unwrap_or(false) => {}
                ("ssh", "key") => return Err(format!("профиль «{}»: key_file — абсолютный путь к файлу ключа", p.name)),
                _ => return Err(format!("профиль «{}»: вид ssh|winrm, вход password|key|current_user", p.name)),
            }
            if let Some(t) = &p.transport {
                if p.kind != "winrm" || !["http_kerberos", "https"].contains(&t.as_str()) {
                    return Err(format!("профиль «{}»: transport только для winrm: http_kerberos | https", p.name));
                }
            }
        }
        for r in &self.rules {
            if !names.contains(r.profile.as_str()) {
                return Err(format!("правило ссылается на неизвестный профиль «{}»", r.profile));
            }
            if let Some(k) = &r.kind {
                if !["linux_ssh", "windows_winrm", "network_snmp"].contains(&k.as_str()) {
                    return Err(format!("правило: вид узла {k} неизвестен"));
                }
            }
            if let Some(s) = &r.subnet {
                Net::parse(s)?;
            }
        }
        Ok(())
    }

    pub fn load(dir: &std::path::Path) -> Result<Profiles, String> {
        match std::fs::read(dir.join(FILE)) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Profiles::default()),
            Err(e) => Err(e.to_string()),
            Ok(raw) => {
                let p: Profiles = serde_json::from_slice(&raw).map_err(|e| format!("{FILE}: {e}"))?;
                p.validate()?;
                Ok(p)
            }
        }
    }

    /// Профиль для узла: первое подходящее правило, вид профиля должен соответствовать виду узла. Домен проверяется,
    /// только если известен; правило с доменом не подходит узлу с неизвестным доменом.
    pub fn bind(&self, ip: &str, kind: &str, domain: Option<&str>) -> Option<&Profile> {
        let addr: u32 = ip.parse::<std::net::Ipv4Addr>().ok()?.into();
        for r in &self.rules {
            if r.kind.as_deref().is_some_and(|k| k != kind) {
                continue;
            }
            if r.subnet.as_deref().and_then(|s| Net::parse(s).ok()).is_some_and(|n| !n.contains(addr)) {
                continue;
            }
            if let Some(d) = &r.domain {
                if !domain.is_some_and(|x| x.eq_ignore_ascii_case(d)) {
                    continue;
                }
            }
            let p = self.profiles.iter().find(|p| p.name == r.profile)?;
            let fits = (p.kind == "ssh" && kind == "linux_ssh") || (p.kind == "winrm" && kind == "windows_winrm");
            if fits {
                return Some(p);
            }
        }
        None
    }
}

/// Секреты профилей на время одного запуска (в памяти, не на диске).
#[derive(Default)]
pub struct Secrets(HashMap<String, String>);

impl Secrets {
    pub fn get(&self, profile: &str) -> Option<&str> {
        self.0.get(profile).map(String::as_str)
    }
    pub fn set(&mut self, profile: &str, secret: String) {
        self.0.insert(profile.to_string(), secret);
    }
    /// Спросить пароль/парольную фразу без эха для каждого используемого профиля (current_user — не нужен).
    pub fn prompt(profiles: &[&Profile]) -> Result<Secrets, String> {
        let mut s = Secrets::default();
        for p in profiles {
            if p.auth == "current_user" || s.0.contains_key(&p.name) {
                continue;
            }
            let what = if p.auth == "key" { "парольная фраза ключа (пусто — без фразы)" } else { "пароль" };
            let v = rpassword::prompt_password(format!("Профиль «{}» ({}): {what}: ", p.name, p.user)).map_err(|e| e.to_string())?;
            s.set(&p.name, v);
        }
        Ok(s)
    }
}

impl Drop for Secrets {
    fn drop(&mut self) {
        for v in self.0.values_mut() {
            // затираем пароли в памяти при завершении
            unsafe { v.as_bytes_mut().fill(0) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Profiles {
        serde_json::from_str(r#"{"profiles":[{"name":"linux-ro","kind":"ssh","user":"scan","auth":"password"},
            {"name":"dom","kind":"winrm","user":"AWM\\scan","auth":"password"},{"name":"office","kind":"ssh","user":"o","auth":"password"}],
            "rules":[{"profile":"office","kind":"linux_ssh","subnet":"10.20.5.0/24"},{"profile":"linux-ro","kind":"linux_ssh"},
            {"profile":"dom","kind":"windows_winrm","domain":"awm.local"}]}"#).unwrap()
    }

    #[test]
    fn one_profile_per_host_no_spraying() {
        let p = sample();
        p.validate().unwrap();
        assert_eq!(p.bind("10.20.5.7", "linux_ssh", None).unwrap().name, "office");
        assert_eq!(p.bind("10.20.6.7", "linux_ssh", None).unwrap().name, "linux-ro");
        assert_eq!(p.bind("10.20.6.8", "windows_winrm", Some("AWM.LOCAL")).unwrap().name, "dom");
        assert!(p.bind("10.20.6.8", "windows_winrm", None).is_none()); // домен неизвестен — правило не подходит
        assert!(p.bind("10.20.6.9", "network_snmp", None).is_none());
    }

    #[test]
    fn invalid_files_are_rejected() {
        for bad in [r#"{"profiles":[{"name":"a","kind":"ssh","user":"u","auth":"key"}],"rules":[]}"#,
            r#"{"profiles":[{"name":"a","kind":"ssh","user":"u","auth":"password","password":"x"}],"rules":[]}"#,
            r#"{"profiles":[],"rules":[{"profile":"none"}]}"#] {
            let r: Result<Profiles, _> = serde_json::from_str(bad);
            assert!(r.is_err() || r.unwrap().validate().is_err(), "{bad}");
        }
    }
}
