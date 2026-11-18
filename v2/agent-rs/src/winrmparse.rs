//! Разбор вывода сценария WinRM — порт internal/remote/winrminv/parse.go: те же нормализация и отбрасывание;
//! сценарий общий с Go (script.ps1). Паритет — общие векторы testdata/winrm (эталон — Go).

use serde::Deserialize;
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::net::IpAddr;

pub const SCRIPT: &str = include_str!("../../internal/remote/winrminv/script.ps1");

#[derive(Deserialize, Default)]
struct JOs {
    #[serde(default)]
    caption: String,
    #[serde(default)]
    version: String,
    #[serde(default)]
    build: String,
    #[serde(default)]
    arch: String,
    #[serde(default)]
    boot: String,
    #[serde(default)]
    memory_kb: u64,
}
#[derive(Deserialize, Default)]
struct JNic {
    #[serde(default)]
    index: i64,
    #[serde(default)]
    name: String,
    #[serde(default)]
    mac: String,
    #[serde(default)]
    ips: Vec<String>,
    #[serde(default)]
    masks: Vec<String>,
    #[serde(default)]
    dns: Vec<String>,
    #[serde(default)]
    gateways: Vec<String>,
    #[serde(default)]
    dhcp: bool,
    #[serde(default)]
    mtu: i64,
}
#[derive(Deserialize, Default)]
struct JSvc {
    #[serde(default)]
    name: String,
    #[serde(default)]
    display: String,
    #[serde(default)]
    state: String,
    #[serde(default)]
    mode: String,
    #[serde(default)]
    account: String,
    #[serde(default)]
    path: String,
}
#[derive(Deserialize, Default)]
struct JSw {
    #[serde(default)]
    view: String,
    #[serde(default)]
    key: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    version: String,
    #[serde(default)]
    vendor: String,
}
#[derive(Deserialize, Default)]
#[allow(non_snake_case)]
struct JBios {
    #[serde(default, alias = "vendor")]
    Vendor: String,
    #[serde(default, alias = "version")]
    Version: String,
    #[serde(default, alias = "serial")]
    Serial: String,
}
#[derive(Deserialize, Default)]
struct Payload {
    #[serde(default)]
    fatal: String,
    #[serde(default)]
    errors: Option<Vec<String>>,
    #[serde(default)]
    hostname: String,
    #[serde(default)]
    domain: String,
    #[serde(default)]
    uuid: String,
    #[serde(default)]
    machine_guid: String,
    os: Option<JOs>,
    bios: Option<JBios>,
    #[serde(default)]
    cpu_logical: i64,
    #[serde(default)]
    cpu_name: String,
    #[serde(default)]
    nics: Option<Vec<JNic>>,
    #[serde(default)]
    services: Option<Vec<JSvc>>,
    #[serde(default)]
    software: Option<Vec<JSw>>,
}

/// Как str в Go: обрезка пробелов; длиннее лимита или с управляющими символами — пусто.
fn s(v: &str, limit: usize) -> String {
    let v = v.trim();
    if v.len() > limit || v.chars().any(|c| (c as u32) < 0x20 || c as u32 == 0x7f) {
        return String::new();
    }
    v.to_string()
}

fn uuid_ok(u: &str) -> bool {
    let b = u.as_bytes();
    b.len() == 36 && b.iter().enumerate().all(|(i, c)| if [8, 13, 18, 23].contains(&i) { *c == b'-' } else { c.is_ascii_hexdigit() })
}

fn mac_ok(m: &str) -> bool {
    let b = m.as_bytes();
    b.len() == 17 && b.iter().enumerate().all(|(i, c)| if i % 3 == 2 { *c == b':' || *c == b'-' } else { c.is_ascii_hexdigit() }) && {
        let sep = b[2];
        // Go regexp ([0-9A-Fa-f]{2}[:-]){5}: разделители могут быть разными — так же
        let _ = sep;
        true
    }
}

fn mask_bits(mask: &str) -> Option<i64> {
    let a: std::net::Ipv4Addr = mask.parse().ok()?;
    let mut bits = 0;
    for mut b in a.octets() {
        while b != 0 {
            bits += (b >> 7) as i64;
            b <<= 1;
        }
    }
    Some(bits)
}

fn fmt_int(v: &str) -> Option<i64> {
    let mut n: i64 = 0;
    for c in v.chars() {
        let d = c.to_digit(10)? as i64;
        n = n * 10 + d;
        if n > 128 {
            return None;
        }
    }
    Some(n)
}

fn os_arch(raw: &str) -> &'static str {
    let v = raw.trim().to_lowercase();
    if v.contains("arm") && v.contains("64") {
        "arm64"
    } else if v.contains("arm") {
        ""
    } else if v.starts_with("64") {
        "amd64"
    } else if v.starts_with("32") {
        "386"
    } else {
        ""
    }
}

fn link_local(a: &IpAddr) -> bool {
    match a {
        IpAddr::V4(v) => v.is_link_local(),
        IpAddr::V6(v) => (v.segments()[0] & 0xffc0) == 0xfe80,
    }
}

fn clean_addrs(list: &[String]) -> Vec<String> {
    let mut out: Vec<String> = vec![];
    for v in list {
        if let Ok(a) = v.parse::<IpAddr>() {
            let t = a.to_string();
            if !out.contains(&t) && out.len() < 32 {
                out.push(t);
            }
        }
    }
    out
}

fn reason_for(name: &str, errs: &[String]) -> &'static str {
    let sources: &[&str] = match name {
        "identity" => &["cs", "prod"],
        "os" => &["os"],
        "network" => &["nics"],
        "hardware" => &["os", "cpu", "bios"],
        "software" => &["sw64", "sw32"],
        "services" => &["svcs"],
        _ => &[],
    };
    let mut reason = "SOURCE_UNAVAILABLE";
    for e in errs {
        let (src, cat) = e.split_once(':').unwrap_or((e, ""));
        if sources.contains(&src) {
            if cat == "PermissionDenied" {
                return "ACCESS_DENIED";
            }
            reason = "SOURCE_ERROR";
        }
    }
    reason
}

fn sec(name: &str, rows: Vec<Value>, now: &str, errs: &[String]) -> Value {
    if rows.is_empty() {
        return json!({"name": name, "collected_at": now, "status": "unavailable", "collection_complete": false, "reason_code": reason_for(name, errs), "record_count": 0, "records": []});
    }
    json!({"name": name, "collected_at": now, "status": "partial", "collection_complete": false, "reason_code": "REMOTE_WINRM_PARTIAL", "record_count": rows.len(), "records": rows})
}

fn placeholder(v: &str) -> bool {
    matches!(v.to_lowercase().as_str(), "" | "to be filled by o.e.m." | "default string" | "none" | "system serial number" | "0")
}

/// Вывод сценария → (6 разделов, кандидаты). Неразбираемый вывод или fatal — ошибка.
fn strip_nulls(v: &mut Value) {
    match v {
        Value::Object(m) => {
            m.retain(|_, x| !x.is_null());
            m.values_mut().for_each(strip_nulls);
        }
        Value::Array(a) => {
            a.retain(|x| !x.is_null());
            a.iter_mut().for_each(strip_nulls);
        }
        _ => {}
    }
}

pub fn parse(raw: &[u8], now: &str) -> Result<(Vec<Value>, Vec<Value>), String> {
    // null в выводе PowerShell (пустые свойства WMI) — как в Go: нулевое значение поля
    let mut v: Value = serde_json::from_slice(raw).map_err(|e| format!("winrm: unexpected output from target ({e})"))?;
    strip_nulls(&mut v);
    let p: Payload = serde_json::from_value(v).map_err(|e| format!("winrm: unexpected output from target ({e})"))?;
    if !p.fatal.is_empty() {
        return Err(format!("winrm: collection script failed on the target ({})", s(&p.fatal, 64)));
    }
    let errs = p.errors.clone().unwrap_or_default();
    let mut cands = vec![];
    let (mut identity, mut os_rows, mut nets, mut hw, mut soft, mut svcs) = (vec![], vec![], vec![], vec![], vec![], vec![]);
    let h = s(&p.hostname, 255);
    if !h.is_empty() {
        let mut row = Map::new();
        row.insert("hostname".into(), h.clone().into());
        cands.push(json!({"kind": "hostname", "namespace": "hostname.raw", "value": h}));
        let d = s(&p.domain, 255);
        if !d.is_empty() {
            row.insert("domain".into(), d.into());
        }
        if uuid_ok(&p.uuid) && !p.uuid.eq_ignore_ascii_case("FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF") && p.uuid != "00000000-0000-0000-0000-000000000000" {
            let u = p.uuid.to_lowercase();
            row.insert("machine_uuid".into(), u.clone().into());
            cands.push(json!({"kind": "bios_uuid", "namespace": "smbios", "value": u}));
        }
        let g = p.machine_guid.trim().to_lowercase();
        if uuid_ok(&g) && g != "00000000-0000-0000-0000-000000000000" {
            cands.push(json!({"kind": "machine_uuid", "namespace": "windows-machine-guid", "value": g}));
        }
        identity.push(Value::Object(row));
    }
    if let Some(o) = &p.os {
        let arch = os_arch(&o.arch);
        let (name, ver) = (s(&o.caption, 128), s(&o.version, 128));
        if !name.is_empty() && !ver.is_empty() && !arch.is_empty() {
            let mut row = Map::new();
            row.insert("name".into(), name.into());
            row.insert("version".into(), ver.into());
            row.insert("architecture".into(), arch.into());
            let b = s(&o.build, 128);
            if !b.is_empty() {
                row.insert("build".into(), b.into());
            }
            if let Ok(t) = time::OffsetDateTime::parse(&o.boot, &time::format_description::well_known::Rfc3339) {
                let t = t.to_offset(time::UtcOffset::UTC).replace_nanosecond(0).unwrap_or(t);
                row.insert("boot_time".into(), t.format(&time::format_description::well_known::Rfc3339).unwrap_or_default().into());
                row.insert("boot_time_quality".into(), "estimated".into());
            }
            os_rows.push(Value::Object(row));
        }
        if o.memory_kb > 0 {
            hw.push(json!({"kind": "memory", "name": "Physical memory", "bytes": o.memory_kb * 1024}));
        }
    }
    if p.cpu_logical > 0 {
        let mut row = Map::new();
        row.insert("kind".into(), "cpu".into());
        row.insert("name".into(), "Logical processors".into());
        row.insert("logical_processors".into(), p.cpu_logical.into());
        let m = s(&p.cpu_name, 256);
        if !m.is_empty() {
            row.insert("model".into(), m.into());
        }
        hw.push(Value::Object(row));
    }
    if let Some(b) = &p.bios {
        let mut row = Map::new();
        row.insert("kind".into(), "bios".into());
        row.insert("name".into(), "System firmware".into());
        let v = s(&b.Version, 190);
        if !v.is_empty() {
            row.insert("name".into(), format!("BIOS {v}").into());
        }
        let v = s(&b.Vendor, 256);
        if !v.is_empty() {
            row.insert("vendor".into(), v.into());
        }
        let v = s(&b.Serial, 256);
        if !v.is_empty() && !placeholder(&v) {
            row.insert("serial".into(), v.into());
        }
        hw.push(Value::Object(row));
    }
    for n in p.nics.as_deref().unwrap_or_default() {
        let name = s(&n.name, 128);
        if name.is_empty() {
            continue;
        }
        let mut row = Map::new();
        row.insert("name".into(), name.into());
        let mut addrs = vec![];
        for (i, ip) in n.ips.iter().enumerate() {
            let Ok(a) = ip.parse::<IpAddr>() else { continue };
            if link_local(&a) || addrs.len() >= 64 {
                continue;
            }
            let mut prefix = 0;
            if let Some(m) = n.masks.get(i) {
                if a.is_ipv4() {
                    if let Some(b) = mask_bits(m) {
                        prefix = b;
                    }
                } else {
                    prefix = fmt_int(m).unwrap_or(64);
                }
            }
            addrs.push(json!({"ip": a.to_string(), "prefix": prefix}));
        }
        row.insert("addresses".into(), addrs.into());
        if mac_ok(&n.mac) {
            row.insert("mac".into(), n.mac.replace('-', ":").to_lowercase().into());
        }
        for (key, list) in [("dns_servers", &n.dns), ("gateways", &n.gateways)] {
            let vals = clean_addrs(list);
            if !vals.is_empty() {
                row.insert(key.into(), vals.into());
            }
        }
        row.insert("dhcp_enabled".into(), n.dhcp.into());
        if n.mtu > 0 {
            row.insert("mtu".into(), n.mtu.into());
        }
        if n.index > 0 {
            row.insert("interface_index".into(), n.index.into());
        }
        nets.push(Value::Object(row));
    }
    let states: HashMap<&str, &str> = [("running", "running"), ("stopped", "stopped"), ("start pending", "start_pending"), ("stop pending", "stop_pending"), ("continue pending", "continue_pending"), ("pause pending", "pause_pending"), ("paused", "paused")].into();
    let modes: HashMap<&str, &str> = [("auto", "auto"), ("manual", "demand"), ("disabled", "disabled"), ("boot", "boot"), ("system", "system")].into();
    for v in p.services.as_deref().unwrap_or_default() {
        let name = s(&v.name, 256);
        if name.is_empty() {
            continue;
        }
        let mut row = Map::new();
        row.insert("name".into(), name.into());
        row.insert("state".into(), states.get(v.state.trim().to_lowercase().as_str()).copied().unwrap_or("unknown").into());
        let d = s(&v.display, 256);
        if !d.is_empty() {
            row.insert("display_name".into(), d.into());
        }
        row.insert("start_mode".into(), modes.get(v.mode.trim().to_lowercase().as_str()).copied().unwrap_or("unknown").into());
        let a = s(&v.account, 256);
        if !a.is_empty() {
            row.insert("account".into(), a.into());
        }
        let e = s(&v.path, 2048);
        if !e.is_empty() {
            row.insert("executable".into(), e.into());
        }
        if svcs.len() < 100000 {
            svcs.push(Value::Object(row));
        }
    }
    for w in p.software.as_deref().unwrap_or_default() {
        let (name, key) = (s(&w.name, 256), s(&w.key, 256));
        if name.is_empty() || key.is_empty() || (w.view != "32" && w.view != "64") || soft.len() >= 100000 {
            continue;
        }
        let mut row = Map::new();
        for (k, v) in [("name", name.as_str()), ("scope", "machine"), ("source", "uninstall_registry"), ("registry_view", w.view.as_str()), ("registry_key", key.as_str())] {
            row.insert(k.into(), v.into());
        }
        for (k, v) in [("version", s(&w.version, 256)), ("vendor", s(&w.vendor, 256))] {
            if !v.is_empty() {
                row.insert(k.into(), v.into());
            }
        }
        soft.push(Value::Object(row));
    }
    let sections = vec![sec("identity", identity, now, &errs), sec("os", os_rows, now, &errs), sec("network", nets, now, &errs), sec("hardware", hw, now, &errs), sec("software", soft, now, &errs), sec("services", svcs, now, &errs)];
    Ok((sections, cands))
}

/// Ровно 12 разделов (как Complete12 в Go): не собираемые по WinRM — unsupported.
pub fn complete12(mut sections: Vec<Value>, now: &str) -> Vec<Value> {
    let mut out = vec![];
    for n in ["identity", "os", "network", "hardware", "software", "updates", "services", "users_groups", "routes_ports", "resources", "protection", "neighbors"] {
        if let Some(i) = sections.iter().position(|s| s["name"] == n) {
            out.push(sections.remove(i));
            continue;
        }
        let (status, reason) = if ["updates", "protection", "neighbors", "users_groups", "routes_ports", "resources"].contains(&n) { ("unsupported", "SECTION_UNSUPPORTED") } else { ("unavailable", "SOURCE_UNAVAILABLE") };
        out.push(json!({"name": n, "collected_at": now, "status": status, "collection_complete": false, "reason_code": reason, "record_count": 0, "records": []}));
    }
    out
}
