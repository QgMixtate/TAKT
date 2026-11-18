//! Сбор Linux по профилю 1.2 (C52.02) — как agent.Collect + CollectLinux12 в Go: identity/os/network из ядра и
//! os-release, затем hardware, software (dpkg/rpm/apk), services (systemd), users_groups, routes_ports, resources.
//! Все секции частичные (partial); сбой одной не отбрасывает остальные; внешние утилиты — по абсолютному пути с
//! пустым окружением и ограничением вывода.

use crate::linuxparse as p;
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, HashMap};
use std::io::Read;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

pub struct Snapshot {
    pub candidates: Value,
    pub sections: Vec<Value>,
}

fn now() -> String {
    crate::client::now_rfc3339()
}

fn read_small(path: &str, limit: u64) -> Option<String> {
    let f = std::fs::File::open(path).ok()?;
    let mut b = Vec::new();
    f.take(limit + 1).read_to_end(&mut b).ok()?;
    if b.len() as u64 > limit {
        return None;
    }
    String::from_utf8(b).ok()
}

fn run_text(limit: usize, path: &str, args: &[&str]) -> Option<String> {
    if !std::path::Path::new(path).exists() {
        return None;
    }
    let mut child = Command::new(path).args(args).env_clear().env("LC_ALL", "C").env("PATH", "/usr/bin:/bin").stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().ok()?;
    let mut out = child.stdout.take()?;
    let reader = std::thread::spawn(move || {
        let mut b = Vec::new();
        let r = (&mut out).take(limit as u64 + 1).read_to_end(&mut b);
        (r, b)
    });
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let (r, b) = reader.join().ok()?;
                if r.is_err() || !status.success() || b.len() > limit {
                    return None;
                }
                return String::from_utf8(b).ok();
            }
            Ok(None) if start.elapsed() > Duration::from_secs(20) => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            Err(_) => return None,
        }
    }
}

fn first_existing(paths: &[&str]) -> Option<String> {
    paths.iter().find(|p| std::path::Path::new(p).exists()).map(|s| s.to_string())
}

fn section(name: &str, at: String, rows: Vec<Value>, complete: bool, reason: &str) -> Value {
    let status = if complete { "ok" } else if rows.is_empty() { "unavailable" } else { "partial" };
    json!({"name": name, "collected_at": at, "status": status, "collection_complete": complete, "reason_code": reason, "record_count": rows.len(), "records": rows})
}

fn failed(name: &str, status: &str, reason: &str) -> Value {
    json!({"name": name, "collected_at": now(), "status": status, "collection_complete": false, "reason_code": reason, "record_count": 0, "records": []})
}

fn partial(name: &str, rows: Vec<p::Row>) -> Value {
    if rows.is_empty() {
        return failed(name, "unavailable", "DATA_UNAVAILABLE");
    }
    json!({"name": name, "collected_at": now(), "status": "partial", "collection_complete": false, "reason_code": "BASELINE_COVERAGE_ONLY", "record_count": rows.len(), "records": rows})
}

/// os-release как данные (без shell): NAME (или ID) и VERSION_ID; кавычки — как strconv.Unquote для простых строк.
pub fn parse_os_release(raw: &str) -> Option<(String, String)> {
    let mut values: HashMap<&str, String> = HashMap::new();
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else { continue };
        if k != "NAME" && k != "VERSION_ID" && k != "ID" {
            continue;
        }
        let v = if v.starts_with('"') {
            let s: String = serde_json::from_str(v).ok()?;
            s
        } else if v.starts_with('\'') && v.ends_with('\'') {
            v.trim_matches('\'').to_string()
        } else {
            v.to_string()
        };
        values.insert(k, v);
    }
    let mut name = values.get("NAME").cloned().unwrap_or_default();
    if name.is_empty() {
        name = values.get("ID").cloned().unwrap_or_default();
    }
    let version = values.get("VERSION_ID").cloned().unwrap_or_default();
    if name.is_empty() || version.is_empty() || name.len() > 128 || version.len() > 128 || (name.clone() + &version).contains(['\0', '\r', '\n']) {
        return None;
    }
    Some((name, version))
}

fn hostname() -> Option<String> {
    let mut buf = [0u8; 256];
    // SAFETY: буфер достаточного размера, gethostname завершает строку NUL при успехе
    let r = unsafe { libc::gethostname(buf.as_mut_ptr() as *mut libc::c_char, buf.len()) };
    if r != 0 {
        return None;
    }
    let end = buf.iter().position(|b| *b == 0).unwrap_or(buf.len());
    String::from_utf8(buf[..end].to_vec()).ok().filter(|h| !h.is_empty() && h.len() <= 255)
}

/// Интерфейсы ядра (getifaddrs): имя, индекс, MAC, адреса с префиксом; петля пропускается — как net.Interfaces.
fn interfaces() -> Result<(Vec<Value>, bool), String> {
    struct Nic {
        index: u32,
        loopback: bool,
        mac: Option<String>,
        addrs: Vec<Value>,
    }
    let mut nics: BTreeMap<String, Nic> = BTreeMap::new();
    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs заполняет связанный список, который освобождается freeifaddrs ниже
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return Err("getifaddrs failed".into());
    }
    let mut cur = head;
    let mut complete = true;
    while !cur.is_null() {
        // SAFETY: cur — элемент списка getifaddrs, живущего до freeifaddrs
        let ifa = unsafe { &*cur };
        cur = ifa.ifa_next;
        let name = unsafe { std::ffi::CStr::from_ptr(ifa.ifa_name) }.to_string_lossy().to_string();
        let index = unsafe { libc::if_nametoindex(ifa.ifa_name) };
        let nic = nics.entry(name).or_insert(Nic { index, loopback: false, mac: None, addrs: vec![] });
        nic.loopback |= ifa.ifa_flags & (libc::IFF_LOOPBACK as u32) != 0;
        if ifa.ifa_addr.is_null() {
            continue;
        }
        let family = unsafe { (*ifa.ifa_addr).sa_family } as i32;
        match family {
            libc::AF_PACKET => {
                let ll = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_ll) };
                if ll.sll_halen == 6 {
                    nic.mac = Some(ll.sll_addr[..6].iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":"));
                }
            }
            libc::AF_INET | libc::AF_INET6 if !ifa.ifa_netmask.is_null() => {
                let (ip, prefix) = if family == libc::AF_INET {
                    let a = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_in) };
                    let m = unsafe { &*(ifa.ifa_netmask as *const libc::sockaddr_in) };
                    (std::net::Ipv4Addr::from(u32::from_be(a.sin_addr.s_addr)).to_string(), u32::from_be(m.sin_addr.s_addr).count_ones())
                } else {
                    let a = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_in6) };
                    let m = unsafe { &*(ifa.ifa_netmask as *const libc::sockaddr_in6) };
                    (std::net::Ipv6Addr::from(a.sin6_addr.s6_addr).to_string(), m.sin6_addr.s6_addr.iter().map(|b| b.count_ones()).sum())
                };
                if nic.addrs.len() == 64 {
                    complete = false;
                } else {
                    nic.addrs.push(json!({"ip": ip, "prefix": prefix}));
                }
            }
            _ => {}
        }
    }
    // SAFETY: список получен getifaddrs выше
    unsafe { libc::freeifaddrs(head) };
    let mut list: Vec<(String, Nic)> = nics.into_iter().collect();
    list.sort_by_key(|(_, n)| n.index);
    let mut rows = vec![];
    for (name, n) in list {
        if rows.len() >= 512 {
            complete = false;
            break;
        }
        if n.loopback {
            continue;
        }
        if name.is_empty() || name.len() > 128 {
            complete = false;
            continue;
        }
        let mut row = Map::new();
        row.insert("name".into(), name.into());
        row.insert("addresses".into(), n.addrs.into());
        if let Some(m) = n.mac {
            row.insert("mac".into(), m.into());
        }
        rows.push(Value::Object(row));
    }
    Ok((rows, complete))
}

fn machine_uuid() -> Option<String> {
    let raw = read_small("/etc/machine-id", 128)?;
    let id = raw.trim();
    let id = if id.len() == 32 { format!("{}-{}-{}-{}-{}", &id[..8], &id[8..12], &id[12..16], &id[16..20], &id[20..]) } else { id.to_string() };
    crate::claims::valid_id(&id).then_some(id)
}

/// identity, os, network — прежние источники (agent.Collect), статус в 1.2 — partial.
fn base() -> (Vec<Value>, Vec<Value>) {
    let mut candidates = vec![];
    let mut sections = vec![];
    let at = now();
    let mut identity = vec![];
    let host = hostname();
    if let Some(h) = &host {
        let mut row = Map::new();
        row.insert("hostname".into(), h.clone().into());
        candidates.push(json!({"kind": "hostname", "namespace": "dns", "value": h}));
        if let Some(id) = machine_uuid() {
            row.insert("machine_uuid".into(), id.clone().into());
            candidates.push(json!({"kind": "machine_uuid", "namespace": "linux-machine-id", "value": id}));
        }
        identity.push(Value::Object(row));
    }
    sections.push(section("identity", at, identity, host.is_some(), if host.is_some() { "COLLECTED" } else { "HOSTNAME_UNAVAILABLE" }));
    let os = read_small("/etc/os-release", 65536).or_else(|| read_small("/usr/lib/os-release", 65536)).and_then(|r| parse_os_release(&r));
    let arch = if cfg!(target_arch = "x86_64") { "amd64" } else if cfg!(target_arch = "aarch64") { "arm64" } else { "386" };
    let os_rows = os.as_ref().map(|(n, v)| vec![json!({"name": n, "version": v, "architecture": arch})]).unwrap_or_default();
    sections.push(section("os", now(), os_rows, os.is_some(), if os.is_some() { "COLLECTED" } else { "OS_RELEASE_UNAVAILABLE" }));
    let (net, complete) = interfaces().unwrap_or((vec![], false));
    sections.push(section("network", now(), net, complete, if complete { "COLLECTED" } else { "NETWORK_COLLECTION_INCOMPLETE" }));
    (candidates, sections)
}

pub fn collect() -> Snapshot {
    let (candidates, base_sections) = base();
    let mut by: HashMap<String, Value> = HashMap::new();
    for mut s in base_sections {
        s["collection_complete"] = false.into();
        if s["status"] == "ok" {
            s["status"] = "partial".into();
            s["reason_code"] = "BASELINE_COVERAGE_ONLY".into();
        }
        by.insert(s["name"].as_str().unwrap_or_default().to_string(), s);
    }
    const SMALL: u64 = 1 << 20;
    const LARGE: u64 = 8 << 20;
    let cpu = read_small("/proc/cpuinfo", SMALL);
    let mem = read_small("/proc/meminfo", SMALL);
    let mut hardware: Option<Vec<p::Row>> = None;
    if cpu.is_some() || mem.is_some() {
        hardware = Some(p::hardware(cpu.as_deref().unwrap_or(""), mem.as_deref().unwrap_or("")));
    }
    let rpm = first_existing(&["/usr/bin/rpm", "/bin/rpm"]);
    if let Some(dpkg) = read_small("/var/lib/dpkg/status", 64 << 20) {
        by.insert("software".into(), partial("software", p::packages(&dpkg)));
    } else if let Some(rpm) = rpm {
        by.insert("software".into(), match run_text(32 << 20, &rpm, &["-qa", "--qf", "%{NAME}\\t%{VERSION}-%{RELEASE}\\t%{ARCH}\\n"]) {
            Some(t) => partial("software", p::rpm_packages(&t)),
            None => failed("software", "unavailable", "SOURCE_UNAVAILABLE"),
        });
    } else if let Some(apk) = read_small("/lib/apk/db/installed", 64 << 20) {
        by.insert("software".into(), partial("software", p::apk_packages(&apk)));
    } else {
        by.insert("software".into(), failed("software", "unsupported", "PACKAGE_MANAGER_UNSUPPORTED"));
    }
    if let Some(systemctl) = first_existing(&["/usr/bin/systemctl", "/bin/systemctl"]) {
        let units = run_text(16 << 20, &systemctl, &["list-units", "--type=service", "--all", "--plain", "--no-legend", "--no-pager"]);
        let files = run_text(16 << 20, &systemctl, &["list-unit-files", "--type=service", "--plain", "--no-legend", "--no-pager"]).unwrap_or_default();
        by.insert("services".into(), match units {
            Some(u) => partial("services", p::systemd_services(&u, &files)),
            None => failed("services", "unavailable", "SOURCE_UNAVAILABLE"),
        });
    }
    let mut dmi = HashMap::new();
    for name in ["bios_vendor", "bios_version", "sys_vendor", "product_name", "product_serial", "product_uuid"] {
        if let Some(t) = read_small(&format!("/sys/class/dmi/id/{name}"), 4096) {
            dmi.insert(name.to_string(), t);
        }
    }
    let dmi_rows = p::dmi(&dmi);
    if !dmi_rows.is_empty() {
        let mut merged = hardware.clone().unwrap_or_default();
        merged.extend(dmi_rows);
        hardware = Some(merged);
    }
    if let Some(h) = hardware {
        by.insert("hardware".into(), partial("hardware", h));
    }
    if let Some(passwd) = read_small("/etc/passwd", SMALL) {
        let group = read_small("/etc/group", SMALL).unwrap_or_default();
        by.insert("users_groups".into(), partial("users_groups", p::accounts(&passwd, &group)));
    }
    let mut rows = vec![];
    let mut read_any = false;
    for (proto, path, v6) in [("tcp", "/proc/net/tcp", false), ("tcp", "/proc/net/tcp6", true), ("udp", "/proc/net/udp", false), ("udp", "/proc/net/udp6", true)] {
        if let Some(t) = read_small(path, LARGE) {
            read_any = true;
            rows.extend(p::sockets(proto, &t, v6));
        }
    }
    if let Some(t) = read_small("/proc/net/route", SMALL) {
        read_any = true;
        rows.extend(p::routes(&t));
    }
    if read_any {
        by.insert("routes_ports".into(), partial("routes_ports", rows));
    }
    if let Some(mi) = read_small("/proc/self/mountinfo", LARGE) {
        by.insert("resources".into(), partial("resources", p::mounts(&mi)));
    }
    let mut sections = vec![];
    for name in ["identity", "os", "network", "hardware", "software", "updates", "services", "users_groups", "routes_ports", "resources", "protection", "neighbors"] {
        let s = match by.remove(name) {
            Some(s) => s,
            None if ["updates", "services", "protection", "neighbors"].contains(&name) => failed(name, "unsupported", "SECTION_UNSUPPORTED"),
            None => failed(name, "unavailable", "SOURCE_UNAVAILABLE"),
        };
        sections.push(s);
    }
    Snapshot { candidates: Value::Array(candidates), sections }
}
