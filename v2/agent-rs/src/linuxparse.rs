//! Чистые парсеры Linux-источников — порт internal/agent/linuxinventory (Go) один к одному: те же строки, порядок и
//! отбрасывание. Паритет проверяется общими векторами testdata/linux12 (Go и Rust сравнивают с одним ожиданием).

use serde_json::{json, Map, Value};
use std::collections::{BTreeSet, HashMap};
use std::net::{Ipv4Addr, Ipv6Addr};

pub type Row = Map<String, Value>;
const MAX_ROWS: usize = 10000;

fn lines(text: &str) -> Vec<&str> {
    // bufio.Scanner: разделитель \n, завершающий \r срезается, последняя строка без \n — тоже строка
    let mut out: Vec<&str> = text.split('\n').map(|l| l.strip_suffix('\r').unwrap_or(l)).collect();
    if text.ends_with('\n') || text.is_empty() {
        out.pop();
    }
    out
}

fn clean(v: &str, limit: usize) -> String {
    if v.len() > limit || v.contains(['\0', '\r', '\n']) {
        return String::new();
    }
    v.to_string()
}

fn row(v: Value) -> Row {
    match v {
        Value::Object(m) => m,
        _ => Row::new(),
    }
}

fn cut<'a>(s: &'a str, sep: &str) -> Option<(&'a str, &'a str)> {
    s.split_once(sep)
}

fn fields(s: &str) -> Vec<&str> {
    s.split_ascii_whitespace().collect()
}

pub fn hardware(cpuinfo: &str, meminfo: &str) -> Vec<Row> {
    let mut rows = vec![];
    let (mut logical, mut model) = (0u64, String::new());
    for l in lines(cpuinfo) {
        if let Some((k, v)) = cut(l, ":") {
            match k.trim() {
                "processor" => logical += 1,
                "model name" if model.is_empty() => model = clean(v.trim(), 256),
                _ => {}
            }
        }
    }
    if logical > 0 {
        let mut r = row(json!({"kind": "cpu", "name": "Logical processors", "logical_processors": logical}));
        if !model.is_empty() {
            r.insert("model".into(), model.into());
        }
        rows.push(r);
    }
    for l in lines(meminfo) {
        if let Some(("MemTotal", v)) = cut(l, ":") {
            let f = fields(v);
            if f.len() == 2 && f[1] == "kB" {
                if let Ok(n) = f[0].parse::<u64>() {
                    if n > 0 {
                        rows.push(row(json!({"kind": "memory", "name": "Physical memory", "bytes": n * 1024})));
                    }
                }
            }
        }
    }
    rows
}

pub fn packages(dpkg: &str) -> Vec<Row> {
    let mut rows = vec![];
    for block in dpkg.split("\n\n") {
        let mut f: HashMap<&str, String> = HashMap::new();
        for l in lines(block) {
            if l.is_empty() || l.starts_with(' ') || l.starts_with('\t') {
                continue;
            }
            if let Some((k, v)) = cut(l, ":") {
                f.insert(k, v.trim().to_string());
            }
        }
        let status = f.get("Status").cloned().unwrap_or_default();
        if !status.ends_with(" installed") || status.starts_with("deinstall") {
            continue;
        }
        let name = clean(f.get("Package").map(String::as_str).unwrap_or(""), 256);
        if name.is_empty() || rows.len() >= MAX_ROWS {
            continue;
        }
        let mut r = row(json!({"name": name, "source": "dpkg", "scope": "machine"}));
        let v = clean(f.get("Version").map(String::as_str).unwrap_or(""), 256);
        if !v.is_empty() {
            r.insert("version".into(), v.into());
        }
        let a = clean(f.get("Architecture").map(String::as_str).unwrap_or(""), 64);
        if !a.is_empty() {
            r.insert("architecture".into(), a.into());
        }
        rows.push(r);
    }
    rows
}

fn parse_u32(s: &str) -> Option<u64> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse::<u32>().ok().map(u64::from)
}

pub fn accounts(passwd: &str, group: &str) -> Vec<Row> {
    let mut rows = vec![];
    for l in lines(passwd) {
        let p: Vec<&str> = l.split(':').collect();
        if p.len() < 7 || l.starts_with('#') {
            continue;
        }
        let name = clean(p[0], 256);
        let (Some(uid), Some(gid)) = (parse_u32(p[2]), parse_u32(p[3])) else { continue };
        if name.is_empty() || rows.len() >= MAX_ROWS {
            continue;
        }
        let mut r = row(json!({"kind": "user", "name": name, "uid": uid, "gid": gid}));
        let shell = clean(p[6], 256);
        if !shell.is_empty() {
            r.insert("shell".into(), shell.into());
        }
        rows.push(r);
    }
    for l in lines(group) {
        let p: Vec<&str> = l.split(':').collect();
        if p.len() < 4 || l.starts_with('#') {
            continue;
        }
        let name = clean(p[0], 256);
        let Some(gid) = parse_u32(p[2]) else { continue };
        if name.is_empty() || rows.len() >= MAX_ROWS {
            continue;
        }
        rows.push(row(json!({"kind": "group", "name": name, "gid": gid})));
        for m in p[3].split(',') {
            let m = clean(m, 256);
            if !m.is_empty() && rows.len() < MAX_ROWS {
                rows.push(row(json!({"kind": "membership", "name": m, "group": name, "gid": gid})));
            }
        }
    }
    rows
}

const PSEUDO_FS: [&str; 17] = ["proc", "sysfs", "devtmpfs", "devpts", "cgroup", "cgroup2", "securityfs", "debugfs", "tracefs", "pstore", "bpf", "autofs", "mqueue", "hugetlbfs", "configfs", "fusectl", "binfmt_misc"];

fn unescape_mount(s: &str) -> String {
    // strings.NewReplacer: слева направо, без повторной замены результата
    let mut out = String::new();
    let mut rest = s;
    'outer: while !rest.is_empty() {
        for (from, to) in [("\\040", " "), ("\\011", "\t"), ("\\012", "\n"), ("\\134", "\\")] {
            if let Some(r) = rest.strip_prefix(from) {
                out.push_str(to);
                rest = r;
                continue 'outer;
            }
        }
        let c = rest.chars().next().unwrap();
        out.push(c);
        rest = &rest[c.len_utf8()..];
    }
    out
}

pub fn mounts(mountinfo: &str) -> Vec<Row> {
    let mut rows: Vec<Row> = vec![];
    let mut index: HashMap<String, usize> = HashMap::new();
    for l in lines(mountinfo) {
        let Some((before, after)) = cut(l, " - ") else { continue };
        let (b, a) = (fields(before), fields(after));
        if b.len() < 6 || a.len() < 2 || PSEUDO_FS.contains(&a[0]) || rows.len() >= MAX_ROWS {
            continue;
        }
        let mp = clean(&unescape_mount(b[4]), 4096);
        if mp.is_empty() {
            continue;
        }
        let r = row(json!({"kind": "mount", "name": mp, "filesystem": a[0], "device_id": clean(&unescape_mount(a[1]), 512), "read_only": format!(",{},", b[5]).contains(",ro,")}));
        if let Some(&i) = index.get(&mp) {
            rows[i] = r;
            continue;
        }
        index.insert(mp, rows.len());
        rows.push(r);
    }
    rows
}

enum Ip {
    V4(Ipv4Addr),
    V6(Ipv6Addr),
}

impl Ip {
    fn text(&self) -> String {
        match self {
            Ip::V4(a) => a.to_string(),
            Ip::V6(a) => go_v6(a),
        }
    }
}

/// Запись IPv6 как у Go netip (RFC 5952; IPv4-mapped — ::ffff:a.b.c.d).
fn go_v6(a: &Ipv6Addr) -> String {
    a.to_string()
}

fn hex_ip(h: &str, v6: bool) -> Option<Ip> {
    if h.len() % 2 != 0 || !h.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let raw: Vec<u8> = (0..h.len()).step_by(2).map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap()).collect();
    if !v6 && raw.len() == 4 {
        return Some(Ip::V4(Ipv4Addr::new(raw[3], raw[2], raw[1], raw[0])));
    }
    if v6 && raw.len() == 16 {
        let mut a = [0u8; 16];
        for i in (0..16).step_by(4) {
            a[i] = raw[i + 3];
            a[i + 1] = raw[i + 2];
            a[i + 2] = raw[i + 1];
            a[i + 3] = raw[i];
        }
        return Some(Ip::V6(Ipv6Addr::from(a)));
    }
    None
}

fn tcp_state(s: &str) -> &'static str {
    match s.to_ascii_uppercase().as_str() {
        "01" => "ESTABLISHED", "02" => "SYN_SENT", "03" => "SYN_RECV", "04" => "FIN_WAIT1", "05" => "FIN_WAIT2", "06" => "TIME_WAIT",
        "07" => "CLOSE", "08" => "CLOSE_WAIT", "09" => "LAST_ACK", "0A" => "LISTEN", "0B" => "CLOSING", _ => "",
    }
}

fn hex_port(s: &str) -> Option<u64> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    u16::from_str_radix(s, 16).ok().map(u64::from)
}

pub fn sockets(proto: &str, text: &str, v6: bool) -> Vec<Row> {
    let mut rows: Vec<Row> = vec![];
    let family = if v6 { "ipv6" } else { "ipv4" };
    for (i, l) in lines(text).into_iter().enumerate() {
        let f = fields(l);
        if i == 0 || f.len() < 4 || rows.len() >= MAX_ROWS {
            continue;
        }
        let (Some((la, lp)), Some((ra, rp))) = (cut(f[1], ":"), cut(f[2], ":")) else { continue };
        let (Some(mut lip), Some(mut rip), Some(lport), Some(rport)) = (hex_ip(la, v6), hex_ip(ra, v6), hex_port(lp), hex_port(rp)) else { continue };
        let mut state = tcp_state(f[3]);
        if proto == "udp" {
            state = "";
        } else if state.is_empty() {
            continue;
        }
        let mut row_family = family;
        let mapped = |a: &Ip| matches!(a, Ip::V6(x) if x.to_ipv4_mapped().is_some());
        if v6 && (mapped(&lip) || mapped(&rip)) {
            row_family = "ipv4";
            let norm = |a: Ip| -> Option<Ip> {
                match a {
                    Ip::V6(x) if x.to_ipv4_mapped().is_some() => Some(Ip::V4(x.to_ipv4_mapped().unwrap())),
                    Ip::V6(x) if x.is_unspecified() => Some(Ip::V4(Ipv4Addr::UNSPECIFIED)),
                    Ip::V4(x) => Some(Ip::V4(x)),
                    _ => None,
                }
            };
            match (norm(lip), norm(rip)) {
                (Some(a), Some(b)) => {
                    lip = a;
                    rip = b;
                }
                _ => continue,
            }
        }
        let mut r = row(json!({"kind": proto, "family": row_family, "local_address": lip.text(), "local_port": lport, "remote_address": rip.text(), "remote_port": rport}));
        if !state.is_empty() {
            r.insert("state".into(), state.into());
        }
        rows.push(r);
    }
    rows.sort_by(|a, b| a["local_port"].to_string().cmp(&b["local_port"].to_string()));
    rows
}

pub fn routes(text: &str) -> Vec<Row> {
    let mut rows = vec![];
    for (i, l) in lines(text).into_iter().enumerate() {
        let f = fields(l);
        if i == 0 || f.len() < 8 || rows.len() >= MAX_ROWS {
            continue;
        }
        let (Some(Ip::V4(dst)), Some(Ip::V4(gw)), Some(Ip::V4(mask))) = (hex_ip(f[1], false), hex_ip(f[2], false), hex_ip(f[7], false)) else { continue };
        let Some(metric) = parse_u32(f[6]) else { continue };
        let mut ones = 0;
        for mut b in mask.octets() {
            while b != 0 {
                ones += 1;
                b <<= 1;
            }
        }
        rows.push(row(json!({"kind": "route", "family": "ipv4", "destination": format!("{dst}/{ones}"), "gateway": gw.to_string(), "interface": clean(f[0], 64), "metric": metric})));
    }
    rows
}

fn sort_rows(rows: &mut [Row]) {
    let key = |r: &Row| match &r["name"] {
        Value::String(s) => s.clone(),
        v => v.to_string(),
    };
    rows.sort_by_key(key);
}

fn arch_ok(a: &str) -> bool {
    !a.is_empty() && a.len() <= 64 && a.bytes().all(|b| b.is_ascii_alphanumeric() || b"_.+-".contains(&b))
}

fn software_row(source: &str, name: &str, version: &str, arch: &str) -> Option<Row> {
    let name = clean(name, 256);
    if name.is_empty() {
        return None;
    }
    let mut r = row(json!({"name": name, "source": source, "scope": "machine"}));
    let v = clean(version, 256);
    if !v.is_empty() {
        r.insert("version".into(), v.into());
    }
    if arch_ok(arch) {
        r.insert("architecture".into(), arch.into());
    }
    Some(r)
}

pub fn rpm_packages(text: &str) -> Vec<Row> {
    let mut rows = vec![];
    for l in lines(text) {
        let f: Vec<&str> = l.split('\t').collect();
        if f.len() < 3 || f[0] == "gpg-pubkey" || rows.len() >= MAX_ROWS {
            continue;
        }
        if let Some(r) = software_row("rpm", f[0], f[1], f[2]) {
            rows.push(r);
        }
    }
    rows
}

pub fn apk_packages(text: &str) -> Vec<Row> {
    let mut rows = vec![];
    for block in text.split("\n\n") {
        let (mut name, mut version, mut arch) = ("", "", "");
        for l in lines(block) {
            if let Some(v) = l.strip_prefix("P:") {
                name = v;
            } else if let Some(v) = l.strip_prefix("V:") {
                version = v;
            } else if let Some(v) = l.strip_prefix("A:") {
                arch = v;
            }
        }
        if rows.len() >= MAX_ROWS {
            break;
        }
        if let Some(r) = software_row("apk", name, version, arch) {
            rows.push(r);
        }
    }
    rows
}

fn start_mode(s: &str) -> &'static str {
    match s {
        "enabled" | "enabled-runtime" | "alias" | "generated" | "transient" => "auto",
        "static" | "indirect" => "demand",
        "disabled" | "masked" | "masked-runtime" => "disabled",
        _ => "unknown",
    }
}

fn service_state(active: &str, sub: &str) -> &'static str {
    match active {
        "active" | "reloading" => {
            if sub == "running" || sub == "reload" || active == "reloading" { "running" } else { "stopped" }
        }
        "activating" => "start_pending",
        "deactivating" => "stop_pending",
        "inactive" | "failed" => "stopped",
        _ => "unknown",
    }
}

pub fn systemd_services(list_units: &str, list_unit_files: &str) -> Vec<Row> {
    let mut modes: HashMap<String, &'static str> = HashMap::new();
    for l in lines(list_unit_files) {
        let f = fields(l);
        if f.len() >= 2 && f[0].ends_with(".service") {
            modes.insert(f[0].to_string(), start_mode(f[1]));
        }
    }
    let mut rows = vec![];
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for l in lines(list_units) {
        let l = l.trim_start_matches(['●', '*', ' ', '\t']);
        let f = fields(l);
        if f.len() < 4 || !f[0].ends_with(".service") || rows.len() >= MAX_ROWS {
            continue;
        }
        let name = clean(&f[0][..f[0].len() - 8], 256);
        if name.is_empty() || f[1] == "not-found" {
            continue;
        }
        seen.insert(f[0].to_string());
        let mut r = row(json!({"name": name, "state": service_state(f[2], f[3])}));
        let d = clean(&f[4..].join(" "), 256);
        if !d.is_empty() {
            r.insert("display_name".into(), d.into());
        }
        r.insert("start_mode".into(), modes.get(f[0]).copied().unwrap_or("unknown").into());
        rows.push(r);
    }
    for (unit, mode) in &modes {
        let name = clean(&unit[..unit.len() - 8], 256);
        if seen.contains(unit) || name.is_empty() || name.ends_with('@') || rows.len() >= MAX_ROWS {
            continue;
        }
        rows.push(row(json!({"name": name, "state": "stopped", "start_mode": mode})));
    }
    sort_rows(&mut rows);
    rows
}

fn placeholder(v: &str) -> bool {
    matches!(v.to_lowercase().as_str(), "" | "none" | "default string" | "to be filled by o.e.m." | "not specified" | "system serial number" | "unknown" | "0")
}

fn dmi_value(v: &str) -> String {
    let v = v.trim();
    if placeholder(v) {
        return String::new();
    }
    clean(v, 256)
}

fn uuid_ok(u: &str) -> bool {
    let b = u.as_bytes();
    b.len() == 36 && b.iter().enumerate().all(|(i, c)| if [8, 13, 18, 23].contains(&i) { *c == b'-' } else { c.is_ascii_hexdigit() })
}

pub fn dmi(files: &HashMap<String, String>) -> Vec<Row> {
    let g = |k: &str| files.get(k).map(String::as_str).unwrap_or("");
    let (vendor, version, product, sys_vendor) = (dmi_value(g("bios_vendor")), dmi_value(g("bios_version")), dmi_value(g("product_name")), dmi_value(g("sys_vendor")));
    if vendor.is_empty() && version.is_empty() && product.is_empty() && sys_vendor.is_empty() {
        return vec![];
    }
    let mut r = row(json!({"kind": "bios", "name": "System firmware"}));
    if !version.is_empty() && version.len() <= 200 {
        r.insert("name".into(), format!("BIOS {version}").into());
    }
    if !sys_vendor.is_empty() {
        r.insert("vendor".into(), sys_vendor.into());
    } else if !vendor.is_empty() {
        r.insert("vendor".into(), vendor.into());
    }
    if !product.is_empty() {
        r.insert("model".into(), product.into());
    }
    let s = dmi_value(g("product_serial"));
    if !s.is_empty() {
        r.insert("serial".into(), s.into());
    }
    let u = g("product_uuid").trim();
    if uuid_ok(u) && !placeholder(u) {
        r.insert("uuid".into(), u.to_lowercase().into());
    }
    vec![r]
}

fn machine_id_ok(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Вывод `hostname` и /etc/machine-id → строка identity (как linuxinventory.Identity).
pub fn identity(hostname: &str, machine_id: &str) -> Vec<Row> {
    let h = clean(hostname.trim(), 255);
    if h.is_empty() {
        return vec![];
    }
    let mut r = row(json!({"hostname": h}));
    let id = machine_id.trim().to_lowercase();
    if machine_id_ok(&id) {
        r.insert("machine_uuid".into(), format!("{}-{}-{}-{}-{}", &id[..8], &id[8..12], &id[12..16], &id[16..20], &id[20..]).into());
    }
    vec![r]
}

/// os-release (как данные) и `uname -m` → строка os (как linuxinventory.OS).
pub fn os(os_release: &str, uname: &str) -> Vec<Row> {
    let mut values: HashMap<&str, String> = HashMap::new();
    for l in lines(os_release) {
        let l = l.trim();
        let Some((k, v)) = cut(l, "=") else { continue };
        if l.starts_with('#') || !["NAME", "VERSION_ID", "ID"].contains(&k) {
            continue;
        }
        let v = if v.starts_with('"') {
            match serde_json::from_str::<String>(v) {
                Ok(u) => u,
                Err(_) => return vec![],
            }
        } else {
            v.trim_matches('\'').to_string()
        };
        values.insert(k, v);
    }
    let mut name = values.get("NAME").cloned().unwrap_or_default();
    if name.is_empty() {
        name = values.get("ID").cloned().unwrap_or_default();
    }
    let version = values.get("VERSION_ID").cloned().unwrap_or_default();
    let arch = match uname.trim() {
        "x86_64" | "amd64" => "amd64",
        "aarch64" | "arm64" => "arm64",
        "i386" | "i686" => "386",
        _ => "",
    };
    if clean(&name, 128).is_empty() || clean(&version, 128).is_empty() || arch.is_empty() {
        return vec![];
    }
    vec![row(json!({"name": name, "version": version, "architecture": arch}))]
}

fn mac_ok(m: &str) -> bool {
    let b = m.as_bytes();
    b.len() == 17 && b.iter().enumerate().all(|(i, c)| if i % 3 == 2 { *c == b':' } else { c.is_ascii_digit() || (b'a'..=b'f').contains(c) })
}

/// `ip -o link show` и `ip -o addr show` → интерфейсы (как linuxinventory.Network); lo и link-local пропускаются.
pub fn network(link: &str, addr: &str) -> Vec<Row> {
    struct Nic {
        index: i64,
        mac: String,
        mtu: i64,
        addrs: Vec<Value>,
    }
    let mut nics: HashMap<String, Nic> = HashMap::new();
    let mut order: Vec<String> = vec![];
    let mut get = |name: &str, nics: &mut HashMap<String, Nic>| {
        if !nics.contains_key(name) {
            nics.insert(name.to_string(), Nic { index: 0, mac: String::new(), mtu: 0, addrs: vec![] });
            order.push(name.to_string());
        }
    };
    for l in lines(link) {
        let f = fields(l);
        if f.len() < 3 {
            continue;
        }
        let idx = f[0].trim_end_matches(':').parse::<i64>();
        let name = f[1].split('@').next().unwrap_or("").trim_end_matches(':');
        let Ok(idx) = idx else { continue };
        if idx < 1 || name == "lo" || clean(name, 128).is_empty() {
            continue;
        }
        get(name, &mut nics);
        let n = nics.get_mut(name).unwrap();
        n.index = idx;
        let mut i = 2;
        while i + 1 < f.len() {
            match f[i] {
                "mtu" => n.mtu = f[i + 1].parse().unwrap_or(0),
                "link/ether" => {
                    let m = f[i + 1].to_lowercase();
                    if m != "00:00:00:00:00:00" && mac_ok(&m) {
                        n.mac = m;
                    }
                }
                _ => {}
            }
            i += 1;
        }
    }
    for l in lines(addr) {
        let f = fields(l);
        if f.len() < 4 || (f[2] != "inet" && f[2] != "inet6") {
            continue;
        }
        let name = f[1].split('@').next().unwrap_or("");
        if name == "lo" {
            continue;
        }
        let Some((ip, bits)) = f[3].split_once('/') else { continue };
        let Ok(ip) = ip.parse::<std::net::IpAddr>() else { continue };
        let Ok(bits) = bits.parse::<u8>() else { continue };
        let link_local = match ip {
            std::net::IpAddr::V4(a) => a.is_link_local(),
            std::net::IpAddr::V6(a) => (a.segments()[0] & 0xffc0) == 0xfe80,
        };
        if bits > if ip.is_ipv4() { 32 } else { 128 } || link_local {
            continue;
        }
        get(name, &mut nics);
        let n = nics.get_mut(name).unwrap();
        if n.addrs.len() < 64 {
            n.addrs.push(json!({"ip": ip.to_string(), "prefix": bits}));
        }
    }
    let mut rows = vec![];
    for name in order {
        if rows.len() >= MAX_ROWS {
            break;
        }
        let n = &nics[&name];
        let mut r = row(json!({"name": name, "addresses": n.addrs}));
        if !n.mac.is_empty() {
            r.insert("mac".into(), n.mac.clone().into());
        }
        if n.mtu > 0 {
            r.insert("mtu".into(), n.mtu.into());
        }
        if n.index > 0 {
            r.insert("interface_index".into(), n.index.into());
        }
        rows.push(r);
    }
    rows
}
