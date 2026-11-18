//! Сбор Windows по профилю 1.2 (C52.02) — порт internal/agent/windowsinventory (Go): только чтение через Win32 API и
//! реестр, без PowerShell. Этот шаг: identity, os, network, hardware, software, services. Разделы на WMI/NetAPI
//! (updates, protection) — следующим шагом; до того — unsupported. users_groups (NetAPI), routes_ports, resources, neighbors — нативно.

#![allow(clippy::missing_safety_doc)]
use serde_json::{json, Map, Value};
use std::ptr::{null, null_mut};
use windows_sys::Win32::Foundation::{LocalFree, ERROR_MORE_DATA, ERROR_SUCCESS, HANDLE};
use windows_sys::Win32::NetworkManagement::IpHelper::{GetAdaptersAddresses, IP_ADAPTER_ADDRESSES_LH, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_MULTICAST, GAA_FLAG_SKIP_DNS_SERVER};
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR_IN, SOCKADDR_IN6};
use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows_sys::Win32::Security::{GetTokenInformation, TokenUser, TOKEN_QUERY, TOKEN_USER};
use windows_sys::Win32::System::Registry::*;
use windows_sys::Win32::System::Services::*;
use windows_sys::Win32::System::SystemInformation::*;
use windows_sys::Win32::System::Threading::{GetActiveProcessorCount, GetCurrentProcess, OpenProcessToken};

pub struct Snapshot {
    pub candidates: Value,
    pub sections: Vec<Value>,
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn from_wide(p: *const u16, limit: usize) -> String {
    if p.is_null() {
        return String::new();
    }
    let mut n = 0;
    // SAFETY: строки Win32 завершаются нулём; чтение ограничено limit+1 символами
    unsafe {
        while n <= limit && *p.add(n) != 0 {
            n += 1;
        }
        if n > limit {
            return String::new();
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(p, n))
    }
}

/// Как safeText в Go: пусто при превышении длины (в символах) или управляющих символах.
fn safe_text(v: String, limit: usize) -> String {
    if v.is_empty() || v.chars().count() > limit || v.chars().any(|c| (c as u32) < 32 || c as u32 == 127) {
        return String::new();
    }
    v
}

struct Key(HKEY);
impl Drop for Key {
    fn drop(&mut self) {
        // SAFETY: ключ открыт RegOpenKeyExW
        unsafe { RegCloseKey(self.0) };
    }
}

fn open_key(root: HKEY, path: &str, access: u32) -> Option<Key> {
    let mut k: HKEY = 0;
    let p = wide(path);
    // SAFETY: строка и выходной указатель действительны
    (unsafe { RegOpenKeyExW(root, p.as_ptr(), 0, access, &mut k) } == ERROR_SUCCESS).then_some(Key(k))
}

fn reg_text(key: &Key, name: &str, limit: usize) -> String {
    let n = wide(name);
    let mut buf = vec![0u8; (limit + 1) * 2];
    let (mut kind, mut size) = (0u32, buf.len() as u32);
    // SAFETY: буфер и длина согласованы
    let r = unsafe { RegQueryValueExW(key.0, n.as_ptr(), null(), &mut kind, buf.as_mut_ptr(), &mut size) };
    if r != ERROR_SUCCESS || kind != REG_SZ || size < 2 || size as usize > buf.len() || size % 2 != 0 {
        return String::new();
    }
    let mut units: Vec<u16> = buf[..size as usize].chunks(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
    if units.last() == Some(&0) {
        units.pop();
    }
    safe_text(String::from_utf16_lossy(&units), limit)
}

fn subkeys(key: &Key, max: u32) -> Vec<String> {
    let mut out = vec![];
    for i in 0..max {
        let mut buf = [0u16; 256];
        let mut len = buf.len() as u32;
        // SAFETY: буфер и длина согласованы, прочие выходы не нужны
        let r = unsafe { RegEnumKeyExW(key.0, i, buf.as_mut_ptr(), &mut len, null(), null_mut(), null_mut(), null_mut()) };
        if r != ERROR_SUCCESS {
            break;
        }
        out.push(String::from_utf16_lossy(&buf[..len as usize]));
    }
    out
}

fn computer_name(kind: COMPUTER_NAME_FORMAT) -> Option<String> {
    let mut buf = [0u16; 256];
    let mut n = buf.len() as u32;
    // SAFETY: буфер и длина согласованы
    if unsafe { GetComputerNameExW(kind, buf.as_mut_ptr(), &mut n) } == 0 || n as usize >= buf.len() {
        return None;
    }
    Some(String::from_utf16_lossy(&buf[..n as usize])).filter(|s| !s.is_empty())
}

/// MachineGuid (HKLM\SOFTWARE\Microsoft\Cryptography, 64-битное представление) — как machineid в Go.
pub fn machine_guid() -> Option<String> {
    let k = open_key(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Cryptography", KEY_QUERY_VALUE | KEY_WOW64_64KEY)?;
    let g = reg_text(&k, "MachineGuid", 128).to_lowercase();
    crate::claims::valid_id(&g).then_some(g)
}

fn identity() -> Vec<Value> {
    let Some(host) = computer_name(ComputerNameDnsHostname) else { return vec![] };
    let mut row = Map::new();
    row.insert("hostname".into(), host.into());
    if let Some(f) = computer_name(ComputerNameDnsFullyQualified) {
        row.insert("fqdn".into(), f.into());
    }
    if let Some(d) = computer_name(ComputerNameDnsDomain) {
        row.insert("domain".into(), d.into());
    }
    if let Some(g) = machine_guid() {
        row.insert("machine_uuid".into(), g.into());
    }
    vec![Value::Object(row)]
}

#[repr(C)]
struct OsVersion {
    size: u32,
    major: u32,
    minor: u32,
    build: u32,
    platform: u32,
    csd: [u16; 128],
    sp_major: u16,
    sp_minor: u16,
    suite: u16,
    product_type: u8,
    reserved: u8,
}

#[link(name = "ntdll")]
extern "system" {
    fn RtlGetVersion(info: *mut OsVersion) -> i32;
}

fn version() -> OsVersion {
    // SAFETY: структура OSVERSIONINFOEXW с заполненным размером
    let mut v: OsVersion = unsafe { std::mem::zeroed() };
    v.size = std::mem::size_of::<OsVersion>() as u32;
    unsafe { RtlGetVersion(&mut v) };
    v
}

fn operating_system() -> Vec<Value> {
    let v = version();
    let product = if v.product_type == 1 { "Windows" } else { "Windows Server" };
    vec![json!({"name": product, "version": format!("{}.{}", v.major, v.minor), "build": v.build.to_string(), "architecture": "amd64"})]
}

fn network() -> Vec<Value> {
    let mut size: u32 = 64 * 1024;
    let mut buf: Vec<u64> = vec![];
    for _ in 0..3 {
        buf = vec![0u64; (size as usize).div_ceil(8)];
        // SAFETY: буфер выровнен и имеет размер size байт
        let r = unsafe { GetAdaptersAddresses(AF_UNSPEC as u32, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER, null(), buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH, &mut size) };
        if r == ERROR_SUCCESS {
            break;
        }
        if r != 111 {
            // ERROR_BUFFER_OVERFLOW = 111
            return vec![];
        }
    }
    let mut rows: Vec<(u32, Value)> = vec![];
    let mut cur = buf.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
    while !cur.is_null() && rows.len() < 512 {
        // SAFETY: элемент списка в нашем буфере
        let a = unsafe { &*cur };
        cur = a.Next;
        if a.IfType == 24 {
            continue; // IF_TYPE_SOFTWARE_LOOPBACK
        }
        let name = from_wide(a.FriendlyName, 256);
        if name.is_empty() || name.chars().count() > 128 {
            continue;
        }
        // SAFETY: объединение заполнено системой
        let mut index = unsafe { a.Anonymous1.Anonymous.IfIndex };
        if index == 0 {
            index = a.Ipv6IfIndex;
        }
        let mut addresses = vec![];
        let mut u = a.FirstUnicastAddress;
        while !u.is_null() && addresses.len() < 64 {
            // SAFETY: элемент списка адресов
            let ua = unsafe { &*u };
            u = ua.Next;
            let sa = ua.Address.lpSockaddr;
            if sa.is_null() {
                continue;
            }
            let fam = unsafe { (*sa).sa_family };
            let ip = if fam == AF_INET {
                let s = unsafe { &*(sa as *const SOCKADDR_IN) };
                std::net::IpAddr::from(unsafe { s.sin_addr.S_un.S_addr }.to_ne_bytes())
            } else if fam == AF_INET6 {
                let s = unsafe { &*(sa as *const SOCKADDR_IN6) };
                std::net::IpAddr::from(unsafe { s.sin6_addr.u.Byte })
            } else {
                continue;
            };
            addresses.push(json!({"ip": ip.to_string(), "prefix": ua.OnLinkPrefixLength}));
        }
        let mut row = Map::new();
        row.insert("name".into(), name.into());
        row.insert("addresses".into(), addresses.into());
        row.insert("interface_index".into(), index.into());
        if a.PhysicalAddressLength == 6 {
            row.insert("mac".into(), a.PhysicalAddress[..6].iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":").into());
        }
        rows.push((index, Value::Object(row)));
    }
    rows.sort_by_key(|r| r.0);
    rows.into_iter().map(|r| r.1).collect()
}

fn hardware() -> Vec<Value> {
    let mut rows = vec![];
    // SAFETY: простой вызов без указателей
    let count = unsafe { GetActiveProcessorCount(0xffff) };
    if count > 0 {
        rows.push(json!({"kind": "cpu", "name": "Logical processors", "logical_processors": count}));
    }
    let mut m: windows_sys::Win32::System::SystemInformation::MEMORYSTATUSEX = unsafe { std::mem::zeroed() };
    m.dwLength = std::mem::size_of_val(&m) as u32;
    // SAFETY: структура с заполненной длиной
    if unsafe { GlobalMemoryStatusEx(&mut m) } != 0 && m.ullTotalPhys > 0 {
        rows.push(json!({"kind": "memory", "name": "Physical memory", "bytes": m.ullTotalPhys}));
    }
    if let Some(k) = open_key(HKEY_LOCAL_MACHINE, "HARDWARE\\DESCRIPTION\\System\\BIOS", KEY_QUERY_VALUE | KEY_WOW64_64KEY) {
        let mut row = Map::new();
        row.insert("kind".into(), "bios".into());
        row.insert("name".into(), "BIOS".into());
        for (prop, value) in [("vendor", "BIOSVendor"), ("model", "BIOSVersion")] {
            let v = reg_text(&k, value, 256);
            if !v.is_empty() {
                row.insert(prop.into(), v.into());
            }
        }
        if row.len() > 2 {
            rows.push(Value::Object(row));
        }
    }
    rows
}

fn current_user_sid() -> Option<String> {
    let mut token: HANDLE = 0;
    // SAFETY: псевдодескриптор текущего процесса; токен закрывается ниже
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return None;
    }
    let mut buf = vec![0u64; 64];
    let mut len = 0u32;
    let ok = unsafe { GetTokenInformation(token, TokenUser, buf.as_mut_ptr() as *mut _, (buf.len() * 8) as u32, &mut len) } != 0;
    unsafe { windows_sys::Win32::Foundation::CloseHandle(token) };
    if !ok {
        return None;
    }
    let user = unsafe { &*(buf.as_ptr() as *const TOKEN_USER) };
    let mut text: *mut u16 = null_mut();
    if unsafe { ConvertSidToStringSidW(user.User.Sid, &mut text) } == 0 {
        return None;
    }
    let sid = from_wide(text, 256);
    unsafe { LocalFree(text as _) };
    Some(sid).filter(|s| !s.is_empty())
}

fn software() -> Vec<Value> {
    let mut rows = vec![];
    let principal = current_user_sid();
    for (root, scope) in [(HKEY_LOCAL_MACHINE, "machine"), (HKEY_CURRENT_USER, "current_user")] {
        if scope == "current_user" && principal.is_none() {
            continue;
        }
        for (flag, view) in [(KEY_WOW64_64KEY, "64"), (KEY_WOW64_32KEY, "32")] {
            if rows.len() >= 10000 {
                return rows;
            }
            let Some(key) = open_key(root, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall", KEY_ENUMERATE_SUB_KEYS | flag) else { continue };
            for sub in subkeys(&key, 10000) {
                if rows.len() >= 10000 {
                    break;
                }
                let Some(entry) = open_key(key.0, &sub, KEY_QUERY_VALUE | flag) else { continue };
                let name = reg_text(&entry, "DisplayName", 256);
                if name.is_empty() || safe_text(sub.clone(), 256).is_empty() {
                    continue;
                }
                let mut row = Map::new();
                for (k, v) in [("name", name.as_str()), ("scope", scope), ("source", "uninstall_registry"), ("registry_view", view), ("registry_key", sub.as_str())] {
                    row.insert(k.into(), v.into());
                }
                if scope == "current_user" {
                    row.insert("principal_sid".into(), principal.clone().unwrap_or_default().into());
                }
                for (prop, value) in [("version", "DisplayVersion"), ("vendor", "Publisher")] {
                    let v = reg_text(&entry, value, 256);
                    if !v.is_empty() {
                        row.insert(prop.into(), v.into());
                    }
                }
                rows.push(Value::Object(row));
            }
        }
    }
    rows
}

fn services() -> Vec<Value> {
    // SAFETY: локальный SCM, только перечисление
    let scm = unsafe { OpenSCManagerW(null(), null(), SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE) };
    if scm == 0 {
        return vec![];
    }
    let mut rows = vec![];
    let mut resume = 0u32;
    for _ in 0..8 {
        if rows.len() >= 4096 {
            break;
        }
        let mut buf = vec![0u64; 256 * 1024 / 8];
        let (mut needed, mut returned) = (0u32, 0u32);
        let ok = unsafe { EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, buf.as_mut_ptr() as *mut u8, (buf.len() * 8) as u32, &mut needed, &mut returned, &mut resume, null()) } != 0;
        let more = !ok && unsafe { windows_sys::Win32::Foundation::GetLastError() } == ERROR_MORE_DATA;
        if !ok && !more {
            break;
        }
        let entries = unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const ENUM_SERVICE_STATUS_PROCESSW, returned as usize) };
        for e in entries {
            if rows.len() == 4096 {
                break;
            }
            let name = safe_text(from_wide(e.lpServiceName, 256), 256);
            if name.is_empty() {
                continue;
            }
            let state = match e.ServiceStatusProcess.dwCurrentState {
                1 => "stopped", 2 => "start_pending", 3 => "stop_pending", 4 => "running", 5 => "continue_pending", 6 => "pause_pending", 7 => "paused", _ => "unknown",
            };
            let mut row = Map::new();
            row.insert("name".into(), name.into());
            row.insert("state".into(), state.into());
            let d = safe_text(from_wide(e.lpDisplayName, 256), 256);
            if !d.is_empty() {
                row.insert("display_name".into(), d.into());
            }
            rows.push(Value::Object(row));
        }
        if ok || returned == 0 {
            break;
        }
    }
    unsafe { CloseServiceHandle(scm) };
    rows
}

fn failed(name: &str, status: &str, reason: &str) -> Value {
    json!({"name": name, "collected_at": crate::client::now_rfc3339(), "status": status, "collection_complete": false, "reason_code": reason, "record_count": 0, "records": []})
}

/// Один раздел — как nativeSection в Go (пустой результат — unavailable/API_DATA_UNAVAILABLE).
pub fn section(name: &str) -> Value {
    let rows = match name {
        "identity" => identity(),
        "os" => operating_system(),
        "network" => network(),
        "hardware" => hardware(),
        "software" => software(),
        "services" => services(),
        "users_groups" => {
            if version().product_type == 2 {
                return failed(name, "unsupported", "LOCAL_SAM_UNSUPPORTED_ON_DC");
            }
            accounts()
        }
        "routes_ports" => routes(),
        "resources" => resources(),
        "neighbors" => neighbors(),
        "updates" | "protection" => return crate::wmi_windows::section(name),
        _ => return failed(name, "unsupported", "SECTION_UNSUPPORTED"),
    };
    if rows.is_empty() {
        return failed(name, "unavailable", "API_DATA_UNAVAILABLE");
    }
    json!({"name": name, "collected_at": crate::client::now_rfc3339(), "status": "partial", "collection_complete": false, "reason_code": "BASELINE_COVERAGE_ONLY", "record_count": rows.len(), "records": rows})
}

/// Кандидаты идентичности — как candidatesFromSections в Go: hostname.raw и MachineGuid.
pub fn collect() -> Snapshot {
    let names = ["identity", "os", "network", "hardware", "software", "updates", "services", "users_groups", "routes_ports", "resources", "protection", "neighbors"];
    let sections: Vec<Value> = names.iter().map(|n| worker_section(n)).collect();
    let mut candidates = vec![];
    if let Some(h) = sections[0]["records"][0]["hostname"].as_str().filter(|h| h.len() <= 512) {
        candidates.push(json!({"kind": "hostname", "namespace": "hostname.raw", "value": h}));
    }
    if let Some(g) = machine_guid() {
        candidates.push(json!({"kind": "machine_uuid", "namespace": "windows-machine-guid", "value": g}));
    }
    Snapshot { candidates: Value::Array(candidates), sections }
}

use windows_sys::Win32::NetworkManagement::IpHelper::{FreeMibTable, GetIpForwardTable2, GetIpNetTable2, MIB_IPFORWARD_TABLE2, MIB_IPNET_TABLE2};
use windows_sys::Win32::NetworkManagement::NetManagement::{NetApiBufferFree, NetLocalGroupEnum, NetLocalGroupGetMembers, NetUserEnum};
use windows_sys::Win32::Networking::WinSock::SOCKADDR_INET;
use windows_sys::Win32::Security::{IsValidSid, LookupAccountNameW};
use windows_sys::Win32::Storage::FileSystem::{GetDiskFreeSpaceExW, GetDriveTypeW, GetLogicalDriveStringsW, GetVolumeInformationW};

fn sockaddr_ip(a: &SOCKADDR_INET) -> Option<std::net::IpAddr> {
    // SAFETY: семейство определяет активное поле объединения
    unsafe {
        match a.si_family {
            AF_INET => Some(std::net::IpAddr::from(a.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes())),
            AF_INET6 => Some(std::net::IpAddr::from(a.Ipv6.sin6_addr.u.Byte)),
            _ => None,
        }
    }
}

fn is_4in6(ip: &std::net::IpAddr) -> bool {
    matches!(ip, std::net::IpAddr::V6(v) if v.to_ipv4_mapped().is_some())
}

fn resources() -> Vec<Value> {
    let mut roots = [0u16; 1024];
    // SAFETY: буфер и длина согласованы
    let n = unsafe { GetLogicalDriveStringsW(roots.len() as u32, roots.as_mut_ptr()) } as usize;
    if n == 0 || n >= roots.len() {
        return vec![];
    }
    let mut rows = vec![];
    for root in roots[..n].split(|c| *c == 0).filter(|r| !r.is_empty()) {
        let name = String::from_utf16_lossy(root);
        let path = wide(&name);
        if unsafe { GetDriveTypeW(path.as_ptr()) } != 3 {
            continue; // только DRIVE_FIXED: без сетевых, съёмных и монтирований
        }
        let (mut caller, mut total, mut free) = (0u64, 0u64, 0u64);
        if unsafe { GetDiskFreeSpaceExW(path.as_ptr(), &mut caller, &mut total, &mut free) } == 0 {
            continue;
        }
        let mut row = Map::new();
        row.insert("kind".into(), "volume".into());
        row.insert("name".into(), name.into());
        row.insert("total_bytes".into(), total.into());
        row.insert("free_bytes".into(), free.into());
        let mut fs = [0u16; 64];
        if unsafe { GetVolumeInformationW(path.as_ptr(), null_mut(), 0, null_mut(), null_mut(), null_mut(), fs.as_mut_ptr(), fs.len() as u32) } != 0 {
            let v = safe_text(from_wide(fs.as_ptr(), 63), 64);
            if !v.is_empty() {
                row.insert("filesystem".into(), v.into());
            }
        }
        rows.push(Value::Object(row));
    }
    rows
}

fn routes() -> Vec<Value> {
    let mut table: *mut MIB_IPFORWARD_TABLE2 = null_mut();
    // SAFETY: таблица выделяется системой и освобождается FreeMibTable
    if unsafe { GetIpForwardTable2(AF_UNSPEC, &mut table) } != 0 || table.is_null() {
        return vec![];
    }
    let count = unsafe { (*table).NumEntries }.min(10000) as usize;
    let entries = unsafe { std::slice::from_raw_parts((*table).Table.as_ptr(), count) };
    let mut rows = vec![];
    for e in entries {
        let Some(ip) = sockaddr_ip(&e.DestinationPrefix.Prefix) else { continue };
        let bits = e.DestinationPrefix.PrefixLength as u32;
        let max = if ip.is_ipv4() { 32 } else { 128 };
        if bits > max || is_4in6(&ip) {
            continue;
        }
        let family = if ip.is_ipv4() { "ipv4" } else { "ipv6" };
        let mut row = Map::new();
        row.insert("kind".into(), "route".into());
        row.insert("family".into(), family.into());
        row.insert("destination".into(), format!("{ip}/{bits}").into());
        row.insert("interface_index".into(), e.InterfaceIndex.into());
        row.insert("metric".into(), e.Metric.into());
        if let Some(gw) = sockaddr_ip(&e.NextHop).filter(|g| g.is_ipv4() == ip.is_ipv4()) {
            row.insert("gateway".into(), gw.to_string().into());
        }
        rows.push(Value::Object(row));
    }
    unsafe { FreeMibTable(table as *const _) };
    rows
}

fn neighbors() -> Vec<Value> {
    let mut table: *mut MIB_IPNET_TABLE2 = null_mut();
    // SAFETY: только чтение кэша ARP/NDP; таблица освобождается FreeMibTable
    if unsafe { GetIpNetTable2(AF_UNSPEC, &mut table) } != 0 || table.is_null() {
        return vec![];
    }
    let count = unsafe { (*table).NumEntries }.min(10000) as usize;
    let entries = unsafe { std::slice::from_raw_parts((*table).Table.as_ptr(), count) };
    let mut rows = vec![];
    for e in entries {
        let Some(ip) = sockaddr_ip(&e.Address) else { continue };
        if is_4in6(&ip) {
            continue;
        }
        let mut row = Map::new();
        row.insert("family".into(), (if ip.is_ipv4() { "ipv4" } else { "ipv6" }).into());
        row.insert("address".into(), ip.to_string().into());
        row.insert("interface_index".into(), e.InterfaceIndex.into());
        let state = match e.State {
            0 => "unreachable", 1 => "incomplete", 2 => "probe", 3 => "delay", 4 => "stale", 5 => "reachable", 6 => "permanent", _ => "",
        };
        if !state.is_empty() {
            row.insert("state".into(), state.into());
        }
        if e.PhysicalAddressLength == 6 {
            row.insert("mac".into(), e.PhysicalAddress[..6].iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":").into());
        }
        rows.push(Value::Object(row));
    }
    unsafe { FreeMibTable(table as *const _) };
    rows
}

/// SID и тип учётной записи по имени (LookupAccountNameW) — как windows.LookupSID в Go.
fn lookup_sid(account: &str) -> Option<(String, i32)> {
    let name = wide(account);
    let mut sid = vec![0u8; 256];
    let (mut sid_len, mut dom_len, mut kind) = (sid.len() as u32, 256u32, 0i32);
    let mut dom = vec![0u16; 256];
    // SAFETY: буферы и длины согласованы
    let ok = unsafe { LookupAccountNameW(null(), name.as_ptr(), sid.as_mut_ptr() as _, &mut sid_len, dom.as_mut_ptr(), &mut dom_len, &mut kind) } != 0;
    if !ok || unsafe { IsValidSid(sid.as_ptr() as _) } == 0 {
        return None;
    }
    sid_text(sid.as_ptr() as _).map(|s| (s, kind))
}

fn sid_text(sid: *mut core::ffi::c_void) -> Option<String> {
    let mut text: *mut u16 = null_mut();
    if sid.is_null() || unsafe { IsValidSid(sid) } == 0 || unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 {
        return None;
    }
    let s = from_wide(text, 256);
    unsafe { LocalFree(text as _) };
    Some(s).filter(|s| !s.is_empty())
}

const PAGE: u32 = 64 * 1024;

/// Каждый элемент страницы NetAPI уровня 0 — один указатель (имя или SID).
fn net_page<F: FnMut(*mut u8, &mut u32, &mut u32) -> u32>(mut call: F, mut each: impl FnMut(*const core::ffi::c_void) -> bool) {
    for _ in 0..32 {
        let mut buf: *mut u8 = null_mut();
        let (mut count, mut total) = (0u32, 0u32);
        let code = call(&mut buf as *mut *mut u8 as *mut u8, &mut count, &mut total);
        if code != 0 && code != ERROR_MORE_DATA {
            if !buf.is_null() {
                unsafe { NetApiBufferFree(buf as _) };
            }
            break;
        }
        let mut stop = false;
        if !buf.is_null() && count <= PAGE / 8 {
            let items = unsafe { std::slice::from_raw_parts(buf as *const *const core::ffi::c_void, count as usize) };
            for p in items {
                if !p.is_null() && !each(*p) {
                    stop = true;
                    break;
                }
            }
        }
        if !buf.is_null() {
            unsafe { NetApiBufferFree(buf as _) };
        }
        if stop || code == 0 || count == 0 {
            break;
        }
    }
}

fn accounts() -> Vec<Value> {
    let Some(host) = computer_name(ComputerNameNetBIOS) else { return vec![] };
    let mut rows: Vec<Value> = vec![];
    let mut resume = 0u32;
    net_page(
        |buf, count, total| unsafe { NetUserEnum(null(), 0, 2, buf as *mut *mut u8, PAGE, count, total, &mut resume) },
        |p| {
            let user = safe_text(from_wide(p as *const u16, 256), 256);
            if !user.is_empty() {
                if let Some((sid, 1)) = lookup_sid(&format!("{host}\\{user}")) {
                    rows.push(json!({"kind": "user", "sid": sid, "name": user}));
                }
            }
            rows.len() < 10000
        },
    );
    let mut groups: Vec<(Vec<u16>, String, String)> = vec![];
    let mut resume = 0usize;
    net_page(
        |buf, count, total| unsafe { NetLocalGroupEnum(null(), 0, buf as *mut *mut u8, PAGE, count, total, &mut resume) },
        |p| {
            let group = safe_text(from_wide(p as *const u16, 256), 256);
            if !group.is_empty() {
                let found = lookup_sid(&format!("{host}\\{group}")).or_else(|| lookup_sid(&format!("BUILTIN\\{group}")));
                if let Some((sid, 4)) = found {
                    groups.push((wide(&group), group, sid));
                }
            }
            groups.len() < 512
        },
    );
    for (wname, group, gid) in groups {
        if rows.len() >= 10000 {
            break;
        }
        rows.push(json!({"kind": "group", "sid": gid, "name": group}));
        let mut resume = 0usize;
        net_page(
            |buf, count, total| unsafe { NetLocalGroupGetMembers(null(), wname.as_ptr(), 0, buf as *mut *mut u8, PAGE, count, total, &mut resume) },
            |p| {
                if let Some(sid) = sid_text(p as *mut _) {
                    rows.push(json!({"kind": "membership", "sid": sid, "group_sid": gid}));
                }
                rows.len() < 10000
            },
        );
    }
    rows
}

/// Раздел в отдельном процессе (этот же exe, `inventory-section`) с лимитом 30 с и вывода — как workerSection в Go:
/// зависший провайдер (COM/WMI, реестр, NetAPI) не останавливает цикл агента и не теряет другие разделы.
pub fn worker_section(name: &str) -> Value {
    use std::io::Read;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};
    const LIMIT: usize = 1 << 20; // wire.Inventory12MaxPayload
    let Ok(exe) = std::env::current_exe() else { return failed(name, "unavailable", "WORKER_UNAVAILABLE") };
    let Ok(mut child) = Command::new(exe).args(["inventory-section", name]).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn() else {
        return failed(name, "unavailable", "WORKER_UNAVAILABLE");
    };
    let mut out = child.stdout.take().expect("piped stdout");
    let reader = std::thread::spawn(move || {
        let mut b = Vec::new();
        let _ = (&mut out).take(LIMIT as u64 + 1).read_to_end(&mut b);
        b
    });
    let start = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(st)) => break Some(st),
            Ok(None) if start.elapsed() > Duration::from_secs(30) => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(25)),
            Err(_) => break None,
        }
    };
    let Some(status) = status else { return failed(name, "unavailable", "TIMEOUT") };
    let raw = reader.join().unwrap_or_default();
    if raw.len() > LIMIT {
        return failed(name, "unavailable", "LIMIT_REACHED");
    }
    if !status.success() {
        return failed(name, "unavailable", "WORKER_FAILED");
    }
    match serde_json::from_slice::<Value>(&raw) {
        Ok(v) if v["name"] == name && v["records"].is_array() && v["record_count"].as_u64() == v["records"].as_array().map(|a| a.len() as u64) => v,
        _ => failed(name, "unavailable", "INVALID_WORKER_RESPONSE"),
    }
}
