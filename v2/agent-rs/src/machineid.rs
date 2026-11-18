//! Устойчивый идентификатор машины — как machineid в Go: Linux /etc/machine-id, Windows MachineGuid.

pub fn normalize(raw: &str) -> Option<String> {
    let mut id = raw.trim().to_lowercase();
    if id.len() == 36 && [8, 13, 18, 23].iter().all(|i| id.as_bytes()[*i] == b'-') {
        id = id.replace('-', "");
    }
    if id.len() != 32 || !id.bytes().all(|c| c.is_ascii_hexdigit()) || id == "0".repeat(32) {
        return None;
    }
    Some(id)
}

#[cfg(target_os = "linux")]
pub fn local() -> Option<String> {
    let raw = std::fs::read_to_string("/etc/machine-id").ok()?;
    if raw.len() > 128 {
        return None;
    }
    normalize(&raw)
}

#[cfg(windows)]
pub fn local() -> Option<String> {
    crate::collect_windows::machine_guid().and_then(|g| normalize(&g))
}

#[cfg(not(any(target_os = "linux", windows)))]
pub fn local() -> Option<String> {
    None
}
