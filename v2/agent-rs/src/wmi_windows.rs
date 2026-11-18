//! Разделы updates и protection через COM (C52.02) — как com_windows.go: WMI (только локальные пространства и
//! фиксированные SELECT), брандмауэр INetFwPolicy2. Выполняется в отдельном процессе раздела с ограничением времени.

use serde_json::{json, Value};
use windows::core::{BSTR, VARIANT};
use windows::Win32::NetworkManagement::WindowsFirewall::{INetFwPolicy2, NetFwPolicy2, NET_FW_PROFILE_TYPE2};
use windows::Win32::System::Com::*;
use windows::Win32::System::Wmi::*;

const LIMIT: usize = 4096;

#[derive(Debug)]
pub enum Failure {
    Com(u32),
    Data,
    Limit,
}

impl From<windows::core::Error> for Failure {
    fn from(e: windows::core::Error) -> Self {
        Failure::Com(e.code().0 as u32)
    }
}

/// Классификация отказа — как providerFailure в Go.
pub fn classify(f: &Failure) -> (&'static str, &'static str) {
    match f {
        Failure::Limit => ("partial", "LIMIT_REACHED"),
        Failure::Com(0x80070005) | Failure::Com(0x80041003) => ("unavailable", "ACCESS_DENIED"),
        Failure::Com(0x80040154) | Failure::Com(0x8004100e) | Failure::Com(0x80041010) => ("unsupported", "PROVIDER_UNAVAILABLE"),
        _ => ("unavailable", "API_DATA_UNAVAILABLE"),
    }
}

fn vt(v: &VARIANT) -> u16 {
    // SAFETY: чтение тега типа VARIANT
    unsafe { v.as_raw().Anonymous.Anonymous.vt }
}

fn prop(o: &IWbemClassObject, name: &str) -> Option<VARIANT> {
    let mut v = VARIANT::new();
    let n: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    // SAFETY: объект WMI и выходной VARIANT действительны
    unsafe { o.Get(windows::core::PCWSTR(n.as_ptr()), 0, &mut v, None, None) }.ok()?;
    Some(v)
}

fn text(v: &VARIANT) -> Option<String> {
    (vt(v) == 8).then(|| BSTR::try_from(v).ok().map(|b| b.to_string())).flatten() // VT_BSTR
}

fn safe(v: &str, limit: usize) -> bool {
    !v.is_empty() && v.chars().count() <= limit && !v.chars().any(|c| (c as u32) < 32 || c as u32 == 127)
}

pub fn init() -> Result<(), Failure> {
    // SAFETY: отдельный процесс раздела; COM инициализируется один раз
    unsafe {
        let hr = CoInitializeEx(None, COINIT_MULTITHREADED);
        if hr.is_err() && hr.0 != 1 {
            return Err(Failure::Com(hr.0 as u32));
        }
        let _ = CoInitializeSecurity(None, -1, None, None, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, None, EOAC_NONE, None);
    }
    Ok(())
}

fn wmi_rows(namespace: &str, query: &str, convert: impl Fn(&IWbemClassObject) -> Result<Value, Failure>) -> (Vec<Value>, Option<Failure>) {
    let mut rows = vec![];
    let r: Result<(), Failure> = (|| unsafe {
        let locator: IWbemLocator = CoCreateInstance(&WbemLocator, None, CLSCTX_INPROC_SERVER)?;
        let services = locator.ConnectServer(&BSTR::from(namespace), &BSTR::new(), &BSTR::new(), &BSTR::new(), 0, &BSTR::new(), None)?;
        let e = services.ExecQuery(&BSTR::from("WQL"), &BSTR::from(query), WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, None)?;
        loop {
            let mut objs = [None];
            let mut got = 0u32;
            let hr = e.Next(WBEM_INFINITE, &mut objs, &mut got);
            if got == 0 {
                return if hr.is_err() { Err(Failure::Com(hr.0 as u32)) } else { Ok(()) };
            }
            let o = objs[0].take().ok_or(Failure::Data)?;
            rows.push(convert(&o)?);
            if rows.len() >= LIMIT {
                return Err(Failure::Limit);
            }
        }
    })();
    (rows, r.err())
}

/// updates: Win32_QuickFixEngineering; дата установки — только однозначная ISO-дата.
pub fn qfe() -> (Vec<Value>, Option<Failure>) {
    wmi_rows("ROOT\\CIMV2", "SELECT HotFixID,Description,InstalledOn FROM Win32_QuickFixEngineering", |o| {
        let id = prop(o, "HotFixID").and_then(|v| text(&v)).filter(|s| safe(s, 128)).ok_or(Failure::Data)?;
        let mut row = serde_json::Map::new();
        row.insert("id".into(), id.into());
        row.insert("source".into(), "qfe".into());
        if let Some(d) = prop(o, "Description").and_then(|v| text(&v)).filter(|s| safe(s, 512)) {
            row.insert("description".into(), d.into());
        }
        if let Some(d) = prop(o, "InstalledOn").and_then(|v| text(&v)) {
            let fmt = time::macros::format_description!("[year]-[month]-[day]");
            if let Ok(date) = time::Date::parse(&d, &fmt) {
                row.insert("installed_on".into(), date.format(&fmt).unwrap_or_default().into());
            }
        }
        Ok(Value::Object(row))
    })
}

fn firewall() -> (Vec<Value>, Option<Failure>) {
    let mut rows = vec![];
    let r: Result<(), Failure> = (|| unsafe {
        let policy: INetFwPolicy2 = CoCreateInstance(&NetFwPolicy2, None, CLSCTX_INPROC_SERVER)?;
        for (id, name) in [(1, "Domain"), (2, "Private"), (4, "Public")] {
            let enabled = policy.get_FirewallEnabled(NET_FW_PROFILE_TYPE2(id))?;
            rows.push(json!({"kind": "firewall", "name": format!("Windows Firewall {name}"), "provider": "INetFwPolicy2", "enabled": enabled.as_bool()}));
        }
        Ok(())
    })();
    (rows, r.err())
}

/// protection: брандмауэр, Microsoft Defender, антивирусы SecurityCenter2 (productState — как есть, без толкования).
pub fn protection() -> (Vec<Value>, Option<Failure>) {
    let (mut rows, fw_err) = firewall();
    let (defender, def_err) = wmi_rows("ROOT\\Microsoft\\Windows\\Defender", "SELECT AntivirusEnabled,AMServiceEnabled,RealTimeProtectionEnabled FROM MSFT_MpComputerStatus", |o| {
        let mut m = serde_json::Map::new();
        for k in ["AntivirusEnabled", "AMServiceEnabled", "RealTimeProtectionEnabled"] {
            if let Some(v) = prop(o, k).filter(|v| vt(v) == 11) {
                m.insert(k.into(), bool::try_from(&v).unwrap_or(false).into());
            }
        }
        if m.is_empty() {
            return Err(Failure::Data);
        }
        Ok(Value::Object(m))
    });
    for values in &defender {
        for (key, name) in [("AntivirusEnabled", "Microsoft Defender antivirus"), ("AMServiceEnabled", "Microsoft Defender service"), ("RealTimeProtectionEnabled", "Microsoft Defender real-time protection")] {
            if let Some(enabled) = values.get(key) {
                rows.push(json!({"kind": "defender", "name": name, "provider": "MSFT_MpComputerStatus", "enabled": enabled}));
            }
        }
    }
    let (antivirus, av_err) = wmi_rows("ROOT\\SecurityCenter2", "SELECT displayName,productState FROM AntiVirusProduct", |o| {
        let name = prop(o, "displayName").and_then(|v| text(&v)).filter(|s| safe(s, 256)).ok_or(Failure::Data)?;
        let mut row = serde_json::Map::new();
        row.insert("kind".into(), "antivirus".into());
        row.insert("name".into(), name.into());
        row.insert("provider".into(), "SecurityCenter2".into());
        if let Some(v) = prop(o, "productState") {
            let state: u64 = match vt(&v) {
                19 => u32::try_from(&v).map_err(|_| Failure::Data)? as u64,
                3 => {
                    let n = i32::try_from(&v).map_err(|_| Failure::Data)?;
                    if n < 0 {
                        return Err(Failure::Data);
                    }
                    n as u64
                }
                _ => return Err(Failure::Data),
            };
            row.insert("state".into(), format!("reported_product_state:{state}").into());
        }
        Ok(Value::Object(row))
    });
    rows.extend(antivirus);
    let first = fw_err.or(def_err).or(av_err);
    if rows.is_empty() && first.is_none() {
        return (rows, Some(Failure::Data));
    }
    (rows, first)
}

/// Раздел COM — как WriteWorkerSection: при ошибке с частью строк — partial.
pub fn section(name: &str) -> Value {
    if let Err(f) = init() {
        let (status, reason) = classify(&f);
        return json!({"name": name, "collected_at": crate::client::now_rfc3339(), "status": status, "collection_complete": false, "reason_code": reason, "record_count": 0, "records": []});
    }
    let (rows, err, ok_reason) = if name == "updates" {
        let (r, e) = qfe();
        (r, e, "QFE_SUBSET")
    } else {
        let (r, e) = protection();
        (r, e, "BASELINE_COVERAGE_ONLY")
    };
    let (mut status, mut reason) = ("partial", ok_reason);
    if let Some(f) = &err {
        (status, reason) = classify(f);
        if !rows.is_empty() {
            status = "partial";
        }
    }
    json!({"name": name, "collected_at": crate::client::now_rfc3339(), "status": status, "collection_complete": false, "reason_code": reason, "record_count": rows.len(), "records": rows})
}
