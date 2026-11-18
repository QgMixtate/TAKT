//! surveyscan-portable (Rust, C52.03): init, center-key, collect (этот хост), verify. Совместим с Go-portable по
//! каталогу состояния и формату пакета C23; обследование подсети, профили учёток и мастер — следующие шаги C52.06.

use ssagent::portable as p;
use std::{env, path::PathBuf, process::ExitCode};

fn arg(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1).cloned())
}

fn host() -> Result<(serde_json::Value, Vec<serde_json::Value>), String> {
    #[cfg(target_os = "linux")]
    {
        let s = ssagent::collect_linux::collect();
        Ok((s.candidates, s.sections))
    }
    #[cfg(windows)]
    {
        let s = ssagent::collect_windows::collect();
        Ok((s.candidates, s.sections))
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    Err("host collection requires Linux or Windows".into())
}

fn hostname(sections: &[serde_json::Value]) -> String {
    sections.iter().find(|s| s["name"] == "identity").and_then(|s| s["records"][0]["hostname"].as_str()).unwrap_or("host").to_string()
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    let state = || arg(&args, "--state").map(PathBuf::from).ok_or_else(|| "--state КАТАЛОГ".to_string());
    let r: Result<(), String> = match args.first().map(String::as_str) {
        Some("version") => {
            println!("surveyscan-portable (rust) {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        #[cfg(windows)]
        Some("inventory-section") | Some("inventory-worker") => match args.get(1) {
            Some(n) => {
                println!("{}", ssagent::collect_windows::section(n));
                Ok(())
            }
            None => Err("inventory-section ИМЯ".into()),
        },
        Some("init") => state().and_then(|dir| {
            let (t, s, sc) = (arg(&args, "--tenant").unwrap_or_default(), arg(&args, "--site").unwrap_or_default(), arg(&args, "--scope").unwrap_or_default());
            let (id, public) = p::init(&dir, &t, &s, &sc)?;
            println!("tenant_id={}\nsite_id={}\nscope_id={}\nsource_id={}\ngeneration_id={}\nkey_id={}\npublic_key={}", id.tenant_id, id.site_id, id.network_scope_id, id.source_id, id.generation_id, id.key_id, p::public_b64url(&public));
            if let Some(k) = arg(&args, "--center-key") {
                println!("encryption_key_id={}", p::set_center_key(&dir, &k)?);
            }
            println!("Передайте public_key в центр для доверия при импорте. Ключ подписи остаётся в {}", dir.display());
            Ok(())
        }),
        Some("center-key") => state().and_then(|dir| {
            let k = arg(&args, "--center-key").ok_or("--center-key КЛЮЧ")?;
            println!("encryption_key_id={}: следующие пакеты шифруются ключом центра", p::set_center_key(&dir, &k)?);
            Ok(())
        }),
        Some("collect") => state().and_then(|dir| {
            let out = arg(&args, "--out").map(PathBuf::from);
            let dry = args.iter().any(|a| a == "--dry-run");
            if out.is_some() == dry {
                return Err("укажите ровно одно из --out FILE или --dry-run".into());
            }
            let (id, key) = p::load(&dir)?;
            println!("source_id={} key_id={}", id.source_id, id.key_id);
            let (candidates, sections) = host()?;
            let name = hostname(&sections);
            let rows: usize = sections.iter().map(|s| s["records"].as_array().map(|a| a.len()).unwrap_or(0)).sum();
            println!("{:<6} {:<24} rows={}", "host", name, rows);
            for s in &sections {
                println!("         {:<13} {}/{}", s["name"].as_str().unwrap_or(""), s["status"].as_str().unwrap_or(""), s["reason_code"].as_str().unwrap_or(""));
            }
            if dry {
                println!("DRY RUN: 1 target(s) ok, 0 failed; package not written");
                return Ok(());
            }
            let o = p::observation(&dir, &id, "host", &name, &candidates, sections)?;
            let signed = p::sign_observation(&key, &o)?;
            let mut data = p::write_package(&key, &id, &[signed])?;
            let center = p::center_key(&dir)?;
            if let Some(c) = center {
                data = p::seal(&c, &data)?;
            }
            let out = out.unwrap();
            p::publish(&out, &data)?;
            println!("EXPORTED: 1 observation(s) -> {}, {} (0 target(s) failed)", out.display(), if center.is_some() { "encrypted for the centre key" } else { "not encrypted" });
            Ok(())
        }),
        Some("verify") => {
            let data = arg(&args, "--package").ok_or("--package ФАЙЛ".to_string()).and_then(|f| std::fs::read(f).map_err(|e| e.to_string()));
            data.and_then(|d| {
                if p::encrypted(&d) {
                    let id = d.get(p::ENC_MAGIC.len()..p::ENC_MAGIC.len() + 16).map(ssagent::sign::hex).ok_or("encrypted package corrupt")?;
                    println!("ENCRYPTED: package for centre key {id} ({} bytes); signature and records are verified on import", d.len());
                    Ok(())
                } else {
                    Err("проверка незашифрованного пакета — в центре (импорт) или Go-portable verify".into())
                }
            })
        }
        _ => Err("используйте init, center-key, collect, verify или version".into()),
    };
    match r {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}
