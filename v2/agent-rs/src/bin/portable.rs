//! surveyscan-portable (Rust, C52.03): init, center-key, collect (этот хост), verify. Совместим с Go-portable по
//! каталогу состояния и формату пакета C23; обследование подсети, профили учёток и мастер — следующие шаги C52.06.

use ssagent::portable as p;
use std::io::Read;
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

fn report(kind: &str, name: &str, sections: &[serde_json::Value]) {
    let rows: usize = sections.iter().map(|s| s["records"].as_array().map(|a| a.len()).unwrap_or(0)).sum();
    println!("{:<6} {:<24} rows={}", kind, name, rows);
    for s in sections {
        println!("         {:<13} {}/{}", s["name"].as_str().unwrap_or(""), s["status"].as_str().unwrap_or(""), s["reason_code"].as_str().unwrap_or(""));
    }
}

/// Пароли профилей из stdin строками «профиль=секрет» (для мастера и автоматизации; на диск не пишутся).
fn secrets_from_stdin() -> Result<ssagent::profiles::Secrets, String> {
    let mut s = ssagent::profiles::Secrets::default();
    let mut text = String::new();
    std::io::Read::read_to_string(&mut std::io::stdin().take(65536), &mut text).map_err(|e| e.to_string())?;
    for line in text.lines() {
        if let Some((k, v)) = line.split_once('=') {
            s.set(k.trim(), v.to_string());
        }
    }
    Ok(s)
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
        Some("discover") => state().and_then(|dir| {
            use ssagent::discover as d;
            let list = |name: &str| arg(&args, name).map(|v| v.split(',').filter(|x| !x.trim().is_empty()).map(d::Net::parse).collect::<Result<Vec<_>, _>>()).unwrap_or(Ok(vec![]));
            let (ranges, excluded) = (list("--range")?, list("--exclude")?);
            if ranges.is_empty() {
                return Err("discover --state КАТАЛОГ --range 10.20.0.0/16[,…] [--exclude …] [--rate 200] [--parallel 64] [--timeout-ms 800] [--max-minutes 60]".into());
            }
            let num = |n: &str, def: u64, lo: u64, hi: u64| -> Result<u64, String> {
                arg(&args, n).map(|v| v.parse::<u64>().ok().filter(|x| (lo..=hi).contains(x)).ok_or(format!("{n}: {lo}..{hi}"))).unwrap_or(Ok(def))
            };
            let addresses = d::hosts(&ranges, &excluded)?;
            let o = d::Options { ports: d::DEFAULT_PORTS.to_vec(), timeout: std::time::Duration::from_millis(num("--timeout-ms", 800, 100, 10000)?), parallel: num("--parallel", 64, 1, 256)? as usize,
                rate_per_sec: num("--rate", 200, 1, 5000)? as u32, deadline: Some(std::time::Instant::now() + std::time::Duration::from_secs(60 * num("--max-minutes", 60, 1, 1440)?)) };
            p::load(&dir)?;
            eprintln!("обследование: {} адресов, порты {:?}, не более {} подключений/с, параллельно {}", addresses.len(), o.ports, o.rate_per_sec, o.parallel);
            let started = ssagent::client::now_rfc3339();
            let (hosts, complete) = d::run(&addresses, &o, &|done, total, found| eprintln!("[{done}/{total}] найдено: {found}"));
            let doc = serde_json::json!({"ranges": ranges.iter().map(|r| r.text()).collect::<Vec<_>>(), "excluded": excluded.iter().map(|r| r.text()).collect::<Vec<_>>(),
                "started_at": started, "finished_at": ssagent::client::now_rfc3339(), "complete": complete, "hosts": hosts});
            ssagent::state::save_json(&dir.join(p::DISCOVERY_FILE), &doc)?;
            let count = |k: &str| hosts.iter().filter(|h| h["kind"] == k).count();
            println!("DISCOVERED: {} узлов (Linux/SSH {}, Windows {}, сетевых {}, не определено {}){}", hosts.len(), count("linux_ssh"), count("windows_winrm"), count("network_snmp"), count("unknown"), if complete { "" } else { "; обследование прервано по сроку" });
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
            let mut observations = vec![];
            let mut failed_targets = 0;
            if !args.iter().any(|a| a == "--no-host") {
                let (candidates, sections) = host()?;
                let name = hostname(&sections);
                report("host", &name, &sections);
                observations.push(p::observation(&dir, &id, "host", &name, &candidates, sections)?);
            }
            // узлы последнего обследования: один профиль по правилам (без перебора), сбор SSH; исход — в discovery.json
            let last: Option<serde_json::Value> = match std::fs::read(dir.join(p::DISCOVERY_FILE)) {
                Ok(raw) => Some(serde_json::from_slice(&raw).map_err(|_| "discovery-last.json повреждён")?),
                Err(_) => None,
            };
            let mut outcomes: std::collections::HashMap<String, serde_json::Value> = Default::default();
            if let Some(last) = &last {
                let profiles = ssagent::profiles::Profiles::load(&dir)?;
                let hosts = last["hosts"].as_array().cloned().unwrap_or_default();
                let mut plan = vec![];
                for h in &hosts {
                    let (ip, kind) = (h["ip"].as_str().unwrap_or_default().to_string(), h["kind"].as_str().unwrap_or_default());
                    match profiles.bind(&ip, kind, None) {
                        Some(pr) if pr.kind == "ssh" => plan.push((ip, pr.clone())),
                        Some(pr) => {
                            // WinRM в Rust-portable — следующий шаг C52.06: узел с профилем помечается, а не пропадает
                            outcomes.insert(ip, serde_json::json!({"outcome": "skipped", "reason": "COLLECTOR_NOT_AVAILABLE", "profile": pr.name}));
                        }
                        None => {}
                    }
                }
                let needed: Vec<&ssagent::profiles::Profile> = plan.iter().map(|(_, pr)| pr).collect();
                let secrets = if args.iter().any(|a| a == "--secrets-stdin") { secrets_from_stdin()? } else { ssagent::profiles::Secrets::prompt(&needed)? };
                let known = ssagent::sshcollect::KnownHosts::load(&dir);
                let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().map_err(|e| e.to_string())?;
                let local = tokio::task::LocalSet::new();
                let results = local.block_on(&rt, async {
                    let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(8));
                    let mut set = tokio::task::JoinSet::new();
                    for (ip, pr) in plan.clone() {
                        let t = ssagent::sshcollect::Target { ip: ip.clone(), port: pr.port.unwrap_or(22), user: pr.user.clone(), secret: secrets.get(&pr.name).unwrap_or("").to_string(), key_file: pr.key_file.clone() };
                        let (known, sem) = (known.clone(), sem.clone());
                        set.spawn_local(async move {
                            let _permit = sem.acquire().await;
                            eprintln!("ssh {ip}: сбор (профиль «{}»)", pr.name);
                            (ip, pr.name, ssagent::sshcollect::collect(&t, &known).await)
                        });
                    }
                    let mut out = vec![];
                    while let Some(r) = set.join_next().await {
                        if let Ok(x) = r {
                            out.push(x);
                        }
                    }
                    out
                });
                known.save(&dir)?;
                let mut results = results;
                results.sort_by(|a, b| a.0.cmp(&b.0));
                for (ip, profile, r) in results {
                    match r {
                        Ok((candidates, sections)) => {
                            report("ssh", &ip, &sections);
                            let o = p::observation(&dir, &id, "ssh", &ip, &candidates, sections)?;
                            outcomes.insert(ip, serde_json::json!({"outcome": "collected", "profile": profile, "observation_id": o["observation_id"]}));
                            observations.push(o);
                        }
                        Err(f) => {
                            failed_targets += 1;
                            println!("{:<6} {:<24} FAILED: {}", "ssh", ip, f.code());
                            outcomes.insert(ip, serde_json::json!({"outcome": f.outcome(), "reason": f.code(), "profile": profile}));
                        }
                    }
                }
            }
            if dry {
                println!("DRY RUN: {} target(s) ok, {} failed; package not written", observations.len(), failed_targets);
                return Ok(());
            }
            if observations.is_empty() {
                return Err("нечего экспортировать: ни один узел не собран".into());
            }
            let discovery = match &last {
                Some(l) => Some(p::discovery_doc(l, &outcomes)?),
                None => None,
            };
            let signed = observations.iter().map(|o| p::sign_observation(&key, o)).collect::<Result<Vec<_>, _>>()?;
            let mut data = p::write_package_with(&key, &id, &signed, discovery.as_deref())?;
            let center = p::center_key(&dir)?;
            if let Some(c) = center {
                data = p::seal(&c, &data)?;
            }
            let out = out.unwrap();
            p::publish(&out, &data)?;
            println!("EXPORTED: {} observation(s) -> {}, {} ({} target(s) failed)", signed.len(), out.display(), if center.is_some() { "encrypted for the centre key" } else { "not encrypted" }, failed_targets);
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
