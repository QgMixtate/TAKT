//! surveyscan-portable (Rust, C52.03): init, center-key, collect (этот хост), verify. Совместим с Go-portable по
//! каталогу состояния и формату пакета C23; discover (обследование подсети), профили учёток, сбор SSH/WinRM и
//! локальный веб-мастер (wizard, 127.0.0.1) — C52.06.

use ssagent::portable as p;
use std::io::Read;
use std::{env, path::PathBuf, process::ExitCode};

fn arg(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1).cloned())
}

/// Адреса интерфейсов этого ПК из раздела network (записи с addresses[].ip).
fn own_addresses(sections: &[serde_json::Value]) -> std::collections::HashSet<String> {
    sections.iter().filter(|s| s["name"] == "network").flat_map(|s| s["records"].as_array().cloned().unwrap_or_default())
        .flat_map(|r| r["addresses"].as_array().cloned().unwrap_or_default())
        .filter_map(|a| a["ip"].as_str().map(str::to_string)).collect()
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

/// Итог узла для мастера (C52.04, страница узла): разделы — имя, статус, код причины и число строк; данных инвентаря нет.
fn summary(transport: &str, target: &str, sections: &[serde_json::Value]) -> serde_json::Value {
    let secs: Vec<serde_json::Value> = sections.iter().map(|s| serde_json::json!({"name": s["name"], "status": s["status"], "reason_code": s["reason_code"], "rows": s["records"].as_array().map(|a| a.len()).unwrap_or(0)})).collect();
    let os = sections.iter().find(|s| s["name"] == "os").and_then(|s| s["records"][0].get("name").or(s["records"][0].get("caption")).cloned()).unwrap_or(serde_json::Value::Null);
    serde_json::json!({"transport": transport, "target": target, "hostname": hostname(sections), "os": os, "sections": secs})
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
            // C52.04: строка подготовки из Web (--prep) вместо трёх идентификаторов и ключа
            let prep = arg(&args, "--prep").map(|x| p::parse_prep(&x)).transpose()?;
            let (t, s, sc) = match &prep {
                Some(x) => (x.tenant.clone(), x.site.clone(), x.scope.clone()),
                None => (arg(&args, "--tenant").unwrap_or_default(), arg(&args, "--site").unwrap_or_default(), arg(&args, "--scope").unwrap_or_default()),
            };
            let (id, public) = p::init(&dir, &t, &s, &sc)?;
            println!("tenant_id={}\nsite_id={}\nscope_id={}\nsource_id={}\ngeneration_id={}\nkey_id={}\npublic_key={}", id.tenant_id, id.site_id, id.network_scope_id, id.source_id, id.generation_id, id.key_id, p::public_b64url(&public));
            if let Some(k) = arg(&args, "--center-key").or_else(|| prep.as_ref().and_then(|x| x.center_key.clone())) {
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
        Some("wizard") => state().and_then(|dir| {
            let port = arg(&args, "--port").map(|v| v.parse::<u16>().map_err(|_| "--port 1..65535".to_string())).unwrap_or(Ok(0))?;
            ssagent::wizard::serve(ssagent::wizard::Options { dir, port, open_browser: !args.iter().any(|a| a == "--no-browser") })
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
            let started = ssagent::client::now_rfc3339();
            let mut summaries: Vec<serde_json::Value> = vec![]; // results-last.json для мастера
            // №59: адреса этого ПК и наблюдение «этот ПК» — тот же узел по сети не собирается повторно
            let mut own: (std::collections::HashSet<String>, Option<serde_json::Value>) = (Default::default(), None);
            if !args.iter().any(|a| a == "--no-host") {
                let (candidates, sections) = host()?;
                let name = hostname(&sections);
                report("host", &name, &sections);
                summaries.push({ let mut r = summary("host", &name, &sections); r["outcome"] = "collected".into(); r });
                own.0 = own_addresses(&sections);
                let o = p::observation(&dir, &id, "host", &name, &candidates, sections)?;
                own.1 = Some(o["observation_id"].clone());
                observations.push(o);
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
                let only: Option<std::collections::HashSet<String>> = arg(&args, "--only").map(|v| v.split(',').map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect());
                let mut plan = vec![];
                let mut winrm_plan: Vec<(String, ssagent::profiles::Profile)> = vec![];
                for h in &hosts {
                    let (ip, kind) = (h["ip"].as_str().unwrap_or_default().to_string(), h["kind"].as_str().unwrap_or_default());
                    if only.as_ref().is_some_and(|o| !o.contains(&ip)) && profiles.bind(&ip, kind, None).is_some() {
                        outcomes.insert(ip, serde_json::json!({"outcome": "skipped"})); // снят аудитором (мастер, --only)
                        continue;
                    }
                    if only.as_ref().is_some_and(|o| !o.contains(&ip)) {
                        continue; // без профиля: в пакете — no_profile
                    }
                    if let (true, Some(obs)) = (own.0.contains(&ip), &own.1) {
                        // этот ПК уже собран локально (полнее, чем по сети): исход — собран, наблюдение «этот ПК»
                        outcomes.insert(ip, serde_json::json!({"outcome": "collected", "reason": "LOCAL_HOST", "observation_id": obs}));
                        continue;
                    }
                    match profiles.bind(&ip, kind, None) {
                        Some(pr) if pr.kind == "ssh" => plan.push((ip, pr.clone())),
                        Some(pr) if pr.kind == "winrm" => winrm_plan.push((ip, pr.clone())),
                        Some(_) => {}
                        None => {}
                    }
                }
                let needed: Vec<&ssagent::profiles::Profile> = plan.iter().chain(winrm_plan.iter()).map(|(_, pr)| pr).collect();
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
                // WinRM: до 8 узлов параллельно (блокирующий клиент — по потоку на узел)
                let winrm_results: Vec<(String, String, Result<(serde_json::Value, Vec<serde_json::Value>), ssagent::winrm::Failure>)> = {
                    let queue = std::sync::Mutex::new(winrm_plan.clone());
                    let out = std::sync::Mutex::new(vec![]);
                    std::thread::scope(|sc| {
                        for _ in 0..8 {
                            sc.spawn(|| loop {
                                let Some((ip, pr)) = queue.lock().unwrap().pop() else { return };
                                eprintln!("winrm {ip}: сбор (профиль «{}»)", pr.name);
                                let t = ssagent::winrm::Target { host: ip.clone(), ip: ip.clone(), port: pr.port.unwrap_or(5985), user: if pr.auth == "current_user" { String::new() } else { pr.user.clone() }, password: secrets.get(&pr.name).unwrap_or("").to_string(), kdc: pr.kdc.clone() };
                                let r = ssagent::winrm::collect(&t);
                                out.lock().unwrap().push((ip, pr.name.clone(), r));
                            });
                        }
                    });
                    out.into_inner().unwrap()
                };
                let mut winrm_results = winrm_results;
                winrm_results.sort_by(|a, b| a.0.cmp(&b.0));
                for (ip, profile, r) in winrm_results {
                    match r {
                        Ok((candidates, sections)) => {
                            report("winrm", &ip, &sections);
                            summaries.push({ let mut r = summary("winrm", &ip, &sections); r["outcome"] = "collected".into(); r["profile"] = profile.clone().into(); r });
                            let o = p::observation(&dir, &id, "winrm", &ip, &candidates, sections)?;
                            outcomes.insert(ip, serde_json::json!({"outcome": "collected", "profile": profile, "observation_id": o["observation_id"]}));
                            observations.push(o);
                        }
                        Err(f) => {
                            failed_targets += 1;
                            println!("{:<6} {:<24} FAILED: {}", "winrm", ip, f.code());
                            summaries.push(serde_json::json!({"transport": "winrm", "target": ip, "outcome": f.outcome(), "reason": f.code(), "profile": profile}));
                            outcomes.insert(ip, serde_json::json!({"outcome": f.outcome(), "reason": f.code(), "profile": profile}));
                        }
                    }
                }
                let mut results = results;
                results.sort_by(|a, b| a.0.cmp(&b.0));
                for (ip, profile, r) in results {
                    match r {
                        Ok((candidates, sections)) => {
                            report("ssh", &ip, &sections);
                            summaries.push({ let mut r = summary("ssh", &ip, &sections); r["outcome"] = "collected".into(); r["profile"] = profile.clone().into(); r });
                            let o = p::observation(&dir, &id, "ssh", &ip, &candidates, sections)?;
                            outcomes.insert(ip, serde_json::json!({"outcome": "collected", "profile": profile, "observation_id": o["observation_id"]}));
                            observations.push(o);
                        }
                        Err(f) => {
                            failed_targets += 1;
                            println!("{:<6} {:<24} FAILED: {}", "ssh", ip, f.code());
                            summaries.push(serde_json::json!({"transport": "ssh", "target": ip, "outcome": f.outcome(), "reason": f.code(), "profile": profile}));
                            outcomes.insert(ip, serde_json::json!({"outcome": f.outcome(), "reason": f.code(), "profile": profile}));
                        }
                    }
                }
            }
            // итоги для мастера: узлы без профиля и снятые аудитором — из обследования
            if let Some(l) = &last {
                for h in l["hosts"].as_array().into_iter().flatten() {
                    let ip = h["ip"].as_str().unwrap_or_default();
                    if !summaries.iter().any(|r| r["target"] == ip) && !own.0.contains(ip) {
                        let o = outcomes.get(ip).and_then(|o| o["outcome"].as_str()).unwrap_or("no_profile");
                        summaries.push(serde_json::json!({"transport": h["kind"], "target": ip, "outcome": o}));
                    }
                }
            }
            ssagent::state::save_json(&dir.join("results-last.json"), &serde_json::json!({"started_at": started, "finished_at": ssagent::client::now_rfc3339(), "dry_run": dry, "hosts": summaries}))?;
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
        _ => Err("используйте wizard, init, center-key, discover, collect, verify или version".into()),
    };
    match r {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}
