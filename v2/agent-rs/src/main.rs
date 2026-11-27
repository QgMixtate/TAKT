//! surveyscan-agent (Rust, C52.02). Пока: `register` (установка по коду из Web) и `version`; цикл сбора и служба —
//! следующие шаги (до их готовности работает Go-агент на том же каталоге состояния).

use std::{env, path::PathBuf, process::ExitCode};

fn arg(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1).cloned())
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    let r = match args.first().map(String::as_str) {
        Some("version") | Some("--version") => {
            println!("surveyscan-agent (rust) {}", ssagent::VERSION);
            Ok(())
        }
        // установщик (MSI, C52.04): повторная установка/обновление поверх зарегистрированного агента — не ошибка
        Some("register") if args.iter().any(|a| a == "--if-unregistered") && arg(&args, "--config").is_some_and(|c| std::path::Path::new(&c).exists()) => {
            println!("already_registered");
            Ok(())
        }
        Some("register") => {
            let code = arg(&args, "--code").or_else(|| env::var("SURVEYSCAN_REGISTRATION_CODE").ok());
            match (arg(&args, "--collector"), code, arg(&args, "--fingerprint"), arg(&args, "--config"), arg(&args, "--state")) {
                (Some(collector_url), Some(code), Some(fingerprint), Some(config), Some(state)) => ssagent::enroll::register(&ssagent::enroll::RegisterOptions {
                    collector_url, code, fingerprint, config_path: PathBuf::from(config), state_dir: PathBuf::from(state),
                    hostname: hostname(),
                })
                .map(|_| println!("agent_registered")),
                _ => Err("register --collector URL --code КОД --fingerprint ОТПЕЧАТОК --config ПУТЬ --state КАТАЛОГ".into()),
            }
        }
        Some("heartbeat") => match arg(&args, "--config") {
            Some(config) => ssagent::enroll::read_config(std::path::Path::new(&config))
                .and_then(ssagent::client::Client::open)
                .and_then(|mut c| c.heartbeat())
                .map(|_| println!("heartbeat_accepted")),
            None => Err("heartbeat --config ПУТЬ".into()),
        },
        Some("profile") => match arg(&args, "--config") {
            Some(config) => ssagent::enroll::read_config(std::path::Path::new(&config))
                .and_then(ssagent::client::Client::open)
                .and_then(|mut c| {
                    let current = ssagent::profile::cached(&c)?;
                    let (p, changed) = ssagent::profile::poll(&mut c, current.as_ref())?;
                    println!("profile_revision={} managed={} changed={}", p["config"]["profile_revision"].as_str().unwrap_or("?"), p["managed"], changed);
                    Ok(())
                }),
            None => Err("profile --config ПУТЬ".into()),
        },
        Some("inventory-section") => match args.get(1) {
            // один раздел сбора этого хоста (JSON) — для сравнения с Go-агентом на эталонных ВМ (C52-01)
            #[cfg(windows)]
            Some(name) => {
                println!("{}", ssagent::collect_windows::section(name));
                Ok(())
            }
            #[cfg(target_os = "linux")]
            Some(name) => {
                let s = ssagent::collect_linux::collect();
                s.sections.into_iter().find(|x| x["name"] == name.as_str()).map(|x| println!("{x}")).ok_or_else(|| "unknown section".to_string())
            }
            _ => Err("inventory-section ИМЯ".into()),
        },
        Some("renew") => match arg(&args, "--config") {
            Some(config) => ssagent::enroll::read_config(std::path::Path::new(&config)).and_then(|cfg| {
                let _lock = ssagent::run::lock_state(std::path::Path::new(&cfg.state_directory))?;
                let mut c = ssagent::client::Client::open(cfg)?;
                c.renew()?;
                println!("certificate_renewed");
                Ok(())
            }),
            None => Err("renew --config ПУТЬ".into()),
        },
        // MSI (C52.04): служба установлена всегда, запускается только у зарегистрированного агента
        #[cfg(windows)]
        Some("start-service") => match arg(&args, "--config") {
            Some(c) if std::path::Path::new(&c).exists() => {
                let name = arg(&args, "--name").unwrap_or_else(|| ssagent::winsvc::DEFAULT_NAME.to_string());
                ssagent::winsvc::start(&name).map(|_| println!("service_started"))
            }
            Some(_) => {
                println!("not_registered: служба запустится после surveyscan-agent register");
                Ok(())
            }
            None => Err("start-service --config ПУТЬ [--name ИМЯ]".into()),
        },
        #[cfg(windows)]
        Some("install-service") | Some("uninstall-service") | Some("service") => {
            let name = arg(&args, "--name").unwrap_or_else(|| ssagent::winsvc::DEFAULT_NAME.to_string());
            match args[0].as_str() {
                "uninstall-service" => ssagent::winsvc::uninstall(&name).map(|_| println!("service_removed")),
                "install-service" => match arg(&args, "--config") {
                    Some(c) if std::path::Path::new(&c).is_absolute() => std::env::current_exe().map_err(|e| e.to_string()).and_then(|exe| {
                        ssagent::winsvc::install(&name, &exe.to_string_lossy(), &["service".into(), "--name".into(), name.clone(), "--config".into(), c])
                    }).map(|_| {
                        println!("service_installed");
                        // №54: служба запускается сразу; отказ запуска не отменяет установку — подсказка оператору
                        match ssagent::winsvc::start(&name) {
                            Ok(()) => println!("service_started"),
                            Err(e) => eprintln!("служба установлена, но не запущена ({e}); запустите: Start-Service {name}"),
                        }
                    }),
                    _ => Err("для службы требуется абсолютный --config".into()),
                },
                _ => match arg(&args, "--config") {
                    None => Err("service --config ПУТЬ".into()),
                    Some(config) => ssagent::winsvc::run(&name, move || {
                        let r = ssagent::enroll::read_config(std::path::Path::new(&config)).and_then(|cfg| {
                            let (mut agent, _lock) = ssagent::run::Agent::open(cfg)?;
                            agent.run(&|| ssagent::winsvc::STOP.load(std::sync::atomic::Ordering::SeqCst));
                            Ok(())
                        });
                        match r {
                            Ok(()) => 0,
                            Err(e) => {
                                eprintln!("{e}");
                                2
                            }
                        }
                    }),
                },
            }
        }
        Some("run") | Some("once") => match arg(&args, "--config") {
            Some(config) => ssagent::enroll::read_config(std::path::Path::new(&config)).and_then(|cfg| {
                let (mut agent, _lock) = ssagent::run::Agent::open(cfg)?;
                if args[0] == "once" {
                    // один проход: профиль 1.2, сбор, очередь, доставка (проверка установки и smoke)
                    if !agent.ensure_profile12() {
                        return Err("inventory profile 1.2 unavailable".into());
                    }
                    let delivery = agent.inventory()?;
                    // результат центра приходит асинхронно через collector — ждём до 2 мин, как цикл доставки
                    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
                    while let Err(e) = agent.client.flush() {
                        if std::time::Instant::now() > deadline {
                            return Err(e);
                        }
                        std::thread::sleep(std::time::Duration::from_secs(2));
                    }
                    println!("inventory_delivered {delivery}");
                    return Ok(());
                }
                agent.run(&|| false);
                Ok(())
            }),
            None => Err("run --config ПУТЬ".into()),
        },
        _ => Err("используйте register (установка по коду), run, once, heartbeat, profile или version".into()),
    };
    match r {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}

fn hostname() -> String {
    env::var("COMPUTERNAME").ok().or_else(|| std::fs::read_to_string("/proc/sys/kernel/hostname").ok()).map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).unwrap_or_else(|| "unknown".into())
}
