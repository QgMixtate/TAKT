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
            println!("surveyscan-agent (rust) {}", env!("CARGO_PKG_VERSION"));
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
            Some(config) => ssagent::state::load_json::<ssagent::enroll::Config>(std::path::Path::new(&config))
                .and_then(ssagent::client::Client::open)
                .and_then(|mut c| c.heartbeat())
                .map(|_| println!("heartbeat_accepted")),
            None => Err("heartbeat --config ПУТЬ".into()),
        },
        Some("profile") => match arg(&args, "--config") {
            Some(config) => ssagent::state::load_json::<ssagent::enroll::Config>(std::path::Path::new(&config))
                .and_then(ssagent::client::Client::open)
                .and_then(|mut c| {
                    let current = ssagent::profile::cached(&c)?;
                    let (p, changed) = ssagent::profile::poll(&mut c, current.as_ref())?;
                    println!("profile_revision={} managed={} changed={}", p["config"]["profile_revision"].as_str().unwrap_or("?"), p["managed"], changed);
                    Ok(())
                }),
            None => Err("profile --config ПУТЬ".into()),
        },
        _ => Err("используйте register (установка по коду), heartbeat, profile или version".into()),
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
