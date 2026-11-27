//! Локальный веб-мастер portable (C52.06 п. 5): только 127.0.0.1, одноразовый токен в адресе. Шаги мастера вызывают
//! те же команды portable дочерним процессом; пароли профилей передаются только в stdin дочернего процесса — на диск,
//! в журнал и в ответы мастера не попадают.

use crate::portable as p;
use crate::profiles::{Profiles, FILE as PROFILES_FILE};
use serde_json::{json, Value};
use sha2::Digest;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};

const PAGE: &str = include_str!("wizard.html");
/// Шрифты мастера (Inter, Manrope; лицензия OFL — assets/fonts): мастер работает без сети, CDN нет.
const FONTS: &[(&str, &[u8])] = &[
    ("inter-latin-400.woff2", include_bytes!("../assets/fonts/inter-latin-400-normal.woff2")),
    ("inter-latin-500.woff2", include_bytes!("../assets/fonts/inter-latin-500-normal.woff2")),
    ("inter-latin-600.woff2", include_bytes!("../assets/fonts/inter-latin-600-normal.woff2")),
    ("inter-cyrillic-400.woff2", include_bytes!("../assets/fonts/inter-cyrillic-400-normal.woff2")),
    ("inter-cyrillic-500.woff2", include_bytes!("../assets/fonts/inter-cyrillic-500-normal.woff2")),
    ("inter-cyrillic-600.woff2", include_bytes!("../assets/fonts/inter-cyrillic-600-normal.woff2")),
    ("manrope-latin-700.woff2", include_bytes!("../assets/fonts/manrope-latin-700-normal.woff2")),
    ("manrope-cyrillic-700.woff2", include_bytes!("../assets/fonts/manrope-cyrillic-700-normal.woff2")),
];
const MAX_BODY: usize = 1 << 20;
const MAX_LINES: usize = 2000;

#[derive(Default)]
struct Job {
    kind: String,
    lines: Vec<String>,
    running: bool,
    ok: Option<bool>,
    package: Option<String>,
}

struct Wizard {
    dir: PathBuf,
    exe: PathBuf,
    token: String,
    host_ok: Vec<String>,
    job: Arc<Mutex<Job>>,
}

pub struct Options {
    pub dir: PathBuf,
    pub port: u16,
    pub open_browser: bool,
}

/// Запустить мастер и обслуживать запросы до Ctrl+C.
pub fn serve(o: Options) -> Result<(), String> {
    crate::state::ensure_dir(&o.dir)?;
    let listener = TcpListener::bind(("127.0.0.1", o.port)).map_err(|e| format!("127.0.0.1:{}: {e}", o.port))?;
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();
    let mut b = [0u8; 24];
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut b);
    let token = crate::sign::hex(&b);
    let w = Arc::new(Wizard {
        dir: o.dir.clone(),
        exe: std::env::current_exe().map_err(|e| e.to_string())?,
        token: token.clone(),
        host_ok: vec![format!("127.0.0.1:{port}"), format!("localhost:{port}")],
        job: Arc::default(),
    });
    let url = format!("http://127.0.0.1:{port}/#{token}");
    println!("Мастер portable: {url}\nАдрес действует, пока открыто это окно; остановка — Ctrl+C.");
    if o.open_browser {
        open(&url);
    }
    for conn in listener.incoming() {
        let Ok(c) = conn else { continue };
        let w = w.clone();
        std::thread::spawn(move || {
            let _ = c.set_read_timeout(Some(std::time::Duration::from_secs(30)));
            let _ = handle(&w, c);
        });
    }
    Ok(())
}

fn open(url: &str) {
    #[cfg(windows)]
    let r = Command::new("rundll32").args(["url.dll,FileProtocolHandler", url]).spawn();
    #[cfg(not(windows))]
    let r = Command::new("xdg-open").arg(url).stdout(Stdio::null()).stderr(Stdio::null()).spawn();
    if r.is_err() {
        println!("Откройте адрес в браузере вручную.");
    }
}

struct Request {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Request {
    fn header(&self, n: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(n)).map(|(_, v)| v.as_str())
    }
}

fn read_request(c: &TcpStream) -> Result<Request, String> {
    let mut r = BufReader::new(c);
    let mut line = String::new();
    r.read_line(&mut line).map_err(|e| e.to_string())?;
    let mut it = line.split_whitespace();
    let (method, path) = (it.next().unwrap_or("").to_string(), it.next().unwrap_or("").to_string());
    let mut headers = vec![];
    loop {
        let mut h = String::new();
        r.read_line(&mut h).map_err(|e| e.to_string())?;
        let h = h.trim_end();
        if h.is_empty() {
            break;
        }
        if headers.len() > 64 {
            return Err("headers".into());
        }
        if let Some((k, v)) = h.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    let n: usize = headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("Content-Length")).and_then(|(_, v)| v.parse().ok()).unwrap_or(0);
    if n > MAX_BODY {
        return Err("body".into());
    }
    let mut body = vec![0u8; n];
    r.read_exact(&mut body).map_err(|e| e.to_string())?;
    Ok(Request { method, path, headers, body })
}

fn respond(mut c: &TcpStream, status: u16, ctype: &str, body: &[u8]) -> std::io::Result<()> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        409 => "Conflict",
        _ => "Error",
    };
    write!(c, "HTTP/1.1 {status} {reason}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: DENY\r\nContent-Security-Policy: default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'\r\nReferrer-Policy: no-referrer\r\nConnection: close\r\n\r\n", body.len())?;
    c.write_all(body)
}

fn handle(w: &Wizard, c: TcpStream) -> std::io::Result<()> {
    let req = match read_request(&c) {
        Ok(r) => r,
        Err(_) => return respond(&c, 400, "text/plain", b"bad request"),
    };
    // защита от DNS rebinding и чужих страниц: только свой Host, свой Origin и токен
    if !w.host_ok.iter().any(|h| req.header("Host") == Some(h)) {
        return respond(&c, 403, "text/plain", b"host");
    }
    if req.method == "GET" && req.path == "/" {
        return respond(&c, 200, "text/html; charset=utf-8", PAGE.as_bytes());
    }
    if req.method == "GET" {
        if let Some(name) = req.path.strip_prefix("/fonts/") {
            return match FONTS.iter().find(|(n, _)| *n == name) {
                Some((_, b)) => respond(&c, 200, "font/woff2", b),
                None => respond(&c, 404, "text/plain", b"not found"),
            };
        }
    }
    if !req.path.starts_with("/api/") {
        return respond(&c, 404, "text/plain", b"not found");
    }
    if let Some(o) = req.header("Origin") {
        if !w.host_ok.iter().any(|h| o == format!("http://{h}")) {
            return respond(&c, 403, "text/plain", b"origin");
        }
    }
    if !req.header("X-Token").is_some_and(|t| ct_eq(t.as_bytes(), w.token.as_bytes())) {
        return respond(&c, 403, "text/plain", b"token");
    }
    let body: Value = if req.body.is_empty() { Value::Null } else {
        match serde_json::from_slice(&req.body) {
            Ok(v) => v,
            Err(_) => return respond(&c, 400, "application/json", br#"{"error":"JSON"}"#),
        }
    };
    let r = route(w, &req.method, &req.path, &body);
    let (status, v) = match r {
        Ok(v) => (200, v),
        Err((s, e)) => (s, json!({"error": e})),
    };
    respond(&c, status, "application/json", &serde_json::to_vec(&v).unwrap_or_default())
}

type R = Result<Value, (u16, String)>;

fn bad(e: impl ToString) -> (u16, String) {
    (400, e.to_string())
}

fn s<'a>(v: &'a Value, k: &str) -> &'a str {
    v[k].as_str().unwrap_or("").trim()
}

fn route(w: &Wizard, method: &str, path: &str, b: &Value) -> R {
    match (method, path) {
        ("GET", "/api/state") => state(w),
        ("GET", "/api/job") => {
            let j = w.job.lock().unwrap();
            Ok(json!({"kind": j.kind, "running": j.running, "ok": j.ok, "lines": j.lines, "package": j.package}))
        }
        ("POST", "/api/init") => {
            if w.dir.join("identity.json").exists() {
                return Err((409, "каталог аудита уже подготовлен".into()));
            }
            let mut a = vec!["init".to_string(), "--state".into(), w.dir.display().to_string()];
            if !s(b, "prep").is_empty() {
                p::parse_prep(s(b, "prep")).map_err(bad)?; // понятная ошибка сразу, до запуска
                a.extend(["--prep".into(), s(b, "prep").to_string()]);
            }
            for k in ["tenant", "site", "scope"] {
                if !s(b, k).is_empty() {
                    a.extend([format!("--{k}"), s(b, k).to_string()]);
                }
            }
            if !s(b, "center_key").is_empty() {
                a.extend(["--center-key".into(), s(b, "center_key").to_string()]);
            }
            start(w, "init", a, String::new(), None)
        }
        ("POST", "/api/prep") => {
            // предпросмотр строки подготовки: что из неё получено (шаг 1 мастера)
            let x = p::parse_prep(s(b, "prep")).map_err(bad)?;
            Ok(json!({"site": x.site, "scope": x.scope, "site_name": x.site_name, "scope_name": x.scope_name, "center_key": x.center_key.is_some()}))
        }
        ("POST", "/api/center-key") => {
            let id = p::set_center_key(&w.dir, s(b, "center_key")).map_err(bad)?;
            Ok(json!({"encryption_key_id": id}))
        }
        ("POST", "/api/discover") => {
            let mut a = vec!["discover".to_string(), "--state".into(), w.dir.display().to_string(), "--range".into(), list(&b["ranges"])?];
            let ex = list(&b["excluded"]).unwrap_or_default();
            if !ex.is_empty() {
                a.extend(["--exclude".into(), ex]);
            }
            if let Some(r) = b["rate"].as_u64() {
                a.extend(["--rate".into(), r.to_string()]);
            }
            start(w, "discover", a, String::new(), None)
        }
        ("PUT", "/api/profiles") => {
            let pr: Profiles = serde_json::from_value(b.clone()).map_err(|e| bad(format!("профили: {e}")))?;
            pr.validate().map_err(bad)?;
            crate::state::save_json(&w.dir.join(PROFILES_FILE), &pr).map_err(|e| (500, e))?;
            Ok(json!({"saved": true}))
        }
        ("POST", "/api/test") | ("POST", "/api/collect") => {
            let test = path == "/api/test";
            let ips: Vec<String> = if test { vec![s(b, "ip").to_string()] } else { b["ips"].as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect()).unwrap_or_default() };
            if ips.iter().any(|ip| ip.parse::<std::net::Ipv4Addr>().is_err()) {
                return Err(bad("адрес узла"));
            }
            let mut a = vec!["collect".to_string(), "--state".into(), w.dir.display().to_string(), "--secrets-stdin".into(), "--only".into(), ips.join(",")];
            if test || !b["host"].as_bool().unwrap_or(false) {
                a.push("--no-host".into());
            }
            let mut package = None;
            if test {
                if ips.len() != 1 {
                    return Err(bad("один узел"));
                }
                a.push("--dry-run".into());
            } else {
                let out = w.dir.join("packages").join(format!("audit-{}.zip", crate::client::now_rfc3339().replace([':', '-'], "").chars().take(15).collect::<String>()));
                crate::state::ensure_dir(out.parent().unwrap()).map_err(|e| (500, e))?;
                a.extend(["--out".into(), out.display().to_string()]);
                package = Some(out.display().to_string());
            }
            // пароли — только в stdin дочернего процесса
            let mut secrets = String::new();
            if let Some(m) = b["secrets"].as_object() {
                for (k, v) in m {
                    let v = v.as_str().unwrap_or("");
                    if k.contains(['=', '\n', '\r']) || v.contains(['\n', '\r']) {
                        return Err(bad("пароль профиля"));
                    }
                    if !v.is_empty() {
                        secrets.push_str(&format!("{k}={v}\n"));
                    }
                }
            }
            start(w, if test { "test" } else { "collect" }, a, secrets, package)
        }
        _ => Err((404, "not found".into())),
    }
}

fn list(v: &Value) -> Result<String, (u16, String)> {
    let items: Vec<&str> = v.as_array().map(|a| a.iter().filter_map(|x| x.as_str()).map(str::trim).filter(|x| !x.is_empty()).collect()).unwrap_or_default();
    if items.is_empty() {
        return Err(bad("укажите хотя бы одну подсеть"));
    }
    for i in &items {
        crate::discover::Net::parse(i).map_err(bad)?;
    }
    Ok(items.join(","))
}

fn state(w: &Wizard) -> R {
    // №58: блок для центра («Portable-аудит» → регистрация источника) — тот же вывод, что у команды init
    let (identity, public, block) = match p::load(&w.dir) {
        Ok((id, key)) => {
            let public = p::public_b64url(&key.verifying_key());
            let block = format!("tenant_id={}\nsite_id={}\nscope_id={}\nsource_id={}\ngeneration_id={}\nkey_id={}\npublic_key={}", id.tenant_id, id.site_id, id.network_scope_id, id.source_id, id.generation_id, id.key_id, public);
            (Some(id.source_id.clone()), Some(public), Some(block))
        }
        Err(_) => (None, None, None),
    };
    let profiles = Profiles::load(&w.dir).map(|p| serde_json::to_value(p).unwrap_or(Value::Null)).map_err(|e| (500, e))?;
    let discovery: Value = std::fs::read(w.dir.join(p::DISCOVERY_FILE)).ok().and_then(|r| serde_json::from_slice(&r).ok()).unwrap_or(Value::Null);
    let bound: Vec<Value> = match (Profiles::load(&w.dir), discovery["hosts"].as_array()) {
        (Ok(pr), Some(hs)) => hs.iter().map(|h| json!(pr.bind(h["ip"].as_str().unwrap_or(""), h["kind"].as_str().unwrap_or(""), None).map(|x| x.name.clone()))).collect(),
        _ => vec![],
    };
    let center = p::center_key(&w.dir).ok().flatten().is_some();
    // C52.04: итоги последнего сбора по узлам и разделам (страница узла мастера)
    let results: Value = std::fs::read(w.dir.join("results-last.json")).ok().and_then(|r| serde_json::from_slice(&r).ok()).unwrap_or(Value::Null);
    let packages: Vec<Value> = std::fs::read_dir(w.dir.join("packages")).map(|d| d.filter_map(Result::ok).filter_map(|e| {
        let m = e.metadata().ok()?;
        let name = e.file_name().to_string_lossy().to_string();
        let sha = std::fs::read(e.path()).ok().map(|b| crate::sign::hex(&sha2::Sha256::digest(&b)));
        Some(json!({"name": name, "bytes": m.len(), "sha256": sha, "path": e.path().display().to_string()}))
    }).collect()).unwrap_or_default();
    Ok(json!({"dir": w.dir.display().to_string(), "initialized": identity.is_some(), "source_id": identity, "public_key": public, "init_block": block, "center_key": center,
        "profiles": profiles, "discovery": discovery, "bound": bound, "results": results, "packages": packages, "platform": std::env::consts::OS, "version": crate::VERSION}))
}

fn start(w: &Wizard, kind: &str, args: Vec<String>, stdin: String, package: Option<String>) -> R {
    let mut j = w.job.lock().unwrap();
    if j.running {
        return Err((409, "уже выполняется другой шаг".into()));
    }
    let mut child = Command::new(&w.exe).args(&args).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().map_err(|e| (500, e.to_string()))?;
    *j = Job { kind: kind.into(), running: true, ..Default::default() };
    drop(j);
    let mut input = child.stdin.take().unwrap();
    std::thread::spawn(move || {
        let _ = input.write_all(stdin.as_bytes());
    });
    let pipe = |r: Box<dyn Read + Send>, job: Arc<Mutex<Job>>| {
        std::thread::spawn(move || {
            for line in BufReader::new(r).lines().map_while(Result::ok) {
                let mut j = job.lock().unwrap();
                if j.lines.len() >= MAX_LINES {
                    j.lines.remove(0);
                }
                j.lines.push(line);
            }
        })
    };
    let a = pipe(Box::new(child.stdout.take().unwrap()), w.job.clone());
    let b = pipe(Box::new(child.stderr.take().unwrap()), w.job.clone());
    let job = w.job.clone();
    std::thread::spawn(move || {
        let ok = child.wait().map(|s| s.success()).unwrap_or(false);
        let _ = (a.join(), b.join());
        let mut j = job.lock().unwrap();
        j.running = false;
        j.ok = Some(ok);
        j.package = if ok { package } else { None };
    });
    Ok(json!({"started": kind}))
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}
