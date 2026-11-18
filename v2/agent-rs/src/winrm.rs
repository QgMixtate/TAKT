//! Клиент WinRM (C52.06) — WS-Man поверх HTTP 5985 с входом Negotiate (Kerberos или NTLM через sspi, чистый Rust) и
//! шифрованием каждого сообщения (MS-WSMV 2.2.9.1, тот же формат, что у Go winrmkrb). Один фиксированный сценарий
//! (script.ps1) передаётся через stdin PowerShell — на диск цели ничего не пишется. Без повторов входа при отказе.

use base64::{engine::general_purpose::STANDARD, Engine};
use sspi::{AuthIdentity, BufferType, ClientRequestFlags, CredentialUse, DataRepresentation, EncryptionFlags, Negotiate, NegotiateConfig, SecurityBuffer, SecurityBufferRef, SecurityStatus, Sspi, SspiImpl, Username};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant};

const PROTOCOL: &str = "application/HTTP-SPNEGO-session-encrypted";
const BOUNDARY: &str = "--Encrypted Boundary";

/// Фиксированная причина отказа (в пакет — только код).
#[derive(Debug, Clone, PartialEq)]
pub enum Failure {
    Unreachable,
    Timeout,
    AuthFailed,
    AccessDenied,
    Unencrypted,
    Protocol(&'static str),
    Script,
}

impl Failure {
    pub fn code(&self) -> &'static str {
        match self {
            Failure::Unreachable => "HOST_UNREACHABLE",
            Failure::Timeout => "TIMEOUT",
            Failure::AuthFailed => "AUTH_FAILED",
            Failure::AccessDenied => "ACCESS_DENIED",
            Failure::Unencrypted => "UNENCRYPTED_REPLY",
            Failure::Protocol(_) => "WINRM_PROTOCOL_ERROR",
            Failure::Script => "SCRIPT_FAILED",
        }
    }
    pub fn outcome(&self) -> &'static str {
        match self {
            Failure::Unreachable | Failure::Timeout => "unreachable",
            _ => "no_access",
        }
    }
}

pub struct Target {
    pub host: String,
    pub ip: String,
    pub port: u16,
    /// DOMAIN\user, user@domain или локальная учётка
    pub user: String,
    pub password: String,
    /// адрес KDC (tcp://dc.domain:88) — Kerberos; без него — NTLM
    pub kdc: Option<String>,
}

struct Http {
    stream: TcpStream,
    reader: BufReader<TcpStream>,
    host: String,
}

struct Response {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Response {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }
}

impl Http {
    fn connect(ip: &str, port: u16, host: &str) -> Result<Http, Failure> {
        let addr: SocketAddr = format!("{ip}:{port}").parse().map_err(|_| Failure::Unreachable)?;
        let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(10)).map_err(|e| if e.kind() == std::io::ErrorKind::TimedOut { Failure::Timeout } else { Failure::Unreachable })?;
        // ответ на Receive WinRM держит до OperationTimeout (20 с): таймаут чтения больше
        stream.set_read_timeout(Some(Duration::from_secs(60))).ok();
        stream.set_write_timeout(Some(Duration::from_secs(30))).ok();
        let reader = BufReader::new(stream.try_clone().map_err(|_| Failure::Unreachable)?);
        Ok(Http { stream, reader, host: format!("{host}:{port}") })
    }

    fn post(&mut self, authorization: Option<&str>, content_type: Option<&str>, body: &[u8]) -> Result<Response, Failure> {
        let mut req = format!("POST /wsman HTTP/1.1\r\nHost: {}\r\nConnection: Keep-Alive\r\nUser-Agent: surveyscan-portable\r\nContent-Length: {}\r\n", self.host, body.len());
        if let Some(a) = authorization {
            req.push_str(&format!("Authorization: {a}\r\n"));
        }
        if let Some(c) = content_type {
            req.push_str(&format!("Content-Type: {c}\r\n"));
        }
        req.push_str("\r\n");
        let io = |_| Failure::Unreachable;
        self.stream.write_all(req.as_bytes()).map_err(io)?;
        self.stream.write_all(body).map_err(io)?;
        self.read()
    }

    fn read(&mut self) -> Result<Response, Failure> {
        let mut line = String::new();
        let timeout = |e: std::io::Error| if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) { Failure::Timeout } else { Failure::Unreachable };
        self.reader.read_line(&mut line).map_err(timeout)?;
        let status: u16 = line.split_whitespace().nth(1).and_then(|s| s.parse().ok()).ok_or(Failure::Protocol("http status"))?;
        let mut headers = vec![];
        loop {
            line.clear();
            self.reader.read_line(&mut line).map_err(timeout)?;
            let l = line.trim_end();
            if l.is_empty() {
                break;
            }
            if let Some((k, v)) = l.split_once(':') {
                headers.push((k.trim().to_string(), v.trim().to_string()));
            }
            if headers.len() > 100 {
                return Err(Failure::Protocol("http headers"));
            }
        }
        let resp = Response { status, headers, body: vec![] };
        let mut body = vec![];
        if resp.header("Transfer-Encoding").is_some_and(|v| v.eq_ignore_ascii_case("chunked")) {
            loop {
                line.clear();
                self.reader.read_line(&mut line).map_err(timeout)?;
                let n = usize::from_str_radix(line.trim().split(';').next().unwrap_or(""), 16).map_err(|_| Failure::Protocol("chunk"))?;
                if n == 0 {
                    line.clear();
                    self.reader.read_line(&mut line).map_err(timeout)?;
                    break;
                }
                if body.len() + n > 64 << 20 {
                    return Err(Failure::Protocol("response too large"));
                }
                let mut chunk = vec![0u8; n + 2];
                self.reader.read_exact(&mut chunk).map_err(timeout)?;
                body.extend_from_slice(&chunk[..n]);
            }
        } else if let Some(n) = resp.header("Content-Length").and_then(|v| v.parse::<usize>().ok()) {
            if n > 64 << 20 {
                return Err(Failure::Protocol("response too large"));
            }
            body = vec![0u8; n];
            self.reader.read_exact(&mut body).map_err(timeout)?;
        }
        Ok(Response { body, ..resp })
    }
}

/// Сетевой клиент sspi для KDC (Kerberos по TCP, длина — 4 байта big-endian).
struct KdcClient;

impl sspi::network_client::NetworkClient for KdcClient {
    fn send(&self, request: &sspi::generator::NetworkRequest) -> sspi::Result<Vec<u8>> {
        let err = |m: &str| sspi::Error::new(sspi::ErrorKind::NoAuthenticatingAuthority, m.to_string());
        let url = &request.url;
        let addr = format!("{}:{}", url.host_str().unwrap_or_default(), url.port().unwrap_or(88));
        let sock = std::net::ToSocketAddrs::to_socket_addrs(&addr).map_err(|_| err("kdc address"))?.next().ok_or_else(|| err("kdc address"))?;
        let mut s = TcpStream::connect_timeout(&sock, Duration::from_secs(5)).map_err(|_| err("kdc unreachable"))?;
        s.set_read_timeout(Some(Duration::from_secs(10))).ok();
        let data = &request.data;
        // sspi передаёт TCP-запрос уже с префиксом длины
        s.write_all(data).map_err(|_| err("kdc write"))?;
        let mut len = [0u8; 4];
        s.read_exact(&mut len).map_err(|_| err("kdc read"))?;
        let n = u32::from_be_bytes(len) as usize;
        if n > 1 << 20 {
            return Err(err("kdc reply too large"));
        }
        let mut out = vec![0u8; n];
        s.read_exact(&mut out).map_err(|_| err("kdc read"))?;
        let mut reply = len.to_vec();
        reply.extend_from_slice(&out);
        Ok(reply)
    }
}

pub struct Session {
    http: Http,
    ctx: Negotiate,
}

fn auth_token(resp: &Response) -> Option<Vec<u8>> {
    resp.headers.iter().filter(|(k, _)| k.eq_ignore_ascii_case("WWW-Authenticate")).find_map(|(_, v)| v.strip_prefix("Negotiate ").and_then(|t| STANDARD.decode(t.trim()).ok()))
}

impl Session {
    /// Вход Negotiate на соединении (Kerberos при известном KDC, иначе NTLM); отказ — без повторов.
    pub fn connect(t: &Target) -> Result<Session, Failure> {
        let mut http = Http::connect(&t.ip, t.port, &t.host)?;
        let computer = std::env::var("COMPUTERNAME").ok().or_else(|| std::fs::read_to_string("/proc/sys/kernel/hostname").ok()).unwrap_or_else(|| "surveyscan".into()).trim().to_string();
        let protocol: Box<dyn sspi::negotiate::ProtocolConfig> = match &t.kdc {
            Some(k) => Box::new(sspi::KerberosConfig::new_with_kdc_url(k, computer.clone())),
            None => Box::new(sspi::ntlm::NtlmConfig::new(computer.clone())),
        };
        let packages = if t.kdc.is_some() { "kerberos,!ntlm" } else { "!kerberos,ntlm" };
        let mut ctx = Negotiate::new_client(NegotiateConfig::new(protocol, Some(packages.into()), computer)).map_err(|_| Failure::Protocol("negotiate"))?;
        let identity = AuthIdentity { username: Username::parse(&t.user).map_err(|_| Failure::AuthFailed)?, password: t.password.clone().into() };
        let mut creds = ctx.acquire_credentials_handle().with_credential_use(CredentialUse::Outbound).with_auth_data(&identity.into()).execute(&mut ctx).map_err(|_| Failure::AuthFailed)?.credentials_handle;
        let target = format!("HTTP/{}", t.host);
        let mut input: Option<Vec<u8>> = None;
        for _ in 0..6 {
            let mut inb = vec![SecurityBuffer::new(input.clone().unwrap_or_default(), BufferType::Token)];
            let mut outb = vec![SecurityBuffer::new(Vec::new(), BufferType::Token)];
            let flags = ClientRequestFlags::MUTUAL_AUTH | ClientRequestFlags::CONFIDENTIALITY | ClientRequestFlags::INTEGRITY | ClientRequestFlags::SEQUENCE_DETECT | ClientRequestFlags::REPLAY_DETECT;
            let mut b = ctx.initialize_security_context().with_credentials_handle(&mut creds).with_context_requirements(flags).with_target_data_representation(DataRepresentation::Native).with_target_name(&target).with_output(&mut outb);
            if input.is_some() {
                b = b.with_input(&mut inb);
            }
            let r = ctx.initialize_security_context_impl(&mut b).map_err(|_| Failure::Protocol("isc"))?.resolve_with_client(&KdcClient).map_err(|e| if matches!(e.error_type, sspi::ErrorKind::NoAuthenticatingAuthority) { Failure::Unreachable } else { Failure::AuthFailed })?;
            let token = outb[0].buffer.clone();
            if token.is_empty() && r.status == SecurityStatus::Ok {
                return Ok(Session { http, ctx });
            }
            let resp = http.post(Some(&format!("Negotiate {}", STANDARD.encode(&token))), None, &[])?;
            match resp.status {
                200 => {
                    // взаимная проверка (Kerberos): последний маркер сервера
                    if let Some(tok) = auth_token(&resp) {
                        let mut inb = vec![SecurityBuffer::new(tok, BufferType::Token)];
                        let mut outb = vec![SecurityBuffer::new(Vec::new(), BufferType::Token)];
                        let mut b = ctx.initialize_security_context().with_credentials_handle(&mut creds).with_context_requirements(flags).with_target_data_representation(DataRepresentation::Native).with_target_name(&target).with_input(&mut inb).with_output(&mut outb);
                        ctx.initialize_security_context_impl(&mut b).map_err(|_| Failure::Protocol("isc"))?.resolve_with_client(&KdcClient).map_err(|_| Failure::AuthFailed)?;
                    }
                    return Ok(Session { http, ctx });
                }
                401 => match auth_token(&resp) {
                    Some(tok) if r.status == SecurityStatus::ContinueNeeded => input = Some(tok),
                    _ => return Err(Failure::AuthFailed),
                },
                _ => return Err(Failure::Protocol("auth status")),
            }
        }
        Err(Failure::AuthFailed)
    }

    fn seal(&mut self, msg: &[u8]) -> Result<Vec<u8>, Failure> {
        let sizes = self.ctx.query_context_sizes().map_err(|_| Failure::Protocol("sizes"))?;
        let mut token = vec![0u8; sizes.security_trailer as usize];
        let mut data = msg.to_vec();
        {
            let mut bufs = [SecurityBufferRef::token_buf(&mut token), SecurityBufferRef::data_buf(&mut data)];
            self.ctx.encrypt_message(EncryptionFlags::empty(), &mut bufs).map_err(|_| Failure::Protocol("encrypt"))?;
            let t = bufs[0].data().to_vec();
            let d = bufs[1].data().to_vec();
            token = t;
            data = d;
        }
        let mut b = format!("{BOUNDARY}\r\n\tContent-Type: {PROTOCOL}\r\n\tOriginalContent: type=application/soap+xml;charset=UTF-8;Length={}\r\n{BOUNDARY}\r\n\tContent-Type: application/octet-stream\r\n", msg.len()).into_bytes();
        b.extend_from_slice(&(token.len() as u32).to_le_bytes());
        b.extend_from_slice(&token);
        b.extend_from_slice(&data);
        b.extend_from_slice(format!("{BOUNDARY}--\r\n").as_bytes());
        Ok(b)
    }

    fn open(&mut self, content_type: &str, body: &[u8]) -> Result<Vec<u8>, Failure> {
        if body.is_empty() {
            return Ok(vec![]);
        }
        if !content_type.contains(&format!("protocol=\"{PROTOCOL}\"")) {
            return Err(Failure::Unencrypted);
        }
        let sep = format!("{BOUNDARY}\r\n");
        let parts: Vec<&[u8]> = split(body, sep.as_bytes()).into_iter().filter(|p| !p.iter().all(|c| c.is_ascii_whitespace())).collect();
        let mut out = vec![];
        let mut i = 0;
        while i + 1 < parts.len() {
            let (meta, mut payload) = (parts[i], parts[i + 1]);
            let m = String::from_utf8_lossy(meta);
            let want: usize = m.split("Length=").nth(1).and_then(|x| x.trim().parse().ok()).ok_or(Failure::Protocol("length"))?;
            let end = format!("{BOUNDARY}--\r\n");
            if payload.ends_with(end.as_bytes()) {
                payload = &payload[..payload.len() - end.len()];
            }
            let pre = b"\tContent-Type: application/octet-stream\r\n";
            if payload.starts_with(pre) {
                payload = &payload[pre.len()..];
            }
            if payload.len() < 4 {
                return Err(Failure::Protocol("payload"));
            }
            let n = u32::from_le_bytes(payload[..4].try_into().unwrap()) as usize;
            if n == 0 || 4 + n > payload.len() {
                return Err(Failure::Protocol("payload"));
            }
            let mut token = payload[4..4 + n].to_vec();
            let mut data = payload[4 + n..].to_vec();
            let plain = {
                let mut bufs = [SecurityBufferRef::token_buf(&mut token), SecurityBufferRef::data_buf(&mut data)];
                self.ctx.decrypt_message(&mut bufs).map_err(|_| Failure::Protocol("decrypt"))?;
                bufs[1].data().to_vec()
            };
            if plain.len() != want {
                return Err(Failure::Protocol("length mismatch"));
            }
            out.extend_from_slice(&plain);
            i += 2;
        }
        Ok(out)
    }

    /// Один зашифрованный SOAP-обмен; отказ сервера (500 с Fault) — Err с текстом ответа.
    fn call(&mut self, soap: &str) -> Result<String, Failure> {
        let body = self.seal(soap.as_bytes())?;
        let resp = self.http.post(None, Some(&format!("multipart/encrypted;protocol=\"{PROTOCOL}\";boundary=\"Encrypted Boundary\"")), &body)?;
        if resp.status == 401 {
            return Err(Failure::AuthFailed);
        }
        let plain = self.open(resp.header("Content-Type").unwrap_or(""), &resp.body)?;
        let text = String::from_utf8_lossy(&plain).into_owned();
        if resp.status != 200 {
            if text.contains("w:TimedOut") || text.contains("2150858793") {
                return Ok(text); // long-poll Receive без вывода: повторить
            }
            if text.contains("AccessDenied") || text.contains("Access is denied") || text.contains("0x80070005") {
                return Err(Failure::AccessDenied);
            }
            return Err(Failure::Protocol("soap fault"));
        }
        Ok(text)
    }
}

fn split<'a>(s: &'a [u8], sep: &[u8]) -> Vec<&'a [u8]> {
    let mut out = vec![];
    let mut start = 0;
    let mut i = 0;
    while i + sep.len() <= s.len() {
        if &s[i..i + sep.len()] == sep {
            out.push(&s[start..i]);
            i += sep.len();
            start = i;
        } else {
            i += 1;
        }
    }
    out.push(&s[start..]);
    out
}

const SHELL_URI: &str = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd";

fn envelope(to: &str, action: &str, shell: Option<&str>, options: &[(&str, &str)], body: &str) -> String {
    let id = crate::state::new_id();
    let selector = shell.map(|s| format!("<w:SelectorSet><w:Selector Name=\"ShellId\">{s}</w:Selector></w:SelectorSet>")).unwrap_or_default();
    let opts = if options.is_empty() { String::new() } else { format!("<w:OptionSet>{}</w:OptionSet>", options.iter().map(|(k, v)| format!("<w:Option Name=\"{k}\">{v}</w:Option>")).collect::<String>()) };
    format!(r#"<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd" xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell"><s:Header><a:To>{to}</a:To><w:ResourceURI s:mustUnderstand="true">{SHELL_URI}</w:ResourceURI><a:ReplyTo><a:Address s:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address></a:ReplyTo><a:Action s:mustUnderstand="true">{action}</a:Action><w:MaxEnvelopeSize s:mustUnderstand="true">153600</w:MaxEnvelopeSize><a:MessageID>uuid:{id}</a:MessageID><w:Locale xml:lang="en-US" s:mustUnderstand="false"/><p:DataLocale xml:lang="en-US" s:mustUnderstand="false"/><w:OperationTimeout>PT20S</w:OperationTimeout>{selector}{opts}</s:Header><s:Body>{body}</s:Body></s:Envelope>"#)
}

fn between<'a>(text: &'a str, open_prefix: &str, close: &str) -> Option<&'a str> {
    let i = text.find(open_prefix)?;
    let rest = &text[i + open_prefix.len()..];
    let gt = rest.find('>')?;
    let rest = &rest[gt + 1..];
    let j = rest.find(close)?;
    Some(&rest[..j])
}

/// Выполнить сценарий: PowerShell читает его из stdin целиком; stdout до limit байт, код выхода.
pub fn run_script(s: &mut Session, to: &str, script: &str, limit: usize, deadline: Instant) -> Result<String, Failure> {
    let ns = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell";
    let created = s.call(&envelope(to, "http://schemas.xmlsoap.org/ws/2004/09/transfer/Create", None, &[("WINRS_NOPROFILE", "TRUE"), ("WINRS_CODEPAGE", "65001")],
        "<rsp:Shell><rsp:InputStreams>stdin</rsp:InputStreams><rsp:OutputStreams>stdout stderr</rsp:OutputStreams></rsp:Shell>"))?;
    let shell = between(&created, "<rsp:ShellId", "</rsp:ShellId>").or_else(|| between(&created, "<w:Selector Name=\"ShellId\"", "</w:Selector>")).ok_or(Failure::Protocol("shell id"))?.trim().to_string();
    let result = (|| {
        let loader = "$s = [Console]::In.ReadToEnd(); Invoke-Expression $s";
        let utf16: Vec<u8> = loader.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
        let args = format!("-NoProfile -NonInteractive -EncodedCommand {}", STANDARD.encode(utf16));
        let cmd = s.call(&envelope(to, &format!("{ns}/Command"), Some(&shell), &[("WINRS_CONSOLEMODE_STDIN", "TRUE"), ("WINRS_SKIP_CMD_SHELL", "FALSE")],
            &format!("<rsp:CommandLine><rsp:Command>powershell.exe</rsp:Command><rsp:Arguments>{args}</rsp:Arguments></rsp:CommandLine>")))?;
        let command = between(&cmd, "<rsp:CommandId", "</rsp:CommandId>").ok_or(Failure::Protocol("command id"))?.trim().to_string();
        // stdin частями (каждая — в пределах MaxEnvelopeSize), последняя с End="true"
        let bytes = script.as_bytes();
        let chunks: Vec<&[u8]> = bytes.chunks(32 * 1024).collect();
        for (i, c) in chunks.iter().enumerate() {
            let end = if i + 1 == chunks.len() { " End=\"true\"" } else { "" };
            s.call(&envelope(to, &format!("{ns}/Send"), Some(&shell), &[], &format!("<rsp:Send><rsp:Stream Name=\"stdin\" CommandId=\"{command}\"{end}>{}</rsp:Stream></rsp:Send>", STANDARD.encode(c))))?;
        }
        let mut out = vec![];
        loop {
            if Instant::now() > deadline {
                return Err(Failure::Timeout);
            }
            let r = s.call(&envelope(to, &format!("{ns}/Receive"), Some(&shell), &[("WSMAN_CMDSHELL_OPTION_KEEPALIVE", "TRUE")],
                &format!("<rsp:Receive><rsp:DesiredStream CommandId=\"{command}\">stdout stderr</rsp:DesiredStream></rsp:Receive>")))?;
            let mut rest = r.as_str();
            while let Some(i) = rest.find("<rsp:Stream") {
                rest = &rest[i..];
                let gt = rest.find('>').ok_or(Failure::Protocol("stream"))?;
                let tag = &rest[..gt];
                if tag.ends_with('/') {
                    rest = &rest[gt + 1..];
                    continue;
                }
                let close = rest.find("</rsp:Stream>").ok_or(Failure::Protocol("stream"))?;
                if tag.contains("Name=\"stdout\"") {
                    out.extend(STANDARD.decode(rest[gt + 1..close].trim()).map_err(|_| Failure::Protocol("base64"))?);
                    if out.len() > limit {
                        return Err(Failure::Protocol("output limit"));
                    }
                }
                rest = &rest[close..];
            }
            if r.contains("CommandState/Done") {
                let code: i64 = between(&r, "<rsp:ExitCode", "</rsp:ExitCode>").and_then(|c| c.trim().parse().ok()).unwrap_or(0);
                if code != 0 {
                    return Err(Failure::Script);
                }
                return Ok(String::from_utf8_lossy(&out).into_owned());
            }
        }
    })();
    let _ = s.call(&envelope(to, "http://schemas.xmlsoap.org/ws/2004/09/transfer/Delete", Some(&shell), &[], ""));
    result
}

/// Сбор Windows по WinRM: (кандидаты, 12 разделов) или причина отказа.
pub fn collect(t: &Target) -> Result<(serde_json::Value, Vec<serde_json::Value>), Failure> {
    let deadline = Instant::now() + Duration::from_secs(150);
    let mut s = Session::connect(t)?;
    let to = format!("http://{}:{}/wsman", t.host, t.port);
    let out = run_script(&mut s, &to, crate::winrmparse::SCRIPT, 16 << 20, deadline)?;
    let now = crate::client::now_rfc3339();
    let (sections, cands) = crate::winrmparse::parse(out.as_bytes(), &now).map_err(|_| Failure::Script)?;
    Ok((serde_json::Value::Array(cands), crate::winrmparse::complete12(sections, &now)))
}
