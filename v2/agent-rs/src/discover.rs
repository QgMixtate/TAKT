//! Обследование подсети portable-аудитом (C52.06 п. 1, формат узлов — C23.04): TCP-подключение к портам без знания
//! узлов, с исключениями, ограничением скорости и параллельности (политика как D13: только указанные диапазоны,
//! без перебора учёток, без UDP/ICMP-сканирования). Узел «найден», если порт принял соединение или ответил RST.

use serde_json::{json, Value};
use std::io::Read;
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub const DEFAULT_PORTS: [u16; 8] = [22, 23, 80, 135, 443, 445, 5985, 5986];
pub const MAX_HOSTS: usize = 65536;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Net {
    pub addr: u32,
    pub bits: u8,
}

impl Net {
    pub fn parse(s: &str) -> Result<Net, String> {
        let (a, b) = s.trim().split_once('/').ok_or_else(|| format!("{s}: нужен CIDR, например 10.20.0.0/16"))?;
        let ip: Ipv4Addr = a.parse().map_err(|_| format!("{s}: не IPv4"))?;
        let bits: u8 = b.parse().ok().filter(|b| *b <= 32).ok_or_else(|| format!("{s}: длина префикса 0..32"))?;
        let mask = if bits == 0 { 0 } else { u32::MAX << (32 - bits) };
        Ok(Net { addr: u32::from(ip) & mask, bits })
    }
    fn mask(&self) -> u32 {
        if self.bits == 0 { 0 } else { u32::MAX << (32 - self.bits) }
    }
    pub fn contains(&self, ip: u32) -> bool {
        ip & self.mask() == self.addr
    }
    pub fn text(&self) -> String {
        format!("{}/{}", Ipv4Addr::from(self.addr), self.bits)
    }
}

/// Адреса диапазонов без исключённых; сеть и broadcast опускаются (кроме /31 и /32). Больше MAX_HOSTS — отказ.
pub fn hosts(ranges: &[Net], excluded: &[Net]) -> Result<Vec<u32>, String> {
    let mut out = vec![];
    for r in ranges {
        let size: u64 = 1u64 << (32 - r.bits as u32);
        for i in 0..size {
            let ip = r.addr.wrapping_add(i as u32);
            if r.bits < 31 && (i == 0 || i == size - 1) {
                continue;
            }
            if excluded.iter().any(|x| x.contains(ip)) {
                continue;
            }
            if out.len() >= MAX_HOSTS {
                return Err(format!("обследование ограничено {MAX_HOSTS} адресами (например, /16): сузьте диапазон"));
            }
            out.push(ip);
        }
    }
    out.sort_unstable();
    out.dedup();
    Ok(out)
}

pub struct Options {
    pub ports: Vec<u16>,
    pub timeout: Duration,
    pub parallel: usize,
    pub rate_per_sec: u32,
    pub deadline: Option<Instant>,
}

/// Баннер SSH (до 255 байт за 2 с): сетевое оборудование отличается от Linux по известным подписям.
fn ssh_banner(addr: SocketAddr, timeout: Duration) -> String {
    let Ok(mut s) = TcpStream::connect_timeout(&addr, timeout) else { return String::new() };
    let _ = s.set_read_timeout(Some(Duration::from_secs(2)));
    let mut buf = [0u8; 255];
    let n = s.read(&mut buf).unwrap_or(0);
    String::from_utf8_lossy(&buf[..n]).lines().next().unwrap_or("").trim().to_string()
}

/// Вид узла по портам и баннеру: Windows — WinRM/SMB/RPC; SSH сетевого оборудования — network_snmp; SSH — Linux.
pub fn classify(ports: &[u16], banner: &str) -> &'static str {
    let b = banner.to_ascii_lowercase();
    if ports.iter().any(|p| [5985, 5986, 135, 445].contains(p)) {
        return "windows_winrm";
    }
    if ports.contains(&22) {
        if ["cisco", "comware", "huawei", "routeros", "mikrotik", "juniper", "fortissh", "hp-ssh", "dropbear_2012", "eltex", "zyxel"].iter().any(|k| b.contains(k)) {
            return "network_snmp";
        }
        return "linux_ssh";
    }
    if ports.contains(&23) {
        return "network_snmp";
    }
    "unknown"
}

/// Проход: каждый адрес — по всем портам; узел найден, если хоть один порт принял соединение или отверг (RST).
/// Возвращает (узлы, complete=false при достижении срока).
pub fn run(addresses: &[u32], o: &Options, progress: &(dyn Fn(usize, usize, usize) + Sync)) -> (Vec<Value>, bool) {
    let next = AtomicUsize::new(0);
    let found: Mutex<Vec<(u32, Vec<u16>, String)>> = Mutex::new(vec![]);
    let stop = AtomicBool::new(false);
    let started = Instant::now();
    let interval = Duration::from_secs_f64(1.0 / o.rate_per_sec.max(1) as f64);
    let slot = Mutex::new(Instant::now());
    let done = AtomicUsize::new(0);
    std::thread::scope(|scope| {
        for _ in 0..o.parallel.clamp(1, 256) {
            scope.spawn(|| loop {
                if o.deadline.map(|d| Instant::now() >= d).unwrap_or(false) {
                    stop.store(true, Ordering::SeqCst);
                    return;
                }
                let i = next.fetch_add(1, Ordering::SeqCst);
                let Some(&ip) = addresses.get(i) else { return };
                let (mut open, mut alive) = (vec![], false);
                for &port in &o.ports {
                    {
                        // общая очередь запусков: не больше rate_per_sec подключений в секунду на весь проход
                        let mut t = slot.lock().unwrap();
                        let now = Instant::now();
                        if *t > now {
                            std::thread::sleep(*t - now);
                        }
                        *t = (*t).max(now) + interval;
                    }
                    let addr = SocketAddr::from((Ipv4Addr::from(ip), port));
                    match TcpStream::connect_timeout(&addr, o.timeout) {
                        Ok(_) => {
                            alive = true;
                            open.push(port);
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => alive = true,
                        Err(_) => {}
                    }
                }
                if alive {
                    let banner = if open.contains(&22) { ssh_banner(SocketAddr::from((Ipv4Addr::from(ip), 22)), o.timeout) } else { String::new() };
                    found.lock().unwrap().push((ip, open, banner));
                }
                let d = done.fetch_add(1, Ordering::SeqCst) + 1;
                if d % 256 == 0 || d == addresses.len() {
                    progress(d, addresses.len(), found.lock().unwrap().len());
                }
            });
        }
    });
    let _ = started;
    let mut list = found.into_inner().unwrap();
    list.sort_by_key(|x| x.0);
    let hosts = list.into_iter().map(|(ip, ports, banner)| json!({"ip": Ipv4Addr::from(ip).to_string(), "ports": ports, "kind": classify(&ports, &banner)})).collect();
    (hosts, !stop.load(Ordering::SeqCst))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranges_exclusions_and_limits() {
        let r = Net::parse("10.20.1.0/30").unwrap();
        assert_eq!(r.text(), "10.20.1.0/30");
        assert_eq!(hosts(&[r], &[]).unwrap().len(), 2); // без сети и broadcast
        assert_eq!(hosts(&[Net::parse("10.20.1.7/32").unwrap()], &[]).unwrap().len(), 1);
        let h = hosts(&[Net::parse("10.20.0.0/24").unwrap()], &[Net::parse("10.20.0.0/25").unwrap()]).unwrap();
        assert_eq!(h.len(), 127);
        assert!(hosts(&[Net::parse("10.0.0.0/15").unwrap()], &[]).is_err());
        assert_eq!(hosts(&[Net::parse("10.0.0.0/16").unwrap()], &[]).unwrap().len(), 65534);
        assert!(Net::parse("10.0.0.0").is_err() && Net::parse("::1/128").is_err() && Net::parse("10.0.0.0/33").is_err());
    }

    #[test]
    fn kinds_by_ports_and_banner() {
        assert_eq!(classify(&[5985], ""), "windows_winrm");
        assert_eq!(classify(&[445, 22], "SSH-2.0-OpenSSH_for_Windows"), "windows_winrm");
        assert_eq!(classify(&[22], "SSH-2.0-OpenSSH_9.6p1 Ubuntu"), "linux_ssh");
        assert_eq!(classify(&[22], "SSH-2.0-Cisco-1.25"), "network_snmp");
        assert_eq!(classify(&[23], ""), "network_snmp");
        assert_eq!(classify(&[], ""), "unknown");
    }
}
