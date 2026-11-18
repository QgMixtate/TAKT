//! Служба Windows (SCM) для Rust-агента (C52.02) — как internal/platform/winservice в Go: LocalSystem, автозапуск
//! с задержкой, перезапуск при сбое (1, 1, 5 мин), остановка — флаг для цикла и до 25 с на завершение.

use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicBool, AtomicIsize, Ordering};
use std::sync::OnceLock;
use windows_sys::Win32::Foundation::ERROR_SERVICE_DOES_NOT_EXIST;
use windows_sys::Win32::System::Services::*;

pub const DEFAULT_NAME: &str = "SurveyscanAgent";

pub static STOP: AtomicBool = AtomicBool::new(false);
static STATUS: AtomicIsize = AtomicIsize::new(0);
static TASK: OnceLock<Box<dyn Fn() -> u32 + Send + Sync>> = OnceLock::new();
static NAME: OnceLock<Vec<u16>> = OnceLock::new();

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn valid_name(n: &str) -> bool {
    !n.is_empty() && n.len() <= 64 && n.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn report(state: u32, exit: u32, specific: u32, wait: u32) {
    let s = SERVICE_STATUS {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS,
        dwCurrentState: state,
        dwControlsAccepted: if state == SERVICE_RUNNING { SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN } else { 0 },
        dwWin32ExitCode: exit,
        dwServiceSpecificExitCode: specific,
        dwCheckPoint: 0,
        dwWaitHint: wait,
    };
    // SAFETY: дескриптор статуса получен RegisterServiceCtrlHandlerExW
    unsafe { SetServiceStatus(STATUS.load(Ordering::SeqCst), &s) };
}

unsafe extern "system" fn handler(control: u32, _: u32, _: *mut core::ffi::c_void, _: *mut core::ffi::c_void) -> u32 {
    match control {
        SERVICE_CONTROL_STOP | SERVICE_CONTROL_SHUTDOWN => {
            report(SERVICE_STOP_PENDING, 0, 0, 30000);
            STOP.store(true, Ordering::SeqCst);
            0
        }
        SERVICE_CONTROL_INTERROGATE => 0,
        _ => 120, // ERROR_CALL_NOT_IMPLEMENTED
    }
}

unsafe extern "system" fn service_main(_: u32, _: *mut *mut u16) {
    let name = NAME.get().expect("service name");
    let h = RegisterServiceCtrlHandlerExW(name.as_ptr(), Some(handler), null());
    if h == 0 {
        return;
    }
    STATUS.store(h, Ordering::SeqCst);
    report(SERVICE_START_PENDING, 0, 0, 30000);
    report(SERVICE_RUNNING, 0, 0, 0);
    let code = TASK.get().map(|t| t()).unwrap_or(1);
    // 0 — штатная остановка; иначе ERROR_SERVICE_SPECIFIC_ERROR с кодом этапа (SCM перезапустит)
    if code == 0 { report(SERVICE_STOPPED, 0, 0, 0) } else { report(SERVICE_STOPPED, 1066, code, 0) }
}

/// Отдать управление SCM; task выполняется в потоке службы, читает STOP и возвращает код выхода.
pub fn run(name: &str, task: impl Fn() -> u32 + Send + Sync + 'static) -> Result<(), String> {
    if !valid_name(name) {
        return Err("service name invalid".into());
    }
    let _ = NAME.set(wide(name));
    let _ = TASK.set(Box::new(task));
    let mut n = wide(name);
    let table = [SERVICE_TABLE_ENTRYW { lpServiceName: n.as_mut_ptr(), lpServiceProc: Some(service_main) }, SERVICE_TABLE_ENTRYW { lpServiceName: null_mut(), lpServiceProc: None }];
    // SAFETY: таблица живёт до возврата диспетчера
    if unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) } == 0 {
        return Err("service must be started by the Service Control Manager".into());
    }
    Ok(())
}

struct Handle(isize);
impl Drop for Handle {
    fn drop(&mut self) {
        if self.0 != 0 {
            // SAFETY: дескриптор SCM/службы
            unsafe { CloseServiceHandle(self.0) };
        }
    }
}

fn manager(access: u32) -> Result<Handle, String> {
    let h = unsafe { OpenSCManagerW(null(), null(), access) };
    if h == 0 {
        return Err("service manager unavailable (administrator rights required)".into());
    }
    Ok(Handle(h))
}

fn quote(a: &str) -> String {
    if a.is_empty() || a.contains([' ', '\t', '"']) { format!("\"{}\"", a.replace('"', "\\\"")) } else { a.to_string() }
}

/// Установка: LocalSystem, автозапуск с задержкой, перезапуск при сбое; уже установленная — отказ.
pub fn install(name: &str, exe: &str, args: &[String]) -> Result<(), String> {
    if !valid_name(name) || !std::path::Path::new(exe).is_absolute() || !std::path::Path::new(exe).is_file() {
        return Err("service name or executable path invalid".into());
    }
    let m = manager(SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE)?;
    let n = wide(name);
    let existing = Handle(unsafe { OpenServiceW(m.0, n.as_ptr(), SERVICE_QUERY_STATUS) });
    if existing.0 != 0 {
        return Err("service already installed".into());
    }
    let command = std::iter::once(quote(exe)).chain(args.iter().map(|a| quote(a))).collect::<Vec<_>>().join(" ");
    let (display, cmd) = (wide("surveyscan agent"), wide(&command));
    let s = Handle(unsafe { CreateServiceW(m.0, n.as_ptr(), display.as_ptr(), SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL, cmd.as_ptr(), null(), null_mut(), null(), null(), null()) });
    if s.0 == 0 {
        return Err("service creation failed".into());
    }
    let delayed = SERVICE_DELAYED_AUTO_START_INFO { fDelayedAutostart: 1 };
    let mut actions = [SC_ACTION { Type: SC_ACTION_RESTART, Delay: 60_000 }, SC_ACTION { Type: SC_ACTION_RESTART, Delay: 60_000 }, SC_ACTION { Type: SC_ACTION_RESTART, Delay: 300_000 }];
    let failure = SERVICE_FAILURE_ACTIONSW { dwResetPeriod: 86400, lpRebootMsg: null_mut(), lpCommand: null_mut(), cActions: 3, lpsaActions: actions.as_mut_ptr() };
    let non_crash = SERVICE_FAILURE_ACTIONS_FLAG { fFailureActionsOnNonCrashFailures: 1 };
    let ok = unsafe {
        ChangeServiceConfig2W(s.0, SERVICE_CONFIG_DELAYED_AUTO_START_INFO, &delayed as *const _ as _) != 0
            && ChangeServiceConfig2W(s.0, SERVICE_CONFIG_FAILURE_ACTIONS, &failure as *const _ as _) != 0
            && ChangeServiceConfig2W(s.0, SERVICE_CONFIG_FAILURE_ACTIONS_FLAG, &non_crash as *const _ as _) != 0
    };
    if !ok {
        unsafe { DeleteService(s.0) };
        return Err("service recovery configuration failed".into());
    }
    Ok(())
}

/// Удаление: остановка (если работает) и пометка на удаление; отсутствующая служба — не ошибка.
pub fn uninstall(name: &str) -> Result<(), String> {
    if !valid_name(name) {
        return Err("service name invalid".into());
    }
    let m = manager(SC_MANAGER_CONNECT)?;
    let n = wide(name);
    let s = Handle(unsafe { OpenServiceW(m.0, n.as_ptr(), SERVICE_STOP | SERVICE_QUERY_STATUS | 0x10000) }); // DELETE
    if s.0 == 0 {
        return if unsafe { windows_sys::Win32::Foundation::GetLastError() } == ERROR_SERVICE_DOES_NOT_EXIST { Ok(()) } else { Err("service unavailable".into()) };
    }
    let mut st: SERVICE_STATUS = unsafe { std::mem::zeroed() };
    unsafe { ControlService(s.0, SERVICE_CONTROL_STOP, &mut st) };
    if unsafe { DeleteService(s.0) } == 0 {
        return Err("service deletion failed".into());
    }
    Ok(())
}
