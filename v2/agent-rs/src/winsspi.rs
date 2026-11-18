//! Вход WinRM текущей учёткой Windows через встроенный SSPI (Negotiate: Kerberos или NTLM) — без пароля.
#![cfg(windows)]

use crate::winrm::Failure;
use windows::core::{w, HRESULT, PCWSTR};
use windows::Win32::Security::Authentication::Identity::*;
use windows::Win32::Security::Credentials::SecHandle;

const SEC_I_CONTINUE_NEEDED: i32 = 0x0009_0312;
const SEC_E_NO_AUTHENTICATING_AUTHORITY: u32 = 0x8009_0311;

pub struct Native {
    cred: SecHandle,
    ctx: Option<SecHandle>,
    target: Vec<u16>,
}

// дескрипторы SSPI используются одним потоком сессии; перенос между потоками допустим
unsafe impl Send for Native {}

fn token(ty: u32, data: &mut [u8]) -> SecBuffer {
    SecBuffer { cbBuffer: data.len() as u32, BufferType: ty, pvBuffer: data.as_mut_ptr().cast() }
}

impl Native {
    /// Учётные данные текущего входа (pAuthData = NULL); target — SPN вида HTTP/host.
    pub fn new(target: &str) -> Result<Native, Failure> {
        let mut cred = SecHandle::default();
        unsafe { AcquireCredentialsHandleW(PCWSTR::null(), w!("Negotiate"), SECPKG_CRED_OUTBOUND, None, None, None, None, &mut cred, None) }.map_err(|_| Failure::AuthFailed)?;
        Ok(Native { cred, ctx: None, target: target.encode_utf16().chain(Some(0)).collect() })
    }

    /// Шаг входа: (маркер для сервера, нужен ли ещё шаг).
    pub fn step(&mut self, input: Option<&[u8]>) -> Result<(Vec<u8>, bool), Failure> {
        let flags = ISC_REQ_FLAGS(ISC_REQ_MUTUAL_AUTH.0 | ISC_REQ_CONFIDENTIALITY.0 | ISC_REQ_INTEGRITY.0 | ISC_REQ_SEQUENCE_DETECT.0 | ISC_REQ_REPLAY_DETECT.0 | ISC_REQ_ALLOCATE_MEMORY.0);
        let mut in_data = input.map(|b| b.to_vec()).unwrap_or_default();
        let mut in_buf = token(SECBUFFER_TOKEN, &mut in_data);
        let in_desc = SecBufferDesc { ulVersion: SECBUFFER_VERSION, cBuffers: 1, pBuffers: &mut in_buf };
        let mut out_buf = SecBuffer { cbBuffer: 0, BufferType: SECBUFFER_TOKEN, pvBuffer: std::ptr::null_mut() };
        let mut out_desc = SecBufferDesc { ulVersion: SECBUFFER_VERSION, cBuffers: 1, pBuffers: &mut out_buf };
        let mut next = self.ctx.unwrap_or_default();
        let mut attrs = 0u32;
        let st: HRESULT = unsafe {
            InitializeSecurityContextW(Some(&self.cred), self.ctx.as_ref().map(|c| c as *const SecHandle), Some(self.target.as_ptr()), flags, 0, SECURITY_NATIVE_DREP, input.map(|_| &in_desc as *const SecBufferDesc), 0, Some(&mut next), Some(&mut out_desc), &mut attrs, None)
        };
        let out = if out_buf.pvBuffer.is_null() {
            vec![]
        } else {
            let v = unsafe { std::slice::from_raw_parts(out_buf.pvBuffer as *const u8, out_buf.cbBuffer as usize) }.to_vec();
            let _ = unsafe { FreeContextBuffer(out_buf.pvBuffer) };
            v
        };
        if st.0 == 0 || st.0 == SEC_I_CONTINUE_NEEDED {
            self.ctx = Some(next);
            return Ok((out, st.0 == SEC_I_CONTINUE_NEEDED));
        }
        Err(if st.0 as u32 == SEC_E_NO_AUTHENTICATING_AUTHORITY { Failure::Unreachable } else { Failure::AuthFailed })
    }

    fn ctx(&self) -> Result<&SecHandle, Failure> {
        self.ctx.as_ref().ok_or(Failure::Protocol("no context"))
    }

    /// Шифрование сообщения: (маркер-подпись, шифротекст) — порядок частей как в MS-WSMV.
    pub fn wrap(&mut self, msg: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Failure> {
        let ctx = *self.ctx()?;
        let mut sizes = SecPkgContext_Sizes::default();
        unsafe { QueryContextAttributesW(&ctx, SECPKG_ATTR_SIZES, (&mut sizes as *mut SecPkgContext_Sizes).cast()) }.map_err(|_| Failure::Protocol("sizes"))?;
        let mut tok = vec![0u8; sizes.cbSecurityTrailer as usize];
        let mut data = msg.to_vec();
        let mut bufs = [token(SECBUFFER_TOKEN, &mut tok), token(SECBUFFER_DATA, &mut data)];
        let desc = SecBufferDesc { ulVersion: SECBUFFER_VERSION, cBuffers: 2, pBuffers: bufs.as_mut_ptr() };
        if unsafe { EncryptMessage(&ctx, 0, &desc, 0) }.is_err() {
            return Err(Failure::Protocol("encrypt"));
        }
        let (tl, dl) = (bufs[0].cbBuffer as usize, bufs[1].cbBuffer as usize);
        tok.truncate(tl);
        data.truncate(dl);
        Ok((tok, data))
    }

    pub fn unwrap(&mut self, mut tok: Vec<u8>, mut data: Vec<u8>) -> Result<Vec<u8>, Failure> {
        let ctx = *self.ctx()?;
        let mut bufs = [token(SECBUFFER_TOKEN, &mut tok), token(SECBUFFER_DATA, &mut data)];
        let desc = SecBufferDesc { ulVersion: SECBUFFER_VERSION, cBuffers: 2, pBuffers: bufs.as_mut_ptr() };
        if unsafe { DecryptMessage(&ctx, &desc, 0, None) }.is_err() {
            return Err(Failure::Protocol("decrypt"));
        }
        let b = bufs[1];
        Ok(unsafe { std::slice::from_raw_parts(b.pvBuffer as *const u8, b.cbBuffer as usize) }.to_vec())
    }
}

impl Drop for Native {
    fn drop(&mut self) {
        unsafe {
            if let Some(c) = self.ctx.take() {
                let _ = DeleteSecurityContext(&c);
            }
            let _ = FreeCredentialsHandle(&self.cred);
        }
    }
}
