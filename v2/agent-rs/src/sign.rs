//! Подписи источника: Ed25519 над «доменный префикс + каноническая форма», base64url без дополнения — как в Go.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey, Signature};
use sha2::{Digest, Sha256};

pub const OBSERVATION_DOMAIN: &[u8] = b"SURVEYSCAN-OBSERVATION-V1\n";

pub fn digest_hex(canonical: &[u8]) -> String {
    hex(&Sha256::digest(canonical))
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub fn sign(key: &SigningKey, domain: &[u8], canonical: &[u8]) -> String {
    let mut msg = Vec::with_capacity(domain.len() + canonical.len());
    msg.extend_from_slice(domain);
    msg.extend_from_slice(canonical);
    URL_SAFE_NO_PAD.encode(key.sign(&msg).to_bytes())
}

pub fn verify(public: &VerifyingKey, domain: &[u8], canonical: &[u8], signature: &str) -> bool {
    let Ok(raw) = URL_SAFE_NO_PAD.decode(signature) else { return false };
    let Ok(sig) = Signature::from_slice(&raw) else { return false };
    let mut msg = domain.to_vec();
    msg.extend_from_slice(canonical);
    public.verify(&msg, &sig).is_ok()
}

pub fn public_b64(key: &SigningKey) -> String {
    URL_SAFE_NO_PAD.encode(key.verifying_key().to_bytes())
}
