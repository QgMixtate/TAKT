//! Утверждения сертификата SurveyScan (SPIFFE URI spiffe://surveyscan/...) — как pki.ClaimsFromCertificate в Go.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use x509_parser::prelude::*;

#[derive(Debug, Default, Clone, PartialEq)]
pub struct Claims {
    pub tenant: String,
    pub source: String,
    pub generation: String,
    pub kind: String,
    pub collector: String,
    pub center_key_id: String,
    pub center_public: Vec<u8>,
    pub key_id: String,
    pub signing_public: Vec<u8>,
}

pub fn valid_id(s: &str) -> bool {
    s.len() == 36 && s.bytes().enumerate().all(|(i, c)| if [8, 13, 18, 23].contains(&i) { c == b'-' } else { c.is_ascii_hexdigit() && !c.is_ascii_uppercase() })
}

pub fn from_der(der: &[u8]) -> Result<Claims, String> {
    let (_, cert) = X509Certificate::from_der(der).map_err(|_| "certificate")?;
    let mut uris = vec![];
    for ext in cert.extensions() {
        if let ParsedExtension::SubjectAlternativeName(san) = ext.parsed_extension() {
            for n in &san.general_names {
                if let GeneralName::URI(u) = n {
                    uris.push(u.to_string());
                }
            }
        }
    }
    if uris.len() != 3 && uris.len() != 4 {
        return Err("unauthorized".into());
    }
    let mut c = Claims::default();
    for u in uris {
        let path = u.strip_prefix("spiffe://surveyscan/").ok_or("unauthorized")?;
        if path.contains(['?', '#']) {
            return Err("unauthorized".into());
        }
        let p: Vec<&str> = path.split('/').collect();
        match p.as_slice() {
            ["tenant", t, "source", s, "generation", g] => (c.tenant, c.source, c.generation) = (t.to_string(), s.to_string(), g.to_string()),
            ["kind", k, "collector", col] => (c.kind, c.collector) = (k.to_string(), col.to_string()),
            ["center-result", id, key] => {
                let key = URL_SAFE_NO_PAD.decode(key).map_err(|_| "unauthorized")?;
                if !valid_id(id) || key.len() != 32 {
                    return Err("unauthorized".into());
                }
                (c.center_key_id, c.center_public) = (id.to_string(), key);
            }
            ["signing", id, key] => (c.key_id, c.signing_public) = (id.to_string(), URL_SAFE_NO_PAD.decode(key).map_err(|_| "unauthorized")?),
            _ => return Err("unauthorized".into()),
        }
    }
    if ![&c.tenant, &c.source, &c.generation, &c.key_id].iter().all(|x| valid_id(x)) || c.signing_public.len() != 32 {
        return Err("unauthorized".into());
    }
    Ok(c)
}
