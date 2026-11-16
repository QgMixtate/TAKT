//! Каноническая форма JSON (RFC 8785, JCS) — побайтно как `wire.Canonical` в Go (testdata/canonical: вход и
//! эталон, полученный Go-реализацией). Числа по RFC 8785 — IEEE 754 double: целые за пределами 2^53 округляются.

use serde_json::{Number, Value};

/// Каноническая форма произвольного JSON-документа.
pub fn canonical(raw: &[u8]) -> Result<Vec<u8>, String> {
    let v: Value = serde_json::from_slice(raw).map_err(|e| e.to_string())?;
    canonical_value(&v)
}

pub fn canonical_value(v: &Value) -> Result<Vec<u8>, String> {
    serde_jcs::to_vec(&as_double(v)).map_err(|e| e.to_string())
}

const EXACT: u64 = 1 << 53;

fn as_double(v: &Value) -> Value {
    match v {
        Value::Number(n) => {
            let big = n.as_u64().map(|x| x > EXACT).or_else(|| n.as_i64().map(|x| x.unsigned_abs() > EXACT)).unwrap_or(false);
            if big {
                n.as_f64().and_then(Number::from_f64).map(Value::Number).unwrap_or(Value::Null)
            } else {
                v.clone()
            }
        }
        Value::Array(a) => Value::Array(a.iter().map(as_double).collect()),
        Value::Object(o) => Value::Object(o.iter().map(|(k, x)| (k.clone(), as_double(x))).collect()),
        _ => v.clone(),
    }
}
