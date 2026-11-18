//! Паритет разбора WinRM с Go (C52.06): тот же вход → тот же expected.json; время сбора не сравнивается.

use serde_json::{json, Value};

#[test]
fn winrm_parse_matches_go_vectors() {
    let dir = format!("{}/testdata/winrm", env!("CARGO_MANIFEST_DIR"));
    let mut got = serde_json::Map::new();
    for name in ["full", "errors", "fatal"] {
        let raw = std::fs::read(format!("{dir}/{name}.json")).unwrap();
        let v = match ssagent::winrmparse::parse(&raw, "2026-01-01T00:00:00Z") {
            Err(_) => json!({"error": true}),
            Ok((secs, cands)) => json!({"sections": secs.iter().map(|s| json!({"name": s["name"], "status": s["status"], "reason_code": s["reason_code"], "record_count": s["record_count"], "records": s["records"]})).collect::<Vec<_>>(), "candidates": cands}),
        };
        got.insert(name.into(), v);
    }
    let want: Value = serde_json::from_str(&std::fs::read_to_string(format!("{dir}/expected.json")).unwrap()).unwrap();
    for (k, v) in want.as_object().unwrap() {
        assert_eq!(&got[k], v, "{k} differs from Go");
    }
}
