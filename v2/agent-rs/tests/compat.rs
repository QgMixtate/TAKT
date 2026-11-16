//! Совместимость с Go: каноническая форма всех эталонов C03 и подпись наблюдения из фикстуры C03-F01.

use std::fs;

#[test]
fn canonical_matches_go() {
    let mut n = 0;
    for entry in fs::read_dir("testdata/canonical").unwrap() {
        let p = entry.unwrap().path();
        if p.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let input = fs::read(&p).unwrap();
        let want = fs::read(p.with_extension("canon")).unwrap();
        let got = ssagent::canonical::canonical(&input).unwrap();
        assert_eq!(String::from_utf8_lossy(&got), String::from_utf8_lossy(&want), "{}", p.display());
        n += 1;
    }
    assert!(n >= 50, "vectors: {n}");
}

#[test]
fn observation_signature_roundtrip() {
    use ed25519_dalek::SigningKey;
    let key = SigningKey::from_bytes(&[7u8; 32]);
    let canon = br#"{"a":1}"#;
    let sig = ssagent::sign::sign(&key, ssagent::sign::OBSERVATION_DOMAIN, canon);
    assert!(ssagent::sign::verify(&key.verifying_key(), ssagent::sign::OBSERVATION_DOMAIN, canon, &sig));
    assert!(!ssagent::sign::verify(&key.verifying_key(), b"OTHER\n", canon, &sig));
    // digest — sha256 канонической формы (как digest в фикстуре C03-F01)
    let f: serde_json::Value = serde_json::from_slice(&fs::read("testdata/canonical/C03-F01.json").unwrap()).unwrap();
    let payload = ssagent::canonical::canonical_value(&f["payload"]).unwrap();
    assert_eq!(ssagent::sign::digest_hex(&payload), f["digest"].as_str().unwrap());
}

/// Детерминированная подготовка (фиксированные ключи и машина) для проверки на стороне Go:
/// v2/internal/agent/rust_state_test.go читает testdata/state и проверяет CSR, ключ, привязку.
#[test]
fn preparation_fixture_for_go() {
    use ed25519_dalek::SigningKey;
    use ssagent::state::*;
    let tls = SigningKey::from_bytes(&[3u8; 32]);
    let signing = SigningKey::from_bytes(&[5u8; 32]);
    let source = "11111111-2222-4333-8444-555555555555";
    let machine = "0123456789abcdef0123456789abcdef";
    let prep = preparation_from(source, &tls, &signing);
    let dir = std::path::Path::new("testdata/state");
    std::fs::create_dir_all(dir).unwrap();
    let want = serde_json::to_vec(&prep).unwrap();
    let files: Vec<(&str, Vec<u8>)> = vec![
        ("preparation.json", want),
        // закрытые ключи в репозиторий не кладём — только SHA-256 их PEM (Go сверяет со своим PEM тех же затравок)
        ("keys.sha256", format!("{}\n{}\n", ssagent::sign::digest_hex(key_pem(&signing).as_bytes()), ssagent::sign::digest_hex(key_pem(&tls).as_bytes())).into_bytes()),
        ("host-binding.json", serde_json::to_vec(&binding(source, machine, &signing)).unwrap()),
    ];
    for (name, body) in files {
        let path = dir.join(name);
        // эталон закоммичен: тест падает, если формат разошёлся (обновить — удалить файл и перезапустить)
        match std::fs::read(&path) {
            Ok(old) => assert_eq!(old, body, "{name} changed"),
            Err(_) => std::fs::write(&path, body).unwrap(),
        }
    }
    assert_eq!(ssagent::machineid::normalize("01234567-89AB-CDEF-0123-456789ABCDEF").unwrap(), machine);
    assert!(ssagent::machineid::normalize(&"0".repeat(32)).is_none());
    // повторная подготовка в каталоге: привязка проверяется
    let tmp = std::env::temp_dir().join(format!("ssagent-{}", ssagent::state::new_id()));
    let a = prepare(&tmp, machine).unwrap();
    assert_eq!(prepare(&tmp, machine).unwrap(), a);
    assert!(prepare(&tmp, "fedcba9876543210fedcba9876543210").is_err());
    std::fs::remove_dir_all(&tmp).unwrap();
}
