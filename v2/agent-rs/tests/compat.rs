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
