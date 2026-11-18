//! Паритет парсеров Linux с Go (C52.02): тот же вход testdata/linux12 → тот же expected.json (эталон — Go).

use serde_json::{json, Value};
use ssagent::linuxparse as p;
use std::collections::HashMap;

fn read(name: &str) -> String {
    std::fs::read_to_string(format!("{}/testdata/linux12/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap()
}

#[test]
fn linux_parsers_match_go_vectors() {
    let dmi: HashMap<String, String> = serde_json::from_str(&read("dmi.json")).unwrap();
    let got = json!({
        "hardware": p::hardware(&read("cpuinfo"), &read("meminfo")),
        "packages": p::packages(&read("dpkg")),
        "accounts": p::accounts(&read("passwd"), &read("group")),
        "mounts": p::mounts(&read("mountinfo")),
        "tcp": p::sockets("tcp", &read("tcp"), false),
        "tcp6": p::sockets("tcp", &read("tcp6"), true),
        "udp": p::sockets("udp", &read("udp"), false),
        "routes": p::routes(&read("route")),
        "rpm": p::rpm_packages(&read("rpm")),
        "apk": p::apk_packages(&read("apk")),
        "services": p::systemd_services(&read("units"), &read("unitfiles")),
        "dmi": p::dmi(&dmi),
    });
    let want: Value = serde_json::from_str(&read("expected.json")).unwrap();
    for (k, v) in want.as_object().unwrap() {
        assert_eq!(&got[k], v, "section {k} differs from Go");
    }
    assert_eq!(got, want);
}
