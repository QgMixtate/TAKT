//! Минимальный DER для запроса сертификата (CSR) с ключом Ed25519 — без тяжёлых зависимостей.

fn len(n: usize) -> Vec<u8> {
    if n < 0x80 {
        vec![n as u8]
    } else {
        let b = n.to_be_bytes();
        let skip = b.iter().take_while(|x| **x == 0).count();
        let mut out = vec![0x80 | (b.len() - skip) as u8];
        out.extend_from_slice(&b[skip..]);
        out
    }
}

pub fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend(len(body.len()));
    out.extend_from_slice(body);
    out
}

pub fn seq(parts: &[Vec<u8>]) -> Vec<u8> {
    tlv(0x30, &parts.concat())
}

const ED25519_OID: [u8; 5] = [0x06, 0x03, 0x2b, 0x65, 0x70]; // 1.3.101.112
const CN_OID: [u8; 5] = [0x06, 0x03, 0x55, 0x04, 0x03]; // 2.5.4.3

/// CSR PKCS#10 c субъектом CN=`common_name` и открытым ключом Ed25519, подписанный `sign`.
pub fn csr_ed25519(common_name: &str, public: &[u8; 32], sign: impl Fn(&[u8]) -> [u8; 64]) -> Vec<u8> {
    let alg = seq(&[ED25519_OID.to_vec()]);
    let rdn = tlv(0x31, &seq(&[CN_OID.to_vec(), tlv(0x0c, common_name.as_bytes())]));
    let name = seq(&[rdn]);
    let mut bits = vec![0u8];
    bits.extend_from_slice(public);
    let spki = seq(&[alg.clone(), tlv(0x03, &bits)]);
    let info = seq(&[tlv(0x02, &[0]), name, spki, tlv(0xa0, &[])]);
    let mut sig = vec![0u8];
    sig.extend_from_slice(&sign(&info));
    seq(&[info, alg, tlv(0x03, &sig)])
}
