//! Los vectores grandes del borrador (apendice «Large Subtree Test
//! Vectors»): pruebas de inclusion y de consistencia sobre arboles de
//! `2^48-1`, `2^63-1` y `2^64-1` hojas. Nadie construye esos arboles; lo
//! que se prueba es que el VERIFICADOR los evalua sin desbordar.
//!
//! El JSON es plano (objetos con valores de cadena) y se lee a mano.

use mtc_core::hash::HashValue;
use mtc_core::subtree::{evaluate_inclusion_proof, verify_consistency_proof, Subtree};

/// Un lector minimo: `[{"K": "v", ...}, ...]` con valores de cadena y sin
/// escapes, que es todo lo que estos ficheros usan.
fn read_records(json: &str) -> Vec<Vec<(String, String)>> {
    let mut records = Vec::new();
    let mut current: Option<Vec<(String, String)>> = None;
    let mut pending_key: Option<String> = None;
    let mut chars = json.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '{' => current = Some(Vec::new()),
            '}' => records.push(current.take().expect("objeto abierto")),
            '"' => {
                let mut s = String::new();
                for c in chars.by_ref() {
                    if c == '"' {
                        break;
                    }
                    assert_ne!(c, '\\', "el lector no admite escapes");
                    s.push(c);
                }
                match pending_key.take() {
                    None => pending_key = Some(s),
                    Some(k) => current.as_mut().expect("dentro de un objeto").push((k, s)),
                }
            }
            _ => {}
        }
    }
    records
}

fn field<'a>(rec: &'a [(String, String)], key: &str) -> &'a str {
    &rec.iter().find(|(k, _)| k == key).unwrap_or_else(|| panic!("falta {key}")).1
}

fn base64(s: &str) -> Vec<u8> {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::new();
    let mut acc = 0u32;
    let mut bits = 0;
    for b in s.bytes() {
        if b == b'=' {
            break;
        }
        let v = TABLE.iter().position(|t| *t == b).expect("base64") as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    out
}

fn hash(s: &str) -> HashValue {
    base64(s).try_into().expect("32 bytes")
}

fn hashes(s: &str) -> Vec<HashValue> {
    base64(s).chunks_exact(32).map(|c| c.try_into().unwrap()).collect()
}

fn u64_field(rec: &[(String, String)], key: &str) -> u64 {
    field(rec, key).parse().expect("entero")
}

#[test]
fn large_inclusion_proofs() {
    let recs = read_records(include_str!("vectors/large_inclusion_proofs.json"));
    assert!(recs.len() >= 20, "{} vectores", recs.len());
    let mut sizes = std::collections::BTreeSet::new();
    for r in &recs {
        let st = Subtree { start: u64_field(r, "Start"), end: u64_field(r, "End") };
        let index = u64_field(r, "Index");
        let proof = hashes(field(r, "Proof"));
        let got = evaluate_inclusion_proof(&hash(field(r, "EntryHash")), st, index, &proof)
            .unwrap_or_else(|e| panic!("{index} en {st}: {e}"));
        assert_eq!(got, hash(field(r, "SubtreeHash")), "{index} en {st}");
        sizes.insert(st.end);
        // Recortada o alargada en un hash entero, no vale.
        if !proof.is_empty() {
            assert!(evaluate_inclusion_proof(&hash(field(r, "EntryHash")), st, index, &proof[..proof.len() - 1]).is_err());
        }
        let mut longer = proof.clone();
        longer.push([0; 32]);
        assert!(evaluate_inclusion_proof(&hash(field(r, "EntryHash")), st, index, &longer).is_err());
    }
    // Los tres tamanos que el apendice anuncia estan representados.
    assert!(sizes.iter().any(|e| *e > (1u64 << 47)), "2^48-1");
    assert!(sizes.iter().any(|e| *e > (1u64 << 62)), "2^63-1");
    assert!(sizes.iter().any(|e| *e > (1u64 << 63)), "2^64-1");
}

#[test]
fn large_consistency_proofs() {
    let recs = read_records(include_str!("vectors/large_consistency_proofs.json"));
    assert!(recs.len() >= 20, "{} vectores", recs.len());
    for r in &recs {
        let st = Subtree { start: u64_field(r, "Start"), end: u64_field(r, "End") };
        let n = u64_field(r, "TreeSize");
        let proof = hashes(field(r, "Proof"));
        let node = hash(field(r, "SubtreeHash"));
        let root = hash(field(r, "TreeHash"));
        verify_consistency_proof(n, st, &proof, &node, &root).unwrap_or_else(|e| panic!("{st} en {n}: {e}"));
        if !proof.is_empty() {
            assert!(verify_consistency_proof(n, st, &proof[..proof.len() - 1], &node, &root).is_err());
        }
        let mut longer = proof.clone();
        longer.push([0; 32]);
        assert!(verify_consistency_proof(n, st, &longer, &node, &root).is_err());
        let mut flipped = node;
        flipped[0] ^= 1;
        assert!(verify_consistency_proof(n, st, &proof, &flipped, &root).is_err());
        if !st.is_empty() {
            let mut flipped = root;
            flipped[31] ^= 1;
            assert!(verify_consistency_proof(n, st, &proof, &node, &flipped).is_err());
        }
    }
}
