//! Los vectores acumulados del borrador (apendice «Test Vectors»): para
//! todos los subarboles de todos los arboles hasta 130 hojas, un hash
//! rodante de las salidas de cada algoritmo: 712 hashes de subarbol,
//! 12.807 pruebas de inclusion, 42.893 pruebas de consistencia y 8.646
//! coberturas, 65.058 casos en total. Si uno solo difiere, el hash final no
//! cuadra.

use mtc_core::der::hex;
use mtc_core::hash::hash_leaf;
use mtc_core::proof::MtcProof;
use mtc_core::subtree::{
    consistency_proof, covering_subtrees, evaluate_inclusion_proof, inclusion_proof,
    is_valid_subtree, verify_consistency_proof, LeafHashes, Subtree, SubtreeError, TreeHashes,
};
use sha2::{Digest, Sha256};

const N: u64 = 130;

/// `d[i] = bytes([i])`, ya como hojas hasheadas.
fn tree() -> LeafHashes {
    LeafHashes((0..N).map(|i| hash_leaf(&[i as u8])).collect())
}

#[test]
fn subtree_hashes() {
    let t = tree();
    let mut h = Sha256::new();
    for end in 0..=N {
        for start in 0..=end {
            if is_valid_subtree(start, end) {
                h.update(format!(
                    "[{start}, {end}) {}\n",
                    hex(&t.range_hash(start, end))
                ));
            }
        }
    }
    assert_eq!(
        hex(&h.finalize()),
        "b82806ad4265bb151c1119c0f4db437bb4d1a1f887b3a7fba1cd4ebf552e3e81"
    );
}

#[test]
fn subtree_inclusion_proofs() {
    let t = tree();
    let mut h = Sha256::new();
    for end in 0..=N {
        for start in 0..=end {
            if !is_valid_subtree(start, end) {
                continue;
            }
            let st = Subtree { start, end };
            let subtree_hash = t.range_hash(start, end);
            for index in start..end {
                let proof = inclusion_proof(&t, st, index).unwrap();
                let mut line = format!("{index} [{start}, {end})");
                for p in &proof {
                    line.push(' ');
                    line.push_str(&hex(p));
                }
                line.push('\n');
                h.update(line);

                // El ejercicio del verificador: evaluar, y rechazar recortes y anadidos.
                assert_eq!(
                    evaluate_inclusion_proof(&t.0[index as usize], st, index, &proof).unwrap(),
                    subtree_hash
                );
                if !proof.is_empty() {
                    assert!(evaluate_inclusion_proof(
                        &t.0[index as usize],
                        st,
                        index,
                        &proof[..proof.len() - 1]
                    )
                    .is_err());
                }
                let mut longer = proof.clone();
                longer.push([0x5a; 32]);
                assert!(
                    evaluate_inclusion_proof(&t.0[index as usize], st, index, &longer).is_err()
                );
            }
        }
    }
    assert_eq!(
        hex(&h.finalize()),
        "ac2a8f989e44d99e399db448050ff5f19757df53cfb716aa81015d3955d8163f"
    );
}

#[test]
fn subtree_consistency_proofs() {
    let t = tree();
    let mut h = Sha256::new();
    for n in 0..=N {
        let root = t.range_hash(0, n);
        for end in 0..=n {
            for start in 0..=end {
                if !is_valid_subtree(start, end) {
                    continue;
                }
                let st = Subtree { start, end };
                let proof = consistency_proof(&t, n, st).unwrap();
                let mut line = format!("[{start}, {end}) {n}");
                for p in &proof {
                    line.push(' ');
                    line.push_str(&hex(p));
                }
                line.push('\n');
                h.update(line);

                // El ejercicio del verificador.
                let node = t.range_hash(start, end);
                verify_consistency_proof(n, st, &proof, &node, &root).unwrap();
                if !proof.is_empty() {
                    assert!(verify_consistency_proof(
                        n,
                        st,
                        &proof[..proof.len() - 1],
                        &node,
                        &root
                    )
                    .is_err());
                }
                let mut longer = proof.clone();
                longer.push([0x5a; 32]);
                assert!(verify_consistency_proof(n, st, &longer, &node, &root).is_err());
                let mut flipped = node;
                flipped[0] ^= 1;
                assert!(verify_consistency_proof(n, st, &proof, &flipped, &root).is_err());
                if start != end {
                    let mut flipped = root;
                    flipped[31] ^= 1;
                    assert!(verify_consistency_proof(n, st, &proof, &node, &flipped).is_err());
                }
            }
        }
    }
    assert_eq!(
        hex(&h.finalize()),
        "10fa99b37bf9bf9ffa26b412fbd98bd75363256d0b75d61bc4538b9c9c5a0a74"
    );
}

#[test]
fn efficient_covering_subtrees() {
    let mut h = Sha256::new();
    for end in 0..=N {
        for start in 0..=end {
            let (l, r) = covering_subtrees(start, end);
            assert!(is_valid_subtree(l.start, l.end) && is_valid_subtree(r.start, r.end));
            assert!(
                l.start <= start
                    && start <= l.end
                    && l.end == r.start
                    && r.start <= end
                    && end == r.end
            );
            h.update(format!(
                "[{}, {}) [{}, {})\n",
                l.start, l.end, r.start, r.end
            ));
        }
    }
    assert_eq!(
        hex(&h.finalize()),
        "7fd9c8b926e9d2b5cf831560e8ce295a5ef97ad5c5ede4ea0dea28a8c8fc8bb0"
    );
}

#[test]
fn large_subtree_validity() {
    for (start, end) in [
        (0, (1u64 << 47) + 1),
        (0, (1u64 << 48) - 1),
        (0, (1u64 << 62) + 1),
        (0, (1u64 << 63) - 1),
        (0, (1u64 << 63) + 1),
        (0, u64::MAX),
    ] {
        assert!(is_valid_subtree(start, end), "[{start}, {end})");
    }
    for (start, end) in [
        (1u64 << 46, (1u64 << 47) + 1),
        (1u64 << 46, (1u64 << 48) - 1),
        (1u64 << 61, (1u64 << 62) + 1),
        (1u64 << 61, (1u64 << 63) - 1),
        (1u64 << 62, (1u64 << 63) + 1),
        (1u64 << 62, u64::MAX),
    ] {
        assert!(!is_valid_subtree(start, end), "[{start}, {end})");
    }
}

/// `(start, end, izquierdo, derecho)`.
type CoveringCase = (u64, u64, (u64, u64), (u64, u64));

#[test]
fn large_covering_subtrees() {
    let cases: [CoveringCase; 15] = [
        (
            0x0,
            0x800000000000,
            (0x0, 0x400000000000),
            (0x400000000000, 0x800000000000),
        ),
        (
            0x500000000000,
            0xd00000000000,
            (0x400000000000, 0x800000000000),
            (0x800000000000, 0xd00000000000),
        ),
        (
            0x7fffffffffff,
            0x800000000001,
            (0x7fffffffffff, 0x800000000000),
            (0x800000000000, 0x800000000001),
        ),
        (
            0xfffffffffffe,
            0xffffffffffff,
            (0xfffffffffffe, 0xffffffffffff),
            (0xffffffffffff, 0xffffffffffff),
        ),
        (
            0xffffffffffff,
            0xffffffffffff,
            (0xffffffffffff, 0xffffffffffff),
            (0xffffffffffff, 0xffffffffffff),
        ),
        (
            0x0,
            0x4000000000000000,
            (0x0, 0x2000000000000000),
            (0x2000000000000000, 0x4000000000000000),
        ),
        (
            0x2800000000000000,
            0x6800000000000000,
            (0x2000000000000000, 0x4000000000000000),
            (0x4000000000000000, 0x6800000000000000),
        ),
        (
            0x3fffffffffffffff,
            0x4000000000000001,
            (0x3fffffffffffffff, 0x4000000000000000),
            (0x4000000000000000, 0x4000000000000001),
        ),
        (
            0x7ffffffffffffffe,
            0x7fffffffffffffff,
            (0x7ffffffffffffffe, 0x7fffffffffffffff),
            (0x7fffffffffffffff, 0x7fffffffffffffff),
        ),
        (
            0x7fffffffffffffff,
            0x7fffffffffffffff,
            (0x7fffffffffffffff, 0x7fffffffffffffff),
            (0x7fffffffffffffff, 0x7fffffffffffffff),
        ),
        (
            0x0,
            0x8000000000000000,
            (0x0, 0x4000000000000000),
            (0x4000000000000000, 0x8000000000000000),
        ),
        (
            0x5000000000000000,
            0xd000000000000000,
            (0x4000000000000000, 0x8000000000000000),
            (0x8000000000000000, 0xd000000000000000),
        ),
        (
            0x7fffffffffffffff,
            0x8000000000000001,
            (0x7fffffffffffffff, 0x8000000000000000),
            (0x8000000000000000, 0x8000000000000001),
        ),
        (
            0xfffffffffffffffe,
            0xffffffffffffffff,
            (0xfffffffffffffffe, 0xffffffffffffffff),
            (0xffffffffffffffff, 0xffffffffffffffff),
        ),
        (
            0xffffffffffffffff,
            0xffffffffffffffff,
            (0xffffffffffffffff, 0xffffffffffffffff),
            (0xffffffffffffffff, 0xffffffffffffffff),
        ),
    ];
    for (start, end, l, r) in cases {
        assert_eq!(
            covering_subtrees(start, end),
            (
                Subtree {
                    start: l.0,
                    end: l.1
                },
                Subtree {
                    start: r.0,
                    end: r.1
                }
            ),
            "[{start:#x}, {end:#x})"
        );
    }
}

/// Un `MTCProof` con un camino recortado o alargado **en un byte** no se
/// decodifica: es la variante «by one byte» del ejercicio del verificador,
/// que solo tiene sentido sobre la codificacion.
#[test]
fn a_proof_off_by_one_byte_does_not_decode() {
    let t = tree();
    let st = Subtree { start: 8, end: 13 };
    let proof = MtcProof {
        extensions: vec![],
        subtree: st,
        inclusion_proof: inclusion_proof(&t, st, 10).unwrap(),
        signatures: vec![],
    };
    let bytes = proof.encode().unwrap();
    assert_eq!(MtcProof::decode(&bytes).unwrap(), proof);
    // Recortar un byte del camino: la longitud declarada ya no cuadra.
    let mut short = bytes.clone();
    let path_len_pos = 2 + 6 + 6;
    let path_len = u16::from_be_bytes([short[path_len_pos], short[path_len_pos + 1]]);
    short[path_len_pos..path_len_pos + 2].copy_from_slice(&(path_len - 1).to_be_bytes());
    short.remove(path_len_pos + 2 + path_len as usize - 1);
    assert!(MtcProof::decode(&short).is_err());
    let mut long = bytes;
    long[path_len_pos..path_len_pos + 2].copy_from_slice(&(path_len + 1).to_be_bytes());
    long.insert(path_len_pos + 2 + path_len as usize, 0);
    assert!(MtcProof::decode(&long).is_err());
    // Y una prueba de otro indice sube a otro hash.
    let other = inclusion_proof(&t, st, 11).unwrap();
    assert_eq!(
        mtc_core::subtree::verify_inclusion_proof(&t.0[10], st, 10, &other, &t.range_hash(8, 13)),
        Err(SubtreeError::HashMismatch)
    );
}
