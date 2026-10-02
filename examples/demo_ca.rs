//! End to end, with numbers: a CA with ML-DSA-44 and a witness, eight
//! requests, two checkpoints, one landmark, and the two certificates of a
//! single entry -- standalone and landmark-relative -- verified by a relying
//! party that does NOT compile the CA (only `verify`).
//!
//!     cargo run --release --example demo_ca

use mtc_core::cosign::mldsa::{MlDsa44, MlDsaCosigner, MlDsaVerifier};
use mtc_core::der;
use mtc_core::verify::{verify_certificate, CosignerEntry, RelyingPartyConfig, TrustedSubtree};
use mtc_core::{
    CaConfig, CertificateRequest, CertificationAuthority, MemoryGuard, TrustAnchorId, Validity,
};

fn main() {
    let now = 1_800_000_000u64;
    let week = 7 * 86_400;

    // ── the CA and its witness ──
    let ca_id = TrustAnchorId::from_ascii("32473.1").unwrap();
    let witness_id = TrustAnchorId::from_ascii("32473.77").unwrap();
    let ca_signer = MlDsaCosigner::<MlDsa44>::from_seed(ca_id.clone(), [1u8; 32]);
    let witness = MlDsaCosigner::<MlDsa44>::from_seed(witness_id.clone(), [2u8; 32]);
    let (ca_key, witness_key) = (
        ca_signer.verifying_key_bytes(),
        witness.verifying_key_bytes(),
    );
    println!("CA's ML-DSA-44 public key: {} bytes", ca_key.len());

    // ⚠️ MemoryGuard does NOT persist: in production, `hbs_state::IndexGuard::open(path)`.
    // ML-DSA signatures are salted (the FIPS 204 recommended variant): two
    // runs yield different certificates that verify all the same.
    let cfg = CaConfig {
        ca_id: ca_id.clone(),
        log_number: 1,
        max_cert_lifetime: week,
        oids: mtc_core::OIDS_IANA,
    };
    let mut ca =
        CertificationAuthority::new(cfg, Box::new(ca_signer), MemoryGuard::default()).unwrap();
    ca.add_cosigner(Box::new(witness)).unwrap();

    // ── 1-3a · already-validated requests enter the log ──
    for i in 0..8u8 {
        let mut spki = der::algorithm_identifier(&[1, 3, 101, 112]); // a toy SPKI
        spki.extend(der::bit_string(&[i; 32]));
        let index = ca
            .submit(CertificateRequest {
                subject: der::sequence(&[]),
                spki: der::sequence(&spki),
                validity: Validity {
                    not_before: now - 60,
                    not_after: now - 60 + week,
                },
                extensions: Some(der::san_dns_extensions(&[&format!("host{i}.example.com")])),
                log_entry_extensions: vec![],
            })
            .unwrap();
        if index == 4 {
            // ── 3b-4 · the first checkpoint covers [0, 5) ──
            let cp = ca.run_checkpoint_job(now).unwrap().unwrap();
            println!(
                "checkpoint {} · tree_size {} · subtrees {:?}",
                cp.number,
                cp.tree_size,
                cp.subtrees
                    .iter()
                    .map(|s| s.subtree.to_string())
                    .collect::<Vec<_>>()
            );
        }
    }
    let cp = ca.run_checkpoint_job(now + 2).unwrap().unwrap();
    println!(
        "checkpoint {} · tree_size {} · subtrees {:?} · root {}",
        cp.number,
        cp.tree_size,
        cp.subtrees
            .iter()
            .map(|s| s.subtree.to_string())
            .collect::<Vec<_>>(),
        der::hex(&cp.root)
    );

    // ── 5 · the standalone certificate of entry 6 ──
    let standalone = ca.standalone_certificate(6).unwrap();
    let standalone_der = standalone.to_der().unwrap();
    println!(
        "standalone(6): subtree {} · {} hashes · {} cosignatures · {} DER bytes",
        standalone.proof.subtree,
        standalone.proof.inclusion_proof.len(),
        standalone.proof.signatures.len(),
        standalone_der.len()
    );

    // ── landmark and landmark-relative certificate ──
    let l = ca.allocate_landmark(now + 3).unwrap().unwrap();
    println!(
        "landmark {} · tree_size {} · expires {}",
        l.number, l.tree_size, l.expiry
    );
    let relative = ca.landmark_relative_certificate(6).unwrap();
    let relative_der = relative.to_der().unwrap();
    println!(
        "relative(6): subtree {} · {} hashes · {} cosignatures · {} DER bytes",
        relative.proof.subtree,
        relative.proof.inclusion_proof.len(),
        relative.proof.signatures.len(),
        relative_der.len()
    );
    print!("published landmarks:\n{}", ca.landmarks().publish(now + 5));

    // ── the relying party ──
    let cosigners: Vec<CosignerEntry> = vec![
        (
            ca_id.clone(),
            Box::new(MlDsaVerifier::<MlDsa44>::from_bytes(&ca_key).unwrap()),
        ),
        (
            witness_id.clone(),
            Box::new(MlDsaVerifier::<MlDsa44>::from_bytes(&witness_key).unwrap()),
        ),
    ];
    let trusted: Vec<TrustedSubtree> = ca
        .active_landmark_subtrees(now + 5)
        .unwrap()
        .into_iter()
        .map(|(_, subtree, hash)| TrustedSubtree {
            log_number: 1,
            subtree,
            hash,
        })
        .collect();
    let rp = RelyingPartyConfig {
        ca_id,
        cosigners,
        required_cosigners: vec![witness_id], // the CA's is always required
        trusted_subtrees: trusted,
        revoked_ranges: vec![],
    };
    let v = verify_certificate(&standalone_der, &rp, now + 5).unwrap();
    println!(
        "standalone verified: index {} · basis {:?}",
        v.index, v.basis
    );
    let v = verify_certificate(&relative_der, &rp, now + 5).unwrap();
    println!(
        "relative verified:   index {} · basis {:?}",
        v.index, v.basis
    );
}
