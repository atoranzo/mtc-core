//! De extremo a extremo, con cifras: una CA con ML-DSA-44 y un testigo,
//! ocho solicitudes, dos checkpoints, un landmark, y los dos certificados
//! de una misma entrada —standalone y relativo a landmark— verificados por
//! una parte que confia que NO compila la CA (solo `verify`).
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

    // ── la CA y su testigo ──
    let ca_id = TrustAnchorId::from_ascii("32473.1").unwrap();
    let witness_id = TrustAnchorId::from_ascii("32473.77").unwrap();
    let ca_signer = MlDsaCosigner::<MlDsa44>::from_seed(ca_id.clone(), [1u8; 32]);
    let witness = MlDsaCosigner::<MlDsa44>::from_seed(witness_id.clone(), [2u8; 32]);
    let (ca_key, witness_key) = (
        ca_signer.verifying_key_bytes(),
        witness.verifying_key_bytes(),
    );
    println!("clave publica ML-DSA-44 de la CA: {} bytes", ca_key.len());

    // ⚠️ MemoryGuard NO persiste: en produccion, `hbs_state::IndexGuard::open(ruta)`.
    // Las firmas ML-DSA llevan sal (variante recomendada de FIPS 204): dos
    // ejecuciones dan certificados distintos que verifican igual.
    let cfg = CaConfig {
        ca_id: ca_id.clone(),
        log_number: 1,
        max_cert_lifetime: week,
    };
    let mut ca =
        CertificationAuthority::new(cfg, Box::new(ca_signer), MemoryGuard::default()).unwrap();
    ca.add_cosigner(Box::new(witness)).unwrap();

    // ── 1-3a · solicitudes ya validadas entran en el log ──
    for i in 0..8u8 {
        let mut spki = der::algorithm_identifier(&[1, 3, 101, 112]); // un SPKI de juguete
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
            // ── 3b-4 · el primer checkpoint cubre [0, 5) ──
            let cp = ca.run_checkpoint_job(now).unwrap().unwrap();
            println!(
                "checkpoint {} · tree_size {} · subarboles {:?}",
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
        "checkpoint {} · tree_size {} · subarboles {:?} · raiz {}",
        cp.number,
        cp.tree_size,
        cp.subtrees
            .iter()
            .map(|s| s.subtree.to_string())
            .collect::<Vec<_>>(),
        der::hex(&cp.root)
    );

    // ── 5 · el certificado standalone de la entrada 6 ──
    let standalone = ca.standalone_certificate(6).unwrap();
    let standalone_der = standalone.to_der().unwrap();
    println!(
        "standalone(6): subarbol {} · {} hashes · {} cofirmas · {} bytes DER",
        standalone.proof.subtree,
        standalone.proof.inclusion_proof.len(),
        standalone.proof.signatures.len(),
        standalone_der.len()
    );

    // ── landmark y certificado relativo ──
    let l = ca.allocate_landmark(now + 3).unwrap().unwrap();
    println!(
        "landmark {} · tree_size {} · caduca {}",
        l.number, l.tree_size, l.expiry
    );
    let relative = ca.landmark_relative_certificate(6).unwrap();
    let relative_der = relative.to_der().unwrap();
    println!(
        "relativo(6): subarbol {} · {} hashes · {} cofirmas · {} bytes DER",
        relative.proof.subtree,
        relative.proof.inclusion_proof.len(),
        relative.proof.signatures.len(),
        relative_der.len()
    );
    print!("landmarks publicados:\n{}", ca.landmarks().publish(now + 5));

    // ── la parte que confia ──
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
        required_cosigners: vec![witness_id], // la de la CA se exige siempre
        trusted_subtrees: trusted,
        revoked_ranges: vec![],
    };
    let v = verify_certificate(&standalone_der, &rp, now + 5).unwrap();
    println!(
        "standalone verificado: indice {} · base {:?}",
        v.index, v.basis
    );
    let v = verify_certificate(&relative_der, &rp, now + 5).unwrap();
    println!(
        "relativo verificado:   indice {} · base {:?}",
        v.index, v.basis
    );
}
