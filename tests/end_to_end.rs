//! De la solicitud al certificado y del certificado a la parte que confia,
//! con ML-DSA-44 en la CA y en un testigo.
#![cfg(feature = "ml-dsa")]

use mtc_core::cosign::mldsa::{MlDsa44, MlDsaCosigner, MlDsaVerifier};
use mtc_core::der;
use mtc_core::guard::{is_fatal, IndexGuard, Reconciliation};

use mtc_core::proof::MtcCertificate;
use mtc_core::verify::{
    verify_certificate, Basis, CosignerEntry, RelyingPartyConfig, TrustedSubtree, VerifyError,
};
use mtc_core::{
    CaConfig, CertificateRequest, CertificationAuthority, MemoryGuard, Subtree, TrustAnchorId,
    Validity,
};

const NOW: u64 = 1_800_000_000;
const WEEK: u64 = 7 * 86_400;

fn toy_spki(seed: u8) -> Vec<u8> {
    let mut c = der::algorithm_identifier(&[1, 3, 101, 112]);
    c.extend(der::bit_string(&[seed; 32]));
    der::sequence(&c)
}

fn request(i: u8) -> CertificateRequest {
    CertificateRequest {
        subject: der::sequence(&[]),
        spki: toy_spki(i),
        validity: Validity {
            not_before: NOW - 60,
            not_after: NOW - 60 + WEEK,
        },
        extensions: Some(der::san_dns_extensions(&[&format!("host{i}.example.com")])),
        log_entry_extensions: vec![],
    }
}

struct World {
    ca: CertificationAuthority<MemoryGuard>,
    ca_id: TrustAnchorId,
    witness_id: TrustAnchorId,
    ca_key: Vec<u8>,
    witness_key: Vec<u8>,
}

fn world() -> World {
    let ca_id = TrustAnchorId::from_ascii("32473.1").unwrap();
    let witness_id = TrustAnchorId::from_ascii("32473.77").unwrap();
    let ca_signer = MlDsaCosigner::<MlDsa44>::from_seed(ca_id.clone(), [1u8; 32]);
    let witness = MlDsaCosigner::<MlDsa44>::from_seed(witness_id.clone(), [2u8; 32]);
    let ca_key = ca_signer.verifying_key_bytes();
    let witness_key = witness.verifying_key_bytes();
    let cfg = CaConfig {
        ca_id: ca_id.clone(),
        log_number: 1,
        max_cert_lifetime: WEEK,
    };
    let mut ca =
        CertificationAuthority::new(cfg, Box::new(ca_signer), MemoryGuard::default()).unwrap();
    ca.add_cosigner(Box::new(witness));
    World {
        ca,
        ca_id,
        witness_id,
        ca_key,
        witness_key,
    }
}

fn rp(w: &World, trusted: Vec<TrustedSubtree>) -> RelyingPartyConfig {
    let cosigners: Vec<CosignerEntry> = vec![
        (
            w.ca_id.clone(),
            Box::new(MlDsaVerifier::<MlDsa44>::from_bytes(&w.ca_key).unwrap()),
        ),
        (
            w.witness_id.clone(),
            Box::new(MlDsaVerifier::<MlDsa44>::from_bytes(&w.witness_key).unwrap()),
        ),
    ];
    RelyingPartyConfig {
        ca_id: w.ca_id.clone(),
        cosigners,
        required_cosigners: vec![w.ca_id.clone(), w.witness_id.clone()],
        trusted_subtrees: trusted,
        revoked_ranges: vec![],
    }
}

#[test]
fn standalone_certificates_verify_with_ca_and_witness_cosignatures() {
    let mut w = world();
    for i in 0..5 {
        assert_eq!(w.ca.submit(request(i)).unwrap(), i as u64);
    }
    assert_eq!(
        w.ca.standalone_certificate(0).err().map(|e| e.to_string()),
        Some("la entrada 0 aun no esta bajo un checkpoint".into())
    );

    let cp =
        w.ca.run_checkpoint_job(NOW)
            .unwrap()
            .expect("hay entradas nuevas");
    assert_eq!((cp.number, cp.tree_size), (1, 5));
    assert_eq!(cp.root, w.ca.log().root());
    let covered: Vec<Subtree> = cp.subtrees.iter().map(|s| s.subtree).collect();
    assert_eq!(
        covered,
        vec![Subtree { start: 0, end: 4 }, Subtree { start: 4, end: 5 }]
    );
    assert!(cp.subtrees.iter().all(|s| s.signatures.len() == 2));
    assert!(
        w.ca.run_checkpoint_job(NOW + 1).unwrap().is_none(),
        "sin entradas nuevas no hay checkpoint"
    );

    let cfg = rp(&w, vec![]);
    for i in 0..5u64 {
        let cert = w.ca.standalone_certificate(i).unwrap();
        let der = cert.to_der().unwrap();
        let v = verify_certificate(&der, &cfg, NOW).unwrap();
        assert_eq!((v.log_number, v.index, v.serial), (1, i, (1u64 << 48) | i));
        assert_eq!(
            v.basis,
            Basis::Cosignatures(vec![w.ca_id.clone(), w.witness_id.clone()])
        );
        assert_eq!(
            v.subtree,
            if i < 4 {
                Subtree { start: 0, end: 4 }
            } else {
                Subtree { start: 4, end: 5 }
            }
        );
        assert_eq!(MtcCertificate::from_der(&der).unwrap(), cert);
        // Dos firmas ML-DSA-44 dominan el tamano: el certificado standalone
        // es grande, el relativo a landmark (mas abajo) no.
        assert!(
            der.len() > 2 * 2420 && der.len() < 2 * 2420 + 600,
            "{}",
            der.len()
        );
    }

    // Manipular el SAN cambia la entrada, el hash esperado y, con el, la
    // cofirma de la CA deja de cuadrar.
    let cert = w.ca.standalone_certificate(2).unwrap();
    let mut tampered = cert.clone();
    let pos = tampered.tbs_certificate.len() - 3;
    tampered.tbs_certificate[pos] ^= 0x01;
    assert_eq!(
        verify_certificate(&tampered.to_der().unwrap(), &cfg, NOW),
        Err(VerifyError::BadCosignature(w.ca_id.clone()))
    );
    // Sin la cofirma del testigo, la politica no se cumple.
    let mut without_witness = cert.clone();
    without_witness
        .proof
        .signatures
        .retain(|s| s.cosigner_id == w.ca_id);
    assert_eq!(
        verify_certificate(&without_witness.to_der().unwrap(), &cfg, NOW),
        Err(VerifyError::MissingCosignature(w.witness_id.clone()))
    );
    // Un indice de otra entrada con esta prueba sube a otro hash.
    let mut other_index = cert.clone();
    other_index.proof.inclusion_proof = w.ca.log().inclusion_proof(cert.proof.subtree, 3).unwrap();
    assert_eq!(
        verify_certificate(&other_index.to_der().unwrap(), &cfg, NOW),
        Err(VerifyError::BadCosignature(w.ca_id.clone()))
    );
    // Revocado por rango, caducado, aun no valido, emisor desconocido.
    let der = cert.to_der().unwrap();
    let mut revoked = rp(&w, vec![]);
    revoked.revoked_ranges = vec![(1u64 << 48, (1u64 << 48) + 3)];
    assert_eq!(
        verify_certificate(&der, &revoked, NOW),
        Err(VerifyError::Revoked((1u64 << 48) | 2))
    );
    assert_eq!(
        verify_certificate(&der, &cfg, NOW + WEEK),
        Err(VerifyError::Expired)
    );
    assert_eq!(
        verify_certificate(&der, &cfg, NOW - 61),
        Err(VerifyError::NotYetValid)
    );
    let mut other_ca = rp(&w, vec![]);
    other_ca.ca_id = TrustAnchorId::from_ascii("32473.9").unwrap();
    assert_eq!(
        verify_certificate(&der, &other_ca, NOW),
        Err(VerifyError::UnknownIssuer)
    );
    let mut no_policy = rp(&w, vec![]);
    no_policy.required_cosigners.clear();
    assert_eq!(
        verify_certificate(&der, &no_policy, NOW),
        Err(VerifyError::NoCosignerPolicy)
    );
}

#[test]
fn landmark_relative_certificates_carry_no_signatures() {
    let mut w = world();
    for i in 0..5 {
        w.ca.submit(request(i)).unwrap();
    }
    w.ca.run_checkpoint_job(NOW).unwrap().unwrap();
    for i in 5..8 {
        w.ca.submit(request(i)).unwrap();
    }
    let cp = w.ca.run_checkpoint_job(NOW + 2).unwrap().unwrap();
    assert_eq!(cp.number, 2);
    let covered: Vec<Subtree> = cp.subtrees.iter().map(|s| s.subtree).collect();
    assert_eq!(
        covered,
        vec![Subtree { start: 5, end: 6 }, Subtree { start: 6, end: 8 }]
    );

    // Antes del landmark no hay certificado relativo.
    assert!(w.ca.landmark_relative_certificate(6).is_err());
    let l = w.ca.allocate_landmark(NOW + 3).unwrap().unwrap();
    assert_eq!((l.number, l.tree_size, l.expiry), (1, 8, NOW + 3 + WEEK));
    assert!(
        w.ca.allocate_landmark(NOW + 4).unwrap().is_none(),
        "el arbol no crecio"
    );
    assert_eq!(
        w.ca.landmarks().publish(NOW + 5),
        format!("1\n8 {}\n0 0\n", NOW + 3 + WEEK)
    );

    let trusted: Vec<TrustedSubtree> =
        w.ca.active_landmark_subtrees(NOW + 5)
            .unwrap()
            .into_iter()
            .map(|(_, subtree, hash)| TrustedSubtree {
                log_number: 1,
                subtree,
                hash,
            })
            .collect();
    assert_eq!(
        trusted.iter().map(|t| t.subtree).collect::<Vec<_>>(),
        vec![Subtree { start: 0, end: 4 }, Subtree { start: 4, end: 8 }]
    );

    let cert = w.ca.landmark_relative_certificate(6).unwrap();
    assert!(cert.proof.signatures.is_empty());
    assert_eq!(cert.proof.subtree, Subtree { start: 4, end: 8 });
    assert_eq!(cert.proof.inclusion_proof.len(), 2);
    let der = cert.to_der().unwrap();
    assert!(der.len() < 400, "{}", der.len());

    let updated = rp(&w, trusted.clone());
    let v = verify_certificate(&der, &updated, NOW + 5).unwrap();
    assert_eq!((v.index, v.basis), (6, Basis::TrustedSubtree));
    // Una parte que confia sin el landmark no puede aceptarlo: no hay firmas.
    let stale = rp(&w, vec![]);
    assert_eq!(
        verify_certificate(&der, &stale, NOW + 5),
        Err(VerifyError::MissingCosignature(w.ca_id.clone()))
    );
    // Y con un hash de landmark equivocado, tampoco.
    let mut wrong = trusted;
    wrong[1].hash[0] ^= 1;
    assert_eq!(
        verify_certificate(&der, &rp(&w, wrong), NOW + 5),
        Err(VerifyError::TrustedSubtreeMismatch)
    );
    // El standalone de la misma entrada sigue valiendo para ambas.
    let standalone = w.ca.standalone_certificate(6).unwrap().to_der().unwrap();
    assert!(verify_certificate(&standalone, &updated, NOW + 5).is_ok());
    assert!(verify_certificate(&standalone, &stale, NOW + 5).is_ok());
}

/// El guardian de `hbs-state`, de verdad y en disco: el numero de
/// checkpoint se persiste antes de firmar, y al reabrir se reconcilia.
#[test]
fn the_checkpoint_number_is_persisted_before_signing() {
    let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("guardian");
    let path = dir.join("checkpoint.bin");
    let _ = std::fs::remove_file(&path);
    let guard = match IndexGuard::open(&path) {
        Ok(g) => g,
        Err(e) => {
            // tmpfs u otro sistema donde fsync no persiste: el guardian se
            // niega, que es su trabajo; este test no puede medir ahi.
            eprintln!("guardian no disponible en {}: {e}", path.display());
            return;
        }
    };
    let ca_id = TrustAnchorId::from_ascii("32473.1").unwrap();
    let signer = MlDsaCosigner::<MlDsa44>::from_seed(ca_id.clone(), [3u8; 32]);
    let cfg = CaConfig {
        ca_id,
        log_number: 1,
        max_cert_lifetime: WEEK,
    };
    let mut ca = CertificationAuthority::new(cfg, Box::new(signer), guard).unwrap();
    ca.submit(request(1)).unwrap();
    let cp = ca.run_checkpoint_job(NOW).unwrap().unwrap();
    assert_eq!(cp.number, 1);
    assert_eq!(ca.guard().current(), 1);
    drop(ca);
    // Reabrir: el contador sobrevivio. Si el diario del log dice que se
    // publico el 1, en sincronia; si dice 0, huerfano (caso normal tras
    // una caida entre reservar y firmar); si dijera 2, fatal.
    let reopened = IndexGuard::open(&path).unwrap();
    assert_eq!(reopened.current(), 1);
    assert!(matches!(
        reopened.reconcile(1),
        Reconciliation::InSync { index: 1 }
    ));
    assert!(!is_fatal(&reopened.reconcile(0)));
    assert!(is_fatal(&reopened.reconcile(2)));
}
