//! From the request to the certificate and from the certificate to the
//! relying party, with ML-DSA-44 at the CA and at a witness.
#![cfg(feature = "ml-dsa")]

use mtc_core::ca::CaError;
use mtc_core::cosign::mldsa::{MlDsa44, MlDsaCosigner, MlDsaVerifier};
use mtc_core::cosign::SubtreeSignature;
use mtc_core::der;
use mtc_core::guard::{is_fatal, GuardError, IndexGuard, Reconciliation};
use mtc_core::tai::TaiError;

use mtc_core::proof::MtcCertificate;
use mtc_core::verify::{
    verify_certificate, Basis, CosignerEntry, RelyingPartyConfig, TrustedSubtree, VerifyError,
};
use mtc_core::{
    CaConfig, CertificateRequest, CertificationAuthority, MemoryGuard, OidSet, Subtree,
    TrustAnchorId, Validity, OIDS_EXPERIMENTAL_06, OIDS_IANA,
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
    oids: OidSet,
}

fn world() -> World {
    world_with(mtc_core::OIDS_IANA)
}

fn world_with(oids: OidSet) -> World {
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
        oids,
    };
    let mut ca =
        CertificationAuthority::new(cfg, Box::new(ca_signer), MemoryGuard::default()).unwrap();
    ca.add_cosigner(Box::new(witness)).unwrap();
    World {
        ca,
        ca_id,
        witness_id,
        ca_key,
        witness_key,
        oids,
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
        ca_oids: w.oids,
        cosigners,
        required_cosigners: vec![w.witness_id.clone()],
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
        Some("entry 0 is not yet under a checkpoint".into())
    );

    let cp =
        w.ca.run_checkpoint_job(NOW)
            .unwrap()
            .expect("there are new entries");
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
        "no new entries, no checkpoint"
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
        // Two ML-DSA-44 signatures dominate the size: the standalone
        // certificate is large, the landmark-relative one (below) is not.
        assert!(
            der.len() > 2 * 2420 && der.len() < 2 * 2420 + 600,
            "{}",
            der.len()
        );
    }

    // Tampering with the SAN changes the entry, the expected hash and, with
    // it, the CA's cosignature no longer matches.
    let cert = w.ca.standalone_certificate(2).unwrap();
    let mut tampered = cert.clone();
    let pos = tampered.tbs_certificate.len() - 3;
    tampered.tbs_certificate[pos] ^= 0x01;
    assert_eq!(
        verify_certificate(&tampered.to_der().unwrap(), &cfg, NOW),
        Err(VerifyError::BadCosignature(w.ca_id.clone()))
    );
    // Without the witness's cosignature, the policy is not met.
    let mut without_witness = cert.clone();
    without_witness
        .proof
        .signatures
        .retain(|s| s.cosigner_id == w.ca_id);
    assert_eq!(
        verify_certificate(&without_witness.to_der().unwrap(), &cfg, NOW),
        Err(VerifyError::MissingCosignature(w.witness_id.clone()))
    );
    // Another entry's index with this proof climbs to a different hash.
    let mut other_index = cert.clone();
    other_index.proof.inclusion_proof = w.ca.log().inclusion_proof(cert.proof.subtree, 3).unwrap();
    assert_eq!(
        verify_certificate(&other_index.to_der().unwrap(), &cfg, NOW),
        Err(VerifyError::BadCosignature(w.ca_id.clone()))
    );
    // Revoked by range, expired, not yet valid, unknown issuer.
    let der = cert.to_der().unwrap();
    let mut revoked = rp(&w, vec![]);
    revoked.revoked_ranges = vec![(1u64 << 48, (1u64 << 48) + 2)]; // inclusive: reaches 2
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
    // The CA's cosignature is ALWAYS required, even if the policy does not
    // list it; and without it there is no certificate, whatever witnesses it has.
    let mut only_ca = rp(&w, vec![]);
    only_ca.required_cosigners.clear();
    let v = verify_certificate(&der, &only_ca, NOW).unwrap();
    assert_eq!(v.basis, Basis::Cosignatures(vec![w.ca_id.clone()]));
    let mut without_ca = cert.clone();
    without_ca
        .proof
        .signatures
        .retain(|s| s.cosigner_id != w.ca_id);
    assert_eq!(
        verify_certificate(&without_ca.to_der().unwrap(), &only_ca, NOW),
        Err(VerifyError::MissingCosignature(w.ca_id.clone()))
    );
    // A cosignature from an unknown ID (GREASE) is ignored, not invalidating.
    let mut greased = cert.clone();
    greased.proof.signatures.push(mtc_core::SubtreeSignature {
        cosigner_id: TrustAnchorId::from_binary(&[0x8f, 0xff, 0x7f]).unwrap(),
        signature: vec![0xee; 7],
    });
    greased
        .proof
        .signatures
        .sort_by(|a, b| a.cosigner_id.cmp(&b.cosigner_id));
    assert!(verify_certificate(&greased.to_der().unwrap(), &cfg, NOW).is_ok());
}

/// `cert` with the `id-alg-mtcProof` of `oids` in both signature fields and
/// everything else, the issuer included, untouched: the shape of OpenSSL's
/// `test/mtc/mtc-landmark-1-iana-alg.pem` (AUDIT.md §19).
fn with_signature_algorithm(cert: &MtcCertificate, oids: OidSet) -> Vec<u8> {
    let (tbs, _) = der::read_tlv(&cert.tbs_certificate).unwrap();
    let old = der::alg_id_mtc_proof(&cert.oids);
    let at: Vec<usize> = (0..tbs.content.len())
        .filter(|&i| tbs.content[i..].starts_with(&old))
        .collect();
    assert_eq!(at.len(), 1, "the TBS names its algorithm once");
    let mut content = tbs.content[..at[0]].to_vec();
    content.extend(der::alg_id_mtc_proof(&oids));
    content.extend(&tbs.content[at[0] + old.len()..]);
    MtcCertificate {
        tbs_certificate: der::sequence(&content),
        oids,
        ..cert.clone()
    }
    .to_der()
    .unwrap()
}

/// One OID set per certificate, kept by the author's decision (AUDIT.md
/// §22) and in line with the draft's principal author's answer on the list,
/// one CA, one draft, one set of OIDs (§24): a certificate whose signature
/// algorithm names one set and whose
/// issuer uses the other's attribute is refused, in both directions. OpenSSL
/// and Bob Beck's `mtc` accept it field by field. What fails is the issuer,
/// not the proof: the log entry omits the signature algorithm.
#[test]
fn a_certificate_that_mixes_oid_sets_is_refused() {
    for (issued, named) in [
        (OIDS_EXPERIMENTAL_06, OIDS_IANA),
        (OIDS_IANA, OIDS_EXPERIMENTAL_06),
    ] {
        let mut w = world_with(issued);
        w.ca.submit(request(0)).unwrap();
        w.ca.run_checkpoint_job(NOW).unwrap();
        let cfg = rp(&w, vec![]);
        let cert = w.ca.standalone_certificate(0).unwrap();
        let v = verify_certificate(&cert.to_der().unwrap(), &cfg, NOW).unwrap();
        assert_eq!(v.oids, issued);

        let mixed = with_signature_algorithm(&cert, named);
        let parsed = MtcCertificate::from_der(&mixed).unwrap();
        assert_eq!(parsed.oids, named);
        assert_eq!(parsed.proof, cert.proof);
        assert_eq!(
            verify_certificate(&mixed, &cfg, NOW),
            Err(VerifyError::UnknownIssuer)
        );
        // Under a CA of the set the algorithm names, the CA's name attribute
        // matches the set's (§25) and only the rule of §22 refuses it: the
        // issuer's attribute is not the one the algorithm names.
        let under_named = RelyingPartyConfig {
            ca_oids: named,
            ..rp(&w, vec![])
        };
        assert_eq!(
            verify_certificate(&mixed, &under_named, NOW),
            Err(VerifyError::UnknownIssuer),
            "{} algorithm, {} issuer",
            named.name,
            issued.name
        );
    }
}

/// One OID family per CA (AUDIT.md §25), a family being the sets whose names
/// use the same trust anchor ID attribute: a relying party configured for a
/// CA of one family refuses a certificate of the other family under the same
/// CA ID, although its proof and cosignatures are good; path validation
/// chains names, and a name includes its attribute's type. Since the
/// interim set was retired (§26), each family is one set.
#[test]
fn a_certificate_of_another_family_is_refused_under_the_same_ca_id() {
    for (issued, configured, accepted) in [
        (OIDS_EXPERIMENTAL_06, OIDS_IANA, false),
        (OIDS_IANA, OIDS_EXPERIMENTAL_06, false),
        (OIDS_EXPERIMENTAL_06, OIDS_EXPERIMENTAL_06, true),
        (OIDS_IANA, OIDS_IANA, true),
    ] {
        let mut w = world_with(issued);
        w.ca.submit(request(0)).unwrap();
        w.ca.run_checkpoint_job(NOW).unwrap();
        let der = w.ca.standalone_certificate(0).unwrap().to_der().unwrap();
        let cfg = RelyingPartyConfig {
            ca_oids: configured,
            ..rp(&w, vec![])
        };
        let got = verify_certificate(&der, &cfg, NOW);
        if accepted {
            assert_eq!(
                got.unwrap().oids,
                issued,
                "{} under {}",
                issued.name,
                configured.name
            );
        } else {
            assert_eq!(
                got,
                Err(VerifyError::UnknownIssuer),
                "{} under {}",
                issued.name,
                configured.name
            );
        }
    }
}

/// Trust anchor IDs are at most 32 bytes (AUDIT.md §27,
/// draft-ietf-tls-trust-anchor-ids-06): a CA refuses a CA ID, a log ID or a
/// cosigner ID that is longer. A relying party still reads an `MTCProof`
/// whose cosigner IDs are longer, as the wire allows: such an ID matches no
/// configured cosigner, and its cosignature is ignored.
#[test]
fn trust_anchor_ids_longer_than_32_bytes_are_refused_where_configured() {
    let id = |n: usize| TrustAnchorId::from_binary(&vec![1; n]).unwrap();
    let ca_with = |ca_id: TrustAnchorId| {
        let cfg = CaConfig {
            ca_id: ca_id.clone(),
            log_number: 1,
            max_cert_lifetime: WEEK,
            oids: OIDS_IANA,
        };
        let signer = MlDsaCosigner::<MlDsa44>::from_seed(ca_id, [1u8; 32]);
        CertificationAuthority::new(cfg, Box::new(signer), MemoryGuard::default())
    };
    // A CA ID of 33 bytes is not a trust anchor ID; one of 31 is, but its
    // log 1, `{caID 0 1}`, would be 33 bytes.
    assert!(matches!(
        ca_with(id(33)).err(),
        Some(CaError::Tai(TaiError::TooLongForTrustAnchor(33)))
    ));
    assert!(matches!(
        ca_with(id(31)).err(),
        Some(CaError::Tai(TaiError::TooLongForTrustAnchor(33)))
    ));
    let mut ca = ca_with(id(30)).unwrap();
    // A cosigner of 33 bytes is refused; one of 32 is accepted.
    let witness = |n: usize| MlDsaCosigner::<MlDsa44>::from_seed(id(n), [2u8; 32]);
    assert!(matches!(
        ca.add_cosigner(Box::new(witness(33))),
        Err(CaError::Tai(TaiError::TooLongForTrustAnchor(33)))
    ));
    ca.add_cosigner(Box::new(witness(32))).unwrap();

    // An unrecognized cosigner of 40 bytes in a certificate: read, ignored.
    let mut w = world();
    w.ca.submit(request(0)).unwrap();
    w.ca.run_checkpoint_job(NOW).unwrap();
    let mut cert = w.ca.standalone_certificate(0).unwrap();
    cert.proof.signatures.push(SubtreeSignature {
        cosigner_id: id(40),
        signature: vec![0; 16],
    });
    let der = cert.to_der().unwrap();
    assert_eq!(
        MtcCertificate::from_der(&der)
            .unwrap()
            .proof
            .signatures
            .last()
            .unwrap()
            .cosigner_id,
        id(40)
    );
    let v = verify_certificate(&der, &rp(&w, vec![]), NOW).unwrap();
    assert_eq!(
        v.basis,
        Basis::Cosignatures(vec![w.ca_id.clone(), w.witness_id.clone()])
    );

    // A relying party configured with an ID of 33 bytes, as the CA's, as a
    // recognized cosigner's or as a required one's, verifies nothing.
    let too_long = |cfg: RelyingPartyConfig| {
        matches!(
            verify_certificate(&der, &cfg, NOW),
            Err(VerifyError::Tai(TaiError::TooLongForTrustAnchor(33)))
        )
    };
    assert!(too_long(RelyingPartyConfig {
        ca_id: id(33),
        ..rp(&w, vec![])
    }));
    let mut cfg = rp(&w, vec![]);
    cfg.cosigners.push((
        id(33),
        Box::new(MlDsaVerifier::<MlDsa44>::from_bytes(&w.witness_key).unwrap()),
    ));
    assert!(too_long(cfg));
    let mut cfg = rp(&w, vec![]);
    cfg.required_cosigners.push(id(33));
    assert!(too_long(cfg));
    // At 32 bytes the recognized cosigner is merely absent from this
    // certificate, and the policy that requires it is not met.
    let mut cfg = rp(&w, vec![]);
    cfg.cosigners.push((
        id(32),
        Box::new(MlDsaVerifier::<MlDsa44>::from_bytes(&w.witness_key).unwrap()),
    ));
    verify_certificate(&der, &cfg, NOW).unwrap();
    cfg.required_cosigners.push(id(32));
    assert!(verify_certificate(&der, &cfg, NOW).is_err());
}

/// A landmark whose ID, or its group's, would be longer than 32 bytes is
/// not allocated (AUDIT.md §27).
#[test]
fn a_landmark_whose_id_would_exceed_32_bytes_is_not_allocated() {
    let id = |n: usize| TrustAnchorId::from_binary(&vec![1; n]).unwrap();
    let ca_with = |ca_id: TrustAnchorId| {
        let cfg = CaConfig {
            ca_id: ca_id.clone(),
            log_number: 1,
            max_cert_lifetime: WEEK,
            oids: OIDS_IANA,
        };
        let signer = MlDsaCosigner::<MlDsa44>::from_seed(ca_id, [1u8; 32]);
        let mut ca =
            CertificationAuthority::new(cfg, Box::new(signer), MemoryGuard::default()).unwrap();
        ca.submit(request(0)).unwrap();
        ca.run_checkpoint_job(NOW).unwrap().unwrap();
        ca
    };
    // 30 bytes: log 1 is `{caID 0 1}`, 32 bytes; landmark 1, `{caID 1 1 1}`,
    // would be 33.
    let mut ca = ca_with(id(30));
    assert!(matches!(
        ca.allocate_landmark(NOW),
        Err(CaError::Tai(TaiError::TooLongForTrustAnchor(33)))
    ));
    assert_eq!(ca.landmarks().latest().number, 0, "nothing allocated");
    // 29 bytes: landmark 1 is 32.
    let mut ca = ca_with(id(29));
    assert_eq!(ca.allocate_landmark(NOW).unwrap().unwrap().number, 1);
}

/// What the CA checks on the way in: validity, DER form, entry extensions;
/// and what it does not accept when configured: misplaced cosigner IDs.
#[test]
fn the_ca_refuses_what_it_could_not_certify() {
    let mut w = world();
    let bad_validity = CertificateRequest {
        validity: Validity {
            not_before: NOW,
            not_after: NOW + WEEK + 1,
        },
        ..request(1)
    };
    assert!(matches!(
        w.ca.submit(bad_validity),
        Err(CaError::InvalidValidity { .. })
    ));
    let inverted = CertificateRequest {
        validity: Validity {
            not_before: NOW + 1,
            not_after: NOW,
        },
        ..request(1)
    };
    assert!(matches!(
        w.ca.submit(inverted),
        Err(CaError::InvalidValidity { .. })
    ));
    let bad_subject = CertificateRequest {
        subject: vec![0x04, 0x00],
        ..request(1)
    };
    assert!(matches!(
        w.ca.submit(bad_subject),
        Err(CaError::InvalidDer {
            field: "subject",
            ..
        })
    ));
    let bad_spki = CertificateRequest {
        spki: vec![0x30, 0x00],
        ..request(1)
    };
    assert!(matches!(
        w.ca.submit(bad_spki),
        Err(CaError::InvalidDer { field: "spki", .. })
    ));
    let bad_ext = CertificateRequest {
        extensions: Some(vec![0x30, 0x00, 0x00]),
        ..request(1)
    };
    assert!(matches!(
        w.ca.submit(bad_ext),
        Err(CaError::InvalidDer {
            field: "extensions",
            ..
        })
    ));
    let unknown_ext = CertificateRequest {
        log_entry_extensions: vec![mtc_core::LogEntryExtension {
            extension_type: 1,
            extension_data: vec![],
        }],
        ..request(1)
    };
    assert!(matches!(
        w.ca.submit(unknown_ext),
        Err(CaError::Entry(
            mtc_core::entry::EntryError::UnknownExtension(1)
        ))
    ));
    assert_eq!(w.ca.log().size(), 0, "none of that entered the log");

    // An external cosigner with the CA's ID, or a repeated one, is not accepted.
    let dup = MlDsaCosigner::<MlDsa44>::from_seed(w.ca_id.clone(), [9u8; 32]);
    assert!(matches!(
        w.ca.add_cosigner(Box::new(dup)),
        Err(CaError::DuplicateCosigner(_))
    ));
    let again = MlDsaCosigner::<MlDsa44>::from_seed(w.witness_id.clone(), [9u8; 32]);
    assert!(matches!(
        w.ca.add_cosigner(Box::new(again)),
        Err(CaError::DuplicateCosigner(_))
    ));
    // And a CA whose cosigner does not carry its ID does not start.
    let other = MlDsaCosigner::<MlDsa44>::from_seed(
        TrustAnchorId::from_ascii("32473.2").unwrap(),
        [9u8; 32],
    );
    let cfg = CaConfig {
        ca_id: w.ca_id.clone(),
        log_number: 1,
        max_cert_lifetime: WEEK,
        oids: mtc_core::OIDS_IANA,
    };
    assert!(matches!(
        CertificationAuthority::new(cfg, Box::new(other), MemoryGuard::default()),
        Err(CaError::CosignerIdMismatch { .. })
    ));
}

/// A landmark's expiry covers the largest `notAfter` of what lies beneath
/// it, even if it is later than `now + max lifetime`.
#[test]
fn a_landmark_never_expires_before_the_entries_it_covers() {
    let mut w = world();
    w.ca.submit(request(1)).unwrap();
    // A validity that starts in three days and lasts a week.
    let future = CertificateRequest {
        validity: Validity {
            not_before: NOW + 3 * 86_400,
            not_after: NOW + 10 * 86_400,
        },
        ..request(2)
    };
    w.ca.submit(future).unwrap();
    w.ca.run_checkpoint_job(NOW).unwrap().unwrap();
    let l = w.ca.allocate_landmark(NOW).unwrap().unwrap();
    assert_eq!(l.expiry, NOW + 10 * 86_400, "not NOW + WEEK");
    assert!(w.ca.landmarks().active(NOW + 9 * 86_400).next().is_some());
    // Prune the signed subtrees of what is already covered.
    assert_eq!(w.ca.prune_signed_subtrees_below(2), 2);
    assert!(matches!(
        w.ca.standalone_certificate(1),
        Err(CaError::NotYetCheckpointed(1))
    ));
    assert!(w.ca.landmark_relative_certificate(1).is_ok());
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

    // Before the landmark there is no landmark-relative certificate.
    assert!(w.ca.landmark_relative_certificate(6).is_err());
    let l = w.ca.allocate_landmark(NOW + 3).unwrap().unwrap();
    assert_eq!((l.number, l.tree_size, l.expiry), (1, 8, NOW + 3 + WEEK));
    assert!(
        w.ca.allocate_landmark(NOW + 4).unwrap().is_none(),
        "the tree did not grow"
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
    // A relying party without the landmark cannot accept it: there are no signatures.
    let stale = rp(&w, vec![]);
    assert_eq!(
        verify_certificate(&der, &stale, NOW + 5),
        Err(VerifyError::MissingCosignature(w.ca_id.clone()))
    );
    // And with a wrong landmark hash, neither.
    let mut wrong = trusted;
    wrong[1].hash[0] ^= 1;
    assert_eq!(
        verify_certificate(&der, &rp(&w, wrong), NOW + 5),
        Err(VerifyError::TrustedSubtreeMismatch)
    );
    // The standalone certificate of the same entry remains valid for both.
    let standalone = w.ca.standalone_certificate(6).unwrap().to_der().unwrap();
    assert!(verify_certificate(&standalone, &updated, NOW + 5).is_ok());
    assert!(verify_certificate(&standalone, &stale, NOW + 5).is_ok());
}

/// The `hbs-state` guard, for real and on disk: the checkpoint number is
/// persisted before signing, and on reopening it is reconciled.
#[test]
fn the_checkpoint_number_is_persisted_before_signing() {
    let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("guardian");
    let path = dir.join("checkpoint.bin");
    let _ = std::fs::remove_file(&path);
    let guard = match IndexGuard::open(&path) {
        Ok(g) => g,
        // tmpfs or another filesystem where fsync does not persist: the guard
        // refuses, which is its job; this test cannot measure there, and says so.
        // Any OTHER error is a test failure.
        Err(GuardError::FakePersistence { ratio, .. }) => {
            eprintln!(
                "SKIPPED: fsync does not persist at {} (ratio {ratio})",
                path.display()
            );
            return;
        }
        Err(e) => panic!("could not open the guard at {}: {e}", path.display()),
    };
    let ca_id = TrustAnchorId::from_ascii("32473.1").unwrap();
    let signer = MlDsaCosigner::<MlDsa44>::from_seed(ca_id.clone(), [3u8; 32]);
    let cfg = CaConfig {
        ca_id,
        log_number: 1,
        max_cert_lifetime: WEEK,
        oids: mtc_core::OIDS_IANA,
    };
    let mut ca = CertificationAuthority::new(cfg, Box::new(signer), guard).unwrap();
    ca.submit(request(1)).unwrap();
    let cp = ca.run_checkpoint_job(NOW).unwrap().unwrap();
    assert_eq!(cp.number, 1);
    assert_eq!(ca.guard().current(), 1);
    drop(ca);
    // Reopen: the counter survived. If the log's journal says 1 was
    // published, in sync; if it says 0, orphaned (the normal case after a
    // crash between reserving and signing); if it said 2, fatal.
    let reopened = IndexGuard::open(&path).unwrap();
    assert_eq!(reopened.current(), 1);
    assert!(matches!(
        reopened.reconcile(1),
        Reconciliation::InSync { index: 1 }
    ));
    assert!(!is_fatal(&reopened.reconcile(0)));
    assert!(is_fatal(&reopened.reconcile(2)));
}
