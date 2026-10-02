//! # The reference implementation's corpus, verified here
//!
//! `tests/vectors/interop-plants-07/` and `tests/vectors/interop-iana/` are
//! the output of `demo generate` from the PLANTS working group's repository
//! (Go, `-version plants-07`, before and after the tool switched to the
//! IANA-assigned OIDs; the provenance is in each README), plus the verdict
//! the Go verifier gave to each certificate. This test hands the same files to this crate's
//! verifier and requires the same verdicts, negative cases included, and
//! the refusal of each corpus under the other's CA certificate; then it
//! rebuilds the issuance log from the Go tool's entry tiles and checks its
//! signed checkpoint. No Go is needed to run it: the corpus is data.
//!
//! What it does NOT cover: the other direction (certificates from here
//! verified by the Go tool), which needs Go and runs from
//! `interop/run.sh`; AUDIT.md records each run.

#![cfg(feature = "ml-dsa")]

use std::path::{Path, PathBuf};

use mtc_core::cacert::{ml_dsa_verifier_from_spki, CaCertificate};
use mtc_core::cosign::mldsa::{tlog_key_id_for, MlDsa44, MlDsaCosigner};
use mtc_core::cosign::CosignedMessage;
use mtc_core::der::DerError;
use mtc_core::proof::ProofError;
use mtc_core::spki::{self, MlDsaParameterSet};
use mtc_core::verify::{verify_certificate, Basis, RelyingPartyConfig, TrustedSubtree};
use mtc_core::{pem, IssuanceLog, Subtree, TrustAnchorId, VerifyError};

/// 2026-09-21, inside the corpus's validity (2020-01-01 to 2030-12-31).
const NOW: u64 = 1_790_000_000;

/// The two corpora of the reference tool: the interim experimental OIDs of
/// AUDIT.md §14, and the IANA OIDs of §18. Same configuration, same verdicts.
struct Corpus {
    dir: &'static str,
    oids: mtc_core::OidSet,
}

const CORPORA: [Corpus; 2] = [
    Corpus {
        dir: "interop-plants-07",
        oids: mtc_core::OIDS_EXPERIMENTAL_47_5,
    },
    Corpus {
        dir: "interop-iana",
        oids: mtc_core::OIDS_IANA,
    },
];

fn dir(c: &Corpus) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("vectors")
        .join(c.dir)
}

fn read(c: &Corpus, name: &str) -> String {
    std::fs::read_to_string(dir(c).join(name)).unwrap_or_else(|e| panic!("{name}: {e}"))
}

fn certificate_der(c: &Corpus, name: &str) -> Vec<u8> {
    let blocks = pem::decode_all(&read(c, name)).unwrap();
    // The Go tool writes a `MTC CERTIFICATE PROPERTIES` block first.
    blocks
        .into_iter()
        .find(|b| b.label == "CERTIFICATE")
        .unwrap_or_else(|| panic!("{name}: no CERTIFICATE block"))
        .der
}

fn ca(c: &Corpus) -> CaCertificate {
    CaCertificate::from_der(&certificate_der(c, "ca_cert.pem")).unwrap()
}

/// The Go tool's `policy.txt` vocabulary, as `interop verify` reads it.
fn relying_party(c: &Corpus, ca: &CaCertificate) -> RelyingPartyConfig {
    let (set, entry) = ca.ml_dsa_cosigner_entry().unwrap();
    assert_eq!(set, MlDsaParameterSet::MlDsa44);
    let mut rp = RelyingPartyConfig {
        ca_id: ca.ca_id.clone(),
        ca_oids: ca.oids,
        cosigners: vec![entry],
        required_cosigners: vec![],
        trusted_subtrees: vec![],
        revoked_ranges: vec![],
    };
    let mut ignored = Vec::new();
    for line in read(c, "policy.txt").lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        match f.as_slice() {
            ["cosigner", id, alg, b64] if alg.starts_with("mldsa") => {
                let (_, v) = ml_dsa_verifier_from_spki(&pem::base64_decode(b64).unwrap()).unwrap();
                rp.cosigners
                    .push((TrustAnchorId::from_ascii(id).unwrap(), v));
            }
            ["cosigner", id, _, _] => ignored.push(id.to_string()),
            ["trusted-subtree", ca_id, log, start, end, hash] => {
                assert_eq!(TrustAnchorId::from_ascii(ca_id).unwrap(), rp.ca_id);
                rp.trusted_subtrees.push(TrustedSubtree {
                    log_number: log.parse().unwrap(),
                    subtree: Subtree::new(start.parse().unwrap(), end.parse().unwrap()).unwrap(),
                    hash: pem::base64_decode(hash).unwrap().try_into().unwrap(),
                });
            }
            _ => {}
        }
    }
    // The ECDSA P-256 cosigner: this build ignores its cosignatures.
    assert_eq!(ignored, ["32473.2.1"]);
    assert_eq!(rp.cosigners.len(), 1 + 6);
    assert_eq!(rp.trusted_subtrees.len(), 6);
    rp
}

#[test]
fn the_ca_certificate_of_the_go_tool_is_read_and_its_key_is_the_documented_seed() {
    for c in &CORPORA {
        the_ca_certificate_of_the_go_tool_is_read_and_its_key_is_the_documented_seed_in(c);
    }
}

fn the_ca_certificate_of_the_go_tool_is_read_and_its_key_is_the_documented_seed_in(c: &Corpus) {
    let ca = ca(c);
    assert_eq!(ca.ca_id, TrustAnchorId::from_ascii("32473.1").unwrap());
    assert_eq!(ca.min_serial, 1 << 48);
    assert_eq!(ca.max_serial, (5 << 48) | ((1 << 48) - 1));
    assert_eq!(ca.log_numbers(), 1..=5);
    assert_eq!(ca.validity.not_before, 1_577_836_800); // 2020-01-01T00:00:00Z
    assert_eq!(ca.validity.not_after, 1_924_991_999); // 2030-12-31T23:59:59Z
                                                      // The Go tool's `mtc.json` gives its CA the ML-DSA-44 seed 00 01 … 1f
                                                      // (a public test key). FIPS 204 key generation here yields the same
                                                      // public key, byte for byte.
    let seed: [u8; 32] = core::array::from_fn(|i| i as u8);
    let ours = MlDsaCosigner::<MlDsa44>::deterministic(ca.ca_id.clone(), seed);
    let parsed = spki::parse(&ca.spki).unwrap();
    assert_eq!(parsed.oid(), &spki::OID_ML_DSA_44);
    assert_eq!(parsed.key, &ours.verifying_key_bytes()[..]);
    // And the certificate written here for that key parses to the same
    // fields when the validity and serial range are the same.
    let rewritten = CaCertificate {
        spki: spki::ml_dsa(MlDsaParameterSet::MlDsa44, parsed.key),
        ..ca.clone()
    }
    .to_der()
    .unwrap();
    assert_eq!(CaCertificate::from_der(&rewritten).unwrap(), ca);
}

#[test]
fn every_verdict_of_the_go_verifier_is_reproduced() {
    for c in &CORPORA {
        every_verdict_of_the_go_verifier_is_reproduced_in(c);
    }
}

fn every_verdict_of_the_go_verifier_is_reproduced_in(c: &Corpus) {
    let ca = ca(c);
    let rp = relying_party(c, &ca);
    let mut checked = 0;
    for line in read(c, "expected.txt").lines() {
        let (name, expected) = line.split_once(' ').unwrap();
        let result = verify_certificate(&certificate_der(c, name), &rp, NOW);
        let got = if result.is_ok() { "OK" } else { "FAIL" };
        assert_eq!(got, expected, "{name}: {result:?}");
        if let Ok(v) = &result {
            assert!(
                ca.covers_serial(v.serial),
                "{name}: serial outside the CA's range"
            );
            assert_eq!(v.log_number, 1);
            assert_eq!(v.oids, c.oids, "{name}: written with another OID set");
        }
        checked += 1;
    }
    assert_eq!(checked, 26);
}

/// A CA certificate fixes the issuer's name attribute (AUDIT.md §25). The
/// two corpora share the CA ID `32473.1` and its key; under the other
/// corpus's CA certificate and policy, every certificate fails, and the 21
/// its own CA accepts fail as `UnknownIssuer`. Before §25, twelve of them
/// verified (the cosigned ones whose subtree is not one of the other
/// corpus's landmarks) and the rest failed as `TrustedSubtreeMismatch`.
#[test]
fn each_corpus_is_refused_under_the_other_corpus_ca_certificate() {
    for (own, other) in [(&CORPORA[0], &CORPORA[1]), (&CORPORA[1], &CORPORA[0])] {
        let other_ca = ca(other);
        let rp = relying_party(other, &other_ca);
        let mut refused = 0;
        for line in read(own, "expected.txt").lines() {
            let (name, expected) = line.split_once(' ').unwrap();
            let result = verify_certificate(&certificate_der(own, name), &rp, NOW);
            assert!(result.is_err(), "{}/{name}: {result:?}", own.dir);
            if expected == "OK" {
                assert_eq!(
                    result,
                    Err(VerifyError::UnknownIssuer),
                    "{}/{name}",
                    own.dir
                );
                refused += 1;
            }
        }
        assert_eq!(refused, 21, "{}", own.dir);
    }
}

#[test]
fn the_negative_cases_fail_for_the_reason_the_go_tool_built_them_for() {
    for c in &CORPORA {
        the_negative_cases_fail_for_the_reason_the_go_tool_built_them_for_in(c);
    }
}

fn the_negative_cases_fail_for_the_reason_the_go_tool_built_them_for_in(c: &Corpus) {
    let ca = ca(c);
    let rp = relying_party(c, &ca);
    let verdict = |name: &str| verify_certificate(&certificate_der(c, name), &rp, NOW);
    // `UnusedBit`: the signature BIT STRING declares one unused bit.
    assert_eq!(
        verdict("cert_10_1.pem"),
        Err(VerifyError::Proof(ProofError::Der(DerError::BadLength)))
    );
    // `BitFlipProof` on a standalone certificate: the CA's cosignature no
    // longer covers the subtree hash the proof evaluates to.
    assert_eq!(
        verdict("cert_10_2.pem"),
        Err(VerifyError::BadCosignature(ca.ca_id.clone()))
    );
    // Seven cosigners but not the CA's.
    assert_eq!(
        verdict("cert_10_8.pem"),
        Err(VerifyError::MissingCosignature(ca.ca_id.clone()))
    );
    // No cosignatures and a subtree that is not a landmark's.
    assert_eq!(
        verdict("cert_10_10.pem"),
        Err(VerifyError::MissingCosignature(ca.ca_id.clone()))
    );
    // `BitFlipProof` on a landmark-relative certificate.
    assert_eq!(
        verdict("cert_2035_2.pem"),
        Err(VerifyError::TrustedSubtreeMismatch)
    );
    // And the positives are accepted for the right reason.
    assert!(matches!(
        verdict("cert_10_12.pem").unwrap().basis,
        Basis::TrustedSubtree
    ));
    match verdict("cert_10_9.pem").unwrap().basis {
        Basis::Cosignatures(ids) => assert_eq!(ids, vec![ca.ca_id.clone()]),
        other => panic!("{other:?}"),
    }
    // Requiring the ML-DSA-87 witness as well is satisfied by cert_10_11
    // (CA + 32473.2.3) and not by cert_10_3 (CA only).
    let mut strict = relying_party(c, &ca);
    strict.required_cosigners = vec![TrustAnchorId::from_ascii("32473.2.3").unwrap()];
    assert!(verify_certificate(&certificate_der(c, "cert_10_11.pem"), &strict, NOW).is_ok());
    assert_eq!(
        verify_certificate(&certificate_der(c, "cert_10_3.pem"), &strict, NOW),
        Err(VerifyError::MissingCosignature(
            TrustAnchorId::from_ascii("32473.2.3").unwrap()
        ))
    );
}

/// The Go tool's entry tiles: `uint16`-length-prefixed entries, 256 per
/// tile, at `tile/entries/NNN` (full) or `tile/entries/NNN.p/<width>`.
fn entries_from_tiles(c: &Corpus) -> Vec<Vec<u8>> {
    let base = dir(c).join("tile").join("entries");
    let mut entries = Vec::new();
    for i in 0.. {
        let full = base.join(format!("{i:03}"));
        let data = if full.is_file() {
            std::fs::read(&full).unwrap()
        } else {
            let partial = base.join(format!("{i:03}.p"));
            if !partial.is_dir() {
                break;
            }
            let file = std::fs::read_dir(&partial)
                .unwrap()
                .next()
                .unwrap()
                .unwrap()
                .path();
            std::fs::read(&file).unwrap()
        };
        let mut cur = &data[..];
        while !cur.is_empty() {
            let len = u16::from_be_bytes([cur[0], cur[1]]) as usize;
            entries.push(cur[2..2 + len].to_vec());
            cur = &cur[2 + len..];
        }
        if full.is_file() {
            continue;
        }
        break;
    }
    entries
}

#[test]
fn the_go_tools_checkpoint_is_reproduced_from_its_entry_tiles() {
    for c in &CORPORA {
        the_go_tools_checkpoint_is_reproduced_from_its_entry_tiles_in(c);
    }
}

fn the_go_tools_checkpoint_is_reproduced_from_its_entry_tiles_in(c: &Corpus) {
    let ca = ca(c);
    let note = read(c, "checkpoint");
    let lines: Vec<&str> = note.lines().collect();
    let log_id = ca.ca_id.log_id(1).unwrap();
    assert_eq!(lines[0], log_id.oid_name().unwrap());
    let size: u64 = lines[1].parse().unwrap();
    let root = pem::base64_decode(lines[2]).unwrap();
    assert_eq!(lines[3], "");

    let entries = entries_from_tiles(c);
    assert_eq!(entries.len() as u64, size);
    assert_eq!(size, 2122);
    let log = IssuanceLog::from_entries(1, entries).unwrap();
    assert_eq!(&log.root()[..], &root[..]);

    // The CA's line of the signed note: `— <name> base64(key_id || sig)`.
    let name = ca.ca_id.oid_name().unwrap();
    let line = lines[4..]
        .iter()
        .find_map(|l| l.strip_prefix(&format!("\u{2014} {name} ")))
        .expect("the CA's signature line");
    let bytes = pem::base64_decode(line).unwrap();
    let key = spki::parse(&ca.spki).unwrap().key.to_vec();
    assert_eq!(bytes[..4], tlog_key_id_for(&ca.ca_id, &key).unwrap());
    let (_, verifier) = ml_dsa_verifier_from_spki(&ca.spki).unwrap();
    let message = |timestamp| {
        CosignedMessage {
            cosigner_id: ca.ca_id.clone(),
            timestamp,
            log_id: log_id.clone(),
            subtree: Subtree {
                start: 0,
                end: size,
            },
            subtree_hash: log.root(),
        }
        .to_bytes()
    };
    // What the Go tool signs today: the subtree [0, size) with timestamp
    // 0 and nothing else on the line (tlog-cosignature would put an
    // 8-byte timestamp before the signature and inside the message; read
    // that way, the first eight signature bytes are not a valid timestamp
    // or the rest is not a valid signature).
    assert!(verifier.verify(&message(0).unwrap(), &bytes[4..]));
    let ts = u64::from_be_bytes(bytes[4..12].try_into().unwrap());
    let as_timestamped = message(ts)
        .map(|m| verifier.verify(&m, &bytes[12..]))
        .unwrap_or(false);
    assert!(!as_timestamped);
}
