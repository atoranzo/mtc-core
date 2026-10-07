//! # Interoperability with the draft's reference implementation
//!
//! A command-line tool in the shape of `demo generate` and `demo verify`
//! from the PLANTS working group's repository (`ietf-plants-wg/
//! merkle-tree-certs`, directory `demo/`), so that the same files and the
//! same policy vocabulary go through both verifiers. `interop/README.md`
//! has the procedure; `AUDIT.md` the record of each run.
//!
//!     cargo run --release --example interop -- generate -out DIR \
//!         [-oids iana|experimental-06] [-tls-key PUBLIC_KEY_PEM]
//!     cargo run --release --example interop -- verify -ca-cert FILE \
//!         [-policy FILE] [-subtrees FILE] [-cosigner-cert FILE]... \
//!         [-require ID]... [-now UNIX] CERT...
//!     cargo run --release --example interop -- checkpoint -dir DIR -ca-cert FILE \
//!         [-log-number N]
//!
//! `generate` writes a CA certificate, a corpus of certificates with their
//! expected verdicts, and a policy file for the Go verifier. `verify` reads
//! a CA certificate and a policy file in the Go tool's format and prints
//! one verdict per certificate, in the Go tool's format. `checkpoint`
//! rebuilds the issuance log from the Go tool's entry tiles and checks its
//! signed checkpoint.
//!
//! The same configuration is also written, and read, in the files of
//! OpenSSL's MTC options (`-mtc_subtrees`, `-mtc_cosigners`), which Bob
//! Beck's `mtc verify` reads as well: `generate` writes `subtrees.txt` and
//! `cosigners.pem`, and `verify` takes them with `-subtrees` and
//! `-cosigner-cert`. With `-tls-key`, `generate` also issues certificates
//! for that key (the DNS name `localhost`) for a TLS handshake with
//! OpenSSL, and `tls_chains.txt` says which trust anchor ID and groups to
//! decorate each with (`openssl generate_tai_chain`).

use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use mtc_core::cacert::{
    ml_dsa_verifier_from_spki, CaCertificate, MTC_MIN_SERIAL, OID_ALG_UNSIGNED, OID_RDNA_UNSIGNED,
};
use mtc_core::cosign::mldsa::{tlog_key_id_for, MlDsa44, MlDsaCosigner};
use mtc_core::cosign::CosignedMessage;
use mtc_core::der;
use mtc_core::pem;
use mtc_core::proof::MAX_U48;
use mtc_core::spki::{self, MlDsaParameterSet};
use mtc_core::verify::{
    verify_certificate, Basis, CosignerEntry, RelyingPartyConfig, TrustedSubtree,
};
use mtc_core::{
    CaConfig, CertificateRequest, CertificationAuthority, IssuanceLog, MemoryGuard, MtcCertificate,
    OidSet, Subtree, TrustAnchorId, Validity, KNOWN_OID_SETS,
};

type Res<T> = Result<T, String>;

/// The CA cosigner `32473.1` of the reference implementation's `mtc.json`
/// is ML-DSA-44 with the seed `00 01 … 1f` (its PKCS#8 `PrivateKey`,
/// decoded). **A public test key from the draft's repository, never for
/// anything real.** Using the same seed here means the two CAs share one
/// key: a certificate from here can be checked by the Go verifier against
/// the Go tool's own `ca_cert.pem`, and the other way round.
const DEMO_CA_SEED: [u8; 32] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];
/// Cosigner `32473.3.1` of the same file (ML-DSA-44), same warning.
const DEMO_WITNESS_SEED: [u8; 32] = [
    0x58, 0xda, 0x8a, 0x64, 0x00, 0x83, 0x90, 0x78, 0x39, 0x36, 0xd9, 0x35, 0x39, 0xed, 0xfd, 0x87,
    0x26, 0x8c, 0xf9, 0x9b, 0x8a, 0x39, 0xf2, 0x9c, 0x79, 0xef, 0xb3, 0x23, 0xcb, 0x93, 0xc4, 0xa0,
];

const DAY: u64 = 86_400;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("generate") => generate(&args[1..]).map(|()| true),
        Some("verify") => verify(&args[1..]),
        Some("checkpoint") => checkpoint(&args[1..]),
        _ => {
            eprintln!(
                "usage:\n  interop generate -out DIR [-oids iana|experimental-06] [-tls-key PUBLIC_KEY_PEM]\n  interop verify -ca-cert FILE [-policy FILE] [-subtrees FILE] [-cosigner-cert FILE]... [-require ID]... [-now UNIX] CERT...\n  interop checkpoint -dir DIR -ca-cert FILE [-log-number N]"
            );
            return ExitCode::from(2);
        }
    };
    match result {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(2)
        }
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn flag_value<'a>(args: &'a [String], i: &mut usize, flag: &str) -> Res<&'a str> {
    *i += 1;
    args.get(*i)
        .map(String::as_str)
        .ok_or_else(|| format!("{flag} needs a value"))
}

fn read_ca_certificates(paths: &[String]) -> Res<Vec<CaCertificate>> {
    let mut out = Vec::new();
    for p in paths {
        let text = fs::read_to_string(p).map_err(|e| format!("{p}: {e}"))?;
        for block in pem::decode_all(&text).map_err(|e| format!("{p}: {e}"))? {
            if block.label == "CERTIFICATE" {
                out.push(CaCertificate::from_der(&block.der).map_err(|e| format!("{p}: {e}"))?);
            }
        }
    }
    Ok(out)
}

/// A cosigner certificate in the form OpenSSL's `-mtc_cosigners` and Bob
/// Beck's `mtc verify --cosigner-cert` read: the CA certificate's unsigned
/// shape (RFC 9925), with the cosigner ID as subject, the cosigner's key,
/// and no extensions. The draft does not define it; it is configuration
/// for those relying parties, not something this crate's verifier needs.
fn cosigner_certificate(
    id: &TrustAnchorId,
    spki: &[u8],
    validity: &Validity,
    oids: &OidSet,
) -> Vec<u8> {
    let mut placeholder = der::oid(&OID_RDNA_UNSIGNED);
    placeholder.extend(der::tlv(0x0c, &[])); // an empty UTF8String
    let issuer = der::sequence(&der::set(&der::sequence(&placeholder)));
    let mut tbs = der::explicit(0, &der::integer_u64(2));
    tbs.extend(der::integer_u64(1));
    tbs.extend(der::algorithm_identifier(&OID_ALG_UNSIGNED));
    tbs.extend(issuer);
    tbs.extend(validity.to_der());
    tbs.extend(der::name_from_ca_id(id, oids));
    tbs.extend_from_slice(spki);
    let mut cert = der::sequence(&tbs);
    cert.extend(der::algorithm_identifier(&OID_ALG_UNSIGNED));
    cert.extend(der::bit_string(&[]));
    der::sequence(&cert)
}

/// Reads cosigner certificates (see [`cosigner_certificate`]), from here or
/// from another implementation: the subject is one trust anchor ID
/// attribute of any known OID set, the key ML-DSA, and a certificate that
/// carries the MTC CA extension is refused (it belongs in `-ca-cert`).
fn read_cosigner_certificates(paths: &[String]) -> Res<Vec<CosignerEntry>> {
    let mut out = Vec::new();
    for p in paths {
        let text = fs::read_to_string(p).map_err(|e| format!("{p}: {e}"))?;
        for block in pem::decode_all(&text).map_err(|e| format!("{p}: {e}"))? {
            if block.label != "CERTIFICATE" {
                continue;
            }
            let parts = der::parse_certificate(&block.der).map_err(|e| format!("{p}: {e:?}"))?;
            let fields = der::parse_tbs(parts.tbs.raw).map_err(|e| format!("{p}: {e:?}"))?;
            let mut tail = fields.after_spki;
            while !tail.is_empty() {
                let (t, next) = der::read_tlv(tail).map_err(|e| format!("{p}: {e:?}"))?;
                if t.tag == 0xa3 {
                    let (seq, _) = der::expect_tlv(t.content, der::TAG_SEQUENCE)
                        .map_err(|e| format!("{p}: {e:?}"))?;
                    let mut cur = seq.content;
                    while !cur.is_empty() {
                        let (ext, rest) = der::expect_tlv(cur, der::TAG_SEQUENCE)
                            .map_err(|e| format!("{p}: {e:?}"))?;
                        cur = rest;
                        let (oid, _) = der::expect_tlv(ext.content, der::TAG_OID)
                            .map_err(|e| format!("{p}: {e:?}"))?;
                        let arcs =
                            spki::oid_arcs(oid.content).map_err(|e| format!("{p}: {e:?}"))?;
                        if OidSet::from_mtc_ca_extension(&arcs).is_some() {
                            return Err(format!(
                                "{p}: a CA certificate, not a cosigner certificate (use -ca-cert)"
                            ));
                        }
                    }
                }
                tail = next;
            }
            let id = KNOWN_OID_SETS
                .iter()
                .find_map(|set| der::ca_id_from_name(fields.subject.raw, set).ok())
                .ok_or_else(|| format!("{p}: the subject is not a trust anchor ID"))?;
            let (_, verifier) =
                ml_dsa_verifier_from_spki(fields.spki.raw).map_err(|e| format!("{p}: {e}"))?;
            out.push((id, verifier));
        }
    }
    Ok(out)
}

/// The lines of an OpenSSL `-mtc_subtrees` file (`<id> <log> <start> <end>
/// <hash>`) are the Go tool's `trusted-subtree` lines without the keyword.
fn subtrees_as_policy(text: &str) -> String {
    text.lines()
        .map(|l| {
            let t = l.trim();
            if t.is_empty() || t.starts_with('#') {
                String::new()
            } else {
                format!("trusted-subtree {t}")
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

// ───────────────────────── generate ─────────────────────────

fn generate(args: &[String]) -> Res<()> {
    let mut out = PathBuf::from("out");
    let mut oids = mtc_core::OIDS_IANA;
    let mut tls_key = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-out" => out = PathBuf::from(flag_value(args, &mut i, "-out")?),
            "-tls-key" => tls_key = Some(flag_value(args, &mut i, "-tls-key")?.to_string()),
            "-oids" => {
                let v = flag_value(args, &mut i, "-oids")?;
                oids = mtc_core::OidSet::from_flag(v).ok_or_else(|| {
                    format!("-oids {v:?}: iana or experimental-06 (the interim experimental-47.5 was retired at draft-07, AUDIT.md §26)")
                })?
            }
            other => return Err(format!("unknown flag {other}")),
        }
        i += 1;
    }
    fs::create_dir_all(&out).map_err(|e| e.to_string())?;
    let now = unix_now();

    // ── the CA (same key as the Go tool's CA) and its witness ──
    let ca_id = TrustAnchorId::from_ascii("32473.1").map_err(|e| e.to_string())?;
    let witness_id = TrustAnchorId::from_ascii("32473.3.1").map_err(|e| e.to_string())?;
    let ca_signer = MlDsaCosigner::<MlDsa44>::from_seed(ca_id.clone(), DEMO_CA_SEED);
    let witness = MlDsaCosigner::<MlDsa44>::from_seed(witness_id.clone(), DEMO_WITNESS_SEED);
    let ca_spki = spki::ml_dsa(MlDsaParameterSet::MlDsa44, &ca_signer.verifying_key_bytes());
    let witness_spki = spki::ml_dsa(MlDsaParameterSet::MlDsa44, &witness.verifying_key_bytes());

    let ca_cert = CaCertificate {
        ca_id: ca_id.clone(),
        spki: ca_spki,
        sig_alg: der::algorithm_identifier(&spki::OID_ML_DSA_44),
        min_serial: MTC_MIN_SERIAL,
        max_serial: MTC_MIN_SERIAL | MAX_U48, // log number 1, whole
        validity: Validity {
            not_before: now - DAY,
            not_after: now + 3650 * DAY,
        },
        oids,
    };
    let ca_cert_der = ca_cert.to_der().map_err(|e| e.to_string())?;
    // Read back what was written: the same parser the relying party uses.
    CaCertificate::from_der(&ca_cert_der).map_err(|e| format!("own CA certificate: {e}"))?;
    let ca_path = out.join("ca_cert.pem");
    fs::write(&ca_path, pem::encode("CERTIFICATE", &ca_cert_der)).map_err(|e| e.to_string())?;
    println!(
        "Wrote CA certificate {:?} with the {} OIDs.\n",
        ca_path, oids.name
    );

    let cfg = CaConfig {
        ca_id: ca_id.clone(),
        log_number: 1,
        max_cert_lifetime: 90 * DAY,
        oids,
    };
    let mut ca = CertificationAuthority::new(cfg, Box::new(ca_signer), MemoryGuard::default())
        .map_err(|e| format!("{e:?}"))?;
    ca.add_cosigner(Box::new(witness))
        .map_err(|e| format!("{e:?}"))?;

    let submit = |ca: &mut CertificationAuthority<MemoryGuard>, i: u8| -> Res<u64> {
        // A toy subject key: Ed25519's OID with 32 arbitrary bytes, so that
        // any X.509 parser accepts the SubjectPublicKeyInfo.
        let key = [i; 32];
        ca.submit(CertificateRequest {
            subject: der::sequence(&[]),
            spki: spki::encode(&spki::OID_ED25519, &key),
            validity: Validity {
                not_before: now - 3600,
                not_after: now - 3600 + 30 * DAY,
            },
            extensions: Some(der::san_dns_extensions(&[&format!("entry{i}.example")])),
            log_entry_extensions: vec![],
        })
        .map_err(|e| format!("{e:?}"))
    };

    // ── 20 entries, four checkpoints, two landmarks ──
    let mut clock = now;
    for i in 0..5u8 {
        submit(&mut ca, i)?;
    }
    let checkpoint = |ca: &mut CertificationAuthority<MemoryGuard>, clock: &mut u64| -> Res<()> {
        *clock += 1;
        let cp = ca
            .run_checkpoint_job(*clock)
            .map_err(|e| format!("{e:?}"))?
            .ok_or("nothing to checkpoint")?;
        println!(
            "Checkpoint {} at tree size {}: subtrees {}",
            cp.number,
            cp.tree_size,
            cp.subtrees
                .iter()
                .map(|s| s.subtree.to_string())
                .collect::<Vec<_>>()
                .join(" ")
        );
        Ok(())
    };
    checkpoint(&mut ca, &mut clock)?;
    for i in 5..11u8 {
        submit(&mut ca, i)?;
    }
    checkpoint(&mut ca, &mut clock)?;
    clock += 1;
    let l1 = ca
        .allocate_landmark(clock)
        .map_err(|e| format!("{e:?}"))?
        .ok_or("no landmark")?;
    for i in 11..15u8 {
        submit(&mut ca, i)?;
    }
    checkpoint(&mut ca, &mut clock)?;
    clock += 1;
    let l2 = ca
        .allocate_landmark(clock)
        .map_err(|e| format!("{e:?}"))?
        .ok_or("no landmark")?;
    for i in 15..20u8 {
        submit(&mut ca, i)?;
    }
    checkpoint(&mut ca, &mut clock)?;
    println!();

    // ── the corpus, with the verdict the Go verifier is expected to give
    //    when handed `policy.txt` (which carries the landmark subtrees) ──
    let mut expected = String::from(
        "# file expected-verdict reason  (verdict of `demo verify -version plants-07 -ca-cert ca_cert.pem -policy policy.txt`)\n",
    );
    let mut write_cert = |name: &str, cert: &MtcCertificate, verdict: &str, why: &str| -> Res<()> {
        let der = cert.to_der().map_err(|e| format!("{e:?}"))?;
        // Every certificate written is read back and its structure checked
        // with the same decoder a relying party uses.
        MtcCertificate::from_der(&der).map_err(|e| format!("{name}: {e:?}"))?;
        let path = out.join(name);
        fs::write(&path, pem::encode("CERTIFICATE", &der)).map_err(|e| e.to_string())?;
        println!(
            "Wrote {:?}: entry {}, subtree {}, {} cosignature(s), expected {verdict} ({why})",
            path,
            cert.index().map_err(|e| format!("{e:?}"))?,
            cert.proof.subtree,
            cert.proof.signatures.len()
        );
        expected.push_str(&format!("{name} {verdict} {why}\n"));
        Ok(())
    };

    let standalone = |ca: &CertificationAuthority<MemoryGuard>, i: u64| {
        ca.standalone_certificate(i).map_err(|e| format!("{e:?}"))
    };
    let relative = |ca: &CertificationAuthority<MemoryGuard>, i: u64| {
        ca.landmark_relative_certificate(i)
            .map_err(|e| format!("{e:?}"))
    };
    let flip = |c: &mut MtcCertificate| {
        if let Some(h) = c.proof.inclusion_proof.first_mut() {
            h[0] ^= 1;
        } else if let Some(s) = c.proof.signatures.first_mut() {
            s.signature[0] ^= 1;
        }
    };

    write_cert(
        "cert_0_standalone.pem",
        &standalone(&ca, 0)?,
        "OK",
        "CA+witness cosignatures",
    )?;
    write_cert(
        "cert_9_standalone.pem",
        &standalone(&ca, 9)?,
        "OK",
        "CA+witness cosignatures",
    )?;
    write_cert(
        "cert_17_standalone.pem",
        &standalone(&ca, 17)?,
        "OK",
        "CA+witness cosignatures",
    )?;
    write_cert(
        "cert_9_landmark.pem",
        &relative(&ca, 9)?,
        "OK",
        "trusted subtree of landmark 1",
    )?;
    write_cert(
        "cert_13_landmark.pem",
        &relative(&ca, 13)?,
        "OK",
        "trusted subtree of landmark 2",
    )?;
    // The standalone negatives use entry 17: its subtree [16, 20) is not a
    // landmark subtree, so a trusted subtree cannot rescue them (entry 9's
    // standalone subtree [8, 11) IS landmark 1's second subtree, and a
    // verifier accepts a trusted subtree before looking at cosignatures).
    let mut c = standalone(&ca, 17)?;
    flip(&mut c);
    write_cert(
        "cert_17_standalone_bitflip.pem",
        &c,
        "FAIL",
        "one bit of the inclusion proof flipped",
    )?;
    let mut c = standalone(&ca, 17)?;
    c.proof.signatures.clear();
    write_cert(
        "cert_17_standalone_nocosig.pem",
        &c,
        "FAIL",
        "no cosignatures and not a trusted subtree",
    )?;
    let mut c = relative(&ca, 9)?;
    flip(&mut c);
    write_cert(
        "cert_9_landmark_bitflip.pem",
        &c,
        "FAIL",
        "one bit of the inclusion proof flipped",
    )?;
    let mut c = standalone(&ca, 17)?;
    c.proof.signatures.retain(|s| s.cosigner_id != ca_id);
    write_cert(
        "cert_17_standalone_witnessonly.pem",
        &c,
        "FAIL",
        "witness cosignature without the CA's",
    )?;
    fs::write(out.join("EXPECTED.txt"), &expected).map_err(|e| e.to_string())?;

    // ── for a TLS handshake with OpenSSL: one more entry, for the given
    //    key, covered by a third landmark. After the corpus, so that none
    //    of the corpus's certificates changes. ──
    if let Some(path) = &tls_key {
        let text = fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
        let spki_der = pem::decode_all(&text)
            .map_err(|e| format!("{path}: {e}"))?
            .into_iter()
            .find(|b| b.label == "PUBLIC KEY")
            .ok_or_else(|| format!("{path}: no PUBLIC KEY block"))?
            .der;
        spki::parse(&spki_der).map_err(|e| format!("{path}: {e:?}"))?;
        let index = ca
            .submit(CertificateRequest {
                subject: der::sequence(&[]),
                spki: spki_der,
                validity: Validity {
                    not_before: now - 3600,
                    not_after: now - 3600 + 30 * DAY,
                },
                extensions: Some(der::san_dns_extensions(&["localhost"])),
                log_entry_extensions: vec![],
            })
            .map_err(|e| format!("{e:?}"))?;
        checkpoint(&mut ca, &mut clock)?;
        clock += 1;
        let l3 = ca
            .allocate_landmark(clock)
            .map_err(|e| format!("{e:?}"))?
            .ok_or("no landmark")?;
        let ca_text = ca_id.to_ascii();
        let landmark_id = ca_id
            .landmark_id(1, l3.number)
            .map_err(|e| format!("{e:?}"))?
            .to_ascii();
        let mut chains = String::from(
            "# file, then the arguments of `openssl generate_tai_chain` for it (draft section 8.2.1)\n",
        );
        let mut write_tls = |name: &str, cert: &MtcCertificate, props: &str| -> Res<()> {
            let der = cert.to_der().map_err(|e| format!("{e:?}"))?;
            MtcCertificate::from_der(&der).map_err(|e| format!("{name}: {e:?}"))?;
            fs::write(out.join(name), pem::encode("CERTIFICATE", &der))
                .map_err(|e| e.to_string())?;
            println!(
                "Wrote {name}: entry {index}, subtree {}, {} cosignature(s)",
                cert.proof.subtree,
                cert.proof.signatures.len()
            );
            chains.push_str(&format!("{name} {props}\n"));
            Ok(())
        };
        let standalone_props = format!("-oid {ca_text} -group {ca_text}.2.{{0-}}.{{0-}}");
        let landmark_props = format!(
            "-oid {landmark_id} -group {ca_text}.2.1.{{{}-}} -trust-anchor-negotiation",
            l3.number
        );
        write_tls(
            "tls_standalone.pem",
            &standalone(&ca, index)?,
            &standalone_props,
        )?;
        let mut c = standalone(&ca, index)?;
        c.proof.signatures.retain(|s| s.cosigner_id == ca_id);
        write_tls("tls_standalone_caonly.pem", &c, &standalone_props)?;
        let mut c = standalone(&ca, index)?;
        flip(&mut c);
        write_tls("tls_standalone_bitflip.pem", &c, &standalone_props)?;
        write_tls("tls_landmark.pem", &relative(&ca, index)?, &landmark_props)?;
        let mut c = relative(&ca, index)?;
        flip(&mut c);
        write_tls("tls_landmark_bitflip.pem", &c, &landmark_props)?;
        fs::write(out.join("tls_chains.txt"), &chains).map_err(|e| e.to_string())?;
        println!(
            "Landmark {} at tree size {} covers the TLS entry. Wrote tls_chains.txt.\n",
            l3.number, l3.tree_size
        );
    }

    // ── the policy for the Go verifier: the witness and the landmarks ──
    let mut policy = String::from("# Generated by mtc-core's `interop generate`: the witness cosigner and the trusted subtrees of the active landmarks.\n");
    let mut subtrees = String::from("# Generated by mtc-core's `interop generate`: the trusted subtrees of the active landmarks, in the format of OpenSSL's -mtc_subtrees.\n");
    policy.push_str(&format!(
        "cosigner {} mldsa44 {}\n",
        witness_id.to_ascii(),
        pem::base64_encode(&witness_spki)
    ));
    println!();
    for (l, st, hash) in ca
        .active_landmark_subtrees(clock)
        .map_err(|e| format!("{e:?}"))?
    {
        println!(
            "Landmark {} at tree size {}: subtree {} with hash {}",
            l.number,
            l.tree_size,
            st,
            pem::base64_encode(&hash)
        );
        let line = format!(
            "{} 1 {} {} {}\n",
            ca_id.to_ascii(),
            st.start,
            st.end,
            pem::base64_encode(&hash)
        );
        policy.push_str(&format!("trusted-subtree {line}"));
        subtrees.push_str(&line);
    }
    fs::write(out.join("policy.txt"), &policy).map_err(|e| e.to_string())?;
    fs::write(out.join("subtrees.txt"), &subtrees).map_err(|e| e.to_string())?;
    let witness_cert = cosigner_certificate(&witness_id, &witness_spki, &ca_cert.validity, &oids);
    fs::write(
        out.join("cosigners.pem"),
        pem::encode("CERTIFICATE", &witness_cert),
    )
    .map_err(|e| e.to_string())?;
    fs::write(out.join("landmarks.txt"), ca.landmarks().publish(clock))
        .map_err(|e| e.to_string())?;
    println!(
        "\nLandmarks allocated for the corpus: {} (size {}) and {} (size {}). Wrote policy.txt, subtrees.txt, cosigners.pem, landmarks.txt and EXPECTED.txt.",
        l1.number, l1.tree_size, l2.number, l2.tree_size
    );
    Ok(())
}

// ───────────────────────── verify ─────────────────────────

/// The Go tool's serial spellings: `LOG:INDEX`, a decimal, or `max`.
fn parse_serial(s: &str) -> Res<u64> {
    if s == "max" {
        return Ok(u64::MAX);
    }
    if let Some((log, index)) = s.split_once(':') {
        let log: u64 = log.parse().map_err(|_| format!("bad log number {log:?}"))?;
        let index: u64 = index.parse().map_err(|_| format!("bad index {index:?}"))?;
        if log > u16::MAX as u64 || index > MAX_U48 {
            return Err(format!("serial {s:?} out of range"));
        }
        return Ok((log << 48) | index);
    }
    s.parse().map_err(|_| format!("bad serial {s:?}"))
}

/// Applies a policy file in the Go tool's format to the configuration of
/// ONE CA. What this crate's minimal policy cannot express is reported,
/// not silently dropped.
fn apply_policy(text: &str, rp: &mut RelyingPartyConfig, notes: &mut Vec<String>) -> Res<()> {
    for (n, raw) in text.lines().enumerate() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let f: Vec<&str> = line.split_whitespace().collect();
        let at = format!("policy line {}", n + 1);
        match f[0] {
            "cosigner" if f.len() == 4 => {
                let id = TrustAnchorId::from_ascii(f[1]).map_err(|e| format!("{at}: {e:?}"))?;
                let spki_der = pem::base64_decode(f[3]).map_err(|e| format!("{at}: {e}"))?;
                if !f[2].starts_with("mldsa") {
                    notes.push(format!(
                        "{at}: cosigner {} uses {}, which this build cannot verify; its cosignatures are ignored",
                        f[1], f[2]
                    ));
                    continue;
                }
                let (set, verifier) =
                    ml_dsa_verifier_from_spki(&spki_der).map_err(|e| format!("{at}: {e}"))?;
                let expected = match set {
                    MlDsaParameterSet::MlDsa44 => "mldsa44",
                    MlDsaParameterSet::MlDsa65 => "mldsa65",
                    MlDsaParameterSet::MlDsa87 => "mldsa87",
                };
                if f[2] != expected {
                    return Err(format!(
                        "{at}: key is {} but the line says {}",
                        set.name(),
                        f[2]
                    ));
                }
                if rp.cosigners.iter().any(|(cid, _)| *cid == id) {
                    return Err(format!("{at}: cosigner {} defined twice", f[1]));
                }
                rp.cosigners.push((id, verifier));
            }
            "trusted-subtree" if f.len() == 6 => {
                let ca = TrustAnchorId::from_ascii(f[1]).map_err(|e| format!("{at}: {e:?}"))?;
                if ca != rp.ca_id {
                    notes.push(format!(
                        "{at}: trusted subtree of another CA ({}), ignored",
                        f[1]
                    ));
                    continue;
                }
                let log_number: u16 = f[2].parse().map_err(|_| format!("{at}: bad log number"))?;
                let start: u64 = f[3].parse().map_err(|_| format!("{at}: bad start"))?;
                let end: u64 = f[4].parse().map_err(|_| format!("{at}: bad end"))?;
                let hash = pem::base64_decode(f[5]).map_err(|e| format!("{at}: {e}"))?;
                let hash: [u8; 32] = hash
                    .try_into()
                    .map_err(|_| format!("{at}: the hash is not 32 bytes"))?;
                let subtree = Subtree::new(start, end).map_err(|e| format!("{at}: {e}"))?;
                rp.trusted_subtrees.push(TrustedSubtree {
                    log_number,
                    subtree,
                    hash,
                });
            }
            "revoke-range" if f.len() == 4 => {
                let ca = TrustAnchorId::from_ascii(f[1]).map_err(|e| format!("{at}: {e:?}"))?;
                if ca != rp.ca_id {
                    notes.push(format!(
                        "{at}: revoked range of another CA ({}), ignored",
                        f[1]
                    ));
                    continue;
                }
                rp.revoked_ranges
                    .push((parse_serial(f[2])?, parse_serial(f[3])?));
            }
            "group" | "require-cosigners" => {
                notes.push(format!(
                    "{at}: {:?} is a quorum rule; this crate's policy is \"the CA and all of -require\", so the line is ignored",
                    line
                ));
            }
            other => return Err(format!("{at}: unrecognized or malformed command {other:?}")),
        }
    }
    Ok(())
}

fn verify(args: &[String]) -> Res<bool> {
    let mut ca_paths = Vec::new();
    let mut policy = None;
    let mut subtree_files = Vec::new();
    let mut cosigner_paths = Vec::new();
    let mut require = Vec::new();
    let mut now = unix_now();
    let mut certs = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-ca-cert" => ca_paths.push(flag_value(args, &mut i, "-ca-cert")?.to_string()),
            "-policy" => policy = Some(flag_value(args, &mut i, "-policy")?.to_string()),
            "-subtrees" => subtree_files.push(flag_value(args, &mut i, "-subtrees")?.to_string()),
            "-cosigner-cert" => {
                cosigner_paths.push(flag_value(args, &mut i, "-cosigner-cert")?.to_string())
            }
            "-require" => require.push(
                TrustAnchorId::from_ascii(flag_value(args, &mut i, "-require")?)
                    .map_err(|e| format!("-require: {e:?}"))?,
            ),
            "-now" => {
                now = flag_value(args, &mut i, "-now")?
                    .parse()
                    .map_err(|_| "-now needs a POSIX time".to_string())?
            }
            other if other.starts_with('-') => return Err(format!("unknown flag {other}")),
            path => certs.push(path.to_string()),
        }
        i += 1;
    }
    if ca_paths.is_empty() {
        return Err("no CA certificates specified (use -ca-cert)".into());
    }
    if certs.is_empty() {
        return Err("no certificate files specified to verify".into());
    }
    let cas = read_ca_certificates(&ca_paths)?;
    let ca = match cas.as_slice() {
        [ca] => ca,
        _ => {
            return Err(format!(
                "{} CA certificates given; this relying party is configured for exactly one CA",
                cas.len()
            ))
        }
    };
    let (set, ca_entry) = ca.ml_dsa_cosigner_entry().map_err(|e| e.to_string())?;
    eprintln!(
        "CA {} ({}), serials {}..={}, log numbers {:?}",
        ca.ca_id.to_ascii(),
        set.name(),
        ca.min_serial,
        ca.max_serial,
        ca.log_numbers()
    );
    let mut rp = RelyingPartyConfig {
        ca_id: ca.ca_id.clone(),
        ca_oids: ca.oids,
        cosigners: vec![ca_entry],
        required_cosigners: require,
        trusted_subtrees: Vec::new(),
        revoked_ranges: Vec::new(),
    };
    let mut notes = Vec::new();
    if let Some(p) = policy {
        let text = fs::read_to_string(&p).map_err(|e| format!("{p}: {e}"))?;
        apply_policy(&text, &mut rp, &mut notes)?;
    }
    for p in &subtree_files {
        let text = fs::read_to_string(p).map_err(|e| format!("{p}: {e}"))?;
        apply_policy(&subtrees_as_policy(&text), &mut rp, &mut notes)
            .map_err(|e| format!("{p}: {e}"))?;
    }
    for (id, verifier) in read_cosigner_certificates(&cosigner_paths)? {
        if rp.cosigners.iter().any(|(cid, _)| *cid == id) {
            return Err(format!("cosigner {} defined twice", id.to_ascii()));
        }
        rp.cosigners.push((id, verifier));
    }
    for n in &notes {
        eprintln!("note: {n}");
    }
    for id in &rp.required_cosigners {
        if !rp.cosigners.iter().any(|(cid, _)| cid == id) {
            return Err(format!(
                "-require {}: no such cosigner in the CA certificate or the policy",
                id.to_ascii()
            ));
        }
    }

    let mut all_ok = true;
    for path in &certs {
        let text = fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
        let blocks = pem::decode_all(&text).map_err(|e| format!("{path}: {e}"))?;
        let mut seen = 0;
        for block in blocks.iter().filter(|b| b.label == "CERTIFICATE") {
            seen += 1;
            match verify_certificate(&block.der, &rp, now) {
                Ok(v) => {
                    println!("{path}: OK");
                    match &v.basis {
                        Basis::TrustedSubtree => println!("- Subtree was trusted"),
                        Basis::Cosignatures(ids) => println!(
                            "- Cosigned by: {}",
                            ids.iter()
                                .map(TrustAnchorId::to_ascii)
                                .collect::<Vec<_>>()
                                .join(", ")
                        ),
                    }
                    println!(
                        "- Serial {} (log {}, index {}), subtree {}, in CA range: {}, OIDs {}",
                        v.serial,
                        v.log_number,
                        v.index,
                        v.subtree,
                        ca.covers_serial(v.serial),
                        v.oids.name
                    );
                }
                Err(e) => {
                    all_ok = false;
                    println!("{path}: {e}");
                }
            }
        }
        if seen == 0 {
            all_ok = false;
            println!("{path}: no CERTIFICATE block");
        }
    }
    Ok(all_ok)
}

// ───────────────────────── checkpoint ─────────────────────────

/// The tlog-tiles path of tile `n` (`NNN`, `xNNN/NNN`, `.p` for partial).
fn tlog_index(mut n: u64, partial: bool) -> PathBuf {
    let mut s = if partial {
        format!("{:03}.p", n % 1000)
    } else {
        format!("{:03}", n % 1000)
    };
    n /= 1000;
    while n != 0 {
        s = format!("x{:03}/{s}", n % 1000);
        n /= 1000;
    }
    PathBuf::from(s)
}

/// The entries of one entry tile: a sequence of `uint16`-length-prefixed
/// `MTCLogEntry`s, as the Go tool writes them.
fn parse_entry_tile(data: &[u8]) -> Res<Vec<Vec<u8>>> {
    let mut out = Vec::new();
    let mut cur = data;
    while !cur.is_empty() {
        if cur.len() < 2 {
            return Err("truncated entry tile".into());
        }
        let len = u16::from_be_bytes([cur[0], cur[1]]) as usize;
        if cur.len() < 2 + len {
            return Err("truncated entry in tile".into());
        }
        out.push(cur[2..2 + len].to_vec());
        cur = &cur[2 + len..];
    }
    Ok(out)
}

fn read_entries(dir: &Path) -> Res<Vec<Vec<u8>>> {
    let base = dir.join("tile").join("entries");
    let mut entries = Vec::new();
    for i in 0u64.. {
        let full = base.join(tlog_index(i, false));
        if full.is_file() {
            let data = fs::read(&full).map_err(|e| format!("{}: {e}", full.display()))?;
            let tile = parse_entry_tile(&data)?;
            if tile.len() != 256 {
                return Err(format!(
                    "{}: a full tile with {} entries",
                    full.display(),
                    tile.len()
                ));
            }
            entries.extend(tile);
            continue;
        }
        let partial = base.join(tlog_index(i, true));
        if partial.is_dir() {
            let mut files: Vec<PathBuf> = fs::read_dir(&partial)
                .map_err(|e| format!("{}: {e}", partial.display()))?
                .filter_map(|e| e.ok().map(|e| e.path()))
                .collect();
            files.sort();
            let last = files
                .pop()
                .ok_or_else(|| format!("{}: empty partial tile directory", partial.display()))?;
            let width: usize = last
                .file_name()
                .and_then(|n| n.to_str())
                .and_then(|n| n.parse().ok())
                .ok_or_else(|| format!("{}: partial tile name is not a width", last.display()))?;
            let data = fs::read(&last).map_err(|e| format!("{}: {e}", last.display()))?;
            let tile = parse_entry_tile(&data)?;
            if tile.len() != width {
                return Err(format!(
                    "{}: named width {width} but {} entries",
                    last.display(),
                    tile.len()
                ));
            }
            entries.extend(tile);
        }
        break;
    }
    Ok(entries)
}

fn checkpoint(args: &[String]) -> Res<bool> {
    let mut dir = None;
    let mut ca_paths = Vec::new();
    let mut log_number: u16 = 1;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-dir" => dir = Some(PathBuf::from(flag_value(args, &mut i, "-dir")?)),
            "-ca-cert" => ca_paths.push(flag_value(args, &mut i, "-ca-cert")?.to_string()),
            "-log-number" => {
                log_number = flag_value(args, &mut i, "-log-number")?
                    .parse()
                    .map_err(|_| "-log-number needs a number".to_string())?
            }
            other => return Err(format!("unknown flag {other}")),
        }
        i += 1;
    }
    let dir = dir.ok_or("-dir is required")?;
    let cas = read_ca_certificates(&ca_paths)?;
    let ca = cas.first().ok_or("-ca-cert is required")?;
    let log_id = ca.ca_id.log_id(log_number).map_err(|e| format!("{e:?}"))?;

    // The note: origin, size, root, blank line, signature lines.
    let note =
        fs::read_to_string(dir.join("checkpoint")).map_err(|e| format!("checkpoint: {e}"))?;
    let lines: Vec<&str> = note.lines().collect();
    if lines.len() < 4 || !lines[3].is_empty() {
        return Err("checkpoint: not a signed note (origin, size, hash, blank line)".into());
    }
    let origin = lines[0];
    let size: u64 = lines[1].parse().map_err(|_| "checkpoint: bad size line")?;
    let root = pem::base64_decode(lines[2]).map_err(|e| format!("checkpoint: {e}"))?;
    let mut all_ok = true;
    let expected_origin = log_id.oid_name().map_err(|e| format!("{e:?}"))?;
    println!(
        "origin line {origin:?}: {}",
        if origin == expected_origin {
            "matches the log ID derived from the CA ID and log number".to_string()
        } else {
            all_ok = false;
            format!("MISMATCH, expected {expected_origin:?}")
        }
    );

    // The tree, rebuilt from the entry tiles with this crate's log.
    let entries = read_entries(&dir)?;
    let log = IssuanceLog::from_entries(log_number, entries).map_err(|e| format!("{e:?}"))?;
    println!(
        "entries read from tiles: {} ({})",
        log.size(),
        if log.size() == size {
            "same as the checkpoint's size"
        } else {
            all_ok = false;
            "DIFFERENT from the checkpoint's size"
        }
    );
    let ours = log.root();
    println!(
        "root recomputed: {} ({})",
        pem::base64_encode(&ours),
        if ours[..] == root[..] {
            "same as the checkpoint's hash"
        } else {
            all_ok = false;
            "DIFFERENT from the checkpoint's hash"
        }
    );

    // The CA's signature line, in the two spellings that exist today.
    let (_, verifier) = ml_dsa_verifier_from_spki(&ca.spki).map_err(|e| e.to_string())?;
    let ca_pk = spki::parse(&ca.spki)
        .map_err(|e| format!("{e:?}"))?
        .key
        .to_vec();
    let ca_name = ca.ca_id.oid_name().map_err(|e| format!("{e:?}"))?;
    let key_id = tlog_key_id_for(&ca.ca_id, &ca_pk).map_err(|e| e.to_string())?;
    let mut ca_lines = 0;
    for line in &lines[4..] {
        let Some(rest) = line.strip_prefix("\u{2014} ") else {
            continue;
        };
        let Some((name, b64)) = rest.split_once(' ') else {
            continue;
        };
        if name != ca_name {
            println!("signature line of {name:?}: not the CA, skipped");
            continue;
        }
        ca_lines += 1;
        let bytes = pem::base64_decode(b64).map_err(|e| format!("checkpoint: {e}"))?;
        if bytes.len() < 4 {
            println!("signature line of the CA: too short");
            all_ok = false;
            continue;
        }
        println!(
            "signature line of the CA: key ID {} ({})",
            der::hex(&bytes[..4]),
            if bytes[..4] == key_id {
                "same as SHA-256(name || \\n || 0x06 || key)[:4]"
            } else {
                all_ok = false;
                "DIFFERENT from the tlog-cosignature key ID"
            }
        );
        let sig = &bytes[4..];
        let message = |timestamp: u64| -> Res<Vec<u8>> {
            CosignedMessage {
                cosigner_id: ca.ca_id.clone(),
                timestamp,
                log_id: log_id.clone(),
                subtree: Subtree {
                    start: 0,
                    end: size,
                },
                subtree_hash: ours,
            }
            .to_bytes()
            .map_err(|e| e.to_string())
        };
        // (a) tlog-cosignature: `timestamp(8) || signature`, the timestamp
        //     inside the signed message.
        let with_timestamp = sig.len() > 8 && {
            let ts = u64::from_be_bytes(sig[..8].try_into().expect("8 bytes"));
            message(ts)
                .map(|m| verifier.verify(&m, &sig[8..]))
                .unwrap_or(false)
        };
        // (b) the reference tool today: the bare signature, timestamp 0.
        let bare = message(0)
            .map(|m| verifier.verify(&m, sig))
            .unwrap_or(false);
        match (with_timestamp, bare) {
            (true, _) => println!("- verifies as a timestamped tlog-cosignature (C2SP form)"),
            (_, true) => println!("- verifies as a bare subtree signature over [0, {size}) with timestamp 0 (the reference tool's form; no timestamp on the line)"),
            _ => {
                all_ok = false;
                println!("- does NOT verify in either form");
            }
        }
    }
    if ca_lines == 0 {
        all_ok = false;
        println!("no signature line of the CA found");
    }
    Ok(all_ok)
}
