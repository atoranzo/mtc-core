//! # The CA's certificate ("Representing Certification Authorities")
//!
//! The X.509 certificate that identifies a Merkle Tree CA to a relying
//! party: `subject` = the CA ID as a distinguished name, the CA cosigner's
//! key in `subjectPublicKeyInfo`, and the critical
//! `MTCCertificationAuthority { sigAlg, minSerial, maxSerial }` extension
//! (experimental OID `…47.4`). Key usage `keyCertSign` and basic
//! constraints `cA = TRUE` are required by the draft, so they are required
//! here in both directions.
//!
//! As the draft recommends for a trust anchor, [`CaCertificate::to_der`]
//! writes an **unsigned** certificate (RFC 9925): `id-alg-unsigned` as the
//! algorithm, an empty signature and the placeholder issuer, exactly as the
//! draft's reference implementation writes it. [`CaCertificate::from_der`]
//! does not look at the outer signature at all: whoever puts a CA
//! certificate in a trust store has decided to trust it; a cross-signed
//! one is read the same way.
//!
//! **One definition** for the CA that publishes itself and for the relying
//! party that reads another implementation's CA (the interoperability
//! target is `demo/` in the draft's repository).

use crate::der::{self, DerError};
use crate::entry::Validity;
use crate::proof::MAX_U48;
use crate::spki;
use crate::tai::{TaiError, TrustAnchorId};

/// `id-alg-unsigned` (RFC 9925).
pub const OID_ALG_UNSIGNED: [u64; 9] = [1, 3, 6, 1, 5, 5, 7, 6, 36];
/// `id-rdna-unsigned` (RFC 9925): the attribute of the placeholder issuer.
pub const OID_RDNA_UNSIGNED: [u64; 9] = [1, 3, 6, 1, 5, 5, 7, 25, 1];
/// `id-ce-keyUsage`.
pub const OID_KEY_USAGE: [u64; 4] = [2, 5, 29, 15];
/// `id-ce-basicConstraints`.
pub const OID_BASIC_CONSTRAINTS: [u64; 4] = [2, 5, 29, 19];
/// `mtcMinSerial`: 2^48, the smallest serial of log number 1.
pub const MTC_MIN_SERIAL: u64 = 1 << 48;

const TAG_UTF8_STRING: u8 = 0x0c;
const TAG_BOOLEAN: u8 = 0x01;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaCertError {
    Der(DerError),
    Tai(TaiError),
    /// `minSerial`/`maxSerial` outside `(mtcMinSerial..mtcMaxSerial)` or
    /// out of order.
    SerialRange {
        min: u64,
        max: u64,
    },
    /// A required extension is not there.
    MissingExtension(&'static str),
    /// An extension appears twice.
    DuplicateExtension(&'static str),
    /// The MTC CA extension is not marked critical (it MUST be).
    NotCritical,
    Malformed(&'static str),
    /// Key usage without `keyCertSign`.
    KeyUsageWithoutCertSign,
    /// Basic constraints without `cA = TRUE`.
    NotACa,
    /// The key is not one this build can verify with.
    UnsupportedKey(String),
}

impl core::fmt::Display for CaCertError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for CaCertError {}

impl From<DerError> for CaCertError {
    fn from(e: DerError) -> Self {
        CaCertError::Der(e)
    }
}

impl From<TaiError> for CaCertError {
    fn from(e: TaiError) -> Self {
        CaCertError::Tai(e)
    }
}

/// What a relying party needs to know about a CA.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaCertificate {
    pub ca_id: TrustAnchorId,
    /// The CA cosigner's `SubjectPublicKeyInfo`, whole.
    pub spki: Vec<u8>,
    /// The `sigAlg` of the extension: the whole `AlgorithmIdentifier`.
    pub sig_alg: Vec<u8>,
    pub min_serial: u64,
    pub max_serial: u64,
    pub validity: Validity,
    /// The OIDs of the extension and of the subject's attribute. On read,
    /// the two experimental sets are indistinguishable here and read as
    /// [`der::OIDS_EXPERIMENTAL_06`] (see [`der::OidSet::from_mtc_ca_extension`]).
    pub oids: der::OidSet,
}

fn extension(oid: &[u64], critical: bool, value: &[u8]) -> Vec<u8> {
    let mut e = der::oid(oid);
    if critical {
        e.extend([TAG_BOOLEAN, 0x01, 0xff]);
    }
    e.extend(der::octet_string(value));
    der::sequence(&e)
}

impl CaCertificate {
    fn check_serials(&self) -> Result<(), CaCertError> {
        if self.min_serial < MTC_MIN_SERIAL || self.max_serial < self.min_serial {
            return Err(CaCertError::SerialRange {
                min: self.min_serial,
                max: self.max_serial,
            });
        }
        Ok(())
    }

    /// `MTCCertificationAuthority ::= SEQUENCE { sigAlg, minSerial, maxSerial }`.
    pub fn extension_value(&self) -> Result<Vec<u8>, CaCertError> {
        self.check_serials()?;
        let mut v = self.sig_alg.clone();
        v.extend(der::integer_u64(self.min_serial));
        v.extend(der::integer_u64(self.max_serial));
        Ok(der::sequence(&v))
    }

    /// The unsigned certificate (RFC 9925): v3, serial 1, `id-alg-unsigned`,
    /// the placeholder issuer, the CA ID as subject, the cosigner's key,
    /// and three critical extensions: key usage `keyCertSign`, basic
    /// constraints `cA = TRUE`, and the MTC CA extension.
    pub fn to_der(&self) -> Result<Vec<u8>, CaCertError> {
        self.check_ids()?;
        self.encode()
    }

    /// The CA ID is a trust anchor ID, and so is the ID of each log its
    /// serial range covers: the highest log number has the longest one
    /// (AUDIT.md §27).
    fn check_ids(&self) -> Result<(), CaCertError> {
        self.ca_id.check_as_ca_id()?;
        self.ca_id.log_id(*self.log_numbers().end())?;
        Ok(())
    }

    /// The DER of [`Self::to_der`], without checking the IDs.
    fn encode(&self) -> Result<Vec<u8>, CaCertError> {
        spki::parse(&self.spki)?;
        der::expect_tlv(&self.sig_alg, der::TAG_SEQUENCE)?;

        let mut placeholder = der::oid(&OID_RDNA_UNSIGNED);
        placeholder.extend(der::tlv(TAG_UTF8_STRING, &[]));
        let issuer = der::sequence(&der::set(&der::sequence(&placeholder)));

        // keyCertSign is bit 5: one byte 0b0000_0100 with two unused bits.
        let key_usage = der::tlv(der::TAG_BIT_STRING, &[0x02, 0x04]);
        let basic_constraints = der::sequence(&[TAG_BOOLEAN, 0x01, 0xff]);
        let mut exts = extension(&OID_KEY_USAGE, true, &key_usage);
        exts.extend(extension(&OID_BASIC_CONSTRAINTS, true, &basic_constraints));
        exts.extend(extension(
            self.oids.mtc_ca_sha256,
            true,
            &self.extension_value()?,
        ));

        let mut tbs = der::explicit(0, &der::integer_u64(2));
        tbs.extend(der::integer_u64(1));
        tbs.extend(der::algorithm_identifier(&OID_ALG_UNSIGNED));
        tbs.extend(issuer);
        tbs.extend(self.validity.to_der());
        tbs.extend(der::name_from_ca_id(&self.ca_id, &self.oids));
        tbs.extend_from_slice(&self.spki);
        tbs.extend(der::explicit(3, &der::sequence(&exts)));

        let mut cert = der::sequence(&tbs);
        cert.extend(der::algorithm_identifier(&OID_ALG_UNSIGNED));
        cert.extend(der::bit_string(&[]));
        Ok(der::sequence(&cert))
    }

    /// Reads a CA certificate, from here or from another implementation.
    /// The outer signature is not checked (see the module's note). Fails
    /// closed on anything the draft states as MUST.
    pub fn from_der(cert: &[u8]) -> Result<Self, CaCertError> {
        let parts = der::parse_certificate(cert)?;
        let fields = der::parse_tbs(parts.tbs.raw)?;
        let validity = Validity::from_der(&fields.validity)?;
        spki::parse(fields.spki.raw)?;

        // The extensions: [3] EXPLICIT SEQUENCE OF Extension.
        let mut extensions = None;
        let mut tail = fields.after_spki;
        while !tail.is_empty() {
            let (t, next) = der::read_tlv(tail)?;
            if t.tag == 0xa3 {
                extensions = Some(t);
            }
            tail = next;
        }
        let exts = extensions.ok_or(CaCertError::MissingExtension("extensions"))?;
        let (seq, rest) = der::expect_tlv(exts.content, der::TAG_SEQUENCE)?;
        if !rest.is_empty() {
            return Err(DerError::TrailingData.into());
        }

        let mut cur = seq.content;
        let mut mtc: Option<(der::OidSet, bool, &[u8])> = None;
        let mut key_usage: Option<&[u8]> = None;
        let mut basic_constraints: Option<&[u8]> = None;
        while !cur.is_empty() {
            let (ext, next) = der::expect_tlv(cur, der::TAG_SEQUENCE)?;
            cur = next;
            let (oid, after) = der::expect_tlv(ext.content, der::TAG_OID)?;
            let (critical, after) = match der::read_tlv(after)? {
                (b, after) if b.tag == TAG_BOOLEAN => (b.content != [0x00], after),
                _ => (false, after),
            };
            let (value, after) = der::expect_tlv(after, der::TAG_OCTET_STRING)?;
            if !after.is_empty() {
                return Err(CaCertError::Malformed("extension"));
            }
            let arcs = spki::oid_arcs(oid.content)?;
            let slot = if let Some(set) = der::OidSet::from_mtc_ca_extension(&arcs) {
                // One MTC CA extension, of whichever set: two (the IANA one
                // and an experimental one) would be two answers to one question.
                if mtc.replace((set, critical, value.content)).is_some() {
                    return Err(CaCertError::DuplicateExtension("mtcCertificationAuthority"));
                }
                continue;
            } else if arcs == OID_KEY_USAGE {
                (&mut key_usage, "keyUsage")
            } else if arcs == OID_BASIC_CONSTRAINTS {
                (&mut basic_constraints, "basicConstraints")
            } else {
                continue;
            };
            if slot.0.replace(value.content).is_some() {
                return Err(CaCertError::DuplicateExtension(slot.1));
            }
        }

        // keyUsage: BIT STRING with keyCertSign (bit 5) set.
        let ku = key_usage.ok_or(CaCertError::MissingExtension("keyUsage"))?;
        let (bits, rest) = der::expect_tlv(ku, der::TAG_BIT_STRING)?;
        if !rest.is_empty() || bits.content.is_empty() {
            return Err(CaCertError::Malformed("keyUsage"));
        }
        let unused = usize::from(bits.content[0]);
        let bytes = &bits.content[1..];
        let cert_sign =
            bytes.first().is_some_and(|b| b & 0x04 != 0) && (bytes.len() > 1 || unused <= 2);
        if !cert_sign {
            return Err(CaCertError::KeyUsageWithoutCertSign);
        }

        // basicConstraints: SEQUENCE { cA BOOLEAN DEFAULT FALSE, pathLen? }.
        let bc = basic_constraints.ok_or(CaCertError::MissingExtension("basicConstraints"))?;
        let (bc_seq, rest) = der::expect_tlv(bc, der::TAG_SEQUENCE)?;
        if !rest.is_empty() {
            return Err(CaCertError::Malformed("basicConstraints"));
        }
        let is_ca = match der::read_tlv(bc_seq.content) {
            Ok((b, _)) if b.tag == TAG_BOOLEAN => b.content != [0x00],
            _ => false,
        };
        if !is_ca {
            return Err(CaCertError::NotACa);
        }

        // The MTC CA extension, critical.
        let (oids, critical, value) =
            mtc.ok_or(CaCertError::MissingExtension("mtcCertificationAuthority"))?;
        if !critical {
            return Err(CaCertError::NotCritical);
        }
        // The subject is the CA ID under the attribute of the extension's set.
        let ca_id = der::ca_id_from_name(fields.subject.raw, &oids)?;
        ca_id.check_as_ca_id()?;
        let (v, rest) = der::expect_tlv(value, der::TAG_SEQUENCE)?;
        if !rest.is_empty() {
            return Err(CaCertError::Malformed("mtcCertificationAuthority"));
        }
        let (sig_alg, rest) = der::expect_tlv(v.content, der::TAG_SEQUENCE)?;
        let (min, rest) = der::expect_tlv(rest, der::TAG_INTEGER)?;
        let (max, rest) = der::expect_tlv(rest, der::TAG_INTEGER)?;
        if !rest.is_empty() {
            return Err(CaCertError::Malformed("mtcCertificationAuthority"));
        }
        let ca = CaCertificate {
            ca_id,
            spki: fields.spki.raw.to_vec(),
            sig_alg: sig_alg.raw.to_vec(),
            min_serial: der::decode_integer_u64(min.content)?,
            max_serial: der::decode_integer_u64(max.content)?,
            validity,
            oids,
        };
        ca.check_serials()?;
        ca.check_ids()?;
        Ok(ca)
    }

    /// The log numbers this CA may use, from its serial range.
    pub fn log_numbers(&self) -> core::ops::RangeInclusive<u16> {
        ((self.min_serial >> 48) as u16)..=((self.max_serial >> 48) as u16)
    }

    /// Whether a serial number is within the CA's declared range.
    pub fn covers_serial(&self, serial: u64) -> bool {
        (self.min_serial..=self.max_serial).contains(&serial)
    }

    /// The index part of the serial range, for information.
    pub fn index_of(serial: u64) -> u64 {
        serial & MAX_U48
    }
}

#[cfg(feature = "ml-dsa")]
mod with_ml_dsa {
    use super::{CaCertError, CaCertificate};
    use crate::cosign::mldsa::{MlDsa44, MlDsa65, MlDsa87, MlDsaVerifier};
    use crate::cosign::CosignatureVerifier;
    use crate::spki::{self, MlDsaParameterSet};
    use crate::verify::CosignerEntry;

    /// A verifier for an ML-DSA SPKI (any of the three parameter sets).
    pub fn ml_dsa_verifier_from_spki(
        spki_der: &[u8],
    ) -> Result<(MlDsaParameterSet, Box<dyn CosignatureVerifier>), CaCertError> {
        let parsed = spki::parse(spki_der)?;
        let set = spki::ml_dsa_parameter_set(&parsed).ok_or_else(|| {
            CaCertError::UnsupportedKey(format!(
                "not an ML-DSA SubjectPublicKeyInfo (OID {:?}, {} key bytes)",
                parsed.oid(),
                parsed.key.len()
            ))
        })?;
        let verifier: Box<dyn CosignatureVerifier> = match set {
            MlDsaParameterSet::MlDsa44 => Box::new(
                MlDsaVerifier::<MlDsa44>::from_bytes(parsed.key)
                    .ok_or_else(|| CaCertError::UnsupportedKey("malformed ML-DSA-44 key".into()))?,
            ),
            MlDsaParameterSet::MlDsa65 => Box::new(
                MlDsaVerifier::<MlDsa65>::from_bytes(parsed.key)
                    .ok_or_else(|| CaCertError::UnsupportedKey("malformed ML-DSA-65 key".into()))?,
            ),
            MlDsaParameterSet::MlDsa87 => Box::new(
                MlDsaVerifier::<MlDsa87>::from_bytes(parsed.key)
                    .ok_or_else(|| CaCertError::UnsupportedKey("malformed ML-DSA-87 key".into()))?,
            ),
        };
        Ok((set, verifier))
    }

    impl CaCertificate {
        /// The CA's cosigner as a relying party's entry, if its key is
        /// ML-DSA and the extension's `sigAlg` names the same parameter
        /// set (RFC 9881 uses one OID for key and signature).
        pub fn ml_dsa_cosigner_entry(
            &self,
        ) -> Result<(MlDsaParameterSet, CosignerEntry), CaCertError> {
            let (set, verifier) = ml_dsa_verifier_from_spki(&self.spki)?;
            let (alg_oid, _) = crate::der::expect_tlv(
                crate::der::expect_tlv(&self.sig_alg, crate::der::TAG_SEQUENCE)?
                    .0
                    .content,
                crate::der::TAG_OID,
            )?;
            if spki::oid_arcs(alg_oid.content)? != set.oid() {
                return Err(CaCertError::UnsupportedKey(format!(
                    "the key is {} but sigAlg is another algorithm",
                    set.name()
                )));
            }
            Ok((set, (self.ca_id.clone(), verifier)))
        }
    }
}

#[cfg(feature = "ml-dsa")]
pub use with_ml_dsa::ml_dsa_verifier_from_spki;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spki::MlDsaParameterSet;

    /// AUDIT.md §27: a CA certificate whose CA ID, or the ID of its highest
    /// log, is longer than 32 bytes is neither written nor read.
    #[test]
    fn a_ca_certificate_with_ids_longer_than_32_bytes_is_refused() {
        let id = |n: usize| crate::TrustAnchorId::from_binary(&vec![1; n]).unwrap();
        assert_eq!(sample().log_numbers(), 1..=5);
        // 33 bytes: not a CA ID. 31 bytes: a CA ID, but log 5's ID is 33.
        for (n, too_long) in [(33, 33), (31, 33)] {
            let ca = CaCertificate {
                ca_id: id(n),
                ..sample()
            };
            let refused = Some(CaCertError::Tai(
                crate::tai::TaiError::TooLongForTrustAnchor(too_long),
            ));
            assert_eq!(ca.to_der().err(), refused);
            let der = ca.encode().unwrap();
            assert_eq!(CaCertificate::from_der(&der).err(), refused);
        }
        let ok = CaCertificate {
            ca_id: id(30),
            ..sample()
        };
        assert_eq!(CaCertificate::from_der(&ok.to_der().unwrap()).unwrap(), ok);
    }

    fn sample() -> CaCertificate {
        CaCertificate {
            ca_id: TrustAnchorId::from_ascii("32473.1").unwrap(),
            spki: spki::ml_dsa(MlDsaParameterSet::MlDsa44, &[9u8; 1312]),
            sig_alg: der::algorithm_identifier(&spki::OID_ML_DSA_44),
            min_serial: MTC_MIN_SERIAL,
            max_serial: (5 << 48) | MAX_U48,
            validity: Validity {
                not_before: 1_577_836_800, // 2020-01-01
                not_after: 1_924_991_999,  // 2030-12-31T23:59:59
            },
            oids: der::OIDS_IANA,
        }
    }

    #[test]
    fn round_trip_and_fixed_prefix() {
        let ca = sample();
        let der = ca.to_der().unwrap();
        assert_eq!(CaCertificate::from_der(&der).unwrap(), ca);
        // Unsigned: the outer algorithm and an empty BIT STRING at the end.
        let tail = [
            0x30, 0x0a, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, 0x24, 0x03, 0x01,
            0x00,
        ];
        assert_eq!(&der[der.len() - tail.len()..], &tail);
        assert_eq!(ca.log_numbers(), 1..=5);
        assert!(ca.covers_serial((3 << 48) | 17));
        assert!(!ca.covers_serial(6 << 48));
    }

    #[test]
    fn the_experimental_set_round_trips_and_a_mixed_one_is_refused() {
        let mut ca = sample();
        ca.oids = der::OIDS_EXPERIMENTAL_06;
        let der_exp = ca.to_der().unwrap();
        assert_eq!(CaCertificate::from_der(&der_exp).unwrap(), ca);
        // The IANA extension over an experimental subject: not a CA ID name
        // under the extension's set.
        let iana = sample().to_der().unwrap();
        let exp_name = der::name_from_ca_id(&sample().ca_id, &der::OIDS_EXPERIMENTAL_06);
        let iana_name = der::name_from_ca_id(&sample().ca_id, &der::OIDS_IANA);
        let pos = iana
            .windows(iana_name.len())
            .rposition(|w| w == &iana_name[..])
            .unwrap();
        let mut mixed = iana[..pos].to_vec();
        mixed.extend(&exp_name);
        mixed.extend(&iana[pos + iana_name.len()..]);
        // Lengths differ by two bytes; re-wrap is not needed for the parser to
        // reject it, because the outer lengths no longer match either.
        assert!(CaCertificate::from_der(&mixed).is_err());
    }

    #[test]
    fn serial_range_is_enforced_both_ways() {
        let mut ca = sample();
        ca.min_serial = 5;
        assert!(matches!(ca.to_der(), Err(CaCertError::SerialRange { .. })));
        ca.min_serial = 2 << 48;
        ca.max_serial = 1 << 48;
        assert!(matches!(ca.to_der(), Err(CaCertError::SerialRange { .. })));
    }

    #[test]
    fn the_musts_of_the_draft_are_checked_on_read() {
        let ca = sample();
        let der = ca.to_der().unwrap();
        // Flip the criticality of the MTC extension: the BOOLEAN 0xff that
        // follows its OID.
        let oid = der::oid(ca.oids.mtc_ca_sha256);
        let pos = der.windows(oid.len()).position(|w| w == &oid[..]).unwrap();
        let mut not_critical = der.clone();
        not_critical[pos + oid.len() + 2] = 0x00;
        assert_eq!(
            CaCertificate::from_der(&not_critical),
            Err(CaCertError::NotCritical)
        );
        // Clear keyCertSign.
        let ku = der::tlv(der::TAG_BIT_STRING, &[0x02, 0x04]);
        let pos = der.windows(ku.len()).position(|w| w == &ku[..]).unwrap();
        let mut no_cert_sign = der.clone();
        no_cert_sign[pos + 3] = 0x80; // digitalSignature only
        assert_eq!(
            CaCertificate::from_der(&no_cert_sign),
            Err(CaCertError::KeyUsageWithoutCertSign)
        );
        // cA = FALSE (encoded, non-DER, but the point is the value).
        let bc = der::sequence(&[TAG_BOOLEAN, 0x01, 0xff]);
        let pos = der.windows(bc.len()).position(|w| w == &bc[..]).unwrap();
        let mut not_ca = der.clone();
        not_ca[pos + 4] = 0x00;
        assert_eq!(CaCertificate::from_der(&not_ca), Err(CaCertError::NotACa));
    }

    #[cfg(feature = "ml-dsa")]
    #[test]
    fn a_real_key_becomes_a_cosigner_entry() {
        use crate::cosign::mldsa::{MlDsa44, MlDsaCosigner};
        let id = TrustAnchorId::from_ascii("32473.1").unwrap();
        let signer = MlDsaCosigner::<MlDsa44>::deterministic(id.clone(), [3u8; 32]);
        let mut ca = sample();
        ca.spki = spki::ml_dsa(MlDsaParameterSet::MlDsa44, &signer.verifying_key_bytes());
        let (set, (cid, _)) = ca.ml_dsa_cosigner_entry().unwrap();
        assert_eq!(set, MlDsaParameterSet::MlDsa44);
        assert_eq!(cid, id);
        // sigAlg naming another set is refused.
        ca.sig_alg = der::algorithm_identifier(&spki::OID_ML_DSA_65);
        assert!(ca.ml_dsa_cosigner_entry().is_err());
    }
}
