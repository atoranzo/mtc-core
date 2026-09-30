//! # The leaf: `MTCLogEntry` and `TBSCertificateLogEntry`
//!
//! In Arqueo the leaf was `native_leaf(public_id, saldo, nonce)`, a
//! commitment to three field elements. In MTC the leaf is what the CA
//! **certifies**: the certificate fields that do not depend on the size
//! of the key. The public key enters **through its hash** (`subjectPublicKey-
//! InfoHash`) and there is no signature inside the entry: that is why the log
//! does not grow with ML-DSA, which is the whole reason MTC exists.
//!
//! [`MtcLeaf`] is the CA's working structure (what the user asked for as
//! `MTCLeaf`: key, subject, validity, extensions); from it come **two**
//! encodings that have to match byte for byte:
//!
//! - [`MtcLeaf::tbs_cert_entry_data`], the fields of a
//!   `TBSCertificateLogEntry` concatenated (without the SEQUENCE header,
//!   so that the verifier hashes in a single pass), which goes inside the
//!   [`MtcLogEntry`] that is recorded in the log;
//! - [`MtcLeaf::tbs_certificate`], the X.509 `TBSCertificate` that travels in
//!   the certificate, with the serial number `(log << 48) | index` and the
//!   whole key.
//!
//! ⚠️ The verifier reconstructs the first from the second. If the two
//! diverge, no certificate verifies: there is a test that cross-checks them.

use crate::der::{self, DerError, Tlv};
use crate::hash::{hash_leaf, sha256, HashValue, HASH_SIZE};

/// `null_entry(0)`.
pub const NULL_ENTRY: u16 = 0;
/// `tbs_cert_entry(1)`.
pub const TBS_CERT_ENTRY: u16 = 1;
/// An `MTCLogEntry` does not exceed 65535 bytes (tlog compatibility).
pub const MAX_ENTRY_SIZE: usize = 65_535;

/// The entry extension types this CA recognizes. **Today, none**:
/// the draft's registry is empty, and "a CA MUST NOT sign a
/// subtree containing an entry with an `extension_type` it does not
/// recognize". When one is defined, it goes here with its semantics.
pub const RECOGNIZED_EXTENSION_TYPES: &[u16] = &[];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryError {
    /// The extensions are not in strictly increasing order of type.
    ExtensionsNotSorted,
    /// A field exceeds the maximum of its length prefix.
    TooLong(&'static str, usize),
    /// Unrecognized entry type: a CA must NOT sign what it does not understand.
    UnknownType(u16),
    /// Unrecognized entry extension type: likewise.
    UnknownExtension(u16),
    Truncated,
    Der(DerError),
}

impl core::fmt::Display for EntryError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for EntryError {}

impl From<DerError> for EntryError {
    fn from(e: DerError) -> Self {
        EntryError::Der(e)
    }
}

/// `MTCLogEntryExtension { extension_type, extension_data<0..2^16-1> }`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogEntryExtension {
    pub extension_type: u16,
    pub extension_data: Vec<u8>,
}

/// `MTCLogEntryExtension extensions<0..2^16-1>`, with its two-byte
/// prefix; requires strictly increasing order by type.
pub fn encode_extensions(exts: &[LogEntryExtension]) -> Result<Vec<u8>, EntryError> {
    let mut body = Vec::new();
    let mut last: Option<u16> = None;
    for e in exts {
        if last.is_some_and(|l| e.extension_type <= l) {
            return Err(EntryError::ExtensionsNotSorted);
        }
        last = Some(e.extension_type);
        if e.extension_data.len() > 0xffff {
            return Err(EntryError::TooLong(
                "extension_data",
                e.extension_data.len(),
            ));
        }
        body.extend_from_slice(&e.extension_type.to_be_bytes());
        body.extend_from_slice(&(e.extension_data.len() as u16).to_be_bytes());
        body.extend_from_slice(&e.extension_data);
    }
    if body.len() > 0xffff {
        return Err(EntryError::TooLong("extensions", body.len()));
    }
    let mut out = Vec::with_capacity(body.len() + 2);
    out.extend_from_slice(&(body.len() as u16).to_be_bytes());
    out.extend(body);
    Ok(out)
}

/// Reads `extensions<0..2^16-1>` and returns the remainder.
pub fn decode_extensions(input: &[u8]) -> Result<(Vec<LogEntryExtension>, &[u8]), EntryError> {
    if input.len() < 2 {
        return Err(EntryError::Truncated);
    }
    let len = u16::from_be_bytes([input[0], input[1]]) as usize;
    let (mut body, rest) = input[2..]
        .split_at_checked(len)
        .ok_or(EntryError::Truncated)?;
    let mut out = Vec::new();
    let mut last: Option<u16> = None;
    while !body.is_empty() {
        if body.len() < 4 {
            return Err(EntryError::Truncated);
        }
        let typ = u16::from_be_bytes([body[0], body[1]]);
        let dlen = u16::from_be_bytes([body[2], body[3]]) as usize;
        let (data, next) = body[4..]
            .split_at_checked(dlen)
            .ok_or(EntryError::Truncated)?;
        if last.is_some_and(|l| typ <= l) {
            return Err(EntryError::ExtensionsNotSorted);
        }
        last = Some(typ);
        out.push(LogEntryExtension {
            extension_type: typ,
            extension_data: data.to_vec(),
        });
        body = next;
    }
    Ok((out, rest))
}

/// `MTCLogEntry`: what is recorded in the log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MtcLogEntry {
    /// `null_entry`: asserts nothing; a CA certifies it without liability.
    Null { extensions: Vec<LogEntryExtension> },
    /// `tbs_cert_entry`: the fields of the `TBSCertificateLogEntry` concatenated.
    TbsCert {
        extensions: Vec<LogEntryExtension>,
        tbs_cert_entry_data: Vec<u8>,
    },
}

impl MtcLogEntry {
    pub fn extensions(&self) -> &[LogEntryExtension] {
        match self {
            MtcLogEntry::Null { extensions } | MtcLogEntry::TbsCert { extensions, .. } => {
                extensions
            }
        }
    }

    /// The TLS serialization of the entry.
    pub fn encode(&self) -> Result<Vec<u8>, EntryError> {
        let mut out = encode_extensions(self.extensions())?;
        match self {
            MtcLogEntry::Null { .. } => out.extend_from_slice(&NULL_ENTRY.to_be_bytes()),
            MtcLogEntry::TbsCert {
                tbs_cert_entry_data,
                ..
            } => {
                out.extend_from_slice(&TBS_CERT_ENTRY.to_be_bytes());
                out.extend_from_slice(tbs_cert_entry_data);
            }
        }
        if out.len() > MAX_ENTRY_SIZE {
            return Err(EntryError::TooLong("MTCLogEntry", out.len()));
        }
        Ok(out)
    }

    /// Reads an entry whose total length is known.
    pub fn decode(input: &[u8]) -> Result<Self, EntryError> {
        if input.len() > MAX_ENTRY_SIZE {
            return Err(EntryError::TooLong("MTCLogEntry", input.len()));
        }
        let (extensions, rest) = decode_extensions(input)?;
        if rest.len() < 2 {
            return Err(EntryError::Truncated);
        }
        let typ = u16::from_be_bytes([rest[0], rest[1]]);
        let data = &rest[2..];
        match typ {
            NULL_ENTRY if data.is_empty() => Ok(MtcLogEntry::Null { extensions }),
            NULL_ENTRY => Err(EntryError::Truncated),
            TBS_CERT_ENTRY => Ok(MtcLogEntry::TbsCert {
                extensions,
                tbs_cert_entry_data: data.to_vec(),
            }),
            other => Err(EntryError::UnknownType(other)),
        }
    }

    /// `MTH({entry}) = HASH(0x00 || entry)`.
    pub fn leaf_hash(&self) -> Result<HashValue, EntryError> {
        Ok(hash_leaf(&self.encode()?))
    }
}

/// `Validity { notBefore, notAfter }` in POSIX seconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Validity {
    pub not_before: u64,
    pub not_after: u64,
}

impl Validity {
    pub fn to_der(&self) -> Vec<u8> {
        let mut c = der::time(self.not_before);
        c.extend(der::time(self.not_after));
        der::sequence(&c)
    }

    /// Reads a `Validity` (the whole TLV).
    pub fn from_der(validity: &Tlv<'_>) -> Result<Self, DerError> {
        if validity.tag != der::TAG_SEQUENCE {
            return Err(DerError::UnexpectedTag {
                expected: der::TAG_SEQUENCE,
                found: validity.tag,
            });
        }
        let (nb, rest) = der::read_tlv(validity.content)?;
        let (na, rest) = der::read_tlv(rest)?;
        if !rest.is_empty() {
            return Err(DerError::TrailingData);
        }
        Ok(Validity {
            not_before: der::decode_time(&nb)?,
            not_after: der::decode_time(&na)?,
        })
    }

    pub fn contains(&self, now: u64) -> bool {
        self.not_before <= now && now <= self.not_after
    }
}

/// **The CA's working leaf**: what it certifies about an applicant.
///
/// The DER fields (`issuer`, `subject`, `spki`, `extensions`) are accepted
/// already encoded: they are produced by the validation layer (ACME + `x509-cert`),
/// not by this crate. `issuer` is set by the CA with [`der::name_from_ca_id`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MtcLeaf {
    /// `Version`: 2 = v3 (mandatory with extensions). 0 (v1) is omitted.
    pub version: u8,
    /// DER `Name` of the issuer: **the CA ID**, always.
    pub issuer: Vec<u8>,
    pub validity: Validity,
    /// DER `Name` of the subject (may be empty, `30 00`, if everything goes in the SAN).
    pub subject: Vec<u8>,
    /// The **whole** DER `SubjectPublicKeyInfo`: the entry carries its hash, the
    /// certificate carries it in full.
    pub spki: Vec<u8>,
    /// `issuerUniqueID [1] IMPLICIT` (BIT STRING content), rarely used.
    pub issuer_unique_id: Option<Vec<u8>>,
    /// `subjectUniqueID [2] IMPLICIT`, rarely used.
    pub subject_unique_id: Option<Vec<u8>>,
    /// DER `Extensions` (the SEQUENCE OF Extension, without the `[3]`).
    pub extensions: Option<Vec<u8>>,
}

impl MtcLeaf {
    /// The `algorithm` of the `SubjectPublicKeyInfo`, as a whole TLV.
    pub fn spki_algorithm(&self) -> Result<&[u8], EntryError> {
        Ok(der::spki_algorithm(&self.spki)?)
    }

    /// `subjectPublicKeyInfoHash`: the log's hash over the DER SPKI.
    pub fn spki_hash(&self) -> HashValue {
        sha256(&self.spki)
    }

    fn version_der(&self) -> Vec<u8> {
        if self.version == 0 {
            Vec::new()
        } else {
            der::explicit(0, &der::integer_u64(self.version as u64))
        }
    }

    fn tail_der(&self) -> Vec<u8> {
        let mut out = Vec::new();
        if let Some(id) = &self.issuer_unique_id {
            out.extend(der::implicit_primitive(1, id));
        }
        if let Some(id) = &self.subject_unique_id {
            out.extend(der::implicit_primitive(2, id));
        }
        if let Some(ext) = &self.extensions {
            out.extend(der::explicit(3, ext));
        }
        out
    }

    /// The fields of the `TBSCertificateLogEntry`, concatenated.
    pub fn tbs_cert_entry_data(&self) -> Result<Vec<u8>, EntryError> {
        let mut out = self.version_der();
        out.extend_from_slice(&self.issuer);
        out.extend(self.validity.to_der());
        out.extend_from_slice(&self.subject);
        out.extend_from_slice(self.spki_algorithm()?);
        out.extend(der::octet_string(&self.spki_hash()));
        out.extend(self.tail_der());
        Ok(out)
    }

    /// The log entry for this leaf. Rejects extensions that are not in
    /// [`RECOGNIZED_EXTENSION_TYPES`]: the CA would not sign them.
    pub fn log_entry(&self, extensions: Vec<LogEntryExtension>) -> Result<MtcLogEntry, EntryError> {
        if let Some(e) = extensions
            .iter()
            .find(|e| !RECOGNIZED_EXTENSION_TYPES.contains(&e.extension_type))
        {
            return Err(EntryError::UnknownExtension(e.extension_type));
        }
        Ok(MtcLogEntry::TbsCert {
            extensions,
            tbs_cert_entry_data: self.tbs_cert_entry_data()?,
        })
    }

    /// The X.509 `TBSCertificate` with `serialNumber = (log << 48) | index` and
    /// `signature = id-alg-mtcProof`.
    pub fn tbs_certificate(&self, serial: u64) -> Result<Vec<u8>, EntryError> {
        let mut c = self.version_der();
        c.extend(der::integer_u64(serial));
        c.extend(der::alg_id_mtc_proof());
        c.extend_from_slice(&self.issuer);
        c.extend(self.validity.to_der());
        c.extend_from_slice(&self.subject);
        c.extend_from_slice(&self.spki);
        c.extend(self.tail_der());
        Ok(der::sequence(&c))
    }
}

/// **The entry reconstructed from a `TBSCertificate`** (section
/// "Verifying Certificate Signatures", the single-pass hash): what the
/// verifier hashes without ever having seen the CA's leaf.
pub fn entry_bytes_from_tbs(
    tbs: &der::TbsFields<'_>,
    extensions: &[LogEntryExtension],
) -> Result<Vec<u8>, EntryError> {
    let mut out = encode_extensions(extensions)?;
    out.extend_from_slice(&TBS_CERT_ENTRY.to_be_bytes());
    if let Some(v) = tbs.version {
        out.extend_from_slice(v.raw);
    }
    out.extend_from_slice(tbs.issuer.raw);
    out.extend_from_slice(tbs.validity.raw);
    out.extend_from_slice(tbs.subject.raw);
    out.extend_from_slice(der::spki_algorithm(tbs.spki.raw)?);
    out.push(der::TAG_OCTET_STRING);
    out.push(HASH_SIZE as u8);
    out.extend_from_slice(&sha256(tbs.spki.raw));
    out.extend_from_slice(tbs.after_spki);
    Ok(out)
}

#[cfg(test)]
pub(crate) mod fixtures {
    use super::*;
    use crate::tai::TrustAnchorId;

    /// A toy SPKI: `SEQUENCE { AlgorithmIdentifier { OID }, BIT STRING key }`.
    pub fn toy_spki(key: &[u8]) -> Vec<u8> {
        let mut c = der::algorithm_identifier(&[1, 3, 101, 112]); // id-Ed25519, to name one
        c.extend(der::bit_string(key));
        der::sequence(&c)
    }

    pub fn leaf(ca: &TrustAnchorId, dns: &str, key: &[u8]) -> MtcLeaf {
        MtcLeaf {
            version: 2,
            issuer: der::name_from_ca_id(ca),
            validity: Validity {
                not_before: 1_800_000_000,
                not_after: 1_800_000_000 + 7 * 86_400,
            },
            subject: der::sequence(&[]),
            spki: toy_spki(key),
            issuer_unique_id: None,
            subject_unique_id: None,
            extensions: Some(der::san_dns_extensions(&[dns])),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tai::TrustAnchorId;

    #[test]
    fn the_entry_the_ca_logs_is_the_entry_the_verifier_rebuilds() {
        let ca = TrustAnchorId::from_ascii("32473.1").unwrap();
        let leaf = fixtures::leaf(&ca, "example.com", &[7u8; 32]);
        let entry = leaf.log_entry(vec![]).unwrap();
        assert_eq!(
            leaf.log_entry(vec![LogEntryExtension {
                extension_type: 9,
                extension_data: vec![]
            }])
            .err(),
            Some(EntryError::UnknownExtension(9))
        );
        let tbs = leaf.tbs_certificate((1u64 << 48) | 5).unwrap();
        let fields = der::parse_tbs(&tbs).unwrap();
        assert_eq!(
            entry_bytes_from_tbs(&fields, &[]).unwrap(),
            entry.encode().unwrap()
        );
        assert_eq!(
            der::decode_integer_u64(fields.serial.content).unwrap(),
            (1u64 << 48) | 5
        );
        assert_eq!(fields.signature.raw, der::alg_id_mtc_proof().as_slice());
        assert_eq!(Validity::from_der(&fields.validity).unwrap(), leaf.validity);
    }

    #[test]
    fn entries_round_trip_and_reject_disorder() {
        let e = MtcLogEntry::TbsCert {
            extensions: vec![
                LogEntryExtension {
                    extension_type: 1,
                    extension_data: vec![9],
                },
                LogEntryExtension {
                    extension_type: 7,
                    extension_data: vec![],
                },
            ],
            tbs_cert_entry_data: vec![1, 2, 3],
        };
        assert_eq!(MtcLogEntry::decode(&e.encode().unwrap()).unwrap(), e);
        let bad = MtcLogEntry::Null {
            extensions: vec![
                LogEntryExtension {
                    extension_type: 7,
                    extension_data: vec![],
                },
                LogEntryExtension {
                    extension_type: 7,
                    extension_data: vec![],
                },
            ],
        };
        assert_eq!(bad.encode(), Err(EntryError::ExtensionsNotSorted));
        assert_eq!(
            MtcLogEntry::decode(&[0, 0, 0, 2]),
            Err(EntryError::UnknownType(2))
        );
        assert_eq!(
            MtcLogEntry::decode(&[0, 0, 0, 0]).unwrap(),
            MtcLogEntry::Null { extensions: vec![] }
        );
    }
}
