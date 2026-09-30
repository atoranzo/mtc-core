//! # The bare minimum of DER and X.509 that an MTC CA needs to compose and read
//!
//! ⚠️ **This is not an X.509 parser.** It is just enough to (a) compose a
//! `TBSCertificateLogEntry` and a `TBSCertificate` from fields that
//! ALREADY arrive in DER (the subject `Name`, the `Extensions`, the
//! `SubjectPublicKeyInfo`) and (b) split a certificate into its fields
//! in order to hash the entry in a single pass, as the section
//! "Verifying Certificate Signatures" describes. Whoever needs to build a
//! `Name` with CN and O, or to parse a PKCS#10 CSR, does so with
//! RustCrypto's `x509-cert`/`der` and hands this crate the bytes.
//!
//! What does live here, because it is a **format decision of the draft**
//! and must have a single definition: the distinguished name of a CA ID
//! (`RELATIVE-OID` under the experimental attribute), the OIDs of the
//! `1.3.6.1.4.1.44363.47` arc and the `AlgorithmIdentifier` of `id-alg-mtcProof`.

use crate::tai::TrustAnchorId;

/// The experimental arc the draft reserves (donated by Cloudflare).
pub const ARC_MTC_EXPERIMENTAL: [u64; 8] = [1, 3, 6, 1, 4, 1, 44363, 47];

/// `id-rdna-trustAnchorID`, in its experimental OID `…47.3`.
pub fn oid_rdna_trust_anchor_id() -> Vec<u64> {
    let mut v = ARC_MTC_EXPERIMENTAL.to_vec();
    v.push(3);
    v
}

/// `id-pe-mtcCertificationAuthority-SHA256`, experimental `…47.4`.
pub fn oid_pe_mtc_ca_sha256() -> Vec<u64> {
    let mut v = ARC_MTC_EXPERIMENTAL.to_vec();
    v.push(4);
    v
}

/// `id-alg-mtcProof`, experimental `…47.5`.
pub fn oid_alg_mtc_proof() -> Vec<u64> {
    let mut v = ARC_MTC_EXPERIMENTAL.to_vec();
    v.push(5);
    v
}

/// `id-ce-subjectAltName`.
pub const OID_SUBJECT_ALT_NAME: [u64; 4] = [2, 5, 29, 17];

pub const TAG_INTEGER: u8 = 0x02;
pub const TAG_BIT_STRING: u8 = 0x03;
pub const TAG_OCTET_STRING: u8 = 0x04;
pub const TAG_OID: u8 = 0x06;
pub const TAG_RELATIVE_OID: u8 = 0x0d;
pub const TAG_IA5_STRING: u8 = 0x16;
pub const TAG_UTC_TIME: u8 = 0x17;
pub const TAG_GENERALIZED_TIME: u8 = 0x18;
pub const TAG_SEQUENCE: u8 = 0x30;
pub const TAG_SET: u8 = 0x31;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DerError {
    Truncated,
    /// Length in non-minimal form, indefinite, or larger than `usize`.
    BadLength,
    UnexpectedTag {
        expected: u8,
        found: u8,
    },
    /// Bytes were left unconsumed where there should have been none.
    TrailingData,
    BadInteger,
    BadTime,
    BadOid,
    /// The `Name` is not that of a CA ID (a single RDN with a single
    /// `id-rdna-trustAnchorID` attribute).
    NotACaIdName,
}

impl core::fmt::Display for DerError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for DerError {}

// ───────────────────────── encoding ─────────────────────────

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// DER length (definite, minimal form).
pub fn encode_len(n: usize) -> Vec<u8> {
    if n < 0x80 {
        vec![n as u8]
    } else {
        let bytes = n.to_be_bytes();
        let first = bytes
            .iter()
            .position(|b| *b != 0)
            .unwrap_or(bytes.len() - 1);
        let mut v = vec![0x80 | (bytes.len() - first) as u8];
        v.extend_from_slice(&bytes[first..]);
        v
    }
}

/// `tag || len || content`.
pub fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(content.len() + 4);
    v.push(tag);
    v.extend(encode_len(content.len()));
    v.extend_from_slice(content);
    v
}

pub fn sequence(content: &[u8]) -> Vec<u8> {
    tlv(TAG_SEQUENCE, content)
}

pub fn set(content: &[u8]) -> Vec<u8> {
    tlv(TAG_SET, content)
}

pub fn octet_string(content: &[u8]) -> Vec<u8> {
    tlv(TAG_OCTET_STRING, content)
}

/// `[n] EXPLICIT`: constructed, context-specific.
pub fn explicit(n: u8, content: &[u8]) -> Vec<u8> {
    tlv(0xa0 | n, content)
}

/// `[n] IMPLICIT` over a primitive type.
pub fn implicit_primitive(n: u8, content: &[u8]) -> Vec<u8> {
    tlv(0x80 | n, content)
}

/// `BIT STRING` with no unused bits.
pub fn bit_string(bytes: &[u8]) -> Vec<u8> {
    let mut content = Vec::with_capacity(bytes.len() + 1);
    content.push(0x00);
    content.extend_from_slice(bytes);
    tlv(TAG_BIT_STRING, &content)
}

pub fn ia5_string(s: &str) -> Vec<u8> {
    tlv(TAG_IA5_STRING, s.as_bytes())
}

/// Non-negative `INTEGER`, in its minimal form.
pub fn integer_u64(v: u64) -> Vec<u8> {
    let bytes = v.to_be_bytes();
    let first = bytes
        .iter()
        .position(|b| *b != 0)
        .unwrap_or(bytes.len() - 1);
    let mut content = Vec::new();
    if bytes[first] & 0x80 != 0 {
        content.push(0x00);
    }
    content.extend_from_slice(&bytes[first..]);
    tlv(TAG_INTEGER, &content)
}

/// A non-negative `INTEGER` that fits in a `u64`.
pub fn decode_integer_u64(content: &[u8]) -> Result<u64, DerError> {
    if content.is_empty() || content[0] & 0x80 != 0 {
        return Err(DerError::BadInteger);
    }
    if content.len() > 1 && content[0] == 0 && content[1] & 0x80 == 0 {
        return Err(DerError::BadInteger); // non-minimal
    }
    let digits = if content[0] == 0 {
        &content[1..]
    } else {
        content
    };
    if digits.len() > 8 {
        return Err(DerError::BadInteger);
    }
    let mut v = 0u64;
    for b in digits {
        v = (v << 8) | *b as u64;
    }
    Ok(v)
}

/// Base 128 of one subidentifier, big-endian, high bit as continuation.
pub fn base128(v: u64, out: &mut Vec<u8>) {
    let mut tmp = [0u8; 10];
    let mut i = tmp.len();
    let mut v = v;
    loop {
        i -= 1;
        tmp[i] = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            break;
        }
    }
    let last = tmp.len() - 1;
    for (j, b) in tmp[i..].iter().enumerate() {
        out.push(if i + j == last { *b } else { *b | 0x80 });
    }
}

/// Reads a whole base 128 sequence (several subidentifiers).
pub fn decode_base128(content: &[u8]) -> Result<Vec<u64>, DerError> {
    let mut out = Vec::new();
    let mut acc: u64 = 0;
    let mut in_progress = false;
    for b in content {
        if !in_progress && *b == 0x80 {
            return Err(DerError::BadOid); // non-minimal padding
        }
        if acc >> 57 != 0 {
            return Err(DerError::BadOid); // would overflow
        }
        acc = (acc << 7) | (*b & 0x7f) as u64;
        in_progress = b & 0x80 != 0;
        if !in_progress {
            out.push(acc);
            acc = 0;
        }
    }
    if in_progress {
        return Err(DerError::Truncated);
    }
    Ok(out)
}

/// The content of an absolute `OBJECT IDENTIFIER`.
pub fn oid_content(arcs: &[u64]) -> Vec<u8> {
    assert!(arcs.len() >= 2, "an OID has at least two arcs");
    let mut out = Vec::new();
    base128(arcs[0] * 40 + arcs[1], &mut out);
    for a in &arcs[2..] {
        base128(*a, &mut out);
    }
    out
}

pub fn oid(arcs: &[u64]) -> Vec<u8> {
    tlv(TAG_OID, &oid_content(arcs))
}

pub fn relative_oid(content: &[u8]) -> Vec<u8> {
    tlv(TAG_RELATIVE_OID, content)
}

/// `AlgorithmIdentifier { algorithm, parameters omitted }`.
pub fn algorithm_identifier(arcs: &[u64]) -> Vec<u8> {
    sequence(&oid(arcs))
}

/// The `AlgorithmIdentifier` of `id-alg-mtcProof`, without parameters.
pub fn alg_id_mtc_proof() -> Vec<u8> {
    algorithm_identifier(&oid_alg_mtc_proof())
}

// ───────────────────────── time ─────────────────────────

/// Days since 1970-01-01 of a civil date (Hinnant's algorithm).
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64;
    let mp = if m > 2 { m - 3 } else { m + 9 } as u64;
    let doy = (153 * mp + 2) / 5 + d as u64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe as i64 - 719468
}

/// Civil date of a number of days since 1970-01-01.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// A POSIX instant as an RFC 5280 `Time`: `UTCTime` through 2049,
/// `GeneralizedTime` from 2050 on.
pub fn time(posix: u64) -> Vec<u8> {
    let days = (posix / 86_400) as i64;
    let secs = posix % 86_400;
    let (y, m, d) = civil_from_days(days);
    let (hh, mm, ss) = (secs / 3600, (secs / 60) % 60, secs % 60);
    if (1950..2050).contains(&y) {
        let s = format!("{:02}{m:02}{d:02}{hh:02}{mm:02}{ss:02}Z", y % 100);
        tlv(TAG_UTC_TIME, s.as_bytes())
    } else {
        let s = format!("{y:04}{m:02}{d:02}{hh:02}{mm:02}{ss:02}Z");
        tlv(TAG_GENERALIZED_TIME, s.as_bytes())
    }
}

fn digits(s: &[u8]) -> Result<u64, DerError> {
    let mut v = 0u64;
    for b in s {
        if !b.is_ascii_digit() {
            return Err(DerError::BadTime);
        }
        v = v * 10 + (b - b'0') as u64;
    }
    Ok(v)
}

/// An RFC 5280 `Time` to POSIX.
pub fn decode_time(t: &Tlv<'_>) -> Result<u64, DerError> {
    let (year, rest) = match t.tag {
        TAG_UTC_TIME if t.content.len() == 13 => {
            let yy = digits(&t.content[..2])?;
            (
                if yy >= 50 { 1900 + yy } else { 2000 + yy },
                &t.content[2..],
            )
        }
        TAG_GENERALIZED_TIME if t.content.len() == 15 => {
            (digits(&t.content[..4])?, &t.content[4..])
        }
        _ => return Err(DerError::BadTime),
    };
    if rest[10] != b'Z' {
        return Err(DerError::BadTime);
    }
    let m = digits(&rest[0..2])? as u32;
    let d = digits(&rest[2..4])? as u32;
    let hh = digits(&rest[4..6])?;
    let mm = digits(&rest[6..8])?;
    let ss = digits(&rest[8..10])?;
    // RFC 5280 does not allow leap seconds (00-59), and a day that does not
    // exist (February 30) must not silently become March 2: the civil date
    // is required to round-trip to the same value.
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) || hh > 23 || mm > 59 || ss > 59 {
        return Err(DerError::BadTime);
    }
    let days = days_from_civil(year as i64, m, d);
    if civil_from_days(days) != (year as i64, m, d) {
        return Err(DerError::BadTime);
    }
    // Before 1970 (UTCTime 1950-1969): no certificate carries them, and a
    // `u64` cannot represent them. Fail closed.
    if days < 0 {
        return Err(DerError::BadTime);
    }
    Ok(days as u64 * 86_400 + hh * 3600 + mm * 60 + ss)
}

// ───────────────────────── reading ─────────────────────────

/// A DER element as read: its tag, its content and the whole TLV.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tlv<'a> {
    pub tag: u8,
    pub content: &'a [u8],
    pub raw: &'a [u8],
}

/// Reads the first TLV of `input` (single-byte tags, definite length).
pub fn read_tlv(input: &[u8]) -> Result<(Tlv<'_>, &[u8]), DerError> {
    if input.len() < 2 {
        return Err(DerError::Truncated);
    }
    let tag = input[0];
    if tag & 0x1f == 0x1f {
        return Err(DerError::BadLength); // long-form tags: out of scope
    }
    let (len, header) = if input[1] < 0x80 {
        (input[1] as usize, 2)
    } else {
        let n = (input[1] & 0x7f) as usize;
        if n == 0 || n > 8 || input.len() < 2 + n {
            return Err(DerError::BadLength);
        }
        if input[2] == 0 {
            return Err(DerError::BadLength); // non-minimal
        }
        let mut len: u64 = 0;
        for b in &input[2..2 + n] {
            len = (len << 8) | *b as u64; // n <= 8: cannot overflow
        }
        if len < 0x80 {
            return Err(DerError::BadLength); // would have fit in short form
        }
        // ⚠️ A `len` close to 2^64 cannot be added to `header` without
        //    overflowing: whatever does not fit in the buffer is, simply, truncated.
        let len = usize::try_from(len).map_err(|_| DerError::Truncated)?;
        (len, 2 + n)
    };
    let end = header.checked_add(len).ok_or(DerError::Truncated)?;
    if input.len() < end {
        return Err(DerError::Truncated);
    }
    let raw = &input[..header + len];
    Ok((
        Tlv {
            tag,
            content: &input[header..header + len],
            raw,
        },
        &input[header + len..],
    ))
}

/// Reads a TLV and requires a given tag.
pub fn expect_tlv(input: &[u8], tag: u8) -> Result<(Tlv<'_>, &[u8]), DerError> {
    let (t, rest) = read_tlv(input)?;
    if t.tag != tag {
        return Err(DerError::UnexpectedTag {
            expected: tag,
            found: t.tag,
        });
    }
    Ok((t, rest))
}

// ───────────────────────── X.509 ─────────────────────────

/// **The `Name` of a CA ID** (section "Certification Authority
/// Identifiers"): a single RDN with a single `id-rdna-trustAnchorID`
/// attribute whose value is the identifier's `RELATIVE-OID`. It goes as the
/// `issuer` of every entry and every certificate, and as the `subject` of
/// the CA's certificate.
pub fn name_from_ca_id(ca_id: &TrustAnchorId) -> Vec<u8> {
    let mut attr = oid(&oid_rdna_trust_anchor_id());
    attr.extend(relative_oid(&ca_id.to_binary()));
    sequence(&set(&sequence(&attr)))
}

/// Reads the CA ID from a `Name` composed by [`name_from_ca_id`].
pub fn ca_id_from_name(name: &[u8]) -> Result<TrustAnchorId, DerError> {
    let (seq, rest) = expect_tlv(name, TAG_SEQUENCE)?;
    if !rest.is_empty() {
        return Err(DerError::TrailingData);
    }
    let (rdn, rest) = expect_tlv(seq.content, TAG_SET)?;
    if !rest.is_empty() {
        return Err(DerError::NotACaIdName);
    }
    let (attr, rest) = expect_tlv(rdn.content, TAG_SEQUENCE)?;
    if !rest.is_empty() {
        return Err(DerError::NotACaIdName);
    }
    let (typ, rest) = expect_tlv(attr.content, TAG_OID)?;
    if typ.content != oid_content(&oid_rdna_trust_anchor_id()) {
        return Err(DerError::NotACaIdName);
    }
    let (val, rest) = expect_tlv(rest, TAG_RELATIVE_OID)?;
    if !rest.is_empty() {
        return Err(DerError::NotACaIdName);
    }
    TrustAnchorId::from_binary(val.content).map_err(|_| DerError::BadOid)
}

/// An `Extensions` with a single `subjectAltName` extension of DNS names,
/// marked critical (RFC 5280 requires it if the `subject` is empty, which is
/// the usual case in TLS). A helper for tests and demonstrations: a real CA
/// receives its extensions from its validation layer.
pub fn san_dns_extensions(names: &[&str]) -> Vec<u8> {
    let mut general_names = Vec::new();
    for n in names {
        general_names.extend(implicit_primitive(2, n.as_bytes())); // dNSName [2]
    }
    let value = sequence(&general_names);
    let mut ext = oid(&OID_SUBJECT_ALT_NAME);
    ext.extend([0x01, 0x01, 0xff]); // critical BOOLEAN TRUE
    ext.extend(octet_string(&value));
    sequence(&sequence(&ext))
}

/// The fields of a `TBSCertificate`, split up without interpretation.
#[derive(Debug, Clone, Copy)]
pub struct TbsFields<'a> {
    pub version: Option<Tlv<'a>>,
    pub serial: Tlv<'a>,
    pub signature: Tlv<'a>,
    pub issuer: Tlv<'a>,
    pub validity: Tlv<'a>,
    pub subject: Tlv<'a>,
    pub spki: Tlv<'a>,
    /// Everything that follows the `subjectPublicKeyInfo`: the unique
    /// identifiers and the extensions, as they are.
    pub after_spki: &'a [u8],
}

/// Splits the `TBSCertificate` (the whole SEQUENCE, with its header).
pub fn parse_tbs(tbs: &[u8]) -> Result<TbsFields<'_>, DerError> {
    let (seq, rest) = expect_tlv(tbs, TAG_SEQUENCE)?;
    if !rest.is_empty() {
        return Err(DerError::TrailingData);
    }
    let mut cur = seq.content;
    let (first, after) = read_tlv(cur)?;
    let version = if first.tag == 0xa0 {
        cur = after;
        Some(first)
    } else {
        None
    };
    let (serial, after) = expect_tlv(cur, TAG_INTEGER)?;
    let (signature, after) = expect_tlv(after, TAG_SEQUENCE)?;
    let (issuer, after) = expect_tlv(after, TAG_SEQUENCE)?;
    let (validity, after) = expect_tlv(after, TAG_SEQUENCE)?;
    let (subject, after) = expect_tlv(after, TAG_SEQUENCE)?;
    let (spki, after_spki) = expect_tlv(after, TAG_SEQUENCE)?;
    // What follows must be a well-formed sequence of [1], [2], [3].
    let mut tail = after_spki;
    let mut last = 0u8;
    while !tail.is_empty() {
        let (t, next) = read_tlv(tail)?;
        let n = t.tag & 0x1f;
        if !matches!(t.tag, 0x81 | 0x82 | 0xa3) || n <= last {
            return Err(DerError::UnexpectedTag {
                expected: 0xa3,
                found: t.tag,
            });
        }
        last = n;
        tail = next;
    }
    Ok(TbsFields {
        version,
        serial,
        signature,
        issuer,
        validity,
        subject,
        spki,
        after_spki,
    })
}

/// The `algorithm` of a `SubjectPublicKeyInfo`, as a whole TLV.
pub fn spki_algorithm(spki: &[u8]) -> Result<&[u8], DerError> {
    let (seq, rest) = expect_tlv(spki, TAG_SEQUENCE)?;
    if !rest.is_empty() {
        return Err(DerError::TrailingData);
    }
    let (alg, rest) = expect_tlv(seq.content, TAG_SEQUENCE)?;
    expect_tlv(rest, TAG_BIT_STRING)?;
    Ok(alg.raw)
}

/// The three parts of a `Certificate`.
#[derive(Debug, Clone, Copy)]
pub struct CertificateParts<'a> {
    pub tbs: Tlv<'a>,
    pub signature_algorithm: Tlv<'a>,
    /// The content of the `BIT STRING`, already without the unused-bits byte
    /// (which must be zero).
    pub signature_value: &'a [u8],
}

pub fn parse_certificate(der: &[u8]) -> Result<CertificateParts<'_>, DerError> {
    let (seq, rest) = expect_tlv(der, TAG_SEQUENCE)?;
    if !rest.is_empty() {
        return Err(DerError::TrailingData);
    }
    let (tbs, after) = expect_tlv(seq.content, TAG_SEQUENCE)?;
    let (signature_algorithm, after) = expect_tlv(after, TAG_SEQUENCE)?;
    let (sig, after) = expect_tlv(after, TAG_BIT_STRING)?;
    if !after.is_empty() {
        return Err(DerError::TrailingData);
    }
    if sig.content.is_empty() || sig.content[0] != 0 {
        return Err(DerError::BadLength); // the MTCProof is in whole bytes
    }
    Ok(CertificateParts {
        tbs,
        signature_algorithm,
        signature_value: &sig.content[1..],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ca_id_name_matches_the_example_of_the_draft() {
        // "1.3.6.1.4.1.44363.47.3=#0d0481fd5901" for the CA ID 32473.1.
        let ca = TrustAnchorId::new(vec![32473, 1]).unwrap();
        let name = name_from_ca_id(&ca);
        assert!(hex(&name).ends_with("0d0481fd5901"));
        assert_eq!(
            hex(&oid(&oid_rdna_trust_anchor_id())),
            "060a2b0601040182da4b2f03"
        );
        assert_eq!(ca_id_from_name(&name).unwrap(), ca);
    }

    #[test]
    fn integers_are_minimal() {
        assert_eq!(integer_u64(0), vec![0x02, 0x01, 0x00]);
        assert_eq!(integer_u64(127), vec![0x02, 0x01, 0x7f]);
        assert_eq!(integer_u64(128), vec![0x02, 0x02, 0x00, 0x80]);
        for v in [0u64, 1, 127, 128, 255, 256, 1 << 48, u64::MAX] {
            let enc = integer_u64(v);
            let (t, _) = read_tlv(&enc).unwrap();
            assert_eq!(decode_integer_u64(t.content).unwrap(), v);
        }
    }

    #[test]
    fn lengths_round_trip() {
        for n in [0usize, 1, 127, 128, 255, 256, 65535, 65536, 1 << 20] {
            let content = vec![0xaa; n];
            let enc = tlv(TAG_OCTET_STRING, &content);
            let (t, rest) = read_tlv(&enc).unwrap();
            assert_eq!(t.content.len(), n);
            assert!(rest.is_empty());
        }
    }

    #[test]
    fn time_round_trips_across_the_utctime_boundary() {
        for posix in [
            0u64,
            1_700_000_000,
            2_524_607_999,
            2_524_608_000,
            4_102_444_800,
        ] {
            let enc = time(posix);
            let (t, _) = read_tlv(&enc).unwrap();
            assert_eq!(
                decode_time(&t).unwrap(),
                posix,
                "{}",
                String::from_utf8_lossy(t.content)
            );
        }
        // 2049-12-31T23:59:59Z is still UTCTime; 2050-01-01 is already GeneralizedTime.
        assert_eq!(time(2_524_607_999)[0], TAG_UTC_TIME);
        assert_eq!(time(2_524_608_000)[0], TAG_GENERALIZED_TIME);
    }

    /// Nothing that arrives over the wire may make the reader panic:
    /// long lengths that overflow, indefinite ones, non-minimal ones,
    /// truncated content, leftovers.
    #[test]
    fn malformed_der_fails_closed() {
        let cases: [(&[u8], DerError); 9] = [
            (
                &[0x30, 0x88, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
                DerError::Truncated,
            ),
            (&[0x30, 0x84, 0xff, 0xff, 0xff, 0xff], DerError::Truncated),
            (&[0x30, 0x80, 0x00, 0x00], DerError::BadLength), // indefinite
            (&[0x30, 0x81, 0x05, 1, 2, 3, 4, 5], DerError::BadLength), // would have fit in short form
            (&[0x30, 0x82, 0x00, 0x80, 0x00], DerError::BadLength),    // non-minimal
            (
                &[0x30, 0x89, 1, 2, 3, 4, 5, 6, 7, 8, 9],
                DerError::BadLength,
            ), // more than 8 bytes
            (&[0x30, 0x05, 1, 2], DerError::Truncated),
            (&[0x30], DerError::Truncated),
            (&[0x1f, 0x01, 0x00], DerError::BadLength), // long-form tag
        ];
        for (input, err) in cases {
            assert_eq!(read_tlv(input).err(), Some(err), "{}", hex(input));
        }
        assert_eq!(
            expect_tlv(&[0x04, 0x00], TAG_SEQUENCE).err(),
            Some(DerError::UnexpectedTag {
                expected: 0x30,
                found: 0x04
            })
        );
        assert_eq!(
            parse_certificate(&[0x30, 0x00, 0x00]).err(),
            Some(DerError::TrailingData)
        );
        assert_eq!(
            parse_tbs(&[0x30, 0x02, 0x05, 0x00]).err(),
            Some(DerError::UnexpectedTag {
                expected: TAG_INTEGER,
                found: 0x05
            })
        );
        // A BIT STRING with unused bits is not an MTCProof.
        let mut cert = sequence(&[]);
        cert.extend(sequence(&[]));
        cert.extend(tlv(TAG_BIT_STRING, &[0x03, 0xaa]));
        assert_eq!(
            parse_certificate(&sequence(&cert)).err(),
            Some(DerError::BadLength)
        );
        // Negative or non-minimal integers.
        assert_eq!(decode_integer_u64(&[0x80]), Err(DerError::BadInteger));
        assert_eq!(decode_integer_u64(&[0x00, 0x01]), Err(DerError::BadInteger));
        assert_eq!(decode_integer_u64(&[0x01; 9]), Err(DerError::BadInteger));
        assert_eq!(decode_integer_u64(&[]), Err(DerError::BadInteger));
    }

    #[test]
    fn impossible_dates_are_rejected() {
        for bad in [
            "230230120000Z", // February 30
            "230229120000Z", // 2023 is not a leap year
            "231301120000Z", // month 13
            "230101120060Z", // second 60
            "230101240000Z", // hour 24
            "23010112000Z",  // too short
            "230101120000",  // no Z
            "691231235959Z", // 1969: before the epoch
        ] {
            let enc = tlv(TAG_UTC_TIME, bad.as_bytes());
            let (t, _) = read_tlv(&enc).unwrap();
            assert_eq!(decode_time(&t), Err(DerError::BadTime), "{bad}");
        }
        let leap = tlv(TAG_GENERALIZED_TIME, b"20240229120000Z");
        let (t, _) = read_tlv(&leap).unwrap();
        assert!(decode_time(&t).is_ok()); // 2024 is a leap year
        let pre_epoch = tlv(TAG_GENERALIZED_TIME, b"19690101000000Z");
        let (t, _) = read_tlv(&pre_epoch).unwrap();
        assert_eq!(decode_time(&t), Err(DerError::BadTime));
    }

    #[test]
    fn base128_round_trips() {
        for v in [
            0u64,
            1,
            127,
            128,
            16383,
            16384,
            44363,
            32473,
            u32::MAX as u64,
            1 << 56,
        ] {
            let mut out = Vec::new();
            base128(v, &mut out);
            assert_eq!(decode_base128(&out).unwrap(), vec![v]);
        }
        assert_eq!(decode_base128(&[0x80, 0x01]), Err(DerError::BadOid));
        assert_eq!(decode_base128(&[0x81]), Err(DerError::Truncated));
    }
}
