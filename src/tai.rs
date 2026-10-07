//! # Trust anchor identifiers (`TrustAnchorID`)
//!
//! The CA ID, the log IDs (`caID.0.N`), landmark IDs (`caID.1.N.L`) and
//! landmark group IDs (`caID.2.N.L`), and the ID of every cosigner, are all
//! *trust anchor IDs* from `draft-ietf-tls-trust-anchor-ids`: a
//! `RELATIVE-OID` under the `1.3.6.1.4.1` arc (the IANA PENs). They have
//! three representations and all three live here, with a single definition:
//!
//! - **binary**, the content octets of the `RELATIVE-OID`
//!   (`81 fd 59 01`): the one that goes in the `MTCProof` and in the `Name`,
//!   and **the canonical form this type stores**;
//! - **ASCII** `32473.1`, the one that goes inside `oid/1.3.6.1.4.1.32473.1`
//!   in the `CosignedMessage`;
//! - the **ordering** of the binary form (shortest first, then
//!   lexicographic), which is the canonical order of the cosignatures in an
//!   `MTCProof`.
//!
//! ⚠️ The binary form is stored rather than the arcs because an `MTCProof`
//! may carry cosigner IDs that the relying party **does not recognize**
//! (GREASE included) with arcs of any size, and the draft requires ignoring
//! them, not rejecting the certificate. Decoding arcs into `u64` when reading
//! from the wire would turn an exotic ID into a verification failure. Arcs
//! are only interpreted on request, and the ASCII form is produced with
//! arbitrary-precision arithmetic, so no well-formed ID is left without a name.

use crate::der::DerError;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TrustAnchorId {
    /// The content octets of the `RELATIVE-OID`, base 128.
    binary: Vec<u8>,
}

/// `TrustAnchorID<1..2^8-1>`: the binary form is between 1 and 255 bytes.
/// This is the bound of the MTC draft's wire format (`MTCProof`'s
/// `cosigner_id`), and the only one applied to IDs read from there.
pub const MAX_BINARY_LEN: usize = 255;
/// draft-ietf-tls-trust-anchor-ids-06, Section 4: "The length of a trust
/// anchor ID's binary representation MUST NOT exceed 32 bytes." The MTC
/// draft makes the CA ID, the log IDs, the landmark and landmark group IDs
/// and the cosigner IDs trust anchor IDs, so each one this crate configures
/// or derives is held to it (AUDIT.md §27). An ID read from an `MTCProof`
/// may be longer: it can then match no configured cosigner, and is ignored
/// like any unrecognized one.
pub const MAX_TRUST_ANCHOR_ID_LEN: usize = 32;
/// `cosigner_name<1..2^8-1>` / `log_origin<1..2^8-1>`: the `oid/…` name
/// is at most 255 bytes.
pub const MAX_NAME_LEN: usize = 255;
const NAME_PREFIX: &str = "oid/1.3.6.1.4.1.";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaiError {
    Empty,
    /// The binary representation does not fit in `TrustAnchorID<1..2^8-1>`.
    TooLong(usize),
    /// Longer than [`MAX_TRUST_ANCHOR_ID_LEN`] bytes: valid on the MTC wire,
    /// but not a trust anchor ID.
    TooLongForTrustAnchor(usize),
    /// The `oid/…` name does not fit in `opaque<1..2^8-1>`.
    NameTooLong(usize),
    Der(DerError),
    /// The ASCII is not a list of dot-separated decimal integers.
    NotAscii,
    /// An arc does not fit in `u64` (only when requesting `arcs()`).
    ArcTooLarge,
}

impl core::fmt::Display for TaiError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for TaiError {}

/// Checks the base 128 form: no truncated subidentifier and no leading
/// `0x80` padding. Does not interpret the values.
fn check_base128(b: &[u8]) -> Result<(), TaiError> {
    let mut in_progress = false;
    for byte in b {
        if !in_progress && *byte == 0x80 {
            return Err(TaiError::Der(DerError::BadOid));
        }
        in_progress = byte & 0x80 != 0;
    }
    if in_progress {
        return Err(TaiError::Der(DerError::Truncated));
    }
    Ok(())
}

/// The subidentifiers as groups of base 128 bytes.
fn subidentifiers(b: &[u8]) -> impl Iterator<Item = &[u8]> {
    b.split_inclusive(|byte| byte & 0x80 == 0)
}

/// A base 128 subidentifier as decimal, with arbitrary precision:
/// repeated long division over the 7-bit digits.
fn base128_to_decimal(sub: &[u8]) -> String {
    let mut digits: Vec<u8> = sub.iter().map(|b| b & 0x7f).collect();
    let mut out = Vec::new();
    while digits.iter().any(|d| *d != 0) {
        let mut rem = 0u32;
        for d in digits.iter_mut() {
            let cur = rem * 128 + *d as u32;
            *d = (cur / 10) as u8;
            rem = cur % 10;
        }
        out.push(b'0' + rem as u8);
    }
    if out.is_empty() {
        out.push(b'0');
    }
    out.reverse();
    String::from_utf8(out).expect("ASCII digits")
}

impl TrustAnchorId {
    /// From the arcs **relative** to `1.3.6.1.4.1`.
    pub fn new(arcs: Vec<u64>) -> Result<Self, TaiError> {
        if arcs.is_empty() {
            return Err(TaiError::Empty);
        }
        let mut binary = Vec::new();
        for a in &arcs {
            crate::der::base128(*a, &mut binary);
        }
        Self::from_binary(&binary)
    }

    /// From the content octets of the `RELATIVE-OID`. Accepts any
    /// well-formed ID of 1 to 255 bytes, whatever its arcs may be: this is
    /// the entry point from the wire.
    pub fn from_binary(b: &[u8]) -> Result<Self, TaiError> {
        if b.is_empty() {
            return Err(TaiError::Empty);
        }
        if b.len() > MAX_BINARY_LEN {
            return Err(TaiError::TooLong(b.len()));
        }
        check_base128(b)?;
        Ok(TrustAnchorId { binary: b.to_vec() })
    }

    /// From `32473.1`. Only digits and dots; no signs, no leading zeros,
    /// no empty components.
    pub fn from_ascii(s: &str) -> Result<Self, TaiError> {
        let mut arcs = Vec::new();
        for part in s.split('.') {
            if part.is_empty()
                || !part.bytes().all(|c| c.is_ascii_digit())
                || (part.len() > 1 && part.starts_with('0'))
            {
                return Err(TaiError::NotAscii);
            }
            arcs.push(part.parse::<u64>().map_err(|_| TaiError::NotAscii)?);
        }
        Self::new(arcs)
    }

    /// The content octets of the `RELATIVE-OID`.
    pub fn to_binary(&self) -> Vec<u8> {
        self.binary.clone()
    }

    pub fn as_binary(&self) -> &[u8] {
        &self.binary
    }

    /// The arcs, if they all fit in `u64`.
    pub fn arcs(&self) -> Result<Vec<u64>, TaiError> {
        let mut out = Vec::new();
        for sub in subidentifiers(&self.binary) {
            let mut acc: u64 = 0;
            for b in sub {
                if acc >> 57 != 0 {
                    return Err(TaiError::ArcTooLarge);
                }
                acc = (acc << 7) | (*b & 0x7f) as u64;
            }
            out.push(acc);
        }
        Ok(out)
    }

    /// `32473.1`, for any well-formed ID.
    pub fn to_ascii(&self) -> String {
        subidentifiers(&self.binary)
            .map(base128_to_decimal)
            .collect::<Vec<_>>()
            .join(".")
    }

    /// `oid/1.3.6.1.4.1.32473.1`: the `cosigner_name` / `log_origin` of the
    /// `CosignedMessage`. Fails if it does not fit in `opaque<1..2^8-1>`.
    pub fn oid_name(&self) -> Result<String, TaiError> {
        let name = format!("{NAME_PREFIX}{}", self.to_ascii());
        if name.len() > MAX_NAME_LEN {
            return Err(TaiError::NameTooLong(name.len()));
        }
        Ok(name)
    }

    fn child(&self, more: &[u64]) -> Result<Self, TaiError> {
        let mut binary = self.binary.clone();
        for a in more {
            crate::der::base128(*a, &mut binary);
        }
        Self::from_binary(&binary)
    }

    /// Whether the ID is short enough to be a trust anchor ID
    /// ([`MAX_TRUST_ANCHOR_ID_LEN`]).
    pub fn check_trust_anchor_len(&self) -> Result<(), TaiError> {
        match self.binary.len() {
            n if n > MAX_TRUST_ANCHOR_ID_LEN => Err(TaiError::TooLongForTrustAnchor(n)),
            _ => Ok(()),
        }
    }

    /// A derived ID, which the MTC draft makes a trust anchor ID.
    fn trust_anchor_child(&self, more: &[u64]) -> Result<Self, TaiError> {
        let id = self.child(more)?;
        id.check_trust_anchor_len()?;
        Ok(id)
    }

    /// `{caID logs(0) N}`: the ID of log `N`, a trust anchor ID.
    pub fn log_id(&self, log_number: u16) -> Result<Self, TaiError> {
        self.trust_anchor_child(&[0, log_number as u64])
    }

    /// `{caID landmarks(1) N L}`, a trust anchor ID.
    pub fn landmark_id(&self, log_number: u16, landmark: u64) -> Result<Self, TaiError> {
        self.trust_anchor_child(&[1, log_number as u64, landmark])
    }

    /// `{caID landmarkGroups(2) N L}`, a trust anchor ID.
    pub fn landmark_group_id(&self, log_number: u16, landmark: u64) -> Result<Self, TaiError> {
        self.trust_anchor_child(&[2, log_number as u64, landmark])
    }

    /// Checks that the ID can serve as a CA ID: that it is a trust anchor ID
    /// ([`MAX_TRUST_ANCHOR_ID_LEN`]), and that its derived IDs, with the
    /// longest possible values, fit on the wire and in an `oid/…` name.
    /// Whether a given derived ID is itself short enough to be a trust anchor
    /// ID is checked when it is derived: a CA ID of 32 bytes is valid, but
    /// leaves no room for a log. Called when configuring a CA, when writing
    /// or reading its certificate, and before each verification, so that it
    /// fails there and not at issuance.
    pub fn check_as_ca_id(&self) -> Result<(), TaiError> {
        self.check_trust_anchor_len()?;
        // Defensive since §27: with at most 32 bytes the longest name is
        // 16 + 127 + 29 = 172 characters ("127." per byte, then
        // ".2.65535.18446744073709551615"), well within 255.
        self.oid_name()?;
        self.child(&[0, u16::MAX as u64])?.oid_name()?;
        self.child(&[1, u16::MAX as u64, u64::MAX])?.oid_name()?;
        self.child(&[2, u16::MAX as u64, u64::MAX])?.oid_name()?;
        Ok(())
    }
}

impl core::fmt::Display for TrustAnchorId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.to_ascii())
    }
}

/// The canonical order of the cosignatures: by the binary representation,
/// shortest first and, at equal length, lexicographic.
impl Ord for TrustAnchorId {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.binary
            .len()
            .cmp(&other.binary.len())
            .then_with(|| self.binary.cmp(&other.binary))
    }
}

impl PartialOrd for TrustAnchorId {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_example_of_the_draft() {
        let ca = TrustAnchorId::from_ascii("32473.1").unwrap();
        assert_eq!(ca.to_binary(), vec![0x81, 0xfd, 0x59, 0x01]);
        assert_eq!(ca.oid_name().unwrap(), "oid/1.3.6.1.4.1.32473.1");
        assert_eq!(
            TrustAnchorId::from_binary(&[0x81, 0xfd, 0x59, 0x01]).unwrap(),
            ca
        );
        assert_eq!(ca.arcs().unwrap(), vec![32473, 1]);
        let ca100 = TrustAnchorId::from_ascii("32473.100").unwrap();
        assert_eq!(
            ca100.landmark_id(8, 42).unwrap().to_ascii(),
            "32473.100.1.8.42"
        );
        assert_eq!(
            ca100.landmark_group_id(8, 42).unwrap().to_ascii(),
            "32473.100.2.8.42"
        );
        assert_eq!(ca100.log_id(8).unwrap().to_ascii(), "32473.100.0.8");
        ca100.check_as_ca_id().unwrap();
    }

    #[test]
    fn ascii_is_strict_and_binary_is_lenient() {
        for bad in ["", ".", "1.", "+5", "01", "a", "1..2", " 1"] {
            assert!(TrustAnchorId::from_ascii(bad).is_err(), "{bad:?}");
        }
        // An ID from the wire with an arc that does not fit in u64 still has
        // a name and an ordering; only `arcs()` refuses.
        let huge = TrustAnchorId::from_binary(
            &[0xff; 10]
                .map(|b| b)
                .iter()
                .chain([0x7f].iter())
                .copied()
                .collect::<Vec<_>>(),
        )
        .unwrap();
        assert!(huge.arcs().is_err());
        assert!(huge.to_ascii().chars().all(|c| c.is_ascii_digit()));
        assert_eq!(
            TrustAnchorId::from_binary(&[0x80, 0x01]).err(),
            Some(TaiError::Der(DerError::BadOid))
        );
        assert_eq!(
            TrustAnchorId::from_binary(&[0x81]).err(),
            Some(TaiError::Der(DerError::Truncated))
        );
        assert_eq!(TrustAnchorId::from_binary(&[]).err(), Some(TaiError::Empty));
        assert_eq!(
            TrustAnchorId::from_binary(&[1; 256]).err(),
            Some(TaiError::TooLong(256))
        );
    }

    #[test]
    fn decimal_of_large_subidentifiers_is_exact() {
        // 2^63 = 9223372036854775808 in base 128: a 1 followed by nine zeros.
        let mut b = Vec::new();
        crate::der::base128(1u64 << 63, &mut b);
        assert_eq!(base128_to_decimal(&b), "9223372036854775808");
        assert_eq!(
            TrustAnchorId::from_binary(&b).unwrap().to_ascii(),
            (1u64 << 63).to_string()
        );
        let mut b = Vec::new();
        crate::der::base128(u64::MAX, &mut b);
        assert_eq!(
            TrustAnchorId::from_binary(&b).unwrap().to_ascii(),
            u64::MAX.to_string()
        );
        assert_eq!(base128_to_decimal(&[0]), "0");
    }

    #[test]
    fn a_long_ca_id_fails_on_its_length_before_its_names() {
        // Before §27 this ID failed for leaving no room for its children's
        // names; now its length stops it first.
        let long = TrustAnchorId::from_binary(&[0x7f; 255]).unwrap();
        assert_eq!(
            long.check_as_ca_id(),
            Err(TaiError::TooLongForTrustAnchor(255))
        );
        // The name bound still holds for an ID read from the wire.
        let names_too_long = TrustAnchorId::from_binary(&[0x7f; 100]).unwrap(); // "127." x 100 = 400 chars
        assert!(matches!(
            names_too_long.oid_name(),
            Err(TaiError::NameTooLong(_))
        ));
    }

    /// AUDIT.md §27: trust anchor IDs are at most 32 bytes
    /// (draft-ietf-tls-trust-anchor-ids-06, Section 4); the MTC wire format
    /// still carries up to 255.
    #[test]
    fn trust_anchor_ids_are_at_most_32_bytes_and_the_wire_is_not() {
        let id = |n: usize| TrustAnchorId::from_binary(&vec![1; n]).unwrap();
        // The wire bound is unchanged: an MTCProof may carry 255 bytes.
        assert_eq!(id(255).as_binary().len(), 255);
        // A CA ID: 32 bytes is one, 33 is not.
        assert_eq!(id(32).check_as_ca_id(), Ok(()));
        assert_eq!(
            id(33).check_as_ca_id(),
            Err(TaiError::TooLongForTrustAnchor(33))
        );
        // Derived IDs are trust anchor IDs too. `{caID 0 1}` adds two bytes
        // and `{caID 0 128}` three; `{caID 1 1 1}` and `{caID 2 1 1}` three.
        assert_eq!(id(30).log_id(1).unwrap().as_binary().len(), 32);
        assert_eq!(id(30).log_id(128), Err(TaiError::TooLongForTrustAnchor(33)));
        assert_eq!(id(29).landmark_id(1, 1).unwrap().as_binary().len(), 32);
        assert_eq!(
            id(30).landmark_id(1, 1),
            Err(TaiError::TooLongForTrustAnchor(33))
        );
        assert_eq!(
            id(29).landmark_group_id(1, 1).unwrap().as_binary().len(),
            32
        );
        assert_eq!(
            id(30).landmark_group_id(1, 1),
            Err(TaiError::TooLongForTrustAnchor(33))
        );
        // A CA ID of 32 bytes is valid, and leaves no room for a log.
        assert_eq!(id(32).log_id(1), Err(TaiError::TooLongForTrustAnchor(34)));
    }

    #[test]
    fn ordering_is_by_length_then_bytes() {
        let a = TrustAnchorId::from_ascii("1").unwrap();
        let b = TrustAnchorId::from_ascii("200").unwrap(); // two bytes
        let c = TrustAnchorId::from_ascii("2").unwrap();
        assert!(a < c && c < b);
    }
}
