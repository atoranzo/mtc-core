//! # Identificadores de ancla de confianza (`TrustAnchorID`)
//!
//! El CA ID, los ID de log (`caID.0.N`), de landmark (`caID.1.N.L`) y de
//! grupo de landmarks (`caID.2.N.L`), y el ID de cada cofirmante, son
//! todos *trust anchor IDs* de `draft-ietf-tls-trust-anchor-ids`: una
//! `RELATIVE-OID` bajo el arco `1.3.6.1.4.1` (los PEN de IANA). Tienen
//! tres representaciones y las tres viven aqui, con una sola definicion:
//!
//! - **ASCII** `32473.1`, la que va dentro de `oid/1.3.6.1.4.1.32473.1` en
//!   el `CosignedMessage`;
//! - **binaria**, los octetos de contenido de la `RELATIVE-OID`
//!   (`81 fd 59 01`), la que va en el `MTCProof` y en el `Name`;
//! - el **orden** de la binaria (primero mas corta, luego lexicografica),
//!   que es el orden canonico de las cofirmas en un `MTCProof`.

use crate::der::{base128, decode_base128, DerError};

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TrustAnchorId {
    arcs: Vec<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaiError {
    Empty,
    /// La representacion binaria no cabe en `TrustAnchorID<1..2^8-1>`.
    TooLong(usize),
    Der(DerError),
    NotAscii,
}

impl core::fmt::Display for TaiError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for TaiError {}

impl TrustAnchorId {
    /// Los arcos **relativos** a `1.3.6.1.4.1`.
    pub fn new(arcs: Vec<u64>) -> Result<Self, TaiError> {
        if arcs.is_empty() {
            return Err(TaiError::Empty);
        }
        let id = TrustAnchorId { arcs };
        let len = id.to_binary().len();
        if len > 255 {
            return Err(TaiError::TooLong(len));
        }
        Ok(id)
    }

    pub fn arcs(&self) -> &[u64] {
        &self.arcs
    }

    /// `32473.1`.
    pub fn to_ascii(&self) -> String {
        self.arcs
            .iter()
            .map(u64::to_string)
            .collect::<Vec<_>>()
            .join(".")
    }

    pub fn from_ascii(s: &str) -> Result<Self, TaiError> {
        let mut arcs = Vec::new();
        for part in s.split('.') {
            if part.is_empty() || (part.len() > 1 && part.starts_with('0')) {
                return Err(TaiError::NotAscii);
            }
            arcs.push(part.parse::<u64>().map_err(|_| TaiError::NotAscii)?);
        }
        Self::new(arcs)
    }

    /// Los octetos de contenido de la `RELATIVE-OID`.
    pub fn to_binary(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for a in &self.arcs {
            base128(*a, &mut out);
        }
        out
    }

    pub fn from_binary(b: &[u8]) -> Result<Self, TaiError> {
        Self::new(decode_base128(b).map_err(TaiError::Der)?)
    }

    /// `oid/1.3.6.1.4.1.32473.1`: el `cosigner_name` / `log_origin` del
    /// `CosignedMessage`.
    pub fn oid_name(&self) -> String {
        format!("oid/1.3.6.1.4.1.{}", self.to_ascii())
    }

    fn child(&self, more: &[u64]) -> Self {
        let mut arcs = self.arcs.clone();
        arcs.extend_from_slice(more);
        TrustAnchorId { arcs }
    }

    /// `{caID logs(0) N}`: el ID del log `N`.
    pub fn log_id(&self, log_number: u16) -> Self {
        self.child(&[0, log_number as u64])
    }

    /// `{caID landmarks(1) N L}`.
    pub fn landmark_id(&self, log_number: u16, landmark: u64) -> Self {
        self.child(&[1, log_number as u64, landmark])
    }

    /// `{caID landmarkGroups(2) N L}`.
    pub fn landmark_group_id(&self, log_number: u16, landmark: u64) -> Self {
        self.child(&[2, log_number as u64, landmark])
    }
}

impl core::fmt::Display for TrustAnchorId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.to_ascii())
    }
}

/// El orden canonico de las cofirmas: por la representacion binaria,
/// primero las mas cortas y a igual longitud lexicografico.
impl Ord for TrustAnchorId {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        let a = self.to_binary();
        let b = other.to_binary();
        a.len().cmp(&b.len()).then_with(|| a.cmp(&b))
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
        assert_eq!(ca.oid_name(), "oid/1.3.6.1.4.1.32473.1");
        assert_eq!(
            TrustAnchorId::from_binary(&[0x81, 0xfd, 0x59, 0x01]).unwrap(),
            ca
        );
        let ca100 = TrustAnchorId::from_ascii("32473.100").unwrap();
        assert_eq!(ca100.landmark_id(8, 42).to_ascii(), "32473.100.1.8.42");
        assert_eq!(
            ca100.landmark_group_id(8, 42).to_ascii(),
            "32473.100.2.8.42"
        );
        assert_eq!(ca100.log_id(8).to_ascii(), "32473.100.0.8");
    }

    #[test]
    fn ordering_is_by_length_then_bytes() {
        let a = TrustAnchorId::from_ascii("1").unwrap();
        let b = TrustAnchorId::from_ascii("200").unwrap(); // dos bytes
        let c = TrustAnchorId::from_ascii("2").unwrap();
        assert!(a < c && c < b);
    }
}
