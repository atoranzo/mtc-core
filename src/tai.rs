//! # Identificadores de ancla de confianza (`TrustAnchorID`)
//!
//! El CA ID, los ID de log (`caID.0.N`), de landmark (`caID.1.N.L`) y de
//! grupo de landmarks (`caID.2.N.L`), y el ID de cada cofirmante, son
//! todos *trust anchor IDs* de `draft-ietf-tls-trust-anchor-ids`: una
//! `RELATIVE-OID` bajo el arco `1.3.6.1.4.1` (los PEN de IANA). Tienen
//! tres representaciones y las tres viven aqui, con una sola definicion:
//!
//! - **binaria**, los octetos de contenido de la `RELATIVE-OID`
//!   (`81 fd 59 01`): la que va en el `MTCProof` y en el `Name`, y **la
//!   forma canonica que este tipo guarda**;
//! - **ASCII** `32473.1`, la que va dentro de `oid/1.3.6.1.4.1.32473.1` en
//!   el `CosignedMessage`;
//! - el **orden** de la binaria (primero mas corta, luego lexicografica),
//!   que es el orden canonico de las cofirmas en un `MTCProof`.
//!
//! ⚠️ Se guarda la binaria y no los arcos porque un `MTCProof` puede
//! traer IDs de cofirmantes que la parte que confia **no reconoce** (GREASE
//! incluido) con arcos de cualquier tamano, y el borrador exige ignorarlos,
//! no rechazar el certificado. Decodificar arcos a `u64` al leer el cable
//! convertiria un ID exotico en un fallo de verificacion. Los arcos solo se
//! interpretan al pedirlos, y el ASCII se produce con aritmetica de
//! precision arbitraria, asi que ningun ID bien formado deja de tener nombre.

use crate::der::DerError;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TrustAnchorId {
    /// Los octetos de contenido de la `RELATIVE-OID`, base 128.
    binary: Vec<u8>,
}

/// `TrustAnchorID<1..2^8-1>`: la binaria mide entre 1 y 255 bytes.
pub const MAX_BINARY_LEN: usize = 255;
/// `cosigner_name<1..2^8-1>` / `log_origin<1..2^8-1>`: el nombre `oid/…`
/// mide como mucho 255 bytes.
pub const MAX_NAME_LEN: usize = 255;
const NAME_PREFIX: &str = "oid/1.3.6.1.4.1.";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaiError {
    Empty,
    /// La representacion binaria no cabe en `TrustAnchorID<1..2^8-1>`.
    TooLong(usize),
    /// El nombre `oid/…` no cabe en `opaque<1..2^8-1>`.
    NameTooLong(usize),
    Der(DerError),
    /// El ASCII no es una lista de enteros decimales separados por puntos.
    NotAscii,
    /// Un arco no cabe en `u64` (solo al pedir `arcs()`).
    ArcTooLarge,
}

impl core::fmt::Display for TaiError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for TaiError {}

/// Comprueba la forma base 128: ningun subidentificador truncado ni con
/// relleno `0x80` inicial. No interpreta los valores.
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

/// Los subidentificadores como grupos de bytes base 128.
fn subidentifiers(b: &[u8]) -> impl Iterator<Item = &[u8]> {
    b.split_inclusive(|byte| byte & 0x80 == 0)
}

/// Un subidentificador base 128 como decimal, con precision arbitraria:
/// division larga repetida sobre los digitos de 7 bits.
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
    String::from_utf8(out).expect("digitos ASCII")
}

impl TrustAnchorId {
    /// Desde los arcos **relativos** a `1.3.6.1.4.1`.
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

    /// Desde los octetos de contenido de la `RELATIVE-OID`. Acepta
    /// cualquier ID bien formado de 1 a 255 bytes, tenga los arcos que
    /// tenga: es la entrada del cable.
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

    /// Desde `32473.1`. Solo digitos y puntos; sin signos, sin ceros a la
    /// izquierda, sin componentes vacios.
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

    /// Los octetos de contenido de la `RELATIVE-OID`.
    pub fn to_binary(&self) -> Vec<u8> {
        self.binary.clone()
    }

    pub fn as_binary(&self) -> &[u8] {
        &self.binary
    }

    /// Los arcos, si todos caben en `u64`.
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

    /// `32473.1`, para cualquier ID bien formado.
    pub fn to_ascii(&self) -> String {
        subidentifiers(&self.binary)
            .map(base128_to_decimal)
            .collect::<Vec<_>>()
            .join(".")
    }

    /// `oid/1.3.6.1.4.1.32473.1`: el `cosigner_name` / `log_origin` del
    /// `CosignedMessage`. Falla si no cabe en `opaque<1..2^8-1>`.
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

    /// `{caID logs(0) N}`: el ID del log `N`.
    pub fn log_id(&self, log_number: u16) -> Result<Self, TaiError> {
        self.child(&[0, log_number as u64])
    }

    /// `{caID landmarks(1) N L}`.
    pub fn landmark_id(&self, log_number: u16, landmark: u64) -> Result<Self, TaiError> {
        self.child(&[1, log_number as u64, landmark])
    }

    /// `{caID landmarkGroups(2) N L}`.
    pub fn landmark_group_id(&self, log_number: u16, landmark: u64) -> Result<Self, TaiError> {
        self.child(&[2, log_number as u64, landmark])
    }

    /// Comprueba que el ID sirve como CA ID: que todos sus derivados
    /// (log, landmark y grupo, con los valores mas largos posibles) caben
    /// en el cable y en un nombre `oid/…`. Se llama al configurar una CA,
    /// para fallar al arrancar y no al emitir.
    pub fn check_as_ca_id(&self) -> Result<(), TaiError> {
        self.oid_name()?;
        self.log_id(u16::MAX)?.oid_name()?;
        self.landmark_id(u16::MAX, u64::MAX)?.oid_name()?;
        self.landmark_group_id(u16::MAX, u64::MAX)?.oid_name()?;
        Ok(())
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
        // Un ID del cable con un arco que no cabe en u64 sigue teniendo
        // nombre y orden; solo `arcs()` se niega.
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
        // 2^63 = 9223372036854775808 en base 128: un 1 seguido de nueve ceros.
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
    fn a_ca_id_that_leaves_no_room_for_its_children_is_rejected() {
        let long = TrustAnchorId::from_binary(&[0x7f; 255]).unwrap();
        assert!(matches!(
            long.check_as_ca_id(),
            Err(TaiError::NameTooLong(_)) | Err(TaiError::TooLong(_))
        ));
        let names_too_long = TrustAnchorId::from_binary(&[0x7f; 100]).unwrap(); // "127." x 100 = 400 chars
        assert!(matches!(
            names_too_long.oid_name(),
            Err(TaiError::NameTooLong(_))
        ));
    }

    #[test]
    fn ordering_is_by_length_then_bytes() {
        let a = TrustAnchorId::from_ascii("1").unwrap();
        let b = TrustAnchorId::from_ascii("200").unwrap(); // dos bytes
        let c = TrustAnchorId::from_ascii("2").unwrap();
        assert!(a < c && c < b);
    }
}
