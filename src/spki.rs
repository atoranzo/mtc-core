//! # `SubjectPublicKeyInfo`
//!
//! The one X.509 structure two implementations have to agree on to trust
//! each other's cosigners: `SEQUENCE { AlgorithmIdentifier, BIT STRING }`
//! (RFC 5280 §4.1.2.7). For ML-DSA the identifiers are those of RFC 9881
//! (`2.16.840.1.101.3.4.3.17/18/19`, parameters absent, the raw `pkEncode`
//! output in the bit string). The rest of the crate treats a subject's
//! SPKI as opaque bytes; this module is for the **cosigners'** keys: the
//! CA's certificate and a relying party's policy file.

use crate::der::{self, DerError};

/// `id-ml-dsa-44` (RFC 9881).
pub const OID_ML_DSA_44: [u64; 9] = [2, 16, 840, 1, 101, 3, 4, 3, 17];
/// `id-ml-dsa-65`.
pub const OID_ML_DSA_65: [u64; 9] = [2, 16, 840, 1, 101, 3, 4, 3, 18];
/// `id-ml-dsa-87`.
pub const OID_ML_DSA_87: [u64; 9] = [2, 16, 840, 1, 101, 3, 4, 3, 19];
/// `id-Ed25519` (RFC 8410), the toy subject key of the examples.
pub const OID_ED25519: [u64; 4] = [1, 3, 101, 112];

/// The three FIPS 204 parameter sets, as they are named on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MlDsaParameterSet {
    MlDsa44,
    MlDsa65,
    MlDsa87,
}

impl MlDsaParameterSet {
    pub fn oid(self) -> &'static [u64] {
        match self {
            MlDsaParameterSet::MlDsa44 => &OID_ML_DSA_44,
            MlDsaParameterSet::MlDsa65 => &OID_ML_DSA_65,
            MlDsaParameterSet::MlDsa87 => &OID_ML_DSA_87,
        }
    }

    pub fn from_oid(arcs: &[u64]) -> Option<Self> {
        [Self::MlDsa44, Self::MlDsa65, Self::MlDsa87]
            .into_iter()
            .find(|s| s.oid() == arcs)
    }

    /// Bytes of `pkEncode` (FIPS 204, table 2).
    pub fn public_key_len(self) -> usize {
        match self {
            MlDsaParameterSet::MlDsa44 => 1312,
            MlDsaParameterSet::MlDsa65 => 1952,
            MlDsaParameterSet::MlDsa87 => 2592,
        }
    }

    pub fn from_public_key_len(len: usize) -> Option<Self> {
        [Self::MlDsa44, Self::MlDsa65, Self::MlDsa87]
            .into_iter()
            .find(|s| s.public_key_len() == len)
    }

    pub fn name(self) -> &'static str {
        match self {
            MlDsaParameterSet::MlDsa44 => "ML-DSA-44",
            MlDsaParameterSet::MlDsa65 => "ML-DSA-65",
            MlDsaParameterSet::MlDsa87 => "ML-DSA-87",
        }
    }
}

/// A parsed `SubjectPublicKeyInfo`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Spki<'a> {
    /// The whole `AlgorithmIdentifier` TLV.
    pub algorithm: &'a [u8],
    /// Its `algorithm` OID, as arcs.
    pub oid_arcs: [u64; 16],
    pub oid_len: usize,
    /// Its `parameters`, if present (the whole TLV).
    pub parameters: Option<&'a [u8]>,
    /// The content of the `BIT STRING`, without the unused-bits byte
    /// (which must be zero: keys are whole bytes).
    pub key: &'a [u8],
}

impl Spki<'_> {
    pub fn oid(&self) -> &[u64] {
        &self.oid_arcs[..self.oid_len]
    }
}

/// The arcs of an absolute OID from its content bytes.
pub fn oid_arcs(content: &[u8]) -> Result<Vec<u64>, DerError> {
    let subids = der::decode_base128(content)?;
    let first = *subids.first().ok_or(DerError::BadOid)?;
    let mut arcs = if first < 80 {
        vec![first / 40, first % 40]
    } else {
        vec![2, first - 80]
    };
    arcs.extend_from_slice(&subids[1..]);
    Ok(arcs)
}

/// Splits an SPKI (the whole SEQUENCE, nothing after it).
pub fn parse(spki: &[u8]) -> Result<Spki<'_>, DerError> {
    let (seq, rest) = der::expect_tlv(spki, der::TAG_SEQUENCE)?;
    if !rest.is_empty() {
        return Err(DerError::TrailingData);
    }
    let (alg, rest) = der::expect_tlv(seq.content, der::TAG_SEQUENCE)?;
    let (bits, rest) = der::expect_tlv(rest, der::TAG_BIT_STRING)?;
    if !rest.is_empty() {
        return Err(DerError::TrailingData);
    }
    if bits.content.is_empty() || bits.content[0] != 0 {
        return Err(DerError::BadLength);
    }
    let (oid, params) = der::expect_tlv(alg.content, der::TAG_OID)?;
    let arcs = oid_arcs(oid.content)?;
    if arcs.len() > 16 {
        return Err(DerError::BadOid);
    }
    let parameters = if params.is_empty() {
        None
    } else {
        let (p, after) = der::read_tlv(params)?;
        if !after.is_empty() {
            return Err(DerError::TrailingData);
        }
        Some(p.raw)
    };
    let mut oid_arcs = [0u64; 16];
    oid_arcs[..arcs.len()].copy_from_slice(&arcs);
    Ok(Spki {
        algorithm: alg.raw,
        oid_arcs,
        oid_len: arcs.len(),
        parameters,
        key: &bits.content[1..],
    })
}

/// `SEQUENCE { AlgorithmIdentifier { oid }, BIT STRING key }`, parameters
/// absent: the form RFC 9881 (ML-DSA) and RFC 8410 (Ed25519) require.
pub fn encode(oid: &[u64], key: &[u8]) -> Vec<u8> {
    let mut c = der::algorithm_identifier(oid);
    c.extend(der::bit_string(key));
    der::sequence(&c)
}

/// The SPKI of an ML-DSA public key.
pub fn ml_dsa(set: MlDsaParameterSet, public_key: &[u8]) -> Vec<u8> {
    encode(set.oid(), public_key)
}

/// Which parameter set an SPKI carries, if it is an ML-DSA key of the
/// right length with no parameters.
pub fn ml_dsa_parameter_set(spki: &Spki<'_>) -> Option<MlDsaParameterSet> {
    let set = MlDsaParameterSet::from_oid(spki.oid())?;
    if spki.parameters.is_some() || spki.key.len() != set.public_key_len() {
        return None;
    }
    Some(set)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ml_dsa_spki_round_trips_and_the_go_prefix_matches() {
        let key = vec![7u8; 1312];
        let spki = ml_dsa(MlDsaParameterSet::MlDsa44, &key);
        let p = parse(&spki).unwrap();
        assert_eq!(p.oid(), &OID_ML_DSA_44);
        assert_eq!(p.parameters, None);
        assert_eq!(p.key, &key[..]);
        assert_eq!(ml_dsa_parameter_set(&p), Some(MlDsaParameterSet::MlDsa44));
        // The prefix the reference implementation's policy file shows for
        // an ML-DSA-44 SPKI (`MIIFMjALBglghkgBZQMEAxEDggUhAA…`): 30 82 05 32
        // 30 0b 06 09 60 86 48 01 65 03 04 03 11 03 82 05 21 00.
        assert_eq!(
            der::hex(&spki[..22]),
            "30820532300b06096086480165030403110382052100"
        );
    }

    #[test]
    fn a_wrong_length_or_parameters_are_not_ml_dsa() {
        let short = ml_dsa(MlDsaParameterSet::MlDsa44, &[0u8; 1311]);
        assert_eq!(ml_dsa_parameter_set(&parse(&short).unwrap()), None);
        // parameters NULL
        let mut alg = der::oid(&OID_ML_DSA_44);
        alg.extend([0x05, 0x00]);
        let mut c = der::sequence(&alg);
        c.extend(der::bit_string(&[0u8; 1312]));
        let with_params = der::sequence(&c);
        let p = parse(&with_params).unwrap();
        assert_eq!(p.parameters, Some(&[0x05u8, 0x00][..]));
        assert_eq!(ml_dsa_parameter_set(&p), None);
        // unused bits
        let mut c = der::algorithm_identifier(&OID_ED25519);
        c.extend(der::tlv(der::TAG_BIT_STRING, &[0x01, 0xfe]));
        assert!(parse(&der::sequence(&c)).is_err());
    }

    #[test]
    fn oid_arcs_decode_both_first_arc_forms() {
        assert_eq!(
            oid_arcs(&der::oid_content(&OID_ML_DSA_44)).unwrap(),
            OID_ML_DSA_44
        );
        assert_eq!(
            oid_arcs(&der::oid_content(&OID_ED25519)).unwrap(),
            OID_ED25519
        );
        assert_eq!(
            oid_arcs(&der::oid_content(der::OIDS_IANA.mtc_proof)).unwrap(),
            der::OIDS_IANA.mtc_proof
        );
    }
}
