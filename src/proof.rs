//! # `MTCProof` y el certificado que lo lleva
//!
//! El equivalente del `ReciboInclusion` de `zk-ssl-verify` (§256): lo que
//! un tercero necesita para comprobar una inclusion **sin el emisor**. Y
//! la misma leccion: **una raiz suelta no prueba nada**. Lo que ata la
//! prueba a algo que la CA no puede cambiar sin firmar es que el hash del
//! subarbol lleve cofirmas —o que la parte que confia lo tenga ya como
//! subarbol de confianza (landmark)—.
//!
//! El `MTCProof` viaja en el `signatureValue` de un certificado X.509
//! cuyo `signatureAlgorithm` es `id-alg-mtcProof`: para todo lo demas
//! (SAN, key usage, caducidad, CRL/OCSP) el certificado es un X.509
//! corriente.

use crate::cosign::SubtreeSignature;
use crate::der;
use crate::entry::{decode_extensions, encode_extensions, EntryError, LogEntryExtension};
use crate::hash::{HashValue, HASH_SIZE};
use crate::subtree::Subtree;
use crate::tai::TrustAnchorId;

/// `2^48 - 1`: el mayor `start`/`end` y el mayor indice.
pub const MAX_U48: u64 = (1u64 << 48) - 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProofError {
    Truncated,
    TrailingData,
    /// `start`/`end` no caben en 48 bits, o `inclusion_proof` no es un
    /// multiplo de `HASH_SIZE`.
    BadLength(&'static str),
    /// Las cofirmas no van en orden canonico estricto (o hay un ID repetido).
    SignaturesNotSorted,
    Entry(EntryError),
    Der(der::DerError),
    /// El `signatureAlgorithm` no es `id-alg-mtcProof` sin parametros.
    NotAnMtcCertificate,
}

impl core::fmt::Display for ProofError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for ProofError {}

impl From<EntryError> for ProofError {
    fn from(e: EntryError) -> Self {
        ProofError::Entry(e)
    }
}

impl From<der::DerError> for ProofError {
    fn from(e: der::DerError) -> Self {
        ProofError::Der(e)
    }
}

/// `MTCProof { extensions, uint48 start, uint48 end, inclusion_proof, signatures }`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MtcProof {
    /// Las extensiones **de la entrada del log**, copiadas.
    pub extensions: Vec<LogEntryExtension>,
    pub subtree: Subtree,
    pub inclusion_proof: Vec<HashValue>,
    /// Vacio en un certificado relativo a landmark.
    pub signatures: Vec<SubtreeSignature>,
}

fn u48(v: u64, name: &'static str) -> Result<[u8; 6], ProofError> {
    if v > MAX_U48 {
        return Err(ProofError::BadLength(name));
    }
    let b = v.to_be_bytes();
    Ok([b[2], b[3], b[4], b[5], b[6], b[7]])
}

fn take(input: &[u8], n: usize) -> Result<(&[u8], &[u8]), ProofError> {
    input.split_at_checked(n).ok_or(ProofError::Truncated)
}

impl MtcProof {
    pub fn encode(&self) -> Result<Vec<u8>, ProofError> {
        let mut out = encode_extensions(&self.extensions)?;
        out.extend_from_slice(&u48(self.subtree.start, "start")?);
        out.extend_from_slice(&u48(self.subtree.end, "end")?);
        let path_len = self.inclusion_proof.len() * HASH_SIZE;
        if path_len > 0xffff {
            return Err(ProofError::BadLength("inclusion_proof"));
        }
        out.extend_from_slice(&(path_len as u16).to_be_bytes());
        for h in &self.inclusion_proof {
            out.extend_from_slice(h);
        }
        let mut sigs = Vec::new();
        let mut last: Option<&TrustAnchorId> = None;
        for s in &self.signatures {
            if last.is_some_and(|l| s.cosigner_id <= *l) {
                return Err(ProofError::SignaturesNotSorted);
            }
            last = Some(&s.cosigner_id);
            let id = s.cosigner_id.to_binary();
            sigs.push(id.len() as u8);
            sigs.extend(id);
            if s.signature.len() > 0xffff {
                return Err(ProofError::BadLength("signature"));
            }
            sigs.extend_from_slice(&(s.signature.len() as u16).to_be_bytes());
            sigs.extend_from_slice(&s.signature);
        }
        if sigs.len() > 0xff_ffff {
            return Err(ProofError::BadLength("signatures"));
        }
        out.extend_from_slice(&(sigs.len() as u32).to_be_bytes()[1..]);
        out.extend(sigs);
        Ok(out)
    }

    /// Lee un `MTCProof` que ocupa `input` entero.
    pub fn decode(input: &[u8]) -> Result<Self, ProofError> {
        let (extensions, rest) = decode_extensions(input)?;
        let (s, rest) = take(rest, 6)?;
        let (e, rest) = take(rest, 6)?;
        let start = u64::from_be_bytes([0, 0, s[0], s[1], s[2], s[3], s[4], s[5]]);
        let end = u64::from_be_bytes([0, 0, e[0], e[1], e[2], e[3], e[4], e[5]]);
        let (l, rest) = take(rest, 2)?;
        let path_len = u16::from_be_bytes([l[0], l[1]]) as usize;
        if !path_len.is_multiple_of(HASH_SIZE) {
            return Err(ProofError::BadLength("inclusion_proof"));
        }
        let (path, rest) = take(rest, path_len)?;
        let inclusion_proof = path
            .chunks_exact(HASH_SIZE)
            .map(|c| {
                let mut h = [0u8; HASH_SIZE];
                h.copy_from_slice(c);
                h
            })
            .collect();
        let (l, rest) = take(rest, 3)?;
        let sigs_len = u32::from_be_bytes([0, l[0], l[1], l[2]]) as usize;
        let (mut sigs, rest) = take(rest, sigs_len)?;
        if !rest.is_empty() {
            return Err(ProofError::TrailingData);
        }
        let mut signatures: Vec<SubtreeSignature> = Vec::new();
        while !sigs.is_empty() {
            let (l, r) = take(sigs, 1)?;
            if l[0] == 0 {
                return Err(ProofError::BadLength("cosigner_id"));
            }
            let (id, r) = take(r, l[0] as usize)?;
            let (l, r) = take(r, 2)?;
            let (sig, r) = take(r, u16::from_be_bytes([l[0], l[1]]) as usize)?;
            let cosigner_id =
                TrustAnchorId::from_binary(id).map_err(|_| ProofError::BadLength("cosigner_id"))?;
            // Estrictamente creciente: ni repetidos ni desordenados.
            if signatures
                .last()
                .is_some_and(|p| cosigner_id <= p.cosigner_id)
            {
                return Err(ProofError::SignaturesNotSorted);
            }
            signatures.push(SubtreeSignature {
                cosigner_id,
                signature: sig.to_vec(),
            });
            sigs = r;
        }
        Ok(MtcProof {
            extensions,
            subtree: Subtree { start, end },
            inclusion_proof,
            signatures,
        })
    }
}

/// Un certificado MTC: su `TBSCertificate` en DER y su prueba.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MtcCertificate {
    pub tbs_certificate: Vec<u8>,
    pub proof: MtcProof,
}

impl MtcCertificate {
    /// `Certificate { tbsCertificate, id-alg-mtcProof, BIT STRING(MTCProof) }`.
    pub fn to_der(&self) -> Result<Vec<u8>, ProofError> {
        let mut c = self.tbs_certificate.clone();
        c.extend(der::alg_id_mtc_proof());
        c.extend(der::bit_string(&self.proof.encode()?));
        Ok(der::sequence(&c))
    }

    pub fn from_der(cert: &[u8]) -> Result<Self, ProofError> {
        let parts = der::parse_certificate(cert)?;
        if parts.signature_algorithm.raw != der::alg_id_mtc_proof().as_slice() {
            return Err(ProofError::NotAnMtcCertificate);
        }
        let fields = der::parse_tbs(parts.tbs.raw)?;
        if fields.signature.raw != der::alg_id_mtc_proof().as_slice() {
            return Err(ProofError::NotAnMtcCertificate);
        }
        Ok(MtcCertificate {
            tbs_certificate: parts.tbs.raw.to_vec(),
            proof: MtcProof::decode(parts.signature_value)?,
        })
    }

    /// El numero de serie `(log_number << 48) | index`.
    pub fn serial(&self) -> Result<u64, ProofError> {
        let fields = der::parse_tbs(&self.tbs_certificate)?;
        Ok(der::decode_integer_u64(fields.serial.content)?)
    }

    pub fn log_number(&self) -> Result<u16, ProofError> {
        Ok((self.serial()? >> 48) as u16)
    }

    pub fn index(&self) -> Result<u64, ProofError> {
        Ok(self.serial()? & MAX_U48)
    }

    /// Tamano en bytes del certificado en DER: lo que cuesta en el handshake.
    pub fn der_len(&self) -> Result<usize, ProofError> {
        Ok(self.to_der()?.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proof_round_trips_and_rejects_disorder() {
        let a = TrustAnchorId::from_ascii("1").unwrap();
        let b = TrustAnchorId::from_ascii("2").unwrap();
        let p = MtcProof {
            extensions: vec![],
            subtree: Subtree { start: 8, end: 13 },
            inclusion_proof: vec![[1; 32], [2; 32], [3; 32]],
            signatures: vec![
                SubtreeSignature {
                    cosigner_id: a.clone(),
                    signature: vec![0xaa; 5],
                },
                SubtreeSignature {
                    cosigner_id: b.clone(),
                    signature: vec![],
                },
            ],
        };
        let bytes = p.encode().unwrap();
        assert_eq!(MtcProof::decode(&bytes).unwrap(), p);
        assert_eq!(
            bytes.len(),
            2 + 6 + 6 + 2 + 96 + 3 + (1 + 1 + 2 + 5) + (1 + 1 + 2)
        );
        let unsorted = MtcProof {
            signatures: p.signatures.iter().rev().cloned().collect(),
            ..p.clone()
        };
        assert_eq!(unsorted.encode(), Err(ProofError::SignaturesNotSorted));
        let mut longer = bytes.clone();
        longer.push(0);
        assert_eq!(MtcProof::decode(&longer), Err(ProofError::TrailingData));
        assert_eq!(
            MtcProof::decode(&bytes[..bytes.len() - 1]),
            Err(ProofError::Truncated)
        );
        let dup = MtcProof {
            signatures: vec![p.signatures[0].clone(), p.signatures[0].clone()],
            ..p.clone()
        };
        assert_eq!(dup.encode(), Err(ProofError::SignaturesNotSorted));
        let big = MtcProof {
            subtree: Subtree {
                start: 0,
                end: 1 << 48,
            },
            ..p
        };
        assert_eq!(big.encode(), Err(ProofError::BadLength("end")));
    }
}
