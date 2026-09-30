//! # La parte que confia: verificar un certificado MTC
//!
//! El papel de `zk-ssl-verify` en Arqueo: **verificar sin compilar al
//! emisor**. Este modulo no usa `ca`, ni `log`, ni ningun cofirmante
//! concreto: recibe el DER del certificado, la configuracion de la parte
//! que confia y la hora, y sigue el procedimiento de la seccion
//! «Verifying Certificate Signatures» paso a paso, incluido el hash de la
//! entrada **en un solo paso desde el `TBSCertificate`**.
//!
//! ⚠️ Sustituye solo la verificacion de la firma del certificado. El
//! resto de la validacion de ruta X.509 (nombres, usos de clave, CRL/OCSP)
//! sigue siendo del cliente TLS. La caducidad se comprueba aqui por
//! comodidad, porque el `Validity` ya esta parseado.

use crate::cosign::{CosignatureVerifier, CosignedMessage};
use crate::der::{self, DerError};
use crate::entry::{entry_bytes_from_tbs, EntryError, Validity};
use crate::hash::{hash_leaf, HashValue};
use crate::proof::{MtcCertificate, ProofError, MAX_U48};
use crate::subtree::{evaluate_inclusion_proof, Subtree, SubtreeError};
use crate::tai::TrustAnchorId;

/// Un subarbol predistribuido (landmark) que la parte que confia ya
/// considera consistente con sus cofirmantes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedSubtree {
    pub log_number: u16,
    pub subtree: Subtree,
    pub hash: HashValue,
}

/// Un cofirmante reconocido: su ID y su verificador (clave + algoritmo).
pub type CosignerEntry = (TrustAnchorId, Box<dyn CosignatureVerifier>);

/// La configuracion de la parte que confia para UNA CA (seccion «Relying
/// Party Configuration»).
pub struct RelyingPartyConfig {
    pub ca_id: TrustAnchorId,
    /// Cada cofirmante reconocido con su verificador.
    pub cosigners: Vec<CosignerEntry>,
    /// La politica, en su forma mas simple: **todos** estos tienen que
    /// haber cofirmado. Lo habitual: el cofirmante de la CA (autenticidad)
    /// mas un quorum de testigos o espejos (transparencia).
    pub required_cosigners: Vec<TrustAnchorId>,
    pub trusted_subtrees: Vec<TrustedSubtree>,
    /// Rangos `[start, end)` de numeros de serie revocados.
    pub revoked_ranges: Vec<(u64, u64)>,
}

/// Por que se acepto.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Basis {
    /// El subarbol era de confianza (certificado relativo a landmark).
    TrustedSubtree,
    /// Estas cofirmas se comprobaron.
    Cosignatures(Vec<TrustAnchorId>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedCertificate {
    pub serial: u64,
    pub log_number: u16,
    pub index: u64,
    pub subtree: Subtree,
    pub subtree_hash: HashValue,
    pub entry_hash: HashValue,
    pub validity: Validity,
    pub basis: Basis,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    Proof(ProofError),
    Der(DerError),
    Entry(EntryError),
    Subtree(SubtreeError),
    /// El numero de serie no es un entero no negativo de 64 bits.
    BadSerial,
    Revoked(u64),
    LogNumberZero,
    /// El `issuer` no es el `Name` de la CA configurada.
    UnknownIssuer,
    /// El subarbol es de confianza pero su hash no coincide.
    TrustedSubtreeMismatch,
    /// La configuracion no exige ningun cofirmante: no hay nada que comprobar.
    NoCosignerPolicy,
    MissingCosignature(TrustAnchorId),
    UnknownCosigner(TrustAnchorId),
    BadCosignature(TrustAnchorId),
    NotYetValid,
    Expired,
}

impl core::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for VerifyError {}

macro_rules! from_error {
    ($($t:ty => $v:ident),*) => { $(impl From<$t> for VerifyError { fn from(e: $t) -> Self { VerifyError::$v(e) } })* };
}
from_error!(ProofError => Proof, DerError => Der, EntryError => Entry, SubtreeError => Subtree);

/// **Verifica un certificado MTC** en DER contra la configuracion, en el
/// instante `now`.
pub fn verify_certificate(
    cert_der: &[u8],
    cfg: &RelyingPartyConfig,
    now: u64,
) -> Result<VerifiedCertificate, VerifyError> {
    // 1-2 · id-alg-mtcProof y el MTCProof, sin restos.
    let cert = MtcCertificate::from_der(cert_der)?;
    let fields = der::parse_tbs(&cert.tbs_certificate)?;

    // 3-4 · el numero de serie y los rangos revocados.
    let serial =
        der::decode_integer_u64(fields.serial.content).map_err(|_| VerifyError::BadSerial)?;
    if cfg
        .revoked_ranges
        .iter()
        .any(|(a, b)| *a <= serial && serial < *b)
    {
        return Err(VerifyError::Revoked(serial));
    }

    // 5-6 · indice, numero de log y el ID del log.
    let index = serial & MAX_U48;
    let log_number = serial >> 48;
    if log_number == 0 {
        return Err(VerifyError::LogNumberZero);
    }
    let log_number = log_number as u16;
    let issuer = der::ca_id_from_name(fields.issuer.raw).map_err(|_| VerifyError::UnknownIssuer)?;
    if issuer != cfg.ca_id {
        return Err(VerifyError::UnknownIssuer);
    }
    let log_id = cfg.ca_id.log_id(log_number);

    // 7-9 · la entrada reconstruida y su hash.
    let entry_hash = hash_leaf(&entry_bytes_from_tbs(&fields, &cert.proof.extensions)?);

    // 10 · evaluar la prueba de inclusion.
    let subtree = cert.proof.subtree;
    let expected =
        evaluate_inclusion_proof(&entry_hash, subtree, index, &cert.proof.inclusion_proof)?;

    // 11 · un subarbol de confianza decide por si solo…
    let basis = match cfg
        .trusted_subtrees
        .iter()
        .find(|t| t.log_number == log_number && t.subtree == subtree)
    {
        Some(t) => {
            if t.hash != expected {
                return Err(VerifyError::TrustedSubtreeMismatch);
            }
            Basis::TrustedSubtree
        }
        // 12 · …y si no, las cofirmas exigidas, cada una sobre el hash ESPERADO.
        None => {
            if cfg.required_cosigners.is_empty() {
                return Err(VerifyError::NoCosignerPolicy);
            }
            let mut used = Vec::new();
            for id in &cfg.required_cosigners {
                let sig = cert
                    .proof
                    .signatures
                    .iter()
                    .find(|s| &s.cosigner_id == id)
                    .ok_or_else(|| VerifyError::MissingCosignature(id.clone()))?;
                let verifier = cfg
                    .cosigners
                    .iter()
                    .find(|(cid, _)| cid == id)
                    .map(|(_, v)| v)
                    .ok_or_else(|| VerifyError::UnknownCosigner(id.clone()))?;
                let message = CosignedMessage {
                    cosigner_id: id.clone(),
                    timestamp: 0,
                    log_id: log_id.clone(),
                    subtree,
                    subtree_hash: expected,
                };
                if !verifier.verify(&message.to_bytes(), &sig.signature) {
                    return Err(VerifyError::BadCosignature(id.clone()));
                }
                used.push(id.clone());
            }
            Basis::Cosignatures(used)
        }
    };

    // El resto de la validacion X.509 sigue; aqui, la caducidad.
    let validity = Validity::from_der(&fields.validity)?;
    if now < validity.not_before {
        return Err(VerifyError::NotYetValid);
    }
    if now > validity.not_after {
        return Err(VerifyError::Expired);
    }

    Ok(VerifiedCertificate {
        serial,
        log_number,
        index,
        subtree,
        subtree_hash: expected,
        entry_hash,
        validity,
        basis,
    })
}
