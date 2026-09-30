//! # The relying party: verifying an MTC certificate
//!
//! The role of `zk-ssl-verify` in Arqueo: **verify without compiling the
//! issuer**. This module uses neither `ca`, nor `log`, nor any concrete
//! cosigner: it receives the certificate's DER, the relying party's
//! configuration and the time, and follows the procedure of the "Verifying
//! Certificate Signatures" section step by step, including hashing the
//! entry **in a single step from the `TBSCertificate`**.
//!
//! ⚠️ It replaces only the verification of the certificate signature. The
//! rest of X.509 path validation (names, key usages, CRL/OCSP) remains the
//! TLS client's job. Expiry is checked here for convenience, because the
//! `Validity` is already parsed.

use crate::cosign::{CosignatureVerifier, CosignedMessage};
use crate::der::{self, DerError};
use crate::entry::{entry_bytes_from_tbs, EntryError, Validity};
use crate::hash::{hash_leaf, HashValue};
use crate::proof::{MtcCertificate, ProofError, MAX_U48};
use crate::subtree::{evaluate_inclusion_proof, Subtree, SubtreeError};
use crate::tai::TrustAnchorId;

/// A predistributed subtree (landmark) that the relying party already
/// considers consistent with its cosigners.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedSubtree {
    pub log_number: u16,
    pub subtree: Subtree,
    pub hash: HashValue,
}

/// A recognized cosigner: its ID and its verifier (key + algorithm).
pub type CosignerEntry = (TrustAnchorId, Box<dyn CosignatureVerifier>);

/// The relying party's configuration for ONE CA ("Relying Party
/// Configuration" section).
pub struct RelyingPartyConfig {
    pub ca_id: TrustAnchorId,
    /// Each recognized cosigner with its verifier.
    pub cosigners: Vec<CosignerEntry>,
    /// The policy, in its simplest form: **all** of these must have
    /// cosigned, **in addition to the CA's cosigner**, which is always
    /// required (it is the certificate's signature; the draft says the
    /// relying party SHOULD require it, and without it there is no
    /// authenticity). Here go the witnesses or mirrors that provide
    /// transparency. May be empty.
    pub required_cosigners: Vec<TrustAnchorId>,
    pub trusted_subtrees: Vec<TrustedSubtree>,
    /// **Inclusive** ranges `[min, max]` of revoked serial numbers, like
    /// `minSerial`/`maxSerial` in the CA's certificate: this way `2^64-1`
    /// is revocable too.
    pub revoked_ranges: Vec<(u64, u64)>,
}

/// Why it was accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Basis {
    /// The subtree was trusted (landmark-relative certificate).
    TrustedSubtree,
    /// These cosignatures were checked.
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
    /// The serial number is not a non-negative 64-bit integer.
    BadSerial,
    Revoked(u64),
    LogNumberZero,
    /// The `issuer` is not the `Name` of the configured CA.
    UnknownIssuer,
    /// The subtree is trusted but its hash does not match.
    TrustedSubtreeMismatch,
    /// A derived identifier does not fit on the wire (CA ID too long).
    Tai(crate::tai::TaiError),
    /// The cosigned message could not be composed.
    Cosign(String),
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
from_error!(ProofError => Proof, DerError => Der, EntryError => Entry, SubtreeError => Subtree, crate::tai::TaiError => Tai);

/// **Verifies an MTC certificate** in DER against the configuration, at
/// instant `now`.
pub fn verify_certificate(
    cert_der: &[u8],
    cfg: &RelyingPartyConfig,
    now: u64,
) -> Result<VerifiedCertificate, VerifyError> {
    // 1-2 · id-alg-mtcProof and the MTCProof, with no trailing data.
    let cert = MtcCertificate::from_der(cert_der)?;
    let fields = der::parse_tbs(&cert.tbs_certificate)?;

    // 3-4 · the serial number and the revoked ranges.
    let serial =
        der::decode_integer_u64(fields.serial.content).map_err(|_| VerifyError::BadSerial)?;
    if cfg
        .revoked_ranges
        .iter()
        .any(|(min, max)| *min <= serial && serial <= *max)
    {
        return Err(VerifyError::Revoked(serial));
    }

    // 5-6 · index, log number and the log ID.
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
    let log_id = cfg.ca_id.log_id(log_number)?;

    // 7-9 · the reconstructed entry and its hash.
    let entry_hash = hash_leaf(&entry_bytes_from_tbs(&fields, &cert.proof.extensions)?);

    // 10 · evaluate the inclusion proof.
    let subtree = cert.proof.subtree;
    let expected =
        evaluate_inclusion_proof(&entry_hash, subtree, index, &cert.proof.inclusion_proof)?;

    // 11 · a trusted subtree decides on its own…
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
        // 12 · …and otherwise, the required cosignatures —the CA's always—,
        //      each over the EXPECTED hash. Those from unrecognized
        //      cosigners are ignored, as the draft mandates.
        None => {
            let mut required: Vec<&TrustAnchorId> = vec![&cfg.ca_id];
            required.extend(cfg.required_cosigners.iter().filter(|id| **id != cfg.ca_id));
            let mut used = Vec::new();
            for id in required {
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
                let bytes = message
                    .to_bytes()
                    .map_err(|e| VerifyError::Cosign(e.to_string()))?;
                if !verifier.verify(&bytes, &sig.signature) {
                    return Err(VerifyError::BadCosignature(id.clone()));
                }
                used.push(id.clone());
            }
            Basis::Cosignatures(used)
        }
    };

    // The rest of X.509 validation follows; here, expiry.
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
