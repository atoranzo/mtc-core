//! # The CA: from validated request to certificate
//!
//! This is the role `zk-ssl-node` played in Arqueo: the `latido` (heartbeat)
//! that closes an epoch, composes the head, signs it with the guard in front
//! and publishes it. Here the "heartbeat" is the **checkpoint job** of the
//! "Standalone Certificates" section, step by step:
//!
//! 1. the CA signs the checkpoint (`[0, tree_size)`, with a timestamp);
//! 2. it determines the **two subtrees** that cover the entries added
//!    since the previous checkpoint;
//! 3. it signs each subtree;
//! 4. it requests cosignatures of each subtree from the external cosigners
//!    (witnesses, mirrors);
//! 5. it builds one certificate per entry with the subtree that contains it
//!    and the cosignatures collected.
//!
//! Before step 1 there is a step 0 that the draft does not write down and
//! Arqueo does: **reserve the checkpoint number in the guard, with `fsync`**,
//! and only then sign. What that number protects and what it does not is
//! stated precisely in [`crate::guard`]: it is a durable record for
//! reconciling at startup, not a cryptographic binding of the signed view.
//! And the full order for a CA with a disk is: persist the entries with
//! `fsync`, reserve the number, sign. This skeleton does not persist the
//! entries: the plan says so, phase 1.
//!
//! ## What is checked on entry, and what is not
//!
//! [`CertificateRequest`] arrives **already validated** as far as issuance
//! policy goes: domain control (ACME), proof of possession of the key (the
//! CSR signature). What is checked here is what the draft turns into an
//! obligation of the CA, or what would break the log: that the validity is
//! ordered and does not exceed the maximum lifetime (the expiry of each
//! landmark has to cover the `notAfter` of everything beneath it), that the
//! DER fields have the shape they claim to have, and that the entry carries
//! no extensions the CA does not recognize (**a CA does not sign what it
//! does not understand**).

use crate::cosign::{CosignError, Cosigner, SignedSubtree, SubtreeSignature};
use crate::der;
use crate::entry::{EntryError, LogEntryExtension, MtcLeaf, Validity};
use crate::guard::{GuardError, SequenceGuard};
use crate::hash::HashValue;
use crate::landmark::{Landmark, LandmarkError, LandmarkSequence};
use crate::log::{IssuanceLog, LogError};
use crate::proof::{MtcCertificate, MtcProof, ProofError};
use crate::subtree::{covering_subtrees, Subtree, SubtreeError};
use crate::tai::{TaiError, TrustAnchorId};

#[derive(Debug, Clone)]
pub struct CaConfig {
    pub ca_id: TrustAnchorId,
    /// The current log. A real CA runs a series; here, one.
    pub log_number: u16,
    /// Maximum lifetime of a certificate, in seconds: it bounds the validity
    /// that is accepted and fixes the expiry of each landmark.
    pub max_cert_lifetime: u64,
}

/// A request **already validated** by the layer above.
#[derive(Debug, Clone)]
pub struct CertificateRequest {
    /// DER `Name` of the subject.
    pub subject: Vec<u8>,
    /// DER `SubjectPublicKeyInfo`, whole.
    pub spki: Vec<u8>,
    pub validity: Validity,
    /// DER `Extensions` (SAN, key usage…), or nothing.
    pub extensions: Option<Vec<u8>>,
    /// Extensions **of the log entry**. None is defined today, so any of
    /// them is rejected: see [`crate::entry::RECOGNIZED_EXTENSION_TYPES`].
    pub log_entry_extensions: Vec<LogEntryExtension>,
}

/// What a checkpoint job produces.
#[derive(Debug, Clone)]
pub struct Checkpoint {
    /// The number reserved in the guard before signing.
    pub number: u64,
    pub tree_size: u64,
    pub root: HashValue,
    /// The CA's signature over `[0, tree_size)` with a timestamp.
    pub ca_signature: SubtreeSignature,
    /// The two subtrees covering what is new, with their cosignatures.
    pub subtrees: Vec<SignedSubtree>,
}

#[derive(Debug)]
pub enum CaError {
    Log(LogError),
    Entry(EntryError),
    Guard(GuardError),
    Cosign(CosignError),
    Subtree(SubtreeError),
    Proof(ProofError),
    Landmark(LandmarkError),
    Tai(TaiError),
    /// The CA's cosigner does not carry the CA ID.
    CosignerIdMismatch {
        expected: TrustAnchorId,
        got: TrustAnchorId,
    },
    /// An external cosigner with the CA's ID or with an already registered ID.
    DuplicateCosigner(TrustAnchorId),
    /// `notBefore > notAfter`, or the lifetime exceeds `max_cert_lifetime`.
    InvalidValidity {
        not_before: u64,
        not_after: u64,
        max_cert_lifetime: u64,
    },
    /// A DER field of the request does not have the shape it claims to have.
    InvalidDer {
        field: &'static str,
        error: der::DerError,
    },
    /// There is no entry with that index.
    NoSuchEntry(u64),
    /// The entry exists but no checkpoint has covered it yet.
    NotYetCheckpointed(u64),
}

impl core::fmt::Display for CaError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CaError::Log(e) => write!(f, "log: {e}"),
            CaError::Entry(e) => write!(f, "entry: {e}"),
            CaError::Guard(e) => write!(f, "guard: {e}"),
            CaError::Cosign(e) => write!(f, "cosignature: {e}"),
            CaError::Subtree(e) => write!(f, "subtree: {e}"),
            CaError::Proof(e) => write!(f, "proof: {e}"),
            CaError::Landmark(e) => write!(f, "landmark: {e}"),
            CaError::Tai(e) => write!(f, "identifier: {e}"),
            CaError::CosignerIdMismatch { expected, got } => {
                write!(
                    f,
                    "the CA's cosigner carries ID {got} and the CA is {expected}"
                )
            }
            CaError::DuplicateCosigner(id) => write!(f, "duplicate cosigner: {id}"),
            CaError::InvalidValidity {
                not_before,
                not_after,
                max_cert_lifetime,
            } => write!(
                f,
                "invalid validity: [{not_before}, {not_after}] with maximum lifetime {max_cert_lifetime}"
            ),
            CaError::InvalidDer { field, error } => write!(f, "invalid DER in {field}: {error}"),
            CaError::NoSuchEntry(i) => write!(f, "no entry {i}"),
            CaError::NotYetCheckpointed(i) => {
                write!(f, "entry {i} is not yet under a checkpoint")
            }
        }
    }
}

impl std::error::Error for CaError {}

macro_rules! from_error {
    ($($t:ty => $v:ident),*) => { $(impl From<$t> for CaError { fn from(e: $t) -> Self { CaError::$v(e) } })* };
}
from_error!(LogError => Log, EntryError => Entry, GuardError => Guard, CosignError => Cosign,
            SubtreeError => Subtree, ProofError => Proof, LandmarkError => Landmark, TaiError => Tai);

/// The MTC CA.
pub struct CertificationAuthority<G: SequenceGuard> {
    cfg: CaConfig,
    log_id: TrustAnchorId,
    log: IssuanceLog,
    /// The leaves, by index: the CA needs them whole (with the SPKI) to
    /// compose the `TBSCertificate`; the log only carries the hash.
    leaves: Vec<MtcLeaf>,
    /// The largest `notAfter` recorded: the lower bound on the expiry of
    /// any landmark that covers the whole log.
    max_not_after: u64,
    ca_cosigner: Box<dyn Cosigner>,
    external_cosigners: Vec<Box<dyn Cosigner>>,
    guard: G,
    last_checkpoint_size: u64,
    /// The signed subtrees, in issuance order. They grow with each
    /// checkpoint; [`Self::prune_signed_subtrees_below`] trims them.
    signed_subtrees: Vec<SignedSubtree>,
    landmarks: LandmarkSequence,
}

impl<G: SequenceGuard> CertificationAuthority<G> {
    /// A CA with its cosigner (the one holding the CA's ID) and its guard.
    /// Fails at startup, not at issuance, if the CA ID leaves no room for
    /// its derived IDs or the cosigner does not carry that ID.
    pub fn new(cfg: CaConfig, ca_cosigner: Box<dyn Cosigner>, guard: G) -> Result<Self, CaError> {
        cfg.ca_id.check_as_ca_id()?;
        if ca_cosigner.cosigner_id() != &cfg.ca_id {
            return Err(CaError::CosignerIdMismatch {
                expected: cfg.ca_id.clone(),
                got: ca_cosigner.cosigner_id().clone(),
            });
        }
        let log = IssuanceLog::new(cfg.log_number)?;
        let log_id = cfg.ca_id.log_id(cfg.log_number)?;
        Ok(CertificationAuthority {
            cfg,
            log_id,
            log,
            leaves: Vec::new(),
            max_not_after: 0,
            ca_cosigner,
            external_cosigners: Vec::new(),
            guard,
            last_checkpoint_size: 0,
            signed_subtrees: Vec::new(),
            landmarks: LandmarkSequence::new(),
        })
    }

    /// An external cosigner (witness, mirror) to request cosignatures from.
    /// Neither the CA's ID nor one already registered: the `MTCProof`
    /// requires unique IDs, and a repeat would silently replace the previous
    /// signature.
    pub fn add_cosigner(&mut self, cosigner: Box<dyn Cosigner>) -> Result<(), CaError> {
        let id = cosigner.cosigner_id();
        if id == &self.cfg.ca_id
            || self
                .external_cosigners
                .iter()
                .any(|c| c.cosigner_id() == id)
        {
            return Err(CaError::DuplicateCosigner(id.clone()));
        }
        self.external_cosigners.push(cosigner);
        Ok(())
    }

    pub fn ca_id(&self) -> &TrustAnchorId {
        &self.cfg.ca_id
    }

    pub fn log_id(&self) -> &TrustAnchorId {
        &self.log_id
    }

    pub fn log(&self) -> &IssuanceLog {
        &self.log
    }

    pub fn landmarks(&self) -> &LandmarkSequence {
        &self.landmarks
    }

    pub fn guard(&self) -> &G {
        &self.guard
    }

    pub fn last_checkpoint_size(&self) -> u64 {
        self.last_checkpoint_size
    }

    fn check_der(field: &'static str, bytes: &[u8], tag: u8) -> Result<(), CaError> {
        let map = |error| CaError::InvalidDer { field, error };
        let (_, rest) = der::expect_tlv(bytes, tag).map_err(map)?;
        if !rest.is_empty() {
            return Err(map(der::DerError::TrailingData));
        }
        Ok(())
    }

    /// **Step 3a**: checks the request, records it in the log and returns
    /// its index.
    pub fn submit(&mut self, req: CertificateRequest) -> Result<u64, CaError> {
        let v = req.validity;
        if v.not_before > v.not_after || v.not_after - v.not_before > self.cfg.max_cert_lifetime {
            return Err(CaError::InvalidValidity {
                not_before: v.not_before,
                not_after: v.not_after,
                max_cert_lifetime: self.cfg.max_cert_lifetime,
            });
        }
        Self::check_der("subject", &req.subject, der::TAG_SEQUENCE)?;
        der::spki_algorithm(&req.spki).map_err(|error| CaError::InvalidDer {
            field: "spki",
            error,
        })?;
        if let Some(ext) = &req.extensions {
            Self::check_der("extensions", ext, der::TAG_SEQUENCE)?;
        }
        let leaf = MtcLeaf {
            version: 2,
            issuer: der::name_from_ca_id(&self.cfg.ca_id),
            validity: v,
            subject: req.subject,
            spki: req.spki,
            issuer_unique_id: None,
            subject_unique_id: None,
            extensions: req.extensions,
        };
        // `log_entry` rejects unrecognized log entry extensions.
        let entry = leaf.log_entry(req.log_entry_extensions)?;
        let index = self.log.append(&entry)?;
        debug_assert_eq!(index as usize, self.leaves.len());
        self.leaves.push(leaf);
        self.max_not_after = self.max_not_after.max(v.not_after);
        Ok(index)
    }

    /// **The checkpoint job** (steps 0 to 4). `None` if nothing is new
    /// since the previous one. If something fails midway, the CA's state
    /// does not change: the reserved number is left orphaned, which is the
    /// case the guard knows how to reconcile.
    pub fn run_checkpoint_job(&mut self, now: u64) -> Result<Option<Checkpoint>, CaError> {
        let tree_size = self.log.size();
        if tree_size == self.last_checkpoint_size {
            return Ok(None);
        }
        let root = self.log.root();

        // ── 0 · reserve and persist BEFORE signing ──
        let number = self.guard.reserve()?;

        // ── 1 · the CA signs the checkpoint ──
        let checkpoint = Subtree {
            start: 0,
            end: tree_size,
        };
        let ca_signature = self
            .ca_cosigner
            .sign_subtree(&self.log_id, checkpoint, root, now)?;

        // ── 2 · the two subtrees covering what is new ──
        let (left, right) = covering_subtrees(self.last_checkpoint_size, tree_size);
        let mut subtrees = Vec::new();
        for st in [left, right] {
            if st.is_empty() {
                continue;
            }
            let hash = self.log.subtree_hash(st)?;
            let mut signed = SignedSubtree::new(st, hash);
            // ── 3 · the CA signs each subtree (timestamp 0) ──
            signed.push(self.ca_cosigner.sign_subtree(&self.log_id, st, hash, 0)?);
            // ── 4 · external cosignatures ──
            for c in self.external_cosigners.iter_mut() {
                signed.push(c.sign_subtree(&self.log_id, st, hash, 0)?);
            }
            subtrees.push(signed);
        }
        self.signed_subtrees.extend(subtrees.iter().cloned());
        self.last_checkpoint_size = tree_size;
        Ok(Some(Checkpoint {
            number,
            tree_size,
            root,
            ca_signature,
            subtrees,
        }))
    }

    fn certificate_with(
        &self,
        index: u64,
        subtree: Subtree,
        signatures: Vec<SubtreeSignature>,
    ) -> Result<MtcCertificate, CaError> {
        let leaf = usize::try_from(index)
            .ok()
            .and_then(|i| self.leaves.get(i))
            .ok_or(CaError::NoSuchEntry(index))?;
        let entry = crate::entry::MtcLogEntry::decode(
            self.log.entry(index).ok_or(CaError::NoSuchEntry(index))?,
        )?;
        let serial = ((self.cfg.log_number as u64) << 48) | index;
        Ok(MtcCertificate {
            tbs_certificate: leaf.tbs_certificate(serial)?,
            proof: MtcProof {
                extensions: entry.extensions().to_vec(),
                subtree,
                inclusion_proof: self.log.inclusion_proof(subtree, index)?,
                signatures,
            },
        })
    }

    /// **Step 5**: the *standalone* certificate of an entry, with the most
    /// recent signed subtree that contains it.
    pub fn standalone_certificate(&self, index: u64) -> Result<MtcCertificate, CaError> {
        if index >= self.log.size() {
            return Err(CaError::NoSuchEntry(index));
        }
        let signed = self
            .signed_subtrees
            .iter()
            .rev()
            .find(|s| s.subtree.contains(index))
            .ok_or(CaError::NotYetCheckpointed(index))?;
        self.certificate_with(index, signed.subtree, signed.signatures.clone())
    }

    /// Forgets the signed subtrees that end before `index`: those of entries
    /// already expired or already covered by a landmark. It is the only
    /// thing that grows with each checkpoint.
    pub fn prune_signed_subtrees_below(&mut self, index: u64) -> usize {
        let before = self.signed_subtrees.len();
        self.signed_subtrees.retain(|s| s.subtree.end > index);
        before - self.signed_subtrees.len()
    }

    /// Allocates a landmark if the tree has grown since the last one
    /// (RECOMMENDED procedure). The expiry is `now + max_cert_lifetime`
    /// **or the largest `notAfter` of the entries it covers, if later**: the
    /// draft requires that a landmark not expire before anything beneath
    /// it.
    pub fn allocate_landmark(&mut self, now: u64) -> Result<Option<Landmark>, CaError> {
        let size = self.last_checkpoint_size;
        if size == self.landmarks.latest().tree_size {
            return Ok(None);
        }
        let expiry = now
            .saturating_add(self.cfg.max_cert_lifetime)
            .max(self.max_not_after);
        Ok(Some(*self.landmarks.allocate(size, expiry)?))
    }

    /// The **landmark-relative** certificate of an entry: only the inclusion
    /// proof to the landmark's subtree, with no signatures.
    pub fn landmark_relative_certificate(&self, index: u64) -> Result<MtcCertificate, CaError> {
        if index >= self.log.size() {
            return Err(CaError::NoSuchEntry(index));
        }
        let (_, subtree) = self.landmarks.subtree_for_index(index)?;
        self.certificate_with(index, subtree, Vec::new())
    }

    /// The subtrees of the active landmarks with their hash: what is
    /// predistributed to relying parties as trusted subtrees.
    pub fn active_landmark_subtrees(
        &self,
        now: u64,
    ) -> Result<Vec<(Landmark, Subtree, HashValue)>, CaError> {
        let mut out = Vec::new();
        for l in self.landmarks.active(now) {
            let (a, b) = self
                .landmarks
                .subtrees(l.number)
                .expect("existing landmark");
            for st in [a, b] {
                if !st.is_empty() {
                    out.push((*l, st, self.log.subtree_hash(st)?));
                }
            }
        }
        Ok(out)
    }
}
