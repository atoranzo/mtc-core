//! # `mtc-core` — the backend of a Merkle Tree Certificates CA
//!
//! Implements the pieces of `draft-ietf-plants-merkle-tree-certs` (PLANTS
//! working group of the IETF; the version read is the one in its working
//! repository as of 2026-09-29) that a **CA backend** and a **verifier**
//! need to share, under the same rule `zk-ssl-hash` imposed in Arqueo: **a
//! format decision has ONE SINGLE definition**, used both by whoever issues
//! and by whoever checks.
//!
//! ## What it is and what it is not
//!
//! - It is the adaptation of Arqueo's tree infrastructure to an RFC 9162
//!   issuance log: `MTCLogEntry` leaves, `[start, end)` subtrees, inclusion
//!   and consistency proofs, `subtree/v1` cosignatures, the `MTCProof` that
//!   goes in the `signatureValue` of an X.509 certificate, the *landmark*
//!   sequence and the CA flow (receive, record in the log, sign the
//!   checkpoint, cover the interval with two subtrees, collect
//!   cosignatures, issue).
//! - It contains **no** ZK, no sums, no Goldilocks field: the hash is
//!   SHA-256 and the signature is ML-DSA (or any `Cosigner`).
//! - It is **not** a complete CA: ACME, domain validation, CSR parsing
//!   (PKCS#10) and the log service (tlog-tiles) are missing. Each one plugs
//!   in through an interface this crate already defines.
//!
//! ## Module map and where each one comes from
//!
//! | module | what it defines | origin in Arqueo / hbs-state |
//! |---|---|---|
//! | [`hash`] | `MTH` of RFC 9162 over SHA-256 | replaces `zk-ssl-hash::{native_merge, mmr_hoja, mmr_nodo}` |
//! | [`subtree`] | subtrees, inclusion and consistency proofs, interval coverage | translation of `zk-ssl-verify::mmr` (MTH/PATH/SUBPROOF) extended to subtrees |
//! | [`log`] | the issuance log with cached internal nodes | the idea of `zk-ssl::sparse_tree` (node cache, O(log n) per write) over an *append-only* tree |
//! | [`entry`] | `MTCLogEntry`, `TBSCertificateLogEntry`, the `MtcLeaf` leaf | replaces `native_leaf` `(cuenta, saldo, nonce)` |
//! | [`cosign`] | `CosignedMessage`, `Cosigner`, ML-DSA | `firma_cabeza::FirmanteCabeza` (reserve, sign, self-check) |
//! | [`guard`] | the counter persisted before signing | `hbs-state::IndexGuard`, whole, not reimplemented |
//! | [`landmark`] | the landmark sequence and its two subtrees | new (no equivalent) |
//! | [`proof`] | `MTCProof` and the X.509 certificate that carries it | `zk-ssl-verify::inclusion::ReciboInclusion` (leaf → root → signed head) |
//! | [`ca`] | the end-to-end CA flow | `zk-ssl-node` (`latido` heartbeat + head signature) |
//! | [`verify`] | the relying party's verifier | `zk-ssl-verify` (without compiling the issuer) |
//! | [`der`] | the minimum of DER/X.509 that is needed | new |
//!
//! ## What this crate does NOT promise yet
//!
//! It is a **verified skeleton**: the tree algorithms pass the four
//! accumulated vectors of the draft (`tests/vectors.rs`, 65,058 cases) and
//! the large vectors of its appendix (`tests/large_vectors.rs`, trees of up
//! to 2^64-1 leaves), and there is an end-to-end issuance and verification
//! flow with ML-DSA-44 (`tests/end_to_end.rs`). It is not audited, it does
//! not persist the log to disk (only the guard's counter), and the OIDs are
//! the experimental ones from the 1.3.6.1.4.1.44363.47 arc that the draft
//! reserves for that purpose.

pub mod ca;
pub mod cosign;
pub mod der;
pub mod entry;
pub mod guard;
pub mod hash;
pub mod landmark;
pub mod log;
pub mod proof;
pub mod subtree;
pub mod tai;
pub mod verify;

pub use ca::{CaConfig, CertificateRequest, CertificationAuthority, Checkpoint};
pub use cosign::{
    CosignError, CosignatureVerifier, CosignedMessage, Cosigner, SignedSubtree, SubtreeSignature,
};
pub use entry::{LogEntryExtension, MtcLeaf, MtcLogEntry, Validity};
pub use guard::{startup_check, MemoryGuard, SequenceGuard, StartupDecision, StartupRefusal};
pub use hash::{HashValue, HASH_SIZE};
pub use landmark::{Landmark, LandmarkSequence};
pub use log::IssuanceLog;
pub use proof::{MtcCertificate, MtcProof};
pub use subtree::{Subtree, SubtreeError};
pub use tai::TrustAnchorId;
pub use verify::{RelyingPartyConfig, TrustedSubtree, VerifiedCertificate, VerifyError};
