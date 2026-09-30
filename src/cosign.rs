//! # Cosignatures: `CosignedMessage`, `Cosigner` and ML-DSA
//!
//! What `zk-ssl-node::firma_cabeza::FirmanteCabeza` (the head signer) did in
//! Arqueo —signing the epoch head with a domain preamble, **reserving the
//! index first** and **verifying its own output before returning it**—
//! is done here by a [`Cosigner`] over the draft's `CosignedMessage`
//! (section "Signature Format"), with the label `subtree/v1\n\0`. It is the
//! same `cosigned_message` structure as the C2SP `tlog-cosignature`
//! specification for ML-DSA-44, byte for byte: a test checks it against
//! the draft's reference implementation in Go.
//!
//! ## Why the CA signs little, and what that enables
//!
//! The CA signs **one checkpoint and two subtrees per cycle**, not one
//! certificate per request. That is what makes a large post-quantum
//! signature (ML-DSA-44: 2,420 bytes) viable, or even **a stateful
//! hash-based signature** (XMSS/LMS), because the index is consumed at
//! the rate of checkpoints, not of issuances. For that second option the
//! `hbs-state` guard is exactly the missing piece, and that is why
//! [`Cosigner::sign_message`] takes `&mut self`: a stateful signer has
//! to be able to reserve its index.
//!
//! ## ML-DSA: hedged (salted) by default
//!
//! FIPS 204 defines two signing variants: the **hedged** one (32 random
//! bytes per signature) is the recommended one, and the deterministic one is
//! optional; the standard itself warns of its lower resistance to fault
//! and side-channel attacks. Neither changes verification, and
//! `tlog-cosignature` fixes neither. [`mldsa::MlDsaCosigner::from_seed`]
//! signs with salt taken from the system; [`mldsa::MlDsaCosigner::deterministic`]
//! exists to reproduce vectors, and says so.

use crate::hash::HashValue;
use crate::subtree::Subtree;
use crate::tai::{TaiError, TrustAnchorId};

/// `uint8 label[12] = "subtree/v1\n\0"`.
pub const SUBTREE_LABEL: &[u8; 12] = b"subtree/v1\n\0";

/// What a cosigner signs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CosignedMessage {
    pub cosigner_id: TrustAnchorId,
    /// Zero in the cosignatures that go inside a certificate. Non-zero
    /// only in a timestamped checkpoint (`start = 0`, `end` = the largest
    /// consistent tree observed). **If `start` is not zero, it has to be
    /// zero**: the draft and `tlog-cosignature` both require it.
    pub timestamp: u64,
    pub log_id: TrustAnchorId,
    pub subtree: Subtree,
    pub subtree_hash: HashValue,
}

impl CosignedMessage {
    /// The rules a message has to satisfy before being signed.
    pub fn check(&self) -> Result<(), CosignError> {
        self.subtree.check()?;
        if self.timestamp != 0 && self.subtree.start != 0 {
            return Err(CosignError::TimestampOnSubtree {
                start: self.subtree.start,
                timestamp: self.timestamp,
            });
        }
        // `tlog-cosignature`: the timestamp does not exceed 2^63 - 1.
        if self.timestamp > i64::MAX as u64 {
            return Err(CosignError::TimestampOnSubtree {
                start: self.subtree.start,
                timestamp: self.timestamp,
            });
        }
        Ok(())
    }

    /// The TLS serialization of the `CosignedMessage`: **a single definition**
    /// for whoever signs and whoever verifies. Fails closed if a name does
    /// not fit in its one-byte prefix or the message violates a rule.
    pub fn to_bytes(&self) -> Result<Vec<u8>, CosignError> {
        self.check()?;
        let name = self.cosigner_id.oid_name()?;
        let origin = self.log_id.oid_name()?;
        let mut out = Vec::with_capacity(12 + 1 + name.len() + 8 + 1 + origin.len() + 8 + 8 + 32);
        out.extend_from_slice(SUBTREE_LABEL);
        out.push(name.len() as u8);
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(&self.timestamp.to_be_bytes());
        out.push(origin.len() as u8);
        out.extend_from_slice(origin.as_bytes());
        out.extend_from_slice(&self.subtree.start.to_be_bytes());
        out.extend_from_slice(&self.subtree.end.to_be_bytes());
        out.extend_from_slice(&self.subtree_hash);
        Ok(out)
    }
}

/// `SubtreeSignature { cosigner_id, signature<0..2^16-1> }`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubtreeSignature {
    pub cosigner_id: TrustAnchorId,
    pub signature: Vec<u8>,
}

/// A subtree with its hash and the collected cosignatures, **in canonical
/// order** (by `cosigner_id`), ready to go into an `MTCProof`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedSubtree {
    pub subtree: Subtree,
    pub hash: HashValue,
    pub signatures: Vec<SubtreeSignature>,
}

impl SignedSubtree {
    pub fn new(subtree: Subtree, hash: HashValue) -> Self {
        SignedSubtree {
            subtree,
            hash,
            signatures: Vec::new(),
        }
    }

    /// Inserts while keeping the order; a second cosignature from the same
    /// ID replaces the first.
    pub fn push(&mut self, sig: SubtreeSignature) {
        match self
            .signatures
            .binary_search_by(|s| s.cosigner_id.cmp(&sig.cosigner_id))
        {
            Ok(i) => self.signatures[i] = sig,
            Err(i) => self.signatures.insert(i, sig),
        }
    }
}

#[derive(Debug)]
pub enum CosignError {
    /// The algorithm could not sign, or the freshly made signature does not verify.
    Signing(String),
    /// No entropy was available for the salt of a hedged signature.
    Randomness(String),
    /// The index guard refused (fake fsync, corrupt counter...).
    Guard(hbs_state::GuardError),
    /// An identifier does not fit in the message.
    Tai(TaiError),
    /// The subtree is not valid.
    Subtree(crate::subtree::SubtreeError),
    /// A timestamp on a subtree that does not start at zero.
    TimestampOnSubtree { start: u64, timestamp: u64 },
}

impl core::fmt::Display for CosignError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CosignError::Signing(s) => write!(f, "signature: {s}"),
            CosignError::Randomness(s) => write!(f, "entropy: {s}"),
            CosignError::Guard(g) => write!(f, "guard: {g}"),
            CosignError::Tai(e) => write!(f, "identifier: {e}"),
            CosignError::Subtree(e) => write!(f, "subtree: {e}"),
            CosignError::TimestampOnSubtree { start, timestamp } => {
                write!(
                    f,
                    "timestamp {timestamp} on a subtree that starts at {start}"
                )
            }
        }
    }
}

impl std::error::Error for CosignError {}

impl From<hbs_state::GuardError> for CosignError {
    fn from(e: hbs_state::GuardError) -> Self {
        CosignError::Guard(e)
    }
}

impl From<TaiError> for CosignError {
    fn from(e: TaiError) -> Self {
        CosignError::Tai(e)
    }
}

impl From<crate::subtree::SubtreeError> for CosignError {
    fn from(e: crate::subtree::SubtreeError) -> Self {
        CosignError::Subtree(e)
    }
}

/// Whoever signs subtrees of a log.
pub trait Cosigner {
    fn cosigner_id(&self) -> &TrustAnchorId;

    /// Signs a `CosignedMessage` whose `cosigner_id` is its own.
    /// `&mut self` because a stateful signer consumes index.
    fn sign_message(&mut self, message: &CosignedMessage) -> Result<Vec<u8>, CosignError>;

    /// Composes the message, checks it and signs.
    fn sign_subtree(
        &mut self,
        log_id: &TrustAnchorId,
        subtree: Subtree,
        subtree_hash: HashValue,
        timestamp: u64,
    ) -> Result<SubtreeSignature, CosignError> {
        let message = CosignedMessage {
            cosigner_id: self.cosigner_id().clone(),
            timestamp,
            log_id: log_id.clone(),
            subtree,
            subtree_hash,
        };
        message.check()?;
        let signature = self.sign_message(&message)?;
        Ok(SubtreeSignature {
            cosigner_id: message.cosigner_id,
            signature,
        })
    }
}

/// Whoever verifies cosignatures of ONE cosigner (key and algorithm fixed
/// by its ID, as section "Signature Algorithms" requires).
pub trait CosignatureVerifier {
    fn verify(&self, message: &[u8], signature: &[u8]) -> bool;
}

#[cfg(feature = "ml-dsa")]
pub mod mldsa {
    //! ML-DSA (FIPS 204) as cosigner and as verifier.

    use super::{CosignError, CosignatureVerifier, CosignedMessage, Cosigner};
    use crate::hash::sha256;
    use crate::tai::TrustAnchorId;
    use ml_dsa::signature::Keypair;
    use ml_dsa::{
        EncodedVerifyingKey, MlDsaParams, Seed, Signature, SigningKey, VerifyingKey, B32,
    };
    use zeroize::Zeroize;

    pub use ml_dsa::{MlDsa44, MlDsa65, MlDsa87};

    /// The `tlog-cosignature` signature type byte for ML-DSA-44.
    pub const TLOG_KEY_TYPE_MLDSA44: u8 = 0x06;
    /// Bytes of an ML-DSA-44 public key (`pkEncode`).
    pub const MLDSA44_PUBLIC_KEY_LEN: usize = 1312;

    /// The `tlog-cosignature` key ID of an ML-DSA-44 cosigner, from its
    /// name and public key: **one definition** for whoever signs a
    /// checkpoint and whoever checks a checkpoint line.
    pub fn tlog_key_id_for(id: &TrustAnchorId, public_key: &[u8]) -> Result<[u8; 4], CosignError> {
        if public_key.len() != MLDSA44_PUBLIC_KEY_LEN {
            return Err(CosignError::Signing(format!(
                "tlog-cosignature only defines the key ID for ML-DSA-44 ({MLDSA44_PUBLIC_KEY_LEN}-byte key, not {})",
                public_key.len()
            )));
        }
        let mut input = id.oid_name()?.into_bytes();
        input.push(b'\n');
        input.push(TLOG_KEY_TYPE_MLDSA44);
        input.extend_from_slice(public_key);
        let h = sha256(&input);
        Ok([h[0], h[1], h[2], h[3]])
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SigningMode {
        /// The variant recommended by FIPS 204: 32 bytes of salt per signature.
        Hedged,
        /// The optional variant: reproducible, and therefore more exposed to
        /// fault attacks. For test vectors.
        Deterministic,
    }

    /// An ML-DSA cosigner. `P` is `MlDsa44` (the one `tlog-cosignature` and
    /// the `mtc-tlog` profile fix), `MlDsa65` or `MlDsa87`.
    pub struct MlDsaCosigner<P: MlDsaParams> {
        id: TrustAnchorId,
        key: SigningKey<P>,
        mode: SigningMode,
    }

    impl<P: MlDsaParams> MlDsaCosigner<P> {
        /// ⚠️ **The seed is key material.** Where it comes from (HSM, KMS,
        /// a 0600 file as in `hbs_state::seed`) is a deployment decision.
        /// The local copy is wiped when done; **the caller's copy is theirs**.
        /// Signs with salt ([`SigningMode::Hedged`]).
        pub fn from_seed(id: TrustAnchorId, seed: [u8; 32]) -> Self {
            Self::with_mode(id, seed, SigningMode::Hedged)
        }

        /// Deterministic signing: same input, same signature. Only to
        /// reproduce vectors; see the module's warning.
        pub fn deterministic(id: TrustAnchorId, seed: [u8; 32]) -> Self {
            Self::with_mode(id, seed, SigningMode::Deterministic)
        }

        fn with_mode(id: TrustAnchorId, mut seed: [u8; 32], mode: SigningMode) -> Self {
            let key = SigningKey::<P>::from_seed(&Seed::from(seed));
            seed.zeroize();
            MlDsaCosigner { id, key, mode }
        }

        pub fn mode(&self) -> SigningMode {
            self.mode
        }

        /// The encoded public key (`pkEncode`), for the CA's certificate
        /// and for the relying party's configuration.
        pub fn verifying_key_bytes(&self) -> Vec<u8> {
            self.key.verifying_key().encode().to_vec()
        }

        pub fn verifier(&self) -> MlDsaVerifier<P> {
            MlDsaVerifier {
                key: self.key.verifying_key(),
            }
        }

        /// The `tlog-cosignature` *key ID* for ML-DSA-44:
        /// `SHA-256(name || "\n" || 0x06 || 1312-byte public key)[:4]`.
        /// It is what precedes the signature on a tlog checkpoint line.
        /// Only defined for ML-DSA-44.
        pub fn tlog_key_id(&self) -> Result<[u8; 4], CosignError> {
            tlog_key_id_for(&self.id, &self.verifying_key_bytes())
        }

        /// The signature as it goes on a tlog note line (before base64):
        /// `key_id || timestamped_signature { u64 timestamp; signature }`.
        pub fn tlog_note_signature(
            &self,
            timestamp: u64,
            signature: &[u8],
        ) -> Result<Vec<u8>, CosignError> {
            let mut out = self.tlog_key_id()?.to_vec();
            out.extend_from_slice(&timestamp.to_be_bytes());
            out.extend_from_slice(signature);
            Ok(out)
        }
    }

    impl<P: MlDsaParams> Cosigner for MlDsaCosigner<P> {
        fn cosigner_id(&self) -> &TrustAnchorId {
            &self.id
        }

        fn sign_message(&mut self, message: &CosignedMessage) -> Result<Vec<u8>, CosignError> {
            let bytes = message.to_bytes()?;
            let expanded = self.key.expanded_key();
            let sig = match self.mode {
                SigningMode::Deterministic => expanded
                    .sign_deterministic(&bytes, &[])
                    .map_err(|e| CosignError::Signing(e.to_string()))?,
                SigningMode::Hedged => {
                    let mut rnd = [0u8; 32];
                    getrandom::fill(&mut rnd)
                        .map_err(|e| CosignError::Randomness(e.to_string()))?;
                    // Algorithm 2 of FIPS 204 in pure mode with empty context:
                    // M' = 0x00 || len(ctx) = 0x00 || ctx (empty) || M.
                    let sig = expanded.sign_internal(&[&[0x00, 0x00], &bytes], &B32::from(rnd));
                    rnd.zeroize();
                    sig
                }
            };
            let encoded = sig.encode().to_vec();
            // ⚠️ Verify our own output BEFORE returning it, with the same
            // verifier a third party will use (rule from §299 of Arqueo).
            if !self.verifier().verify(&bytes, &encoded) {
                return Err(CosignError::Signing(
                    "the freshly produced signature does not verify".into(),
                ));
            }
            Ok(encoded)
        }
    }

    /// The verifier of an ML-DSA cosigner.
    pub struct MlDsaVerifier<P: MlDsaParams> {
        key: VerifyingKey<P>,
    }

    impl<P: MlDsaParams> MlDsaVerifier<P> {
        pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
            let enc = EncodedVerifyingKey::<P>::try_from(bytes).ok()?;
            Some(MlDsaVerifier {
                key: VerifyingKey::<P>::decode(&enc),
            })
        }

        /// The encoded public key (`pkEncode`), as it went in.
        pub fn verifying_key_bytes(&self) -> Vec<u8> {
            self.key.encode().to_vec()
        }
    }

    impl<P: MlDsaParams> CosignatureVerifier for MlDsaVerifier<P> {
        fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
            match Signature::<P>::try_from(signature) {
                Ok(sig) => self.key.verify_with_context(message, &[], &sig),
                Err(_) => false,
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::subtree::Subtree;

        fn message(id: &TrustAnchorId, hash: u8) -> CosignedMessage {
            CosignedMessage {
                cosigner_id: id.clone(),
                timestamp: 0,
                log_id: id.log_id(1).unwrap(),
                subtree: Subtree { start: 0, end: 5 },
                subtree_hash: [hash; 32],
            }
        }

        #[test]
        fn a_cosignature_verifies_and_a_tampered_one_does_not() {
            let id = TrustAnchorId::from_ascii("32473.1").unwrap();
            let mut signer = MlDsaCosigner::<MlDsa44>::from_seed(id.clone(), [1u8; 32]);
            let log = id.log_id(1).unwrap();
            let sig = signer
                .sign_subtree(&log, Subtree { start: 0, end: 5 }, [9u8; 32], 0)
                .unwrap();
            assert_eq!(sig.signature.len(), 2420); // ML-DSA-44
            let verifier =
                MlDsaVerifier::<MlDsa44>::from_bytes(&signer.verifying_key_bytes()).unwrap();
            let msg = message(&id, 9);
            assert!(verifier.verify(&msg.to_bytes().unwrap(), &sig.signature));
            let other = message(&id, 8);
            assert!(!verifier.verify(&other.to_bytes().unwrap(), &sig.signature));
            assert!(!verifier.verify(&[], &sig.signature[..100]));
            assert!(MlDsaVerifier::<MlDsa44>::from_bytes(&[0; 100]).is_none());
        }

        /// Hedged, two signatures of the same message differ and both verify;
        /// deterministic, they coincide. Verification does not tell them apart.
        #[test]
        fn hedged_signatures_differ_and_verify_while_deterministic_ones_repeat() {
            let id = TrustAnchorId::from_ascii("32473.1").unwrap();
            let msg = message(&id, 3);
            let mut hedged = MlDsaCosigner::<MlDsa44>::from_seed(id.clone(), [5u8; 32]);
            let a = hedged.sign_message(&msg).unwrap();
            let b = hedged.sign_message(&msg).unwrap();
            assert_ne!(a, b);
            let v = hedged.verifier();
            assert!(
                v.verify(&msg.to_bytes().unwrap(), &a) && v.verify(&msg.to_bytes().unwrap(), &b)
            );
            let mut det = MlDsaCosigner::<MlDsa44>::deterministic(id, [5u8; 32]);
            let c = det.sign_message(&msg).unwrap();
            assert_eq!(c, det.sign_message(&msg).unwrap());
            assert!(
                v.verify(&msg.to_bytes().unwrap(), &c),
                "same key, different variant, same verification"
            );
        }

        #[test]
        fn tlog_key_id_follows_c2sp() {
            let id = TrustAnchorId::from_ascii("32473.1").unwrap();
            let signer = MlDsaCosigner::<MlDsa44>::from_seed(id.clone(), [1u8; 32]);
            let mut input = b"oid/1.3.6.1.4.1.32473.1\n\x06".to_vec();
            input.extend(signer.verifying_key_bytes());
            let h = sha256(&input);
            assert_eq!(signer.tlog_key_id().unwrap(), [h[0], h[1], h[2], h[3]]);
            let note = signer
                .tlog_note_signature(1_700_000_000, &[0xaa; 3])
                .unwrap();
            assert_eq!(note.len(), 4 + 8 + 3);
            assert_eq!(&note[4..12], &1_700_000_000u64.to_be_bytes());
            // ML-DSA-65 has no defined key ID.
            let big = MlDsaCosigner::<MlDsa65>::from_seed(id, [1u8; 32]);
            assert!(big.tlog_key_id().is_err());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_message_layout_is_the_one_of_the_draft() {
        let ca = TrustAnchorId::from_ascii("32473.1").unwrap();
        let m = CosignedMessage {
            cosigner_id: ca.clone(),
            timestamp: 0,
            log_id: ca.log_id(1).unwrap(),
            subtree: Subtree { start: 4, end: 8 },
            subtree_hash: [0xab; 32],
        };
        let b = m.to_bytes().unwrap();
        assert_eq!(&b[..12], b"subtree/v1\n\0");
        let name = b"oid/1.3.6.1.4.1.32473.1";
        assert_eq!(b[12] as usize, name.len());
        assert_eq!(&b[13..13 + name.len()], name);
        let origin = b"oid/1.3.6.1.4.1.32473.1.0.1";
        let o = 13 + name.len() + 8;
        assert_eq!(b[o] as usize, origin.len());
        assert_eq!(&b[o + 1..o + 1 + origin.len()], origin);
        let s = o + 1 + origin.len();
        assert_eq!(&b[s..s + 8], &4u64.to_be_bytes());
        assert_eq!(&b[s + 8..s + 16], &8u64.to_be_bytes());
        assert_eq!(&b[s + 16..], &[0xab; 32]);
    }

    #[test]
    fn a_timestamp_on_a_subtree_that_does_not_start_at_zero_is_rejected() {
        let ca = TrustAnchorId::from_ascii("32473.1").unwrap();
        let m = CosignedMessage {
            cosigner_id: ca.clone(),
            timestamp: 7,
            log_id: ca.log_id(1).unwrap(),
            subtree: Subtree { start: 4, end: 8 },
            subtree_hash: [0; 32],
        };
        assert!(matches!(
            m.to_bytes(),
            Err(CosignError::TimestampOnSubtree {
                start: 4,
                timestamp: 7
            })
        ));
        let checkpoint = CosignedMessage {
            subtree: Subtree { start: 0, end: 8 },
            ..m.clone()
        };
        assert!(checkpoint.to_bytes().is_ok());
        let invalid = CosignedMessage {
            subtree: Subtree { start: 1, end: 5 },
            timestamp: 0,
            ..m
        };
        assert!(matches!(invalid.to_bytes(), Err(CosignError::Subtree(_))));
    }

    #[test]
    fn a_name_that_does_not_fit_fails_closed() {
        let long = TrustAnchorId::from_binary(&[0x7f; 100]).unwrap();
        let m = CosignedMessage {
            cosigner_id: long.clone(),
            timestamp: 0,
            log_id: long,
            subtree: Subtree { start: 0, end: 1 },
            subtree_hash: [0; 32],
        };
        assert!(matches!(
            m.to_bytes(),
            Err(CosignError::Tai(TaiError::NameTooLong(_)))
        ));
    }

    #[test]
    fn signatures_stay_in_canonical_order() {
        let mut s = SignedSubtree::new(Subtree { start: 0, end: 1 }, [0; 32]);
        for id in ["300", "2", "1"] {
            s.push(SubtreeSignature {
                cosigner_id: TrustAnchorId::from_ascii(id).unwrap(),
                signature: vec![],
            });
        }
        let ids: Vec<String> = s
            .signatures
            .iter()
            .map(|x| x.cosigner_id.to_ascii())
            .collect();
        assert_eq!(ids, ["1", "2", "300"]);
        s.push(SubtreeSignature {
            cosigner_id: TrustAnchorId::from_ascii("2").unwrap(),
            signature: vec![1],
        });
        assert_eq!(s.signatures.len(), 3);
        assert_eq!(s.signatures[1].signature, vec![1]);
    }
}
