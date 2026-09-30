//! # The tree hash: `MTH` from RFC 9162 over SHA-256
//!
//! Three primitives and no more, with the two domain prefixes that
//! RFC 6962/9162 fix: `0x00` for a leaf, `0x01` for an internal node.
//! It is the same second-preimage defence that `zk-ssl-hash` applied with
//! `MMRHOJA1`/`MMRNODO1`: an internal node presented as a leaf composes
//! differently.
//!
//! ⚠️ There is **no finite field** here. `zk-ssl-hash::native_merge` was
//! Rescue Prime over Goldilocks because it had to be cheap **inside a
//! STARK circuit**. In MTC nobody proves anything in a circuit: the hash is
//! the one the draft RECOMMENDS (SHA-256, `id-pe-mtcCertificationAuthority-
//! SHA256`) and the one the tlog cosigners already speak.

use sha2::{Digest, Sha256};

/// Output bytes of the log hash (`HASH_SIZE` in the draft).
pub const HASH_SIZE: usize = 32;

/// A tree hash value (`HashValue[HASH_SIZE]`).
pub type HashValue = [u8; HASH_SIZE];

/// SHA-256 of an arbitrary message. Exposed because the entry's
/// `subjectPublicKeyInfoHash` uses **the same hash as the log**.
pub fn sha256(data: &[u8]) -> HashValue {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

/// `MTH({}) = HASH("")`: the root of an empty tree and the hash of a
/// subtree `[x, x)`.
pub fn hash_empty() -> HashValue {
    sha256(&[])
}

/// `MTH({d}) = HASH(0x00 || d)`: the leaf.
pub fn hash_leaf(entry: &[u8]) -> HashValue {
    let mut h = Sha256::new();
    h.update([0x00]);
    h.update(entry);
    h.finalize().into()
}

/// `HASH(0x01 || left || right)`: the internal node.
pub fn hash_node(left: &HashValue, right: &HashValue) -> HashValue {
    let mut h = Sha256::new();
    h.update([0x01]);
    h.update(left);
    h.update(right);
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_tree_is_sha256_of_nothing() {
        // The classic SHA-256("") vector.
        let esperado = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        assert_eq!(crate::der::hex(&hash_empty()), esperado);
    }

    #[test]
    fn leaf_and_node_are_domain_separated() {
        let a = hash_leaf(&[1, 2]);
        let b = hash_node(&a, &a);
        // A leaf whose content is two hashes is not a node.
        let mut concat = Vec::new();
        concat.extend_from_slice(&a);
        concat.extend_from_slice(&a);
        assert_ne!(hash_leaf(&concat), b);
    }
}
