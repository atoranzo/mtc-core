//! # Subtrees, inclusion proofs and consistency proofs
//!
//! The MTC translation of `zk-ssl-verify::mmr` (§291 of Arqueo): there
//! lived `MTH`, `PATH` and `SUBPROOF` from RFC 6962 over the in-house
//! primitives; here live the same three algorithms over SHA-256 and
//! **extended to subtrees `[start, end)`**, which is what the draft adds
//! to RFC 9162 (section "Subtrees").
//!
//! ⚠️ **Generation and verification share the same partition** of the
//! tree —`k = the largest power of two < n`— but not the same shape:
//! generation is the RFC 9162 recursion over a hash provider, and
//! verification is the draft's iterative bit walk (`fn`, `sn`, `tn`),
//! which does not need the tree. What ties them together is that the
//! verifier demands consuming the **whole** path: a path with leftovers or
//! with gaps does not pass. The four accumulated vectors from the draft
//! (`tests/vectors.rs`) check this for every subtree of every tree up to
//! 130 leaves, and the large vectors (`tests/large_vectors.rs`) for trees
//! of up to 2^64-1.
//!
//! ## The hash provider
//!
//! The generation algorithms do not know whether the tree is in memory as
//! a list of leaves or as a log with cached nodes: they ask a
//! [`TreeHashes`] for `MTH(D[a:b])`. [`LeafHashes`] is the reference
//! implementation (the literal recursion, O(n)); [`crate::log::IssuanceLog`]
//! is the production one (O(log n) for valid subtrees). A test crosses the
//! two for every subtree up to 130 leaves: two routes to the same contract,
//! tied by a test and not trusted to coincide.

use crate::hash::{hash_empty, hash_node, HashValue};

/// A subtree `[start, end)` of a log, in the log's coordinates.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Subtree {
    pub start: u64,
    pub end: u64,
}

/// What can go wrong with a subtree or with a proof.
///
/// ⚠️ Three different things with three different meanings, as in
/// `zk-ssl-verify::inclusion`: an interval that is not a subtree or a
/// misaligned path are **a malformed proof**; a hash that does not come
/// out is **an entry that was not there** (or a subtree of ANOTHER log).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubtreeError {
    /// `[start, end)` does not satisfy the subtree definition.
    InvalidSubtree { start: u64, end: u64 },
    /// The index does not fall in `[start, end)`.
    IndexOutOfSubtree { index: u64, start: u64, end: u64 },
    /// The subtree ends beyond the tree size.
    SubtreeBeyondTree { end: u64, tree_size: u64 },
    /// The path ran out before reaching the root.
    ProofTooShort,
    /// There are leftover hashes in the path.
    ProofTooLong,
    /// The path climbs to a different hash.
    HashMismatch,
}

impl core::fmt::Display for SubtreeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SubtreeError::InvalidSubtree { start, end } => {
                write!(f, "[{start}, {end}) is not a valid subtree")
            }
            SubtreeError::IndexOutOfSubtree { index, start, end } => {
                write!(f, "index {index} does not fall in [{start}, {end})")
            }
            SubtreeError::SubtreeBeyondTree { end, tree_size } => {
                write!(
                    f,
                    "the subtree ends at {end} and the tree has {tree_size} leaves"
                )
            }
            SubtreeError::ProofTooShort => write!(f, "the path ends before the root"),
            SubtreeError::ProofTooLong => write!(f, "leftover hashes in the path"),
            SubtreeError::HashMismatch => write!(f, "the path climbs to a different hash"),
        }
    }
}

impl std::error::Error for SubtreeError {}

/// `BIT_CEIL(n)` for `n <= 2^63`: the smallest power of two `>= n`.
fn bit_ceil(n: u64) -> u64 {
    if n <= 1 {
        1
    } else {
        1u64 << (64 - (n - 1).leading_zeros())
    }
}

/// The largest power of two **strictly** less than `n` (`n >= 2`).
/// It is the RFC 9162 partition, shared by generation and verification.
pub fn largest_power_of_two_below(n: u64) -> u64 {
    debug_assert!(n >= 2);
    1u64 << (63 - (n - 1).leading_zeros())
}

/// The draft's subtree definition, with the overflow guard from its C++
/// example: `start <= end` and `start` a multiple of
/// `BIT_CEIL(end - start)`.
pub fn is_valid_subtree(start: u64, end: u64) -> bool {
    if start > end {
        return false;
    }
    let size = end - start;
    if size > (1u64 << 63) {
        return start == 0; // bit_ceil would overflow
    }
    (start & (bit_ceil(size) - 1)) == 0
}

impl Subtree {
    /// A checked subtree.
    pub fn new(start: u64, end: u64) -> Result<Self, SubtreeError> {
        if is_valid_subtree(start, end) {
            Ok(Subtree { start, end })
        } else {
            Err(SubtreeError::InvalidSubtree { start, end })
        }
    }

    /// Re-checks the definition (a `Subtree` may come from a decode).
    pub fn check(&self) -> Result<(), SubtreeError> {
        Subtree::new(self.start, self.end).map(|_| ())
    }

    pub fn size(&self) -> u64 {
        self.end - self.start
    }

    pub fn is_empty(&self) -> bool {
        self.start == self.end
    }

    pub fn contains(&self, index: u64) -> bool {
        self.start <= index && index < self.end
    }
}

impl core::fmt::Display for Subtree {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "[{}, {})", self.start, self.end)
    }
}

/// **The two subtrees that efficiently cover `[start, end)`**
/// (section "Selecting Two Subtrees"). It is what the CA signs at each
/// checkpoint: the interval of new entries since the previous one, covered
/// by two valid subtrees whose inclusion path is no longer than that of
/// `MTH(D[start:end])` and which CAN be proven consistent with the whole
/// tree.
///
/// Returns `(left, right)` with `left.start <= start <= left.end =
/// right.start <= end = right.end`.
pub fn covering_subtrees(start: u64, end: u64) -> (Subtree, Subtree) {
    assert!(start <= end, "inverted interval");
    if end - start <= 1 {
        return (Subtree { start, end }, Subtree { start: end, end });
    }
    let last = end - 1;
    // Where the paths of `start` and `last` diverge: the height of the cut.
    let split = 63 - (start ^ last).leading_zeros();
    let mask = (1u64 << split) - 1;
    let mid = last & !mask;
    // The left one widens until just before the path of `start` leaves
    // the right edge of its new subtree.
    let left_split = 64 - (!start & mask).leading_zeros();
    let left_start = start & !((1u64 << left_split) - 1);
    (
        Subtree {
            start: left_start,
            end: mid,
        },
        Subtree { start: mid, end },
    )
}

/// Whoever knows how to compute `MTH(D[start:end])` over a tree of `size` leaves.
pub trait TreeHashes {
    /// How many leaves the tree has.
    fn size(&self) -> u64;
    /// `MTH(D[start:end])` for `0 <= start <= end <= size`. Does **not**
    /// require the interval to be a valid subtree.
    fn range_hash(&self, start: u64, end: u64) -> HashValue;
}

/// The reference implementation: the leaves already hashed, and the
/// literal RFC 9162 recursion. O(n) per query; for tests and for tying
/// down the production one.
#[derive(Clone, Debug, Default)]
pub struct LeafHashes(pub Vec<HashValue>);

/// RFC 9162 `MTH` over **already-hashed** leaves (`MTH({d}) = HASH(0x00 || d)`).
pub fn mth(leaves: &[HashValue]) -> HashValue {
    match leaves.len() {
        0 => hash_empty(),
        1 => leaves[0],
        n => {
            let k = largest_power_of_two_below(n as u64) as usize;
            hash_node(&mth(&leaves[..k]), &mth(&leaves[k..]))
        }
    }
}

impl TreeHashes for LeafHashes {
    fn size(&self) -> u64 {
        self.0.len() as u64
    }
    fn range_hash(&self, start: u64, end: u64) -> HashValue {
        mth(&self.0[start as usize..end as usize])
    }
}

fn check_in_tree<T: TreeHashes + ?Sized>(tree: &T, subtree: Subtree) -> Result<(), SubtreeError> {
    subtree.check()?;
    if subtree.end > tree.size() {
        return Err(SubtreeError::SubtreeBeyondTree {
            end: subtree.end,
            tree_size: tree.size(),
        });
    }
    Ok(())
}

/// **The inclusion proof** of entry `index` in the subtree
/// (RFC 9162 `PATH` over `D[start:end]`). At most
/// `BIT_WIDTH(size - 1)` hashes.
pub fn inclusion_proof<T: TreeHashes + ?Sized>(
    tree: &T,
    subtree: Subtree,
    index: u64,
) -> Result<Vec<HashValue>, SubtreeError> {
    check_in_tree(tree, subtree)?;
    if !subtree.contains(index) {
        return Err(SubtreeError::IndexOutOfSubtree {
            index,
            start: subtree.start,
            end: subtree.end,
        });
    }
    let mut out = Vec::new();
    path(tree, index, subtree.start, subtree.end, &mut out);
    Ok(out)
}

/// `PATH(m, D[lo:hi])` in absolute log coordinates.
fn path<T: TreeHashes + ?Sized>(tree: &T, m: u64, lo: u64, hi: u64, out: &mut Vec<HashValue>) {
    let n = hi - lo;
    if n == 1 {
        return;
    }
    let k = largest_power_of_two_below(n);
    if m < lo + k {
        path(tree, m, lo, lo + k, out);
        out.push(tree.range_hash(lo + k, hi));
    } else {
        path(tree, m, lo + k, hi, out);
        out.push(tree.range_hash(lo, lo + k));
    }
}

/// **Evaluates** an inclusion proof: returns the subtree hash that the
/// proof reconstructs from `entry_hash` (section "Evaluating a Subtree
/// Inclusion Proof"), without comparing it against anything. It is what
/// the certificate verifier needs: the expected hash is compared afterwards
/// against a trusted subtree or against the cosignatures.
pub fn evaluate_inclusion_proof(
    entry_hash: &HashValue,
    subtree: Subtree,
    index: u64,
    proof: &[HashValue],
) -> Result<HashValue, SubtreeError> {
    subtree.check()?;
    if !subtree.contains(index) {
        return Err(SubtreeError::IndexOutOfSubtree {
            index,
            start: subtree.start,
            end: subtree.end,
        });
    }
    let mut fnum = index - subtree.start;
    let mut snum = subtree.end - subtree.start - 1;
    let mut r = *entry_hash;
    for p in proof {
        if snum == 0 {
            return Err(SubtreeError::ProofTooLong);
        }
        if fnum & 1 == 1 || fnum == snum {
            r = hash_node(p, &r);
            while fnum != 0 && fnum & 1 == 0 {
                fnum >>= 1;
                snum >>= 1;
            }
        } else {
            r = hash_node(&r, p);
        }
        fnum >>= 1;
        snum >>= 1;
    }
    if snum != 0 {
        return Err(SubtreeError::ProofTooShort);
    }
    Ok(r)
}

/// **Verifies** an inclusion proof against a known subtree hash.
pub fn verify_inclusion_proof(
    entry_hash: &HashValue,
    subtree: Subtree,
    index: u64,
    proof: &[HashValue],
    subtree_hash: &HashValue,
) -> Result<(), SubtreeError> {
    let expected = evaluate_inclusion_proof(entry_hash, subtree, index, proof)?;
    if &expected == subtree_hash {
        Ok(())
    } else {
        Err(SubtreeError::HashMismatch)
    }
}

/// **The consistency proof** of the subtree with the tree of `n` leaves
/// (the draft's `SUBTREE_PROOF`). With `start = 0` it is the RFC 9162
/// consistency proof; with `end = start + 1`, the inclusion proof.
pub fn consistency_proof<T: TreeHashes + ?Sized>(
    tree: &T,
    n: u64,
    subtree: Subtree,
) -> Result<Vec<HashValue>, SubtreeError> {
    subtree.check()?;
    if n > tree.size() {
        return Err(SubtreeError::SubtreeBeyondTree {
            end: n,
            tree_size: tree.size(),
        });
    }
    if subtree.end > n {
        return Err(SubtreeError::SubtreeBeyondTree {
            end: subtree.end,
            tree_size: n,
        });
    }
    if subtree.is_empty() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    subproof(tree, subtree.start, subtree.end, 0, n, true, &mut out);
    Ok(out)
}

/// `SUBTREE_SUBPROOF(start, end, D[lo:hi], b)` in absolute coordinates.
fn subproof<T: TreeHashes + ?Sized>(
    tree: &T,
    s: u64,
    e: u64,
    lo: u64,
    hi: u64,
    b: bool,
    out: &mut Vec<HashValue>,
) {
    if s == lo && e == hi {
        if !b {
            out.push(tree.range_hash(lo, hi));
        }
        return;
    }
    let k = largest_power_of_two_below(hi - lo);
    if e <= lo + k {
        subproof(tree, s, e, lo, lo + k, b, out);
        out.push(tree.range_hash(lo + k, hi));
    } else if lo + k <= s {
        subproof(tree, s, e, lo + k, hi, b, out);
        out.push(tree.range_hash(lo, lo + k));
    } else {
        // s < lo + k < e, which implies s == lo: the subtree splits at the
        // same k as the tree, and its left child is MTH(D[lo:lo+k]).
        subproof(tree, lo + k, e, lo + k, hi, false, out);
        out.push(tree.range_hash(lo, lo + k));
    }
}

/// **Verifies** a consistency proof (section "Verifying a Subtree
/// Consistency Proof"): that `root_hash`, of `n` leaves, CONTAINS the
/// subtree with hash `node_hash`.
pub fn verify_consistency_proof(
    n: u64,
    subtree: Subtree,
    proof: &[HashValue],
    node_hash: &HashValue,
    root_hash: &HashValue,
) -> Result<(), SubtreeError> {
    subtree.check()?;
    if subtree.end > n {
        return Err(SubtreeError::SubtreeBeyondTree {
            end: subtree.end,
            tree_size: n,
        });
    }
    if subtree.is_empty() {
        return if proof.is_empty() && *node_hash == hash_empty() {
            Ok(())
        } else if !proof.is_empty() {
            Err(SubtreeError::ProofTooLong)
        } else {
            Err(SubtreeError::HashMismatch)
        };
    }
    let mut fnum = subtree.start;
    let mut snum = subtree.end - 1;
    let mut tnum = n - 1;
    if snum == tnum {
        while fnum != snum {
            fnum >>= 1;
            snum >>= 1;
            tnum >>= 1;
        }
    } else {
        while fnum != snum && snum & 1 == 1 {
            fnum >>= 1;
            snum >>= 1;
            tnum >>= 1;
        }
    }
    let (mut fr, mut sr, rest): (HashValue, HashValue, &[HashValue]) = if fnum == snum {
        (*node_hash, *node_hash, proof)
    } else {
        match proof.split_first() {
            Some((first, rest)) => (*first, *first, rest),
            None => return Err(SubtreeError::ProofTooShort),
        }
    };
    for c in rest {
        if tnum == 0 {
            return Err(SubtreeError::ProofTooLong);
        }
        if snum & 1 == 1 || snum == tnum {
            if fnum < snum {
                fr = hash_node(c, &fr);
            }
            sr = hash_node(c, &sr);
            while snum != 0 && snum & 1 == 0 {
                fnum >>= 1;
                snum >>= 1;
                tnum >>= 1;
            }
        } else {
            sr = hash_node(&sr, c);
        }
        fnum >>= 1;
        snum >>= 1;
        tnum >>= 1;
    }
    if tnum != 0 {
        return Err(SubtreeError::ProofTooShort);
    }
    if fr != *node_hash || sr != *root_hash {
        return Err(SubtreeError::HashMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::hash_leaf;

    fn tree(n: u64) -> LeafHashes {
        LeafHashes((0..n).map(|i| hash_leaf(&[i as u8])).collect())
    }

    #[test]
    fn examples_from_the_draft() {
        // [4, 8) and [8, 13) are subtrees; [1, 5) is not.
        assert!(is_valid_subtree(4, 8));
        assert!(is_valid_subtree(8, 13));
        assert!(!is_valid_subtree(1, 5));
        assert!(is_valid_subtree(0, 0));
        assert!(is_valid_subtree(7, 7));
        // [5, 13) is covered by [4, 8) and [8, 13).
        assert_eq!(
            covering_subtrees(5, 13),
            (Subtree { start: 4, end: 8 }, Subtree { start: 8, end: 13 })
        );
        // The interval [7, 9) from the counterexample figure.
        assert_eq!(
            covering_subtrees(7, 9),
            (Subtree { start: 7, end: 8 }, Subtree { start: 8, end: 9 })
        );
    }

    #[test]
    fn inclusion_proof_for_entry_10_of_8_13_has_three_hashes() {
        let t = tree(13);
        let st = Subtree::new(8, 13).unwrap();
        let p = inclusion_proof(&t, st, 10).unwrap();
        // MTH({d[11]}), MTH(D[8:10]), MTH({d[12]}): the figure from the draft.
        assert_eq!(p, vec![t.0[11], t.range_hash(8, 10), t.0[12]]);
        assert_eq!(
            evaluate_inclusion_proof(&t.0[10], st, 10, &p).unwrap(),
            t.range_hash(8, 13)
        );
    }

    #[test]
    fn consistency_examples_from_the_draft() {
        let t = tree(14);
        // [4, 8) in a tree of 14: MTH(D[0:4]) and MTH(D[8:14]).
        let p = consistency_proof(&t, 14, Subtree::new(4, 8).unwrap()).unwrap();
        assert_eq!(p, vec![t.range_hash(0, 4), t.range_hash(8, 14)]);
        verify_consistency_proof(
            14,
            Subtree::new(4, 8).unwrap(),
            &p,
            &t.range_hash(4, 8),
            &t.range_hash(0, 14),
        )
        .unwrap();
        // [8, 13) in a tree of 14: d[12], d[13], MTH(D[8:12]), MTH(D[0:8]).
        let p = consistency_proof(&t, 14, Subtree::new(8, 13).unwrap()).unwrap();
        assert_eq!(
            p,
            vec![t.0[12], t.0[13], t.range_hash(8, 12), t.range_hash(0, 8)]
        );
        verify_consistency_proof(
            14,
            Subtree::new(8, 13).unwrap(),
            &p,
            &t.range_hash(8, 13),
            &t.range_hash(0, 14),
        )
        .unwrap();
        // With start = 0 it is RFC 9162 consistency; with size 1, inclusion.
        let p = consistency_proof(&t, 14, Subtree::new(0, 6).unwrap()).unwrap();
        verify_consistency_proof(
            14,
            Subtree::new(0, 6).unwrap(),
            &p,
            &t.range_hash(0, 6),
            &t.range_hash(0, 14),
        )
        .unwrap();
        let p = consistency_proof(&t, 14, Subtree::new(9, 10).unwrap()).unwrap();
        assert_eq!(
            p,
            inclusion_proof(&t, Subtree::new(0, 14).unwrap(), 9).unwrap()
        );
    }

    #[test]
    fn a_proof_of_another_subtree_does_not_verify() {
        let t = tree(13);
        let st = Subtree::new(8, 13).unwrap();
        let mut p = inclusion_proof(&t, st, 10).unwrap();
        assert_eq!(
            verify_inclusion_proof(&t.0[10], st, 10, &p, &t.range_hash(0, 13)),
            Err(SubtreeError::HashMismatch)
        );
        p.pop();
        assert_eq!(
            evaluate_inclusion_proof(&t.0[10], st, 10, &p),
            Err(SubtreeError::ProofTooShort)
        );
        p.push(t.0[0]);
        p.push(t.0[0]);
        assert_eq!(
            evaluate_inclusion_proof(&t.0[10], st, 10, &p),
            Err(SubtreeError::ProofTooLong)
        );
    }
}
