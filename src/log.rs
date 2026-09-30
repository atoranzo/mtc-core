//! # The issuance log: an *append-only* RFC 9162 tree with cached nodes
//!
//! What in Arqueo was `zk-ssl::sparse_tree::SparseTree` —a sparse tree of
//! fixed depth with the non-empty internal nodes in a map, O(depth) per
//! write (§207)— is here a **dense, grow-only** tree: certificates are
//! neither overwritten nor deleted, they are appended at the end and
//! revoked by serial-number range. That simplifies the cache: instead of a
//! `(level, index) -> node` map, one vector per level holding **only the
//! full nodes** (those covering an aligned power of two of leaves).
//! Appending a leaf costs O(log n) hashes amortized; the hash of any valid
//! subtree, O(log n) lookups; memory, `2n` hashes.
//!
//! ⚠️ The semantics are fixed by [`crate::subtree::LeafHashes`], the
//! literal recursion: a test walks every subtree of every size up to 130
//! and demands the same hash and the same proofs by both routes. It is what
//! §221 did with `rebuild_from` against N `set_leaf`.
//!
//! ## What this module does NOT do
//!
//! It does not persist. A real CA's log lives on disk (Arqueo uses `sled`
//! in `zk-ssl::persistence`, and the draft points to tlog-tiles to serve
//! it); here [`IssuanceLog::from_entries`] rebuilds the cache from the
//! entries, which is the point where any store hooks in.

use crate::entry::MtcLogEntry;
use crate::hash::{hash_empty, hash_leaf, hash_node, HashValue};
use crate::subtree::{self, largest_power_of_two_below, Subtree, SubtreeError, TreeHashes};

/// A log holds at most `2^48 - 1` entries: `index` travels in 48 bits
/// inside the serial number and the `MTCProof`.
pub const MAX_ENTRIES: u64 = (1u64 << 48) - 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LogError {
    /// Log numbers run from 1 to 65535.
    InvalidLogNumber(u16),
    /// The log is full.
    Full,
    /// An entry could not be encoded.
    Entry(crate::entry::EntryError),
}

impl core::fmt::Display for LogError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            LogError::InvalidLogNumber(n) => write!(f, "invalid log number: {n}"),
            LogError::Full => write!(f, "the log reached 2^48 - 1 entries"),
            LogError::Entry(e) => write!(f, "invalid entry: {e}"),
        }
    }
}

impl std::error::Error for LogError {}

impl From<crate::entry::EntryError> for LogError {
    fn from(e: crate::entry::EntryError) -> Self {
        LogError::Entry(e)
    }
}

/// Issuance log number `log_number` of a CA.
#[derive(Clone, Debug)]
pub struct IssuanceLog {
    log_number: u16,
    /// `levels[0]` are the already-hashed leaves; `levels[j][i]` is the
    /// full node covering `[i << j, (i + 1) << j)`. Invariant:
    /// `levels[j + 1].len() == levels[j].len() / 2`.
    levels: Vec<Vec<HashValue>>,
    /// The serialized entries, to serve them and to rebuild.
    entries: Vec<Vec<u8>>,
}

impl IssuanceLog {
    /// An empty log.
    pub fn new(log_number: u16) -> Result<Self, LogError> {
        if log_number == 0 {
            return Err(LogError::InvalidLogNumber(log_number));
        }
        Ok(IssuanceLog {
            log_number,
            levels: vec![Vec::new()],
            entries: Vec::new(),
        })
    }

    /// **Rebuilds the cache from the entries** at startup. It is the
    /// equivalent of `SparseTree::rebuild_from` (§221): whoever holds the
    /// log on disk loads it through here.
    pub fn from_entries(
        log_number: u16,
        entries: impl IntoIterator<Item = Vec<u8>>,
    ) -> Result<Self, LogError> {
        let mut log = Self::new(log_number)?;
        for e in entries {
            log.append_raw(e)?;
        }
        Ok(log)
    }

    pub fn log_number(&self) -> u16 {
        self.log_number
    }

    /// How many entries there are: the `tree_size` of the current checkpoint.
    pub fn size(&self) -> u64 {
        self.levels[0].len() as u64
    }

    /// Appends an entry and returns its index.
    pub fn append(&mut self, entry: &MtcLogEntry) -> Result<u64, LogError> {
        self.append_raw(entry.encode()?)
    }

    /// Appends an already-serialized entry. It must be a well-formed entry
    /// of a known type: **a CA does not record what it does not
    /// understand**, because it would sign it afterwards.
    pub fn append_raw(&mut self, entry: Vec<u8>) -> Result<u64, LogError> {
        if self.size() >= MAX_ENTRIES {
            return Err(LogError::Full);
        }
        MtcLogEntry::decode(&entry)?;
        let index = self.size();
        self.levels[0].push(hash_leaf(&entry));
        self.entries.push(entry);
        // Climb the levels, closing each pair that becomes complete.
        let mut level = 0;
        loop {
            let len = self.levels[level].len();
            if !len.is_multiple_of(2) {
                break;
            }
            let parent = hash_node(&self.levels[level][len - 2], &self.levels[level][len - 1]);
            if self.levels.len() == level + 1 {
                self.levels.push(Vec::new());
            }
            debug_assert_eq!(self.levels[level + 1].len(), len / 2 - 1);
            self.levels[level + 1].push(parent);
            level += 1;
        }
        Ok(index)
    }

    /// The serialized entry at `index`.
    pub fn entry(&self, index: u64) -> Option<&[u8]> {
        self.entries
            .get(usize::try_from(index).ok()?)
            .map(|v| v.as_slice())
    }

    /// `MTH({entry})` of the entry at `index`.
    pub fn leaf_hash(&self, index: u64) -> Option<HashValue> {
        self.levels[0].get(usize::try_from(index).ok()?).copied()
    }

    /// The full node `(level, index)`, if it exists.
    fn full_node(&self, level: usize, idx: u64) -> Option<HashValue> {
        self.levels
            .get(level)?
            .get(usize::try_from(idx).ok()?)
            .copied()
    }

    /// The hash of the current checkpoint: `MTH(D[0:size])`.
    pub fn root(&self) -> HashValue {
        self.range_hash(0, self.size())
    }

    /// The hash of a valid subtree of the log.
    pub fn subtree_hash(&self, subtree: Subtree) -> Result<HashValue, SubtreeError> {
        subtree.check()?;
        if subtree.end > self.size() {
            return Err(SubtreeError::SubtreeBeyondTree {
                end: subtree.end,
                tree_size: self.size(),
            });
        }
        Ok(self.range_hash(subtree.start, subtree.end))
    }

    /// The inclusion proof of `index` in `subtree`.
    pub fn inclusion_proof(
        &self,
        subtree: Subtree,
        index: u64,
    ) -> Result<Vec<HashValue>, SubtreeError> {
        subtree::inclusion_proof(self, subtree, index)
    }

    /// The consistency proof of `subtree` with the current checkpoint.
    pub fn consistency_proof(&self, subtree: Subtree) -> Result<Vec<HashValue>, SubtreeError> {
        subtree::consistency_proof(self, self.size(), subtree)
    }

    /// Diagnostics: how many full internal nodes are cached.
    pub fn cached_nodes(&self) -> usize {
        self.levels.iter().skip(1).map(Vec::len).sum()
    }
}

impl TreeHashes for IssuanceLog {
    fn size(&self) -> u64 {
        IssuanceLog::size(self)
    }

    /// For a valid subtree it descends along the right edge: O(log n)
    /// lookups. For an arbitrary interval it is still correct (full
    /// recursion), just more expensive.
    fn range_hash(&self, start: u64, end: u64) -> HashValue {
        let n = end - start;
        if n == 0 {
            return hash_empty();
        }
        if n.is_power_of_two() && start.is_multiple_of(n) {
            if let Some(h) = self.full_node(n.trailing_zeros() as usize, start / n) {
                return h;
            }
        }
        if n == 1 {
            return self.levels[0][start as usize];
        }
        let k = largest_power_of_two_below(n);
        hash_node(
            &self.range_hash(start, start + k),
            &self.range_hash(start + k, end),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::subtree::{is_valid_subtree, LeafHashes};

    /// Distinct null entries: `null_entry` with an extension whose data is `i`.
    fn raw_entry(i: u64) -> Vec<u8> {
        MtcLogEntry::Null {
            extensions: vec![crate::entry::LogEntryExtension {
                extension_type: 0,
                extension_data: i.to_be_bytes().to_vec(),
            }],
        }
        .encode()
        .unwrap()
    }

    fn both(n: u64) -> (IssuanceLog, LeafHashes) {
        let entries: Vec<Vec<u8>> = (0..n).map(raw_entry).collect();
        let log = IssuanceLog::from_entries(1, entries.clone()).unwrap();
        let reference = LeafHashes(entries.iter().map(|e| hash_leaf(e)).collect());
        (log, reference)
    }

    /// Both routes —cache and literal recursion— give the same result for
    /// every valid subtree of every tree up to 130 leaves, and the same proofs.
    #[test]
    fn cached_log_matches_the_reference_for_every_subtree() {
        for n in 0..=130u64 {
            let (log, reference) = both(n);
            assert_eq!(log.size(), n);
            assert_eq!(log.root(), reference.range_hash(0, n));
            for end in 0..=n {
                for start in 0..=end {
                    if !is_valid_subtree(start, end) {
                        continue;
                    }
                    let st = Subtree { start, end };
                    assert_eq!(
                        log.subtree_hash(st).unwrap(),
                        reference.range_hash(start, end),
                        "{st} n={n}"
                    );
                    for index in start..end {
                        assert_eq!(
                            log.inclusion_proof(st, index).unwrap(),
                            subtree::inclusion_proof(&reference, st, index).unwrap()
                        );
                    }
                    assert_eq!(
                        log.consistency_proof(st).unwrap(),
                        subtree::consistency_proof(&reference, n, st).unwrap()
                    );
                }
            }
        }
    }

    #[test]
    fn appending_one_by_one_equals_rebuilding() {
        let (rebuilt, _) = both(37);
        let mut incremental = IssuanceLog::new(1).unwrap();
        for i in 0..37u64 {
            incremental.append_raw(raw_entry(i)).unwrap();
        }
        assert_eq!(incremental.root(), rebuilt.root());
        assert_eq!(incremental.cached_nodes(), rebuilt.cached_nodes());
        // 37 leaves: 18 + 9 + 4 + 2 + 1 full nodes.
        assert_eq!(incremental.cached_nodes(), 18 + 9 + 4 + 2 + 1);
    }

    #[test]
    fn log_number_zero_is_rejected() {
        assert_eq!(
            IssuanceLog::new(0).err(),
            Some(LogError::InvalidLogNumber(0))
        );
    }
}
