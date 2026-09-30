//! # Landmarks: the predistributed reference points
//!
//! A *landmark* is a tree size chosen every so often (every hour, the
//! draft says) that the CA publishes and relying parties receive through
//! their update channel. Each landmark `L` defines **two subtrees** —the
//! ones covering `[size(L-1), size(L))`— and a *landmark-relative*
//! certificate is just an inclusion proof to one of them, **with no
//! signature at all**: the relying party already has the hash.
//!
//! This module has no equivalent in Arqueo: there the head of each epoch
//! was the unit of trust and always travelled signed.

use crate::subtree::{covering_subtrees, Subtree};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Landmark {
    pub number: u64,
    pub tree_size: u64,
    /// POSIX seconds; `>=` the `notAfter` of every entry under `tree_size`.
    pub expiry: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LandmarkError {
    /// The size does not grow strictly or the expiry decreases.
    NotMonotonic { tree_size: u64, expiry: u64 },
    /// The index is not yet under any landmark: one has to wait.
    NotYetCovered(u64),
}

impl core::fmt::Display for LandmarkError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for LandmarkError {}

/// The landmark sequence of a log. Landmark 0 is `(0, 0)` and is never
/// active.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LandmarkSequence {
    landmarks: Vec<Landmark>,
}

impl Default for LandmarkSequence {
    fn default() -> Self {
        Self::new()
    }
}

impl LandmarkSequence {
    pub fn new() -> Self {
        LandmarkSequence {
            landmarks: vec![Landmark {
                number: 0,
                tree_size: 0,
                expiry: 0,
            }],
        }
    }

    pub fn latest(&self) -> &Landmark {
        self.landmarks.last().expect("landmark 0 always exists")
    }

    pub fn get(&self, number: u64) -> Option<&Landmark> {
        self.landmarks.get(number as usize)
    }

    pub fn all(&self) -> &[Landmark] {
        &self.landmarks
    }

    /// Adds a landmark. The draft's RECOMMENDED procedure: at most one per
    /// time interval, with `expiry = now + maximum certificate lifetime`,
    /// and none if the tree did not grow.
    pub fn allocate(&mut self, tree_size: u64, expiry: u64) -> Result<&Landmark, LandmarkError> {
        let prev = self.latest();
        if tree_size <= prev.tree_size || expiry < prev.expiry {
            return Err(LandmarkError::NotMonotonic { tree_size, expiry });
        }
        let number = prev.number + 1;
        self.landmarks.push(Landmark {
            number,
            tree_size,
            expiry,
        });
        Ok(self.latest())
    }

    /// The two subtrees of landmark `number`.
    pub fn subtrees(&self, number: u64) -> Option<(Subtree, Subtree)> {
        let l = self.get(number)?;
        if number == 0 {
            return Some((Subtree { start: 0, end: 0 }, Subtree { start: 0, end: 0 }));
        }
        let prev = self.get(number - 1)?;
        Some(covering_subtrees(prev.tree_size, l.tree_size))
    }

    /// The active (unexpired) landmarks at `now`, from newest to oldest.
    pub fn active(&self, now: u64) -> impl Iterator<Item = &Landmark> {
        self.landmarks.iter().rev().filter(move |l| l.expiry > now)
    }

    /// **The landmark of an index**, to build its landmark-relative
    /// certificate: the lowest-numbered one whose size strictly exceeds the index.
    pub fn landmark_for_index(&self, index: u64) -> Result<&Landmark, LandmarkError> {
        self.landmarks
            .iter()
            .find(|l| l.tree_size > index)
            .ok_or(LandmarkError::NotYetCovered(index))
    }

    /// The subtree of `index`'s landmark that contains it.
    pub fn subtree_for_index(&self, index: u64) -> Result<(&Landmark, Subtree), LandmarkError> {
        let l = self.landmark_for_index(index)?;
        let (left, right) = self.subtrees(l.number).expect("existing landmark");
        let st = if right.contains(index) { right } else { left };
        debug_assert!(st.contains(index));
        Ok((l, st))
    }

    /// The publication document (section "Publishing Landmarks"): the
    /// number of the latest landmark, and one `tree_size expiry` line per
    /// active landmark plus the first expired one, which acts as terminator.
    pub fn publish(&self, now: u64) -> String {
        let mut out = format!("{}\n", self.latest().number);
        for l in self.landmarks.iter().rev() {
            out.push_str(&format!("{} {}\n", l.tree_size, l.expiry));
            if l.expiry <= now {
                break;
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn landmark_subtrees_cover_the_gap_since_the_previous_one() {
        let mut s = LandmarkSequence::new();
        s.allocate(5, 1_000).unwrap();
        s.allocate(13, 2_000).unwrap();
        assert_eq!(
            s.subtrees(0).unwrap(),
            (Subtree { start: 0, end: 0 }, Subtree { start: 0, end: 0 })
        );
        assert_eq!(
            s.subtrees(1).unwrap(),
            (Subtree { start: 0, end: 4 }, Subtree { start: 4, end: 5 })
        );
        assert_eq!(
            s.subtrees(2).unwrap(),
            (Subtree { start: 4, end: 8 }, Subtree { start: 8, end: 13 })
        );
        let (l, st) = s.subtree_for_index(6).unwrap();
        assert_eq!((l.number, st), (2, Subtree { start: 4, end: 8 }));
        let (l, st) = s.subtree_for_index(2).unwrap();
        assert_eq!((l.number, st), (1, Subtree { start: 0, end: 4 }));
        assert_eq!(
            s.subtree_for_index(13).err(),
            Some(LandmarkError::NotYetCovered(13))
        );
        assert_eq!(
            s.allocate(13, 3_000).err(),
            Some(LandmarkError::NotMonotonic {
                tree_size: 13,
                expiry: 3_000
            })
        );
        assert_eq!(
            s.allocate(14, 1_999).err(),
            Some(LandmarkError::NotMonotonic {
                tree_size: 14,
                expiry: 1_999
            })
        );
    }

    #[test]
    fn publication_ends_at_the_first_expired_landmark() {
        let mut s = LandmarkSequence::new();
        s.allocate(5, 1_000).unwrap();
        s.allocate(13, 2_000).unwrap();
        s.allocate(20, 3_000).unwrap();
        assert_eq!(s.publish(1_500), "3\n20 3000\n13 2000\n5 1000\n");
        assert_eq!(s.publish(5_000), "3\n20 3000\n");
        assert_eq!(
            s.active(1_500).map(|l| l.number).collect::<Vec<_>>(),
            vec![3, 2]
        );
    }
}
