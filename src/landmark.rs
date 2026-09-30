//! # Landmarks: los puntos de referencia predistribuidos
//!
//! Un *landmark* es un tamano de arbol elegido de tarde en tarde (cada
//! hora, dice el borrador) que la CA publica y las partes que confian
//! reciben por su canal de actualizacion. Cada landmark `L` define **dos
//! subarboles** —los que cubren `[tamano(L-1), tamano(L))`— y un
//! certificado *relativo a landmark* es solo una prueba de inclusion a uno
//! de ellos, **sin ninguna firma**: la parte que confia ya tiene el hash.
//!
//! Este modulo no tiene equivalente en Arqueo: alli la cabeza de cada
//! epoca era la unidad de confianza y viajaba firmada siempre.

use crate::subtree::{covering_subtrees, Subtree};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Landmark {
    pub number: u64,
    pub tree_size: u64,
    /// Segundos POSIX; `>=` al `notAfter` de toda entrada bajo `tree_size`.
    pub expiry: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LandmarkError {
    /// El tamano no crece estrictamente o la caducidad decrece.
    NotMonotonic { tree_size: u64, expiry: u64 },
    /// El indice no esta aun bajo ningun landmark: hay que esperar.
    NotYetCovered(u64),
}

impl core::fmt::Display for LandmarkError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for LandmarkError {}

/// La secuencia de landmarks de un log. El landmark 0 es `(0, 0)` y nunca
/// esta activo.
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
        self.landmarks.last().expect("el landmark 0 siempre existe")
    }

    pub fn get(&self, number: u64) -> Option<&Landmark> {
        self.landmarks.get(number as usize)
    }

    pub fn all(&self) -> &[Landmark] {
        &self.landmarks
    }

    /// Anade un landmark. El procedimiento RECOMENDADO del borrador: como
    /// mucho uno por intervalo de tiempo, con `expiry = ahora + vida
    /// maxima del certificado`, y ninguno si el arbol no crecio.
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

    /// Los dos subarboles del landmark `number`.
    pub fn subtrees(&self, number: u64) -> Option<(Subtree, Subtree)> {
        let l = self.get(number)?;
        if number == 0 {
            return Some((Subtree { start: 0, end: 0 }, Subtree { start: 0, end: 0 }));
        }
        let prev = self.get(number - 1)?;
        Some(covering_subtrees(prev.tree_size, l.tree_size))
    }

    /// Los landmarks activos (no caducados) en `now`, del mas nuevo al mas viejo.
    pub fn active(&self, now: u64) -> impl Iterator<Item = &Landmark> {
        self.landmarks.iter().rev().filter(move |l| l.expiry > now)
    }

    /// **El landmark de un indice** para construir su certificado relativo:
    /// el de menor numero cuyo tamano supera estrictamente al indice.
    pub fn landmark_for_index(&self, index: u64) -> Result<&Landmark, LandmarkError> {
        self.landmarks
            .iter()
            .find(|l| l.tree_size > index)
            .ok_or(LandmarkError::NotYetCovered(index))
    }

    /// El subarbol del landmark de `index` que lo contiene.
    pub fn subtree_for_index(&self, index: u64) -> Result<(&Landmark, Subtree), LandmarkError> {
        let l = self.landmark_for_index(index)?;
        let (left, right) = self.subtrees(l.number).expect("landmark existente");
        let st = if right.contains(index) { right } else { left };
        debug_assert!(st.contains(index));
        Ok((l, st))
    }

    /// El documento de publicacion (seccion «Publishing Landmarks»): el
    /// numero del ultimo landmark, y una linea `tree_size expiry` por
    /// landmark activo mas el primer caducado, que hace de terminador.
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
