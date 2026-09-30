//! # El log de emision: un arbol RFC 9162 *append-only* con nodos en cache
//!
//! Lo que en Arqueo era `zk-ssl::sparse_tree::SparseTree` —un arbol
//! disperso de profundidad fija con los nodos internos no vacios en un
//! mapa, O(profundidad) por escritura (§207)— aqui es un arbol **denso y
//! solo creciente**: los certificados no se sobreescriben ni se borran,
//! se anaden al final y se revocan por rango de numero de serie. Eso
//! simplifica la cache: en vez de un mapa `(nivel, indice) -> nodo`, un
//! vector por nivel con **solo los nodos completos** (los que cubren una
//! potencia de dos de hojas alineada). Anadir una hoja cuesta O(log n)
//! hashes amortizado; el hash de cualquier subarbol valido, O(log n)
//! consultas; la memoria, `2n` hashes.
//!
//! ⚠️ La semantica la fija [`crate::subtree::LeafHashes`], la recursion
//! literal: un test recorre todos los subarboles de todos los tamanos
//! hasta 130 y exige el mismo hash y las mismas pruebas por las dos vias.
//! Es lo que §221 hizo con `rebuild_from` frente a N `set_leaf`.
//!
//! ## Lo que este modulo NO hace
//!
//! No persiste. El log de una CA real vive en disco (Arqueo usa `sled` en
//! `zk-ssl::persistence`, y el borrador remite a tlog-tiles para servirlo);
//! aqui [`IssuanceLog::from_entries`] reconstruye la cache desde las
//! entradas, que es el punto donde engancha cualquier almacen.

use crate::entry::MtcLogEntry;
use crate::hash::{hash_empty, hash_leaf, hash_node, HashValue};
use crate::subtree::{self, largest_power_of_two_below, Subtree, SubtreeError, TreeHashes};

/// Un log tiene a lo sumo `2^48 - 1` entradas: `index` viaja en 48 bits
/// dentro del numero de serie y del `MTCProof`.
pub const MAX_ENTRIES: u64 = (1u64 << 48) - 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LogError {
    /// Los numeros de log van de 1 a 65535.
    InvalidLogNumber(u16),
    /// El log esta lleno.
    Full,
    /// Una entrada no se pudo codificar.
    Entry(crate::entry::EntryError),
}

impl core::fmt::Display for LogError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            LogError::InvalidLogNumber(n) => write!(f, "numero de log invalido: {n}"),
            LogError::Full => write!(f, "el log alcanzo 2^48 - 1 entradas"),
            LogError::Entry(e) => write!(f, "entrada invalida: {e}"),
        }
    }
}

impl std::error::Error for LogError {}

impl From<crate::entry::EntryError> for LogError {
    fn from(e: crate::entry::EntryError) -> Self {
        LogError::Entry(e)
    }
}

/// El log de emision numero `log_number` de una CA.
#[derive(Clone, Debug)]
pub struct IssuanceLog {
    log_number: u16,
    /// `levels[0]` son las hojas ya hasheadas; `levels[j][i]` es el nodo
    /// completo que cubre `[i << j, (i + 1) << j)`. Invariante:
    /// `levels[j + 1].len() == levels[j].len() / 2`.
    levels: Vec<Vec<HashValue>>,
    /// Las entradas serializadas, para servirlas y para reconstruir.
    entries: Vec<Vec<u8>>,
}

impl IssuanceLog {
    /// Un log vacio.
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

    /// **Reconstruye la cache desde las entradas** al arrancar. Es el
    /// equivalente de `SparseTree::rebuild_from` (§221): quien tenga el
    /// log en disco lo carga por aqui.
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

    /// Cuantas entradas hay: el `tree_size` del checkpoint actual.
    pub fn size(&self) -> u64 {
        self.levels[0].len() as u64
    }

    /// Anade una entrada y devuelve su indice.
    pub fn append(&mut self, entry: &MtcLogEntry) -> Result<u64, LogError> {
        self.append_raw(entry.encode()?)
    }

    /// Anade una entrada ya serializada.
    pub fn append_raw(&mut self, entry: Vec<u8>) -> Result<u64, LogError> {
        if self.size() >= MAX_ENTRIES {
            return Err(LogError::Full);
        }
        let index = self.size();
        self.levels[0].push(hash_leaf(&entry));
        self.entries.push(entry);
        // Sube por los niveles cerrando cada par que se completa.
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

    /// La entrada serializada en `index`.
    pub fn entry(&self, index: u64) -> Option<&[u8]> {
        self.entries.get(index as usize).map(|v| v.as_slice())
    }

    /// `MTH({entry})` de la entrada en `index`.
    pub fn leaf_hash(&self, index: u64) -> Option<HashValue> {
        self.levels[0].get(index as usize).copied()
    }

    /// El nodo completo `(nivel, indice)`, si existe.
    fn full_node(&self, level: usize, idx: u64) -> Option<HashValue> {
        self.levels.get(level)?.get(idx as usize).copied()
    }

    /// El hash del checkpoint actual: `MTH(D[0:size])`.
    pub fn root(&self) -> HashValue {
        self.range_hash(0, self.size())
    }

    /// El hash de un subarbol valido del log.
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

    /// La prueba de inclusion de `index` en `subtree`.
    pub fn inclusion_proof(
        &self,
        subtree: Subtree,
        index: u64,
    ) -> Result<Vec<HashValue>, SubtreeError> {
        subtree::inclusion_proof(self, subtree, index)
    }

    /// La prueba de consistencia de `subtree` con el checkpoint actual.
    pub fn consistency_proof(&self, subtree: Subtree) -> Result<Vec<HashValue>, SubtreeError> {
        subtree::consistency_proof(self, self.size(), subtree)
    }

    /// Diagnostico: cuantos nodos internos completos hay en cache.
    pub fn cached_nodes(&self) -> usize {
        self.levels.iter().skip(1).map(Vec::len).sum()
    }
}

impl TreeHashes for IssuanceLog {
    fn size(&self) -> u64 {
        IssuanceLog::size(self)
    }

    /// Para un subarbol valido baja por el borde derecho: O(log n)
    /// consultas. Para un intervalo cualquiera sigue siendo correcto
    /// (recursion completa), solo mas caro.
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

    fn both(n: u64) -> (IssuanceLog, LeafHashes) {
        let entries: Vec<Vec<u8>> = (0..n).map(|i| vec![i as u8]).collect();
        let log = IssuanceLog::from_entries(1, entries.clone()).unwrap();
        let reference = LeafHashes(entries.iter().map(|e| hash_leaf(e)).collect());
        (log, reference)
    }

    /// Las dos vias —cache y recursion literal— dan lo mismo para todo
    /// subarbol valido de todo arbol hasta 130 hojas, y las mismas pruebas.
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
        for i in 0..37u8 {
            incremental.append_raw(vec![i]).unwrap();
        }
        assert_eq!(incremental.root(), rebuilt.root());
        assert_eq!(incremental.cached_nodes(), rebuilt.cached_nodes());
        // 37 hojas: 18 + 9 + 4 + 2 + 1 nodos completos.
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
