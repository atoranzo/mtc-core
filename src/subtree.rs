//! # Subarboles, pruebas de inclusion y pruebas de consistencia
//!
//! La traduccion a MTC de `zk-ssl-verify::mmr` (§291 de Arqueo): alli
//! vivian `MTH`, `PATH` y `SUBPROOF` de RFC 6962 sobre las primitivas de
//! la casa; aqui viven los mismos tres algoritmos sobre SHA-256 y
//! **extendidos a subarboles `[start, end)`**, que es lo que el borrador
//! anade a RFC 9162 (seccion «Subtrees»).
//!
//! ⚠️ **Generacion y verificacion comparten la misma particion** del
//! arbol —`k = la mayor potencia de dos < n`— pero no la misma forma: la
//! generacion es la recursion de RFC 9162 sobre un proveedor de hashes, y
//! la verificacion es el recorrido iterativo por bits del borrador
//! (`fn`, `sn`, `tn`), que no necesita el arbol. Lo que las ata es que el
//! verificador exige consumir el camino **entero**: un camino con sobras o
//! con faltas no pasa. Los cuatro vectores acumulados del borrador
//! (`tests/vectors.rs`) lo comprueban para todos los subarboles de todos
//! los arboles hasta 130 hojas, y los vectores grandes
//! (`tests/large_vectors.rs`) para arboles de hasta 2^64-1.
//!
//! ## El proveedor de hashes
//!
//! Los algoritmos de generacion no saben si el arbol esta en memoria como
//! lista de hojas o como log con nodos en cache: piden `MTH(D[a:b])` a un
//! [`TreeHashes`]. [`LeafHashes`] es la implementacion de referencia (la
//! recursion literal, O(n)); [`crate::log::IssuanceLog`] es la de
//! produccion (O(log n) para subarboles validos). Un test cruza las dos
//! para todos los subarboles hasta 130 hojas: dos caminos del mismo
//! contrato, atados por un test y no fiados a que coincidan.

use crate::hash::{hash_empty, hash_node, HashValue};

/// Un subarbol `[start, end)` de un log, en las coordenadas del log.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Subtree {
    pub start: u64,
    pub end: u64,
}

/// Lo que puede ir mal con un subarbol o con una prueba.
///
/// ⚠️ Tres cosas distintas con tres significados distintos, como en
/// `zk-ssl-verify::inclusion`: un intervalo que no es subarbol o un camino
/// descuadrado son **una prueba mal formada**; un hash que no sale es
/// **una entrada que no estaba** (o un subarbol de OTRO log).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubtreeError {
    /// `[start, end)` no cumple la definicion de subarbol.
    InvalidSubtree { start: u64, end: u64 },
    /// El indice no cae en `[start, end)`.
    IndexOutOfSubtree { index: u64, start: u64, end: u64 },
    /// El subarbol termina mas alla del tamano del arbol.
    SubtreeBeyondTree { end: u64, tree_size: u64 },
    /// El camino se acabo antes de llegar a la cima.
    ProofTooShort,
    /// Sobran hashes en el camino.
    ProofTooLong,
    /// El camino sube a otro hash.
    HashMismatch,
}

impl core::fmt::Display for SubtreeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SubtreeError::InvalidSubtree { start, end } => {
                write!(f, "[{start}, {end}) no es un subarbol valido")
            }
            SubtreeError::IndexOutOfSubtree { index, start, end } => {
                write!(f, "el indice {index} no cae en [{start}, {end})")
            }
            SubtreeError::SubtreeBeyondTree { end, tree_size } => {
                write!(
                    f,
                    "el subarbol termina en {end} y el arbol tiene {tree_size} hojas"
                )
            }
            SubtreeError::ProofTooShort => write!(f, "el camino se acaba antes de la cima"),
            SubtreeError::ProofTooLong => write!(f, "sobran hashes en el camino"),
            SubtreeError::HashMismatch => write!(f, "el camino sube a otro hash"),
        }
    }
}

impl std::error::Error for SubtreeError {}

/// `BIT_CEIL(n)` para `n <= 2^63`: la menor potencia de dos `>= n`.
fn bit_ceil(n: u64) -> u64 {
    if n <= 1 {
        1
    } else {
        1u64 << (64 - (n - 1).leading_zeros())
    }
}

/// La mayor potencia de dos **estrictamente** menor que `n` (`n >= 2`).
/// Es la particion de RFC 9162, compartida por generacion y verificacion.
pub fn largest_power_of_two_below(n: u64) -> u64 {
    debug_assert!(n >= 2);
    1u64 << (63 - (n - 1).leading_zeros())
}

/// La definicion de subarbol del borrador, con la guarda de desbordamiento
/// de su ejemplo en C++: `start <= end` y `start` multiplo de
/// `BIT_CEIL(end - start)`.
pub fn is_valid_subtree(start: u64, end: u64) -> bool {
    if start > end {
        return false;
    }
    let size = end - start;
    if size > (1u64 << 63) {
        return start == 0; // bit_ceil desbordaria
    }
    (start & (bit_ceil(size) - 1)) == 0
}

impl Subtree {
    /// Un subarbol comprobado.
    pub fn new(start: u64, end: u64) -> Result<Self, SubtreeError> {
        if is_valid_subtree(start, end) {
            Ok(Subtree { start, end })
        } else {
            Err(SubtreeError::InvalidSubtree { start, end })
        }
    }

    /// Re-comprueba la definicion (un `Subtree` puede venir de un decode).
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

/// **Los dos subarboles que cubren eficientemente `[start, end)`**
/// (seccion «Selecting Two Subtrees»). Es lo que la CA firma en cada
/// checkpoint: el intervalo de entradas nuevas desde el anterior, cubierto
/// por dos subarboles validos cuyo camino de inclusion no es mayor que el
/// de `MTH(D[start:end])` y que SI se pueden probar consistentes con el
/// arbol entero.
///
/// Devuelve `(izquierdo, derecho)` con `left.start <= start <= left.end =
/// right.start <= end = right.end`.
pub fn covering_subtrees(start: u64, end: u64) -> (Subtree, Subtree) {
    assert!(start <= end, "intervalo invertido");
    if end - start <= 1 {
        return (Subtree { start, end }, Subtree { start: end, end });
    }
    let last = end - 1;
    // Donde divergen los caminos de `start` y `last`: la altura del corte.
    let split = 63 - (start ^ last).leading_zeros();
    let mask = (1u64 << split) - 1;
    let mid = last & !mask;
    // El izquierdo se ensancha hasta justo antes de que el camino de
    // `start` abandone el borde derecho de su nuevo subarbol.
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

/// Quien sabe calcular `MTH(D[start:end])` sobre un arbol de `size` hojas.
pub trait TreeHashes {
    /// Cuantas hojas tiene el arbol.
    fn size(&self) -> u64;
    /// `MTH(D[start:end])` para `0 <= start <= end <= size`. **No** exige
    /// que el intervalo sea un subarbol valido.
    fn range_hash(&self, start: u64, end: u64) -> HashValue;
}

/// La implementacion de referencia: las hojas ya hasheadas, y la recursion
/// literal de RFC 9162. O(n) por consulta; para tests y para atar la de
/// produccion.
#[derive(Clone, Debug, Default)]
pub struct LeafHashes(pub Vec<HashValue>);

/// `MTH` de RFC 9162 sobre hojas **ya hasheadas** (`MTH({d}) = HASH(0x00 || d)`).
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

/// **La prueba de inclusion** de la entrada `index` en el subarbol
/// (`PATH` de RFC 9162 sobre `D[start:end]`). A lo sumo
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

/// `PATH(m, D[lo:hi])` en coordenadas absolutas del log.
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

/// **Evalua** una prueba de inclusion: devuelve el hash de subarbol que
/// esa prueba reconstruye desde `entry_hash` (seccion «Evaluating a
/// Subtree Inclusion Proof»), sin compararlo con nada. Es lo que el
/// verificador de certificados necesita: el hash esperado se compara
/// despues contra un subarbol de confianza o contra las cofirmas.
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

/// **Verifica** una prueba de inclusion contra un hash de subarbol conocido.
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

/// **La prueba de consistencia** del subarbol con el arbol de `n` hojas
/// (`SUBTREE_PROOF` del borrador). Con `start = 0` es la prueba de
/// consistencia de RFC 9162; con `end = start + 1`, la de inclusion.
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

/// `SUBTREE_SUBPROOF(start, end, D[lo:hi], b)` en coordenadas absolutas.
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
        // s < lo + k < e, lo que implica s == lo: el subarbol se parte por
        // el mismo k que el arbol, y su hijo izquierdo es MTH(D[lo:lo+k]).
        subproof(tree, lo + k, e, lo + k, hi, false, out);
        out.push(tree.range_hash(lo, lo + k));
    }
}

/// **Verifica** una prueba de consistencia (seccion «Verifying a Subtree
/// Consistency Proof»): que `root_hash`, de `n` hojas, CONTIENE al
/// subarbol con hash `node_hash`.
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
        // [4, 8) y [8, 13) son subarboles; [1, 5) no.
        assert!(is_valid_subtree(4, 8));
        assert!(is_valid_subtree(8, 13));
        assert!(!is_valid_subtree(1, 5));
        assert!(is_valid_subtree(0, 0));
        assert!(is_valid_subtree(7, 7));
        // [5, 13) se cubre con [4, 8) y [8, 13).
        assert_eq!(
            covering_subtrees(5, 13),
            (Subtree { start: 4, end: 8 }, Subtree { start: 8, end: 13 })
        );
        // El intervalo [7, 9) de la figura del contraejemplo.
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
        // MTH({d[11]}), MTH(D[8:10]), MTH({d[12]}): la figura del borrador.
        assert_eq!(p, vec![t.0[11], t.range_hash(8, 10), t.0[12]]);
        assert_eq!(
            evaluate_inclusion_proof(&t.0[10], st, 10, &p).unwrap(),
            t.range_hash(8, 13)
        );
    }

    #[test]
    fn consistency_examples_from_the_draft() {
        let t = tree(14);
        // [4, 8) en un arbol de 14: MTH(D[0:4]) y MTH(D[8:14]).
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
        // [8, 13) en un arbol de 14: d[12], d[13], MTH(D[8:12]), MTH(D[0:8]).
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
        // Con start = 0 es la consistencia de RFC 9162; con size 1, la inclusion.
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
