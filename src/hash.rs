//! # El hash del arbol: `MTH` de RFC 9162 sobre SHA-256
//!
//! Tres primitivas y ninguna mas, con los dos prefijos de dominio que
//! RFC 6962/9162 fijan: `0x00` para una hoja, `0x01` para un nodo interno.
//! Es la misma defensa de segunda preimagen que `zk-ssl-hash` aplicaba con
//! `MMRHOJA1`/`MMRNODO1`: un nodo interno presentado como hoja compone
//! distinto.
//!
//! ⚠️ Aqui **no hay campo finito**. `zk-ssl-hash::native_merge` era Rescue
//! Prime sobre Goldilocks porque tenia que ser barato **dentro de un
//! circuito STARK**. En MTC nadie prueba nada en circuito: el hash es el
//! que el borrador RECOMIENDA (SHA-256, `id-pe-mtcCertificationAuthority-
//! SHA256`) y el que los cofirmantes tlog ya hablan.

use sha2::{Digest, Sha256};

/// Bytes de salida del hash del log (`HASH_SIZE` en el borrador).
pub const HASH_SIZE: usize = 32;

/// Un valor de hash del arbol (`HashValue[HASH_SIZE]`).
pub type HashValue = [u8; HASH_SIZE];

/// SHA-256 de un mensaje cualquiera. Se expone porque el
/// `subjectPublicKeyInfoHash` de la entrada usa **el mismo hash del log**.
pub fn sha256(data: &[u8]) -> HashValue {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

/// `MTH({}) = HASH("")`: la cima de un arbol vacio y el hash de un
/// subarbol `[x, x)`.
pub fn hash_empty() -> HashValue {
    sha256(&[])
}

/// `MTH({d}) = HASH(0x00 || d)`: la hoja.
pub fn hash_leaf(entry: &[u8]) -> HashValue {
    let mut h = Sha256::new();
    h.update([0x00]);
    h.update(entry);
    h.finalize().into()
}

/// `HASH(0x01 || left || right)`: el nodo interno.
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
        // El vector clasico de SHA-256("").
        let esperado = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        assert_eq!(crate::der::hex(&hash_empty()), esperado);
    }

    #[test]
    fn leaf_and_node_are_domain_separated() {
        let a = hash_leaf(&[1, 2]);
        let b = hash_node(&a, &a);
        // Una hoja cuyo contenido son dos hashes no es un nodo.
        let mut concat = Vec::new();
        concat.extend_from_slice(&a);
        concat.extend_from_slice(&a);
        assert_ne!(hash_leaf(&concat), b);
    }
}
