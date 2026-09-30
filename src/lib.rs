//! # `mtc-core` — el backend de una CA de Merkle Tree Certificates
//!
//! Implementa las piezas de `draft-ietf-plants-merkle-tree-certs` (grupo
//! PLANTS del IETF; la version leida es la de su repositorio de trabajo a
//! 29-09-2026) que un **backend de CA** y un **verificador** necesitan
//! compartir, con la misma regla que `zk-ssl-hash` impuso en Arqueo: **una
//! decision de formato tiene UNA SOLA definicion**, y la usa tanto quien
//! emite como quien comprueba.
//!
//! ## Que es y que no es
//!
//! - Es la adaptacion de la infraestructura de arbol de Arqueo a un log de
//!   emision RFC 9162: hojas `MTCLogEntry`, subarboles `[start, end)`,
//!   pruebas de inclusion y de consistencia, cofirmas `subtree/v1`, el
//!   `MTCProof` que va en el `signatureValue` de un certificado X.509, la
//!   secuencia de *landmarks* y el flujo de la CA (recibir, anotar en el
//!   log, firmar el checkpoint, cubrir el intervalo con dos subarboles,
//!   recoger cofirmas, emitir).
//! - **No** contiene ZK, ni sumas, ni campo de Goldilocks: el hash es
//!   SHA-256 y la firma es ML-DSA (o cualquier `Cosigner`).
//! - **No** es una CA completa: falta ACME, la validacion de dominio, el
//!   parseo de CSR (PKCS#10) y el servicio del log (tlog-tiles). Cada uno
//!   entra por una interfaz que este crate ya deja definida.
//!
//! ## Mapa de modulos y de donde viene cada uno
//!
//! | modulo | que define | procedencia en Arqueo / hbs-state |
//! |---|---|---|
//! | [`hash`] | `MTH` de RFC 9162 sobre SHA-256 | sustituye a `zk-ssl-hash::{native_merge, mmr_hoja, mmr_nodo}` |
//! | [`subtree`] | subarboles, pruebas de inclusion y de consistencia, cobertura de intervalos | traduccion de `zk-ssl-verify::mmr` (MTH/PATH/SUBPROOF) extendida a subarboles |
//! | [`log`] | el log de emision con nodos internos en cache | la idea de `zk-ssl::sparse_tree` (cache de nodos, O(log n) por escritura) sobre un arbol *append-only* |
//! | [`entry`] | `MTCLogEntry`, `TBSCertificateLogEntry`, la hoja `MtcLeaf` | sustituye a `native_leaf` `(cuenta, saldo, nonce)` |
//! | [`cosign`] | `CosignedMessage`, `Cosigner`, ML-DSA | `firma_cabeza::FirmanteCabeza` (reservar, firmar, autocomprobar) |
//! | [`guard`] | el contador persistido antes de firmar | `hbs-state::IndexGuard`, entero, sin reimplementar |
//! | [`landmark`] | la secuencia de landmarks y sus dos subarboles | nuevo (no hay equivalente) |
//! | [`proof`] | `MTCProof` y el certificado X.509 que lo lleva | `zk-ssl-verify::inclusion::ReciboInclusion` (hoja → raiz → cabeza firmada) |
//! | [`ca`] | el flujo de la CA de extremo a extremo | `zk-ssl-node` (latido + firma de cabeza) |
//! | [`verify`] | el verificador de la parte que confia | `zk-ssl-verify` (sin compilar el emisor) |
//! | [`der`] | lo minimo de DER/X.509 que hace falta | nuevo |
//!
//! ## Lo que este crate NO promete todavia
//!
//! Es un **esqueleto verificado**: los algoritmos del arbol pasan los cuatro
//! vectores acumulados del borrador (`tests/vectors.rs`, 65.058 casos) y
//! los vectores grandes de su apendice (`tests/large_vectors.rs`, arboles
//! de hasta 2^64-1 hojas), y hay un flujo de emision y verificacion de
//! extremo a extremo con ML-DSA-44 (`tests/end_to_end.rs`). No esta
//! auditado, no persiste el log a disco (solo el contador del guardian) y
//! los OID son los experimentales del arco 1.3.6.1.4.1.44363.47 que el
//! borrador reserva para eso.

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
pub use guard::{MemoryGuard, SequenceGuard};
pub use hash::{HashValue, HASH_SIZE};
pub use landmark::{Landmark, LandmarkSequence};
pub use log::IssuanceLog;
pub use proof::{MtcCertificate, MtcProof};
pub use subtree::{Subtree, SubtreeError};
pub use tai::TrustAnchorId;
pub use verify::{RelyingPartyConfig, TrustedSubtree, VerifiedCertificate, VerifyError};
