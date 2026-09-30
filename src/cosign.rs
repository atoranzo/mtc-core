//! # Cofirmas: `CosignedMessage`, `Cosigner` y ML-DSA
//!
//! Lo que en Arqueo hacia `zk-ssl-node::firma_cabeza::FirmanteCabeza`
//! —firmar la cabeza de epoca con un preambulo de dominio, **reservando el
//! indice antes** y **verificando la propia salida antes de devolverla**—
//! aqui lo hace un [`Cosigner`] sobre el `CosignedMessage` del borrador
//! (seccion «Signature Format»), con la etiqueta `subtree/v1\n\0`.
//!
//! ## Por que la CA firma poco, y que permite eso
//!
//! La CA firma **un checkpoint y dos subarboles por ciclo**, no un
//! certificado por solicitud. Es lo que hace viable una firma
//! poscuantica grande (ML-DSA-44: 2.420 bytes) o incluso **una firma
//! basada en hashes con estado** (XMSS/LMS), porque el indice se consume
//! a ritmo de checkpoints y no de emisiones. Para esa segunda opcion el
//! guardian de `hbs-state` es exactamente la pieza que falta, y por eso
//! [`Cosigner::sign_message`] toma `&mut self`: un firmante con estado
//! tiene que poder reservar su indice.
//!
//! ## ML-DSA
//!
//! [`mldsa::MlDsaCosigner`] firma en modo puro y determinista con contexto
//! vacio, que es lo que `TLOG-COSIGNATURE` fija para ML-DSA-44. La
//! alineacion fina con esa especificacion (como se nombra la clave, el
//! `key id`) queda declarada como pendiente en el plan.

use crate::hash::HashValue;
use crate::subtree::Subtree;
use crate::tai::TrustAnchorId;

/// `uint8 label[12] = "subtree/v1\n\0"`.
pub const SUBTREE_LABEL: &[u8; 12] = b"subtree/v1\n\0";

/// Lo que un cofirmante firma.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CosignedMessage {
    pub cosigner_id: TrustAnchorId,
    /// Cero en las cofirmas que van dentro de un certificado. Distinto de
    /// cero solo en un checkpoint con sello de tiempo (`start = 0`, `end`
    /// = el mayor arbol consistente observado).
    pub timestamp: u64,
    pub log_id: TrustAnchorId,
    pub subtree: Subtree,
    pub subtree_hash: HashValue,
}

impl CosignedMessage {
    /// La serializacion TLS del `CosignedMessage`: **una sola definicion**
    /// para quien firma y para quien verifica.
    pub fn to_bytes(&self) -> Vec<u8> {
        let name = self.cosigner_id.oid_name();
        let origin = self.log_id.oid_name();
        debug_assert!(name.len() <= 255 && origin.len() <= 255);
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
        out
    }
}

/// `SubtreeSignature { cosigner_id, signature<0..2^16-1> }`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubtreeSignature {
    pub cosigner_id: TrustAnchorId,
    pub signature: Vec<u8>,
}

/// Un subarbol con su hash y las cofirmas recogidas, **en el orden
/// canonico** (por `cosigner_id`), listo para entrar en un `MTCProof`.
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

    /// Inserta manteniendo el orden; una segunda cofirma del mismo ID
    /// sustituye a la primera.
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
    /// El algoritmo no pudo firmar, o la firma recien hecha no verifica.
    Signing(String),
    /// El guardian del indice se nego (fsync falso, contador corrupto…).
    Guard(hbs_state::GuardError),
}

impl core::fmt::Display for CosignError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CosignError::Signing(s) => write!(f, "firma: {s}"),
            CosignError::Guard(g) => write!(f, "guardian: {g}"),
        }
    }
}

impl std::error::Error for CosignError {}

impl From<hbs_state::GuardError> for CosignError {
    fn from(e: hbs_state::GuardError) -> Self {
        CosignError::Guard(e)
    }
}

/// Quien firma subarboles de un log.
pub trait Cosigner {
    fn cosigner_id(&self) -> &TrustAnchorId;

    /// Firma los bytes de un `CosignedMessage` cuyo `cosigner_id` es el
    /// propio. `&mut self` porque un firmante con estado consume indice.
    fn sign_message(&mut self, message: &CosignedMessage) -> Result<Vec<u8>, CosignError>;

    /// Compone el mensaje y firma.
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
        let signature = self.sign_message(&message)?;
        Ok(SubtreeSignature {
            cosigner_id: message.cosigner_id,
            signature,
        })
    }
}

/// Quien verifica cofirmas de UN cofirmante (clave y algoritmo fijados
/// por su ID, como pide la seccion «Signature Algorithms»).
pub trait CosignatureVerifier {
    fn verify(&self, message: &[u8], signature: &[u8]) -> bool;
}

#[cfg(feature = "ml-dsa")]
pub mod mldsa {
    //! ML-DSA (FIPS 204) como cofirmante y como verificador.

    use super::{CosignError, CosignatureVerifier, CosignedMessage, Cosigner};
    use crate::tai::TrustAnchorId;
    use ml_dsa::signature::{Keypair, Signer};
    use ml_dsa::{EncodedVerifyingKey, MlDsaParams, Seed, Signature, SigningKey, VerifyingKey};

    pub use ml_dsa::{MlDsa44, MlDsa65, MlDsa87};

    /// Un cofirmante ML-DSA. `P` es `MlDsa44` (el que TLOG-COSIGNATURE
    /// fija), `MlDsa65` o `MlDsa87`.
    pub struct MlDsaCosigner<P: MlDsaParams> {
        id: TrustAnchorId,
        key: SigningKey<P>,
    }

    impl<P: MlDsaParams> MlDsaCosigner<P> {
        /// ⚠️ **La semilla es material de clave.** De donde sale (HSM, KMS,
        /// fichero 0600 como `hbs_state::seed`) es decision de despliegue.
        pub fn from_seed(id: TrustAnchorId, seed: [u8; 32]) -> Self {
            MlDsaCosigner {
                id,
                key: SigningKey::<P>::from_seed(&Seed::from(seed)),
            }
        }

        /// La clave publica codificada (`pkEncode`), para el certificado de
        /// la CA y para la configuracion de la parte que confia.
        pub fn verifying_key_bytes(&self) -> Vec<u8> {
            self.key.verifying_key().encode().to_vec()
        }

        pub fn verifier(&self) -> MlDsaVerifier<P> {
            MlDsaVerifier {
                key: self.key.verifying_key(),
            }
        }
    }

    impl<P: MlDsaParams> Cosigner for MlDsaCosigner<P> {
        fn cosigner_id(&self) -> &TrustAnchorId {
            &self.id
        }

        fn sign_message(&mut self, message: &CosignedMessage) -> Result<Vec<u8>, CosignError> {
            let bytes = message.to_bytes();
            let sig = self
                .key
                .try_sign(&bytes)
                .map_err(|e| CosignError::Signing(e.to_string()))?;
            let encoded = sig.encode().to_vec();
            // ⚠️ Verificar la propia salida ANTES de devolverla, con el mismo
            // verificador que usara un tercero (regla de §299 de Arqueo).
            if !self.verifier().verify(&bytes, &encoded) {
                return Err(CosignError::Signing(
                    "la firma recien producida no verifica".into(),
                ));
            }
            Ok(encoded)
        }
    }

    /// El verificador de un cofirmante ML-DSA.
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

        #[test]
        fn a_cosignature_verifies_and_a_tampered_one_does_not() {
            let id = TrustAnchorId::from_ascii("32473.1").unwrap();
            let mut signer = MlDsaCosigner::<MlDsa44>::from_seed(id.clone(), [1u8; 32]);
            let log = id.log_id(1);
            let sig = signer
                .sign_subtree(&log, Subtree { start: 0, end: 5 }, [9u8; 32], 0)
                .unwrap();
            assert_eq!(sig.signature.len(), 2420); // ML-DSA-44
            let verifier =
                MlDsaVerifier::<MlDsa44>::from_bytes(&signer.verifying_key_bytes()).unwrap();
            let msg = CosignedMessage {
                cosigner_id: id.clone(),
                timestamp: 0,
                log_id: log.clone(),
                subtree: Subtree { start: 0, end: 5 },
                subtree_hash: [9u8; 32],
            };
            assert!(verifier.verify(&msg.to_bytes(), &sig.signature));
            let other = CosignedMessage {
                subtree_hash: [8u8; 32],
                ..msg
            };
            assert!(!verifier.verify(&other.to_bytes(), &sig.signature));
            assert!(!verifier.verify(&[], &sig.signature[..100]));
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
            log_id: ca.log_id(1),
            subtree: Subtree { start: 4, end: 8 },
            subtree_hash: [0xab; 32],
        };
        let b = m.to_bytes();
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
