//! # Cofirmas: `CosignedMessage`, `Cosigner` y ML-DSA
//!
//! Lo que en Arqueo hacia `zk-ssl-node::firma_cabeza::FirmanteCabeza`
//! —firmar la cabeza de epoca con un preambulo de dominio, **reservando el
//! indice antes** y **verificando la propia salida antes de devolverla**—
//! aqui lo hace un [`Cosigner`] sobre el `CosignedMessage` del borrador
//! (seccion «Signature Format»), con la etiqueta `subtree/v1\n\0`. Es la
//! misma estructura `cosigned_message` de la especificacion C2SP
//! `tlog-cosignature` para ML-DSA-44, byte a byte: lo comprueba un test
//! contra la implementacion de referencia en Go del borrador.
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
//! ## ML-DSA: con sal («hedged») por defecto
//!
//! FIPS 204 define dos variantes de firma: la **hedged** (32 bytes
//! aleatorios por firma) es la recomendada, y la determinista es opcional y
//! el propio estandar advierte de su menor resistencia a ataques de fallo
//! y de canal lateral. Ninguna de las dos cambia la verificacion, y
//! `tlog-cosignature` no fija ninguna. [`mldsa::MlDsaCosigner::from_seed`]
//! firma con sal tomada del sistema; [`mldsa::MlDsaCosigner::deterministic`]
//! existe para reproducir vectores, y lo dice.

use crate::hash::HashValue;
use crate::subtree::Subtree;
use crate::tai::{TaiError, TrustAnchorId};

/// `uint8 label[12] = "subtree/v1\n\0"`.
pub const SUBTREE_LABEL: &[u8; 12] = b"subtree/v1\n\0";

/// Lo que un cofirmante firma.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CosignedMessage {
    pub cosigner_id: TrustAnchorId,
    /// Cero en las cofirmas que van dentro de un certificado. Distinto de
    /// cero solo en un checkpoint con sello de tiempo (`start = 0`, `end`
    /// = el mayor arbol consistente observado). **Si `start` no es cero,
    /// tiene que ser cero**: lo exigen el borrador y `tlog-cosignature`.
    pub timestamp: u64,
    pub log_id: TrustAnchorId,
    pub subtree: Subtree,
    pub subtree_hash: HashValue,
}

impl CosignedMessage {
    /// Las reglas que un mensaje tiene que cumplir antes de firmarse.
    pub fn check(&self) -> Result<(), CosignError> {
        self.subtree.check()?;
        if self.timestamp != 0 && self.subtree.start != 0 {
            return Err(CosignError::TimestampOnSubtree {
                start: self.subtree.start,
                timestamp: self.timestamp,
            });
        }
        // `tlog-cosignature`: el sello de tiempo no supera 2^63 - 1.
        if self.timestamp > i64::MAX as u64 {
            return Err(CosignError::TimestampOnSubtree {
                start: self.subtree.start,
                timestamp: self.timestamp,
            });
        }
        Ok(())
    }

    /// La serializacion TLS del `CosignedMessage`: **una sola definicion**
    /// para quien firma y para quien verifica. Falla cerrado si un nombre
    /// no cabe en su prefijo de un byte o el mensaje viola una regla.
    pub fn to_bytes(&self) -> Result<Vec<u8>, CosignError> {
        self.check()?;
        let name = self.cosigner_id.oid_name()?;
        let origin = self.log_id.oid_name()?;
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
        Ok(out)
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
    /// No hubo entropia para la sal de una firma con sal.
    Randomness(String),
    /// El guardian del indice se nego (fsync falso, contador corrupto…).
    Guard(hbs_state::GuardError),
    /// Un identificador no cabe en el mensaje.
    Tai(TaiError),
    /// El subarbol no es valido.
    Subtree(crate::subtree::SubtreeError),
    /// Un sello de tiempo sobre un subarbol que no empieza en cero.
    TimestampOnSubtree { start: u64, timestamp: u64 },
}

impl core::fmt::Display for CosignError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CosignError::Signing(s) => write!(f, "firma: {s}"),
            CosignError::Randomness(s) => write!(f, "entropia: {s}"),
            CosignError::Guard(g) => write!(f, "guardian: {g}"),
            CosignError::Tai(e) => write!(f, "identificador: {e}"),
            CosignError::Subtree(e) => write!(f, "subarbol: {e}"),
            CosignError::TimestampOnSubtree { start, timestamp } => {
                write!(
                    f,
                    "sello de tiempo {timestamp} sobre un subarbol que empieza en {start}"
                )
            }
        }
    }
}

impl std::error::Error for CosignError {}

impl From<hbs_state::GuardError> for CosignError {
    fn from(e: hbs_state::GuardError) -> Self {
        CosignError::Guard(e)
    }
}

impl From<TaiError> for CosignError {
    fn from(e: TaiError) -> Self {
        CosignError::Tai(e)
    }
}

impl From<crate::subtree::SubtreeError> for CosignError {
    fn from(e: crate::subtree::SubtreeError) -> Self {
        CosignError::Subtree(e)
    }
}

/// Quien firma subarboles de un log.
pub trait Cosigner {
    fn cosigner_id(&self) -> &TrustAnchorId;

    /// Firma un `CosignedMessage` cuyo `cosigner_id` es el propio.
    /// `&mut self` porque un firmante con estado consume indice.
    fn sign_message(&mut self, message: &CosignedMessage) -> Result<Vec<u8>, CosignError>;

    /// Compone el mensaje, lo comprueba y firma.
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
        message.check()?;
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
    use crate::hash::sha256;
    use crate::tai::TrustAnchorId;
    use ml_dsa::signature::Keypair;
    use ml_dsa::{
        EncodedVerifyingKey, MlDsaParams, Seed, Signature, SigningKey, VerifyingKey, B32,
    };
    use zeroize::Zeroize;

    pub use ml_dsa::{MlDsa44, MlDsa65, MlDsa87};

    /// El byte de tipo de firma de `tlog-cosignature` para ML-DSA-44.
    pub const TLOG_KEY_TYPE_MLDSA44: u8 = 0x06;
    /// Bytes de una clave publica ML-DSA-44 (`pkEncode`).
    pub const MLDSA44_PUBLIC_KEY_LEN: usize = 1312;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SigningMode {
        /// La variante recomendada por FIPS 204: 32 bytes de sal por firma.
        Hedged,
        /// La variante opcional: reproducible, y por eso mas expuesta a
        /// ataques de fallo. Para vectores de prueba.
        Deterministic,
    }

    /// Un cofirmante ML-DSA. `P` es `MlDsa44` (el que `tlog-cosignature` y
    /// el perfil `mtc-tlog` fijan), `MlDsa65` o `MlDsa87`.
    pub struct MlDsaCosigner<P: MlDsaParams> {
        id: TrustAnchorId,
        key: SigningKey<P>,
        mode: SigningMode,
    }

    impl<P: MlDsaParams> MlDsaCosigner<P> {
        /// ⚠️ **La semilla es material de clave.** De donde sale (HSM, KMS,
        /// fichero 0600 como `hbs_state::seed`) es decision de despliegue.
        /// Se borra la copia local al terminar; **la del llamante es suya**.
        /// Firma con sal ([`SigningMode::Hedged`]).
        pub fn from_seed(id: TrustAnchorId, seed: [u8; 32]) -> Self {
            Self::with_mode(id, seed, SigningMode::Hedged)
        }

        /// Firma determinista: la misma entrada, la misma firma. Solo para
        /// reproducir vectores; ver el aviso del modulo.
        pub fn deterministic(id: TrustAnchorId, seed: [u8; 32]) -> Self {
            Self::with_mode(id, seed, SigningMode::Deterministic)
        }

        fn with_mode(id: TrustAnchorId, mut seed: [u8; 32], mode: SigningMode) -> Self {
            let key = SigningKey::<P>::from_seed(&Seed::from(seed));
            seed.zeroize();
            MlDsaCosigner { id, key, mode }
        }

        pub fn mode(&self) -> SigningMode {
            self.mode
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

        /// El *key ID* de `tlog-cosignature` para ML-DSA-44:
        /// `SHA-256(nombre || "\n" || 0x06 || clave publica de 1312 bytes)[:4]`.
        /// Es lo que va delante de la firma en la linea de un checkpoint
        /// tlog. Solo esta definido para ML-DSA-44.
        pub fn tlog_key_id(&self) -> Result<[u8; 4], CosignError> {
            let pk = self.verifying_key_bytes();
            if pk.len() != MLDSA44_PUBLIC_KEY_LEN {
                return Err(CosignError::Signing(format!(
                    "tlog-cosignature solo define el key ID para ML-DSA-44 (clave de {MLDSA44_PUBLIC_KEY_LEN} bytes, no {})",
                    pk.len()
                )));
            }
            let mut input = self.id.oid_name()?.into_bytes();
            input.push(b'\n');
            input.push(TLOG_KEY_TYPE_MLDSA44);
            input.extend_from_slice(&pk);
            let h = sha256(&input);
            Ok([h[0], h[1], h[2], h[3]])
        }

        /// La firma tal como va en una linea de nota tlog (antes de base64):
        /// `key_id || timestamped_signature { u64 timestamp; firma }`.
        pub fn tlog_note_signature(
            &self,
            timestamp: u64,
            signature: &[u8],
        ) -> Result<Vec<u8>, CosignError> {
            let mut out = self.tlog_key_id()?.to_vec();
            out.extend_from_slice(&timestamp.to_be_bytes());
            out.extend_from_slice(signature);
            Ok(out)
        }
    }

    impl<P: MlDsaParams> Cosigner for MlDsaCosigner<P> {
        fn cosigner_id(&self) -> &TrustAnchorId {
            &self.id
        }

        fn sign_message(&mut self, message: &CosignedMessage) -> Result<Vec<u8>, CosignError> {
            let bytes = message.to_bytes()?;
            let expanded = self.key.expanded_key();
            let sig = match self.mode {
                SigningMode::Deterministic => expanded
                    .sign_deterministic(&bytes, &[])
                    .map_err(|e| CosignError::Signing(e.to_string()))?,
                SigningMode::Hedged => {
                    let mut rnd = [0u8; 32];
                    getrandom::fill(&mut rnd)
                        .map_err(|e| CosignError::Randomness(e.to_string()))?;
                    // Algoritmo 2 de FIPS 204 en modo puro con contexto vacio:
                    // M' = 0x00 || len(ctx) = 0x00 || ctx (vacio) || M.
                    let sig = expanded.sign_internal(&[&[0x00, 0x00], &bytes], &B32::from(rnd));
                    rnd.zeroize();
                    sig
                }
            };
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

        fn message(id: &TrustAnchorId, hash: u8) -> CosignedMessage {
            CosignedMessage {
                cosigner_id: id.clone(),
                timestamp: 0,
                log_id: id.log_id(1).unwrap(),
                subtree: Subtree { start: 0, end: 5 },
                subtree_hash: [hash; 32],
            }
        }

        #[test]
        fn a_cosignature_verifies_and_a_tampered_one_does_not() {
            let id = TrustAnchorId::from_ascii("32473.1").unwrap();
            let mut signer = MlDsaCosigner::<MlDsa44>::from_seed(id.clone(), [1u8; 32]);
            let log = id.log_id(1).unwrap();
            let sig = signer
                .sign_subtree(&log, Subtree { start: 0, end: 5 }, [9u8; 32], 0)
                .unwrap();
            assert_eq!(sig.signature.len(), 2420); // ML-DSA-44
            let verifier =
                MlDsaVerifier::<MlDsa44>::from_bytes(&signer.verifying_key_bytes()).unwrap();
            let msg = message(&id, 9);
            assert!(verifier.verify(&msg.to_bytes().unwrap(), &sig.signature));
            let other = message(&id, 8);
            assert!(!verifier.verify(&other.to_bytes().unwrap(), &sig.signature));
            assert!(!verifier.verify(&[], &sig.signature[..100]));
            assert!(MlDsaVerifier::<MlDsa44>::from_bytes(&[0; 100]).is_none());
        }

        /// Con sal, dos firmas del mismo mensaje difieren y las dos verifican;
        /// sin sal, coinciden. La verificacion no distingue.
        #[test]
        fn hedged_signatures_differ_and_verify_while_deterministic_ones_repeat() {
            let id = TrustAnchorId::from_ascii("32473.1").unwrap();
            let msg = message(&id, 3);
            let mut hedged = MlDsaCosigner::<MlDsa44>::from_seed(id.clone(), [5u8; 32]);
            let a = hedged.sign_message(&msg).unwrap();
            let b = hedged.sign_message(&msg).unwrap();
            assert_ne!(a, b);
            let v = hedged.verifier();
            assert!(
                v.verify(&msg.to_bytes().unwrap(), &a) && v.verify(&msg.to_bytes().unwrap(), &b)
            );
            let mut det = MlDsaCosigner::<MlDsa44>::deterministic(id, [5u8; 32]);
            let c = det.sign_message(&msg).unwrap();
            assert_eq!(c, det.sign_message(&msg).unwrap());
            assert!(
                v.verify(&msg.to_bytes().unwrap(), &c),
                "misma clave, distinta variante, misma verificacion"
            );
        }

        #[test]
        fn tlog_key_id_follows_c2sp() {
            let id = TrustAnchorId::from_ascii("32473.1").unwrap();
            let signer = MlDsaCosigner::<MlDsa44>::from_seed(id.clone(), [1u8; 32]);
            let mut input = b"oid/1.3.6.1.4.1.32473.1\n\x06".to_vec();
            input.extend(signer.verifying_key_bytes());
            let h = sha256(&input);
            assert_eq!(signer.tlog_key_id().unwrap(), [h[0], h[1], h[2], h[3]]);
            let note = signer
                .tlog_note_signature(1_700_000_000, &[0xaa; 3])
                .unwrap();
            assert_eq!(note.len(), 4 + 8 + 3);
            assert_eq!(&note[4..12], &1_700_000_000u64.to_be_bytes());
            // ML-DSA-65 no tiene key ID definido.
            let big = MlDsaCosigner::<MlDsa65>::from_seed(id, [1u8; 32]);
            assert!(big.tlog_key_id().is_err());
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
            log_id: ca.log_id(1).unwrap(),
            subtree: Subtree { start: 4, end: 8 },
            subtree_hash: [0xab; 32],
        };
        let b = m.to_bytes().unwrap();
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
    fn a_timestamp_on_a_subtree_that_does_not_start_at_zero_is_rejected() {
        let ca = TrustAnchorId::from_ascii("32473.1").unwrap();
        let m = CosignedMessage {
            cosigner_id: ca.clone(),
            timestamp: 7,
            log_id: ca.log_id(1).unwrap(),
            subtree: Subtree { start: 4, end: 8 },
            subtree_hash: [0; 32],
        };
        assert!(matches!(
            m.to_bytes(),
            Err(CosignError::TimestampOnSubtree {
                start: 4,
                timestamp: 7
            })
        ));
        let checkpoint = CosignedMessage {
            subtree: Subtree { start: 0, end: 8 },
            ..m.clone()
        };
        assert!(checkpoint.to_bytes().is_ok());
        let invalid = CosignedMessage {
            subtree: Subtree { start: 1, end: 5 },
            timestamp: 0,
            ..m
        };
        assert!(matches!(invalid.to_bytes(), Err(CosignError::Subtree(_))));
    }

    #[test]
    fn a_name_that_does_not_fit_fails_closed() {
        let long = TrustAnchorId::from_binary(&[0x7f; 100]).unwrap();
        let m = CosignedMessage {
            cosigner_id: long.clone(),
            timestamp: 0,
            log_id: long,
            subtree: Subtree { start: 0, end: 1 },
            subtree_hash: [0; 32],
        };
        assert!(matches!(
            m.to_bytes(),
            Err(CosignError::Tai(TaiError::NameTooLong(_)))
        ));
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
