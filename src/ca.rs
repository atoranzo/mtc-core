//! # La CA: de la solicitud validada al certificado
//!
//! Es el papel que en Arqueo hacia `zk-ssl-node`: el latido que cierra
//! una epoca, compone la cabeza, la firma con el guardian delante y la
//! publica. Aqui el «latido» es el **trabajo de checkpoint** de la
//! seccion «Standalone Certificates», paso a paso:
//!
//! 1. la CA firma el checkpoint (`[0, tree_size)`, con sello de tiempo);
//! 2. determina los **dos subarboles** que cubren las entradas nuevas
//!    desde el checkpoint anterior;
//! 3. firma cada subarbol;
//! 4. pide cofirmas de cada subarbol a los cofirmantes externos (testigos,
//!    espejos);
//! 5. construye un certificado por entrada con el subarbol que la contiene
//!    y las cofirmas recogidas.
//!
//! Antes del paso 1 hay un paso 0 que el borrador no escribe y Arqueo si:
//! **reservar el numero de checkpoint en el guardian, con `fsync`**, y
//! solo entonces firmar. Lo que ese numero protege y lo que no esta dicho
//! con precision en [`crate::guard`]: es un registro duradero para
//! reconciliar al arrancar, no una atadura criptografica de la vista
//! firmada. Y el orden completo de una CA con disco es: persistir las
//! entradas con `fsync`, reservar el numero, firmar. Este esqueleto no
//! persiste las entradas: lo dice el plan, fase 1.
//!
//! ## Lo que se comprueba al entrar, y lo que no
//!
//! [`CertificateRequest`] llega **ya validada** en lo que es politica de
//! emision: el control del dominio (ACME), la prueba de posesion de la
//! clave (la firma del CSR). Lo que si se comprueba aqui es lo que el
//! borrador convierte en obligacion de la CA o lo que romperia el log:
//! que la validez este ordenada y no supere la vida maxima (la caducidad
//! de cada landmark tiene que cubrir el `notAfter` de todo lo que hay
//! debajo), que los campos DER tengan la forma que dicen tener, y que la
//! entrada no lleve extensiones que la CA no reconoce (**una CA no firma
//! lo que no entiende**).

use crate::cosign::{CosignError, Cosigner, SignedSubtree, SubtreeSignature};
use crate::der;
use crate::entry::{EntryError, LogEntryExtension, MtcLeaf, Validity};
use crate::guard::{GuardError, SequenceGuard};
use crate::hash::HashValue;
use crate::landmark::{Landmark, LandmarkError, LandmarkSequence};
use crate::log::{IssuanceLog, LogError};
use crate::proof::{MtcCertificate, MtcProof, ProofError};
use crate::subtree::{covering_subtrees, Subtree, SubtreeError};
use crate::tai::{TaiError, TrustAnchorId};

#[derive(Debug, Clone)]
pub struct CaConfig {
    pub ca_id: TrustAnchorId,
    /// El log actual. Una CA real lleva una serie; aqui, uno.
    pub log_number: u16,
    /// Vida maxima de un certificado, en segundos: acota la validez que se
    /// admite y fija la caducidad de cada landmark.
    pub max_cert_lifetime: u64,
}

/// Una solicitud **ya validada** por la capa de arriba.
#[derive(Debug, Clone)]
pub struct CertificateRequest {
    /// `Name` DER del sujeto.
    pub subject: Vec<u8>,
    /// `SubjectPublicKeyInfo` DER, entero.
    pub spki: Vec<u8>,
    pub validity: Validity,
    /// `Extensions` DER (SAN, key usage…), o nada.
    pub extensions: Option<Vec<u8>>,
    /// Extensiones **de la entrada del log**. Hoy no hay ninguna definida,
    /// asi que cualquiera se rechaza: ver [`crate::entry::RECOGNIZED_EXTENSION_TYPES`].
    pub log_entry_extensions: Vec<LogEntryExtension>,
}

/// Lo que produce un trabajo de checkpoint.
#[derive(Debug, Clone)]
pub struct Checkpoint {
    /// El numero reservado en el guardian antes de firmar.
    pub number: u64,
    pub tree_size: u64,
    pub root: HashValue,
    /// La firma de la CA sobre `[0, tree_size)` con sello de tiempo.
    pub ca_signature: SubtreeSignature,
    /// Los dos subarboles que cubren lo nuevo, con sus cofirmas.
    pub subtrees: Vec<SignedSubtree>,
}

#[derive(Debug)]
pub enum CaError {
    Log(LogError),
    Entry(EntryError),
    Guard(GuardError),
    Cosign(CosignError),
    Subtree(SubtreeError),
    Proof(ProofError),
    Landmark(LandmarkError),
    Tai(TaiError),
    /// El cofirmante de la CA no lleva el CA ID.
    CosignerIdMismatch {
        expected: TrustAnchorId,
        got: TrustAnchorId,
    },
    /// Un cofirmante externo con el ID de la CA o con un ID ya registrado.
    DuplicateCosigner(TrustAnchorId),
    /// `notBefore > notAfter`, o la vida supera `max_cert_lifetime`.
    InvalidValidity {
        not_before: u64,
        not_after: u64,
        max_cert_lifetime: u64,
    },
    /// Un campo DER de la solicitud no tiene la forma que dice tener.
    InvalidDer {
        field: &'static str,
        error: der::DerError,
    },
    /// No hay entrada con ese indice.
    NoSuchEntry(u64),
    /// La entrada existe pero ningun checkpoint la ha cubierto todavia.
    NotYetCheckpointed(u64),
}

impl core::fmt::Display for CaError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CaError::Log(e) => write!(f, "log: {e}"),
            CaError::Entry(e) => write!(f, "entrada: {e}"),
            CaError::Guard(e) => write!(f, "guardian: {e}"),
            CaError::Cosign(e) => write!(f, "cofirma: {e}"),
            CaError::Subtree(e) => write!(f, "subarbol: {e}"),
            CaError::Proof(e) => write!(f, "prueba: {e}"),
            CaError::Landmark(e) => write!(f, "landmark: {e}"),
            CaError::Tai(e) => write!(f, "identificador: {e}"),
            CaError::CosignerIdMismatch { expected, got } => {
                write!(
                    f,
                    "el cofirmante de la CA lleva el ID {got} y la CA es {expected}"
                )
            }
            CaError::DuplicateCosigner(id) => write!(f, "cofirmante repetido: {id}"),
            CaError::InvalidValidity {
                not_before,
                not_after,
                max_cert_lifetime,
            } => write!(
                f,
                "validez invalida: [{not_before}, {not_after}] con vida maxima {max_cert_lifetime}"
            ),
            CaError::InvalidDer { field, error } => write!(f, "DER invalido en {field}: {error}"),
            CaError::NoSuchEntry(i) => write!(f, "no hay entrada {i}"),
            CaError::NotYetCheckpointed(i) => {
                write!(f, "la entrada {i} aun no esta bajo un checkpoint")
            }
        }
    }
}

impl std::error::Error for CaError {}

macro_rules! from_error {
    ($($t:ty => $v:ident),*) => { $(impl From<$t> for CaError { fn from(e: $t) -> Self { CaError::$v(e) } })* };
}
from_error!(LogError => Log, EntryError => Entry, GuardError => Guard, CosignError => Cosign,
            SubtreeError => Subtree, ProofError => Proof, LandmarkError => Landmark, TaiError => Tai);

/// La CA de MTC.
pub struct CertificationAuthority<G: SequenceGuard> {
    cfg: CaConfig,
    log_id: TrustAnchorId,
    log: IssuanceLog,
    /// Las hojas, por indice: la CA las necesita enteras (con el SPKI)
    /// para componer el `TBSCertificate`; el log solo lleva el hash.
    leaves: Vec<MtcLeaf>,
    /// El mayor `notAfter` anotado: la cota inferior de la caducidad de
    /// cualquier landmark que cubra el log entero.
    max_not_after: u64,
    ca_cosigner: Box<dyn Cosigner>,
    external_cosigners: Vec<Box<dyn Cosigner>>,
    guard: G,
    last_checkpoint_size: u64,
    /// Los subarboles firmados, en orden de emision. Crecen con cada
    /// checkpoint; [`Self::prune_signed_subtrees_below`] los recorta.
    signed_subtrees: Vec<SignedSubtree>,
    landmarks: LandmarkSequence,
}

impl<G: SequenceGuard> CertificationAuthority<G> {
    /// Una CA con su cofirmante (el que tiene el ID de la CA) y su guardian.
    /// Falla al arrancar, no al emitir, si el CA ID no deja sitio a sus
    /// derivados o el cofirmante no lleva ese ID.
    pub fn new(cfg: CaConfig, ca_cosigner: Box<dyn Cosigner>, guard: G) -> Result<Self, CaError> {
        cfg.ca_id.check_as_ca_id()?;
        if ca_cosigner.cosigner_id() != &cfg.ca_id {
            return Err(CaError::CosignerIdMismatch {
                expected: cfg.ca_id.clone(),
                got: ca_cosigner.cosigner_id().clone(),
            });
        }
        let log = IssuanceLog::new(cfg.log_number)?;
        let log_id = cfg.ca_id.log_id(cfg.log_number)?;
        Ok(CertificationAuthority {
            cfg,
            log_id,
            log,
            leaves: Vec::new(),
            max_not_after: 0,
            ca_cosigner,
            external_cosigners: Vec::new(),
            guard,
            last_checkpoint_size: 0,
            signed_subtrees: Vec::new(),
            landmarks: LandmarkSequence::new(),
        })
    }

    /// Un cofirmante externo (testigo, espejo) al que pedir cofirmas. Ni el
    /// ID de la CA ni uno ya registrado: el `MTCProof` exige IDs unicos y
    /// una repeticion sustituiria en silencio la firma anterior.
    pub fn add_cosigner(&mut self, cosigner: Box<dyn Cosigner>) -> Result<(), CaError> {
        let id = cosigner.cosigner_id();
        if id == &self.cfg.ca_id
            || self
                .external_cosigners
                .iter()
                .any(|c| c.cosigner_id() == id)
        {
            return Err(CaError::DuplicateCosigner(id.clone()));
        }
        self.external_cosigners.push(cosigner);
        Ok(())
    }

    pub fn ca_id(&self) -> &TrustAnchorId {
        &self.cfg.ca_id
    }

    pub fn log_id(&self) -> &TrustAnchorId {
        &self.log_id
    }

    pub fn log(&self) -> &IssuanceLog {
        &self.log
    }

    pub fn landmarks(&self) -> &LandmarkSequence {
        &self.landmarks
    }

    pub fn guard(&self) -> &G {
        &self.guard
    }

    pub fn last_checkpoint_size(&self) -> u64 {
        self.last_checkpoint_size
    }

    fn check_der(field: &'static str, bytes: &[u8], tag: u8) -> Result<(), CaError> {
        let map = |error| CaError::InvalidDer { field, error };
        let (_, rest) = der::expect_tlv(bytes, tag).map_err(map)?;
        if !rest.is_empty() {
            return Err(map(der::DerError::TrailingData));
        }
        Ok(())
    }

    /// **Paso 3a**: comprueba la solicitud, la anota en el log y devuelve
    /// su indice.
    pub fn submit(&mut self, req: CertificateRequest) -> Result<u64, CaError> {
        let v = req.validity;
        if v.not_before > v.not_after || v.not_after - v.not_before > self.cfg.max_cert_lifetime {
            return Err(CaError::InvalidValidity {
                not_before: v.not_before,
                not_after: v.not_after,
                max_cert_lifetime: self.cfg.max_cert_lifetime,
            });
        }
        Self::check_der("subject", &req.subject, der::TAG_SEQUENCE)?;
        der::spki_algorithm(&req.spki).map_err(|error| CaError::InvalidDer {
            field: "spki",
            error,
        })?;
        if let Some(ext) = &req.extensions {
            Self::check_der("extensions", ext, der::TAG_SEQUENCE)?;
        }
        let leaf = MtcLeaf {
            version: 2,
            issuer: der::name_from_ca_id(&self.cfg.ca_id),
            validity: v,
            subject: req.subject,
            spki: req.spki,
            issuer_unique_id: None,
            subject_unique_id: None,
            extensions: req.extensions,
        };
        // `log_entry` rechaza las extensiones de entrada no reconocidas.
        let entry = leaf.log_entry(req.log_entry_extensions)?;
        let index = self.log.append(&entry)?;
        debug_assert_eq!(index as usize, self.leaves.len());
        self.leaves.push(leaf);
        self.max_not_after = self.max_not_after.max(v.not_after);
        Ok(index)
    }

    /// **El trabajo de checkpoint** (pasos 0 a 4). `None` si no hay nada
    /// nuevo desde el anterior. Si algo falla a medias, el estado de la CA
    /// no cambia: el numero reservado queda huerfano, que es el caso que
    /// el guardian sabe reconciliar.
    pub fn run_checkpoint_job(&mut self, now: u64) -> Result<Option<Checkpoint>, CaError> {
        let tree_size = self.log.size();
        if tree_size == self.last_checkpoint_size {
            return Ok(None);
        }
        let root = self.log.root();

        // ── 0 · reservar y persistir ANTES de firmar ──
        let number = self.guard.reserve()?;

        // ── 1 · la CA firma el checkpoint ──
        let checkpoint = Subtree {
            start: 0,
            end: tree_size,
        };
        let ca_signature = self
            .ca_cosigner
            .sign_subtree(&self.log_id, checkpoint, root, now)?;

        // ── 2 · los dos subarboles que cubren lo nuevo ──
        let (left, right) = covering_subtrees(self.last_checkpoint_size, tree_size);
        let mut subtrees = Vec::new();
        for st in [left, right] {
            if st.is_empty() {
                continue;
            }
            let hash = self.log.subtree_hash(st)?;
            let mut signed = SignedSubtree::new(st, hash);
            // ── 3 · la CA firma cada subarbol (timestamp 0) ──
            signed.push(self.ca_cosigner.sign_subtree(&self.log_id, st, hash, 0)?);
            // ── 4 · cofirmas externas ──
            for c in self.external_cosigners.iter_mut() {
                signed.push(c.sign_subtree(&self.log_id, st, hash, 0)?);
            }
            subtrees.push(signed);
        }
        self.signed_subtrees.extend(subtrees.iter().cloned());
        self.last_checkpoint_size = tree_size;
        Ok(Some(Checkpoint {
            number,
            tree_size,
            root,
            ca_signature,
            subtrees,
        }))
    }

    fn certificate_with(
        &self,
        index: u64,
        subtree: Subtree,
        signatures: Vec<SubtreeSignature>,
    ) -> Result<MtcCertificate, CaError> {
        let leaf = usize::try_from(index)
            .ok()
            .and_then(|i| self.leaves.get(i))
            .ok_or(CaError::NoSuchEntry(index))?;
        let entry = crate::entry::MtcLogEntry::decode(
            self.log.entry(index).ok_or(CaError::NoSuchEntry(index))?,
        )?;
        let serial = ((self.cfg.log_number as u64) << 48) | index;
        Ok(MtcCertificate {
            tbs_certificate: leaf.tbs_certificate(serial)?,
            proof: MtcProof {
                extensions: entry.extensions().to_vec(),
                subtree,
                inclusion_proof: self.log.inclusion_proof(subtree, index)?,
                signatures,
            },
        })
    }

    /// **Paso 5**: el certificado *standalone* de una entrada, con el
    /// subarbol firmado mas reciente que la contiene.
    pub fn standalone_certificate(&self, index: u64) -> Result<MtcCertificate, CaError> {
        if index >= self.log.size() {
            return Err(CaError::NoSuchEntry(index));
        }
        let signed = self
            .signed_subtrees
            .iter()
            .rev()
            .find(|s| s.subtree.contains(index))
            .ok_or(CaError::NotYetCheckpointed(index))?;
        self.certificate_with(index, signed.subtree, signed.signatures.clone())
    }

    /// Olvida los subarboles firmados que terminan antes de `index`: los de
    /// entradas ya caducadas o ya cubiertas por un landmark. Es lo unico
    /// que crece con cada checkpoint.
    pub fn prune_signed_subtrees_below(&mut self, index: u64) -> usize {
        let before = self.signed_subtrees.len();
        self.signed_subtrees.retain(|s| s.subtree.end > index);
        before - self.signed_subtrees.len()
    }

    /// Asigna un landmark si el arbol crecio desde el ultimo (procedimiento
    /// RECOMENDADO). La caducidad es `now + max_cert_lifetime` **o el mayor
    /// `notAfter` de las entradas que cubre, si es posterior**: el borrador
    /// exige que un landmark no caduque antes que nada de lo que hay
    /// debajo.
    pub fn allocate_landmark(&mut self, now: u64) -> Result<Option<Landmark>, CaError> {
        let size = self.last_checkpoint_size;
        if size == self.landmarks.latest().tree_size {
            return Ok(None);
        }
        let expiry = now
            .saturating_add(self.cfg.max_cert_lifetime)
            .max(self.max_not_after);
        Ok(Some(*self.landmarks.allocate(size, expiry)?))
    }

    /// El certificado **relativo a landmark** de una entrada: solo la
    /// prueba de inclusion al subarbol del landmark, sin firmas.
    pub fn landmark_relative_certificate(&self, index: u64) -> Result<MtcCertificate, CaError> {
        if index >= self.log.size() {
            return Err(CaError::NoSuchEntry(index));
        }
        let (_, subtree) = self.landmarks.subtree_for_index(index)?;
        self.certificate_with(index, subtree, Vec::new())
    }

    /// Los subarboles de los landmarks activos con su hash: lo que se
    /// predistribuye a las partes que confian como subarboles de confianza.
    pub fn active_landmark_subtrees(
        &self,
        now: u64,
    ) -> Result<Vec<(Landmark, Subtree, HashValue)>, CaError> {
        let mut out = Vec::new();
        for l in self.landmarks.active(now) {
            let (a, b) = self
                .landmarks
                .subtrees(l.number)
                .expect("landmark existente");
            for st in [a, b] {
                if !st.is_empty() {
                    out.push((*l, st, self.log.subtree_hash(st)?));
                }
            }
        }
        Ok(out)
    }
}
