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
//! solo entonces firmar.
//!
//! ## Lo que queda fuera, a proposito
//!
//! [`CertificateRequest`] llega **ya validada**: el control del dominio
//! (ACME), la prueba de posesion de la clave (la firma del CSR) y la
//! politica de emision son de la capa de arriba. Este crate certifica lo
//! que le dan; que lo que le dan sea verdad es responsabilidad del
//! operador, exactamente como en Arqueo la capa aplicaba y el operador
//! decidia.

use crate::cosign::{CosignError, Cosigner, SignedSubtree, SubtreeSignature};
use crate::der;
use crate::entry::{EntryError, LogEntryExtension, MtcLeaf, Validity};
use crate::guard::{GuardError, SequenceGuard};
use crate::hash::HashValue;
use crate::landmark::{Landmark, LandmarkError, LandmarkSequence};
use crate::log::{IssuanceLog, LogError};
use crate::proof::{MtcCertificate, MtcProof, ProofError};
use crate::subtree::{covering_subtrees, Subtree, SubtreeError};
use crate::tai::TrustAnchorId;

#[derive(Debug, Clone)]
pub struct CaConfig {
    pub ca_id: TrustAnchorId,
    /// El log actual. Una CA real lleva una serie; aqui, uno.
    pub log_number: u16,
    /// Vida maxima de un certificado, en segundos: fija la caducidad de
    /// cada landmark.
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
    /// Extensiones **de la entrada del log**, normalmente ninguna.
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
            SubtreeError => Subtree, ProofError => Proof, LandmarkError => Landmark);

/// La CA de MTC.
pub struct CertificationAuthority<G: SequenceGuard> {
    cfg: CaConfig,
    log: IssuanceLog,
    /// Las hojas, por indice: la CA las necesita enteras (con el SPKI)
    /// para componer el `TBSCertificate`; el log solo lleva el hash.
    leaves: Vec<MtcLeaf>,
    ca_cosigner: Box<dyn Cosigner>,
    external_cosigners: Vec<Box<dyn Cosigner>>,
    guard: G,
    last_checkpoint_size: u64,
    /// Los subarboles firmados, del mas reciente al mas antiguo.
    signed_subtrees: Vec<SignedSubtree>,
    landmarks: LandmarkSequence,
}

impl<G: SequenceGuard> CertificationAuthority<G> {
    /// Una CA con su cofirmante (el que tiene el ID de la CA) y su guardian.
    pub fn new(cfg: CaConfig, ca_cosigner: Box<dyn Cosigner>, guard: G) -> Result<Self, CaError> {
        debug_assert_eq!(
            ca_cosigner.cosigner_id(),
            &cfg.ca_id,
            "el cofirmante de la CA lleva el CA ID"
        );
        let log = IssuanceLog::new(cfg.log_number)?;
        Ok(CertificationAuthority {
            cfg,
            log,
            leaves: Vec::new(),
            ca_cosigner,
            external_cosigners: Vec::new(),
            guard,
            last_checkpoint_size: 0,
            signed_subtrees: Vec::new(),
            landmarks: LandmarkSequence::new(),
        })
    }

    /// Un cofirmante externo (testigo, espejo) al que pedir cofirmas.
    pub fn add_cosigner(&mut self, cosigner: Box<dyn Cosigner>) {
        self.external_cosigners.push(cosigner);
    }

    pub fn ca_id(&self) -> &TrustAnchorId {
        &self.cfg.ca_id
    }

    pub fn log_id(&self) -> TrustAnchorId {
        self.cfg.ca_id.log_id(self.cfg.log_number)
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

    /// **Paso 3a**: anota la solicitud en el log y devuelve su indice.
    pub fn submit(&mut self, req: CertificateRequest) -> Result<u64, CaError> {
        let leaf = MtcLeaf {
            version: 2,
            issuer: der::name_from_ca_id(&self.cfg.ca_id),
            validity: req.validity,
            subject: req.subject,
            spki: req.spki,
            issuer_unique_id: None,
            subject_unique_id: None,
            extensions: req.extensions,
        };
        let entry = leaf.log_entry(req.log_entry_extensions)?;
        let index = self.log.append(&entry)?;
        debug_assert_eq!(index as usize, self.leaves.len());
        self.leaves.push(leaf);
        Ok(index)
    }

    /// **El trabajo de checkpoint** (pasos 0 a 4). `None` si no hay nada
    /// nuevo desde el anterior.
    pub fn run_checkpoint_job(&mut self, now: u64) -> Result<Option<Checkpoint>, CaError> {
        let tree_size = self.log.size();
        if tree_size == self.last_checkpoint_size {
            return Ok(None);
        }
        let log_id = self.log_id();
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
            .sign_subtree(&log_id, checkpoint, root, now)?;

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
            signed.push(self.ca_cosigner.sign_subtree(&log_id, st, hash, 0)?);
            // ── 4 · cofirmas externas ──
            for c in self.external_cosigners.iter_mut() {
                signed.push(c.sign_subtree(&log_id, st, hash, 0)?);
            }
            subtrees.push(signed);
        }
        for s in subtrees.iter().rev() {
            self.signed_subtrees.insert(0, s.clone());
        }
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
        let leaf = self
            .leaves
            .get(index as usize)
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
            .find(|s| s.subtree.contains(index))
            .ok_or(CaError::NotYetCheckpointed(index))?;
        self.certificate_with(index, signed.subtree, signed.signatures.clone())
    }

    /// Asigna un landmark si el arbol crecio desde el ultimo (procedimiento
    /// RECOMENDADO): `expiry = now + max_cert_lifetime`.
    pub fn allocate_landmark(&mut self, now: u64) -> Result<Option<Landmark>, CaError> {
        let size = self.last_checkpoint_size;
        if size == self.landmarks.latest().tree_size {
            return Ok(None);
        }
        Ok(Some(
            *self
                .landmarks
                .allocate(size, now + self.cfg.max_cert_lifetime)?,
        ))
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
