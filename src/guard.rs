//! # El guardian: persistir ANTES de firmar
//!
//! `hbs-state` es **el guardian del indice de las firmas basadas en hashes
//! con estado**, extraido de `zk-ssl-guardian` (§296 de Arqueo): un
//! contador monotono persistido con `fsync`, que se niega a operar donde
//! `fsync` no persiste (tmpfs) y que reconcilia el estado tras un
//! reinicio en cuatro casos, de los que solo uno es fatal.
//!
//! ⚠️ **No es un gestor del estado del arbol**, y conviene decirlo porque
//! la hipotesis de partida lo describia asi. Lo que aporta a una CA de
//! MTC es el **invariante**, que aqui aplica dos veces:
//!
//! 1. **El numero de checkpoint.** La CA persiste el numero del checkpoint
//!    que va a firmar ANTES de firmarlo. Si el proceso muere entre medias,
//!    el numero queda huerfano (caso normal, `CounterAhead`); si al
//!    arrancar el diario del log va por delante del contador (`KeyAhead`),
//!    alguien firmo sin pasar por el guardian y **no se arranca**.
//!
//!    ⚠️ **Lo que protege, dicho con precision:** el numero NO entra en el
//!    mensaje firmado (el `CosignedMessage` del borrador no tiene sitio para
//!    el), asi que el guardian **no impide** que la CA firme dos vistas
//!    distintas del log: eso lo detectan los testigos con pruebas de
//!    consistencia, y es su papel. Lo que el guardian da es un **registro
//!    duradero, anterior a cada firma**, con el que al arrancar se sabe
//!    cuantas firmas de checkpoint pudieron salir y cuantas anoto el diario,
//!    para reconstruir el log hasta un estado que las cubra y no publicar
//!    una vista incoherente por descuido. Es el mismo invariante que en XMSS
//!    y la misma reconciliacion; lo que cambia es la consecuencia de
//!    romperlo: alli se filtra una clave, aqui se pierde la confianza.
//! 2. **El indice de firma**, si el cofirmante de la CA es XMSS/LMS: ahi
//!    se usa tal cual, como en `FirmanteCabeza`.
//!
//! [`SequenceGuard`] es la interfaz minima que la CA necesita;
//! `hbs_state::IndexGuard` la implementa sin adaptador, y [`MemoryGuard`]
//! existe **solo para tests**: no persiste nada y lo dice.

pub use hbs_state::{is_fatal, reconcile_values, GuardError, IndexGuard, Reconciliation};

/// Un contador monotono cuyo valor reservado sobrevive al proceso.
pub trait SequenceGuard {
    /// Persiste `current + 1` y lo devuelve; **solo entonces** se firma.
    fn reserve(&mut self) -> Result<u64, GuardError>;
    /// El ultimo valor persistido. Nunca retrocede.
    fn current(&self) -> u64;
    /// Compara el contador con lo que el diario del log dice haber
    /// publicado. Solo `KeyAhead` es fatal ([`is_fatal`]).
    fn reconcile(&self, observed: u64) -> Reconciliation {
        reconcile_values(self.current(), observed)
    }
}

impl SequenceGuard for IndexGuard {
    fn reserve(&mut self) -> Result<u64, GuardError> {
        IndexGuard::reserve(self)
    }
    fn current(&self) -> u64 {
        IndexGuard::current(self)
    }
}

/// ⚠️ **No persiste.** Para tests y para medir sin disco. Una CA que
/// arranque con esto reutilizara numeros de checkpoint tras cada caida.
#[derive(Debug, Default)]
pub struct MemoryGuard {
    current: u64,
}

impl SequenceGuard for MemoryGuard {
    fn reserve(&mut self) -> Result<u64, GuardError> {
        self.current = self
            .current
            .checked_add(1)
            .ok_or_else(|| GuardError::Io("el contador desbordo".into()))?;
        Ok(self.current)
    }
    fn current(&self) -> u64 {
        self.current
    }
}

/// What a CA decides at start-up after comparing the guard with the log's
/// journal: the last checkpoint number the journal recorded as published.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StartupDecision {
    /// Start. `orphans` is how many reserved numbers never reached the
    /// journal: the normal case after a crash between reserving and signing.
    Start { orphans: u64 },
    /// Do not start, and say why.
    Refuse(StartupRefusal),
}

/// The two states in which the pair (counter, journal) forbids starting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StartupRefusal {
    /// The journal recorded a checkpoint the counter never reserved: the
    /// counter file was deleted (`IndexGuard::open` recreates a missing
    /// file at zero, silently) or restored from an older copy. Starting
    /// would reuse checkpoint numbers behind published signatures.
    CounterBehindJournal { counter: u64, journal: u64 },
    /// The counter reserved checkpoints but the journal has none: the log
    /// was lost or restored from before its first checkpoint. Starting
    /// would publish a tree inconsistent with signatures already out.
    JournalMissing { counter: u64 },
}

impl core::fmt::Display for StartupRefusal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            StartupRefusal::CounterBehindJournal { counter, journal } => write!(
                f,
                "the journal recorded checkpoint {journal} but the counter only reserved {counter}: \
                 counter deleted or restored; do not start"
            ),
            StartupRefusal::JournalMissing { counter } => write!(
                f,
                "the counter reserved {counter} checkpoints but the journal has none: log lost or \
                 restored; do not start"
            ),
        }
    }
}

/// **The start-up policy, applied to the pair ALWAYS.**
///
/// `journal_last` is the highest checkpoint number the log's journal
/// recorded as published, or `None` if it recorded none. The four states
/// of `hbs-state` map to two decisions, and the journal is consulted in
/// every one of them, not only when the counter reads zero. That is the
/// lesson of a defect found by reading Arqueo's node (its start-up policy
/// consulted the journal only in one branch, so a deleted counter file
/// reopened at zero and would have re-signed used XMSS leaves): the datum
/// outside the pair has to be looked at whatever the pair says.
pub fn startup_check(guard: &impl SequenceGuard, journal_last: Option<u64>) -> StartupDecision {
    let counter = guard.current();
    match journal_last {
        None if counter == 0 => StartupDecision::Start { orphans: 0 },
        None => StartupDecision::Refuse(StartupRefusal::JournalMissing { counter }),
        Some(journal) => match reconcile_values(counter, journal) {
            Reconciliation::InSync { .. } => StartupDecision::Start { orphans: 0 },
            Reconciliation::CounterAhead { orphans, .. } => StartupDecision::Start { orphans },
            // `journal == 0` with a counter ahead is a journal that recorded
            // nothing yet: same as `None`.
            Reconciliation::KeyAtZero { .. } => {
                StartupDecision::Refuse(StartupRefusal::JournalMissing { counter })
            }
            Reconciliation::KeyAhead { .. } => {
                StartupDecision::Refuse(StartupRefusal::CounterBehindJournal { counter, journal })
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_journal_is_consulted_in_every_state() {
        let mut g = MemoryGuard::default();
        assert_eq!(
            startup_check(&g, None),
            StartupDecision::Start { orphans: 0 }
        );
        g.reserve().unwrap();
        g.reserve().unwrap();
        assert_eq!(
            startup_check(&g, Some(2)),
            StartupDecision::Start { orphans: 0 }
        );
        assert_eq!(
            startup_check(&g, Some(1)),
            StartupDecision::Start { orphans: 1 }
        );
        assert_eq!(
            startup_check(&g, Some(3)),
            StartupDecision::Refuse(StartupRefusal::CounterBehindJournal {
                counter: 2,
                journal: 3
            })
        );
        assert_eq!(
            startup_check(&g, None),
            StartupDecision::Refuse(StartupRefusal::JournalMissing { counter: 2 })
        );
        assert_eq!(
            startup_check(&g, Some(0)),
            StartupDecision::Refuse(StartupRefusal::JournalMissing { counter: 2 })
        );
        // A counter at zero with a journal ahead: the deleted-file case.
        let fresh = MemoryGuard::default();
        assert_eq!(
            startup_check(&fresh, Some(5)),
            StartupDecision::Refuse(StartupRefusal::CounterBehindJournal {
                counter: 0,
                journal: 5
            })
        );
    }

    #[test]
    fn only_key_ahead_is_fatal_for_the_checkpoint_counter() {
        let mut g = MemoryGuard::default();
        assert_eq!(g.reserve().unwrap(), 1);
        assert_eq!(g.reserve().unwrap(), 2);
        // El diario publico el 2: en sincronia.
        assert!(!is_fatal(&g.reconcile(2)));
        // El diario se quedo en el 1: huerfano, caso normal tras caida.
        assert!(matches!(
            g.reconcile(1),
            Reconciliation::CounterAhead { orphans: 1, .. }
        ));
        // El diario dice 3 y el contador 2: alguien firmo sin reservar.
        assert!(is_fatal(&g.reconcile(3)));
    }
}
