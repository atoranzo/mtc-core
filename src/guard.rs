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

#[cfg(test)]
mod tests {
    use super::*;

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
