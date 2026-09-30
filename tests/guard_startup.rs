//! A deleted counter file reopens at zero: the reading finding of the ECST
//! report on Arqueo's node, reproduced here on the real `hbs-state` guard,
//! and the start-up check that turns it into a refusal instead of a reuse.

use mtc_core::guard::{startup_check, IndexGuard, StartupDecision, StartupRefusal};

#[test]
fn a_deleted_counter_reopens_at_zero_and_the_startup_check_refuses() {
    let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("guard-startup");
    let path = dir.join("checkpoint.bin");
    let _ = std::fs::remove_file(&path);
    let mut guard = match IndexGuard::open(&path) {
        Ok(g) => g,
        Err(mtc_core::guard::GuardError::FakePersistence { ratio, .. }) => {
            eprintln!(
                "SKIPPED: fsync does not persist at {} (ratio {ratio})",
                path.display()
            );
            return;
        }
        Err(e) => panic!("cannot open the guard at {}: {e}", path.display()),
    };
    // Two checkpoints reserved and, say, both recorded by the journal.
    assert_eq!(guard.reserve().unwrap(), 1);
    assert_eq!(guard.reserve().unwrap(), 2);
    assert_eq!(
        startup_check(&guard, Some(2)),
        StartupDecision::Start { orphans: 0 }
    );
    drop(guard);

    // The counter file disappears (an operator "cleaning up", a partial
    // restore). `IndexGuard::open` recreates it at zero without a word.
    std::fs::remove_file(&path).unwrap();
    let reopened = IndexGuard::open(&path).unwrap();
    assert_eq!(
        reopened.current(),
        0,
        "the finding: a missing counter reopens at zero"
    );

    // With the journal consulted ALWAYS, that is a refusal, not a restart
    // from checkpoint 1 behind two published signatures.
    assert_eq!(
        startup_check(&reopened, Some(2)),
        StartupDecision::Refuse(StartupRefusal::CounterBehindJournal {
            counter: 0,
            journal: 2
        })
    );
    // And a journal that recorded nothing while the counter is ahead is
    // the mirror case: the log was lost, not the counter.
    let _ = std::fs::remove_file(&path);
    let mut again = IndexGuard::open(&path).unwrap();
    again.reserve().unwrap();
    assert_eq!(
        startup_check(&again, None),
        StartupDecision::Refuse(StartupRefusal::JournalMissing { counter: 1 })
    );
}
