# AUDIT — one entry per verified change

This is the per-change record that [`GENAI.md`](./GENAI.md) points to, in
Arqueo's manner: one entry per verified change, with its commit, its counters,
what the change does **not** close and the lessons it left. Entries §1 to §10
were written on 2026-09-30 from the commits of the extraction branch, and their
counters were **re-derived on that date by checking out each commit and running
the four cargo gates again** (`cargo fmt --check`, `cargo clippy
--all-targets`, `cargo test --release` with and without `ml-dsa`) in the
assistant's cloud session (the same environment in which they first ran; not
the author's machine). Arqueo's document gates were not re-run; the entries
that cite them (§6, §7) report the run of the original session. A change that
does not carry its own entry has not been verified.

Commit hashes are those of this repository's history (the `git subtree split`
of Arqueo's `mtc/` directory).

## The record of the independent reviews

| review | agents | outcome |
|---|---|---|
| verification of the chronology (§4) | 6 finders, 6 sceptics, 1 synthesis | every claim of the starting note confirmed, corrected or marked unverified, with sources |
| adversarial review of the crate (§5) | 6 reviewers by dimension, 24 sceptics (one per finding that reached verification) | 51 raw findings, 41 after de-duplication; 24 reached a sceptic: 15 confirmed, 9 refuted; 17 of lower severity did not. The 15 confirmed and 15 of the 17 unverified fixed in §5, one more in §12, one left as is |
| translation to English (§10) | 7 translators, 7 verifiers | 7 clean verdicts: Rust code byte-identical outside comments and strings, three placeholder names renamed inside README code fences (disclosed), no Spanish left, meaning preserved |

The agents' full transcripts are not part of this repository; what survives is
what each entry records and what the tests prove.

## The counters, commit by commit

| § | commit | date | fmt | clippy | tests (passed/failed) | without `ml-dsa` |
|---|---|---|---|---|---|---|
| 1 | `853f3a7` | 2026-09-30 | clean | 0 | 35/0 | 31/0 |
| 2 | `d3d55d8` | 2026-09-30 | DIFF | 0 | 37/0 | 33/0 |
| 3 | `c679eac` | 2026-09-30 | clean | 0 | 37/0 | 33/0 |
| 4 | `022f2ee` | 2026-09-30 | clean | 0 | 37/0 | 33/0 |
| 5 | `3d769f3` | 2026-09-30 | clean | 0 | 48/0 | 40/0 |
| 6 | `55e0546` | 2026-09-30 | clean | 0 | 48/0 | 40/0 |
| 7 | `d6a3ee8` | 2026-09-30 | clean | 0 | 48/0 | 40/0 |
| 8 | `923619a` | 2026-09-30 | clean | 0 | 48/0 | 40/0 |
| 9 | `cad4c00` | 2026-09-30 | clean | 0 | 50/0 | 42/0 |
| 10 | `270495d` | 2026-09-30 | clean | 0 | 50/0 | 42/0 |

---

## §1 · The seed: a verified core for a Merkle Tree Certificates CA

**Commit** `853f3a7` · 2026-09-30

**What changed.** Twelve modules in a standalone Cargo workspace: SHA-256 tree hashing (RFC 9162
prefixes), subtrees with inclusion and consistency proofs and interval
covering, an append-only issuance log with cached full nodes, `MTCLogEntry` and
`MtcLeaf`, the minimum of DER and X.509, trust anchor IDs, cosignatures with
ML-DSA, the checkpoint counter on `hbs-state::IndexGuard`, landmarks,
`MTCProof` and the X.509 certificate that carries it, the CA's checkpoint job
and the relying-party verifier.

**What was verified.** The four accumulated test vectors of the draft's appendix (subtree hashes,
inclusion proofs, consistency proofs, covering subtrees) matched their published
SHA-256 digests. The cached log matched the reference recursion for every
subtree of every tree up to 130 leaves. An end-to-end flow issued and verified
standalone and landmark-relative certificates with ML-DSA-44 in the CA and in a
witness. Measured with the example: 5,095 DER bytes for the standalone
certificate with two cosignatures, 271 for the landmark-relative one (before
the SAN extension was made critical in §5).

**Counters, re-run at this commit.** `cargo fmt --check`: clean · `cargo clippy --all-targets`: 0 warnings · `cargo test --release`: 35/0 (passed/failed) · without `ml-dsa`: 31/0.

**What it does not close.** Persistence of the log, CSR parsing and ACME, serving the log with
tlog-tiles, real witnesses, an XMSS cosigner, interoperability with another
implementation, an audit. The OIDs are the experimental ones of the arc
1.3.6.1.4.1.44363.47.

**Lesson.** `hbs-state` is the index guard of stateful hash-based signatures, not a tree
state manager; the current draft (PLANTS working group, redesigned in -05) has
issuance logs and subtrees, not the batches of 2023; what Arqueo contributes is
its RFC 6962 algorithms, its inclusion receipt, its signing discipline and its
one-definition-per-format rule, not `SparseTree`.

## §2 · The draft's large test vectors, with a hand-written reader

**Commit** `d3d55d8` · 2026-09-30

**What changed.** `tests/large_vectors.rs` evaluates the inclusion and consistency proofs that
the draft's repository publishes for trees of 2^48-1, 2^63-1 and 2^64-1 leaves,
copied to `tests/vectors/` with their provenance declared. JSON and base64 are
read by hand: no serde, no new dependency.

**What was verified.** 24 inclusion proofs and 21 consistency proofs accepted as published; each
rejected when truncated by a hash, extended by a hash, and with a bit flipped in
the subtree hash or the tree hash.

**Counters, re-run at this commit.** `cargo fmt --check`: DIFF · `cargo clippy --all-targets`: 0 warnings · `cargo test --release`: 37/0 (passed/failed) · without `ml-dsa`: 33/0.

**What it does not close.** Interoperability with the reference Go implementation is still unexecuted:
these vectors exercise the verifier's arithmetic, not a certificate exchange.

**Lesson.** Vectors for trees no implementation can build are the only way to test the
verifier's 64-bit arithmetic near its limits; they cost nothing to keep.

## §3 · rustfmt of the large-vector test

**Commit** `c679eac` · 2026-09-30

**What changed.** Format only.

**What was verified.** The previous commit had entered without passing rustfmt: its message says so,
and in the session the non-zero exit of `cargo fmt --check` had been masked by
a `tail` in the same pipeline, which the history does not show.

**Counters, re-run at this commit.** `cargo fmt --check`: clean · `cargo clippy --all-targets`: 0 warnings · `cargo test --release`: 37/0 (passed/failed) · without `ml-dsa`: 33/0.

**What it does not close.** Nothing.

**Lesson.** A gate that is piped into `tail` does not fail the chain; the formatting
gate now runs on its own and its exit code is the one that decides.

## §4 · The verified chronology of the post-quantum transition in the plan

**Commit** `022f2ee` · 2026-09-30

**What changed.** Six independent researchers, one per claim of the starting note, and six
sceptics, one per finding, verified the dates of NIST's FIPS 203/204/205,
Chrome 116/124/131, the draft's versions, the PLANTS working group and the
Cloudflare and Let's Encrypt announcements. The README carries the table with a
status per row (confirmed, corrected, unverified), the corrections to the
starting note and what could not be verified.

**What was verified.** The dates of the draft's versions were read directly from the git tags of
its repository (`-00` 2023-03-10, `-04` 2025-03-03, `-05` 2025-06-20,
`plants-00` 2026-02-18, `plants-06` 2026-09-21). Several other dates rest on search snippets or mirrors of the primary pages,
because the NIST, Google and IETF hosts are not reachable from the session; the
Chromium commits were read from github.com directly; the table says which is
which, row by row.

**Counters, re-run at this commit.** `cargo fmt --check`: clean · `cargo clippy --all-targets`: 0 warnings · `cargo test --release`: 37/0 (passed/failed) · without `ml-dsa`: 33/0.

**What it does not close.** The headline, date and byline of the newspaper article that started the
conversation: its domain is unreachable and no search returned its
identifier.

**Lesson.** When primary hosts are blocked, git tags are primary evidence and search
snippets are not; the status column exists so that the difference is never
hidden.

## §5 · The corrections of the adversarial review against the draft and the C2SP specifications

**Commit** `3d769f3` · 2026-09-30

**What changed.** Six reviewers (tree, encoding, verifier, security, CA flow, documentation)
and one sceptic for each of the 24 findings of highest severity, against the
draft, its reference Go implementation and the C2SP tlog specifications. 51
raw findings, 41 after de-duplication; 24 reached a sceptic: 15 confirmed, 9
refuted; the 17 of lowest severity did not. The 15 confirmed and 15 of the 17
unverified ones were fixed in this commit and covered by tests; one more, the
test of the decoder's own rejection of unsorted or duplicate cosigner IDs, was
believed fixed here and was not (the patch had silently failed to apply) and
lands in §12; the one left as is holds that a landmark whose expiry equals the
current second counts as expired, an edge that turns on whether the draft's
"before the current time" is read strictly.

**What was verified.** `der::read_tlv` no longer panics on lengths that overflow (`30 88 ff…`);
impossible dates and pre-1970 dates are rejected; `TrustAnchorId` stores the
binary form and tolerates any well-formed ID on the wire (GREASE, arcs beyond
2^64) so that unrecognised cosigners can be ignored as the draft requires;
`CosignedMessage::to_bytes` is fallible (timestamp only with `start = 0` and at
most 2^63-1, names that fit); ML-DSA signs hedged by default with the seed
zeroized; the relying party always requires the CA's cosignature and uses
inclusive revocation ranges; the CA rejects inverted or over-long validity,
malformed DER, unknown log-entry extensions and duplicate cosigners, and a
landmark's expiry covers the largest `notAfter` beneath it. The SAN helper is
critical, as RFC 5280 requires with an empty subject: 5,098 and 274 DER bytes
from then on.

**Counters, re-run at this commit.** `cargo fmt --check`: clean · `cargo clippy --all-targets`: 0 warnings · `cargo test --release`: 48/0 (passed/failed) · without `ml-dsa`: 40/0.

**What it does not close.** Interoperability, persistence, ACME, tlog serving, an external audit: the
review is not an audit and the README says so.

**Lesson.** A relying party's parser must never panic on untrusted bytes; a checked
addition is the whole difference. The documentation overclaimed twice (what the
guard protects; "the mirror recursion") and the reviewers caught prose, not only
code.

## §6 · One figure of the plan reworded so that Arqueo's figure gate does not read it as tests

**Commit** `55e0546` · 2026-09-30

**What changed.** Arqueo's figure gate read the Spanish figure for the inclusion paths of the
accumulated vectors (a number followed by the Spanish word for tests) as a test
count and compared it with the canon; the figure is now worded as what it is,
a count of paths.

**What was verified.** Arqueo's citation and figure gates green.

**Counters, re-run at this commit.** `cargo fmt --check`: clean · `cargo clippy --all-targets`: 0 warnings · `cargo test --release`: 48/0 (passed/failed) · without `ml-dsa`: 40/0.

**What it does not close.** Nothing.

**Lesson.** A gate written for one vocabulary reads any number next to that vocabulary;
the fix is the wording, not the gate.

## §7 · The licence of the vectors copied from the IETF repository, declared

**Commit** `d6a3ee8` · 2026-09-30

**What changed.** The two JSON files under `tests/vectors/` are code components of an IETF
contribution: Simplified BSD License of the IETF Trust, with its notice next to
the crate's MIT OR Apache-2.0.

**What was verified.** Arqueo's citation and figure gates green; no code change.

**Counters, re-run at this commit.** `cargo fmt --check`: clean · `cargo clippy --all-targets`: 0 warnings · `cargo test --release`: 48/0 (passed/failed) · without `ml-dsa`: 40/0.

**What it does not close.** Nothing.

**Lesson.** Third-party material, however small, carries its licence text with it.

## §8 · The files the extracted repository needs

**Commit** `923619a` · 2026-09-30

**What changed.** Copies of `LICENSE-MIT` and `LICENSE-APACHE`; a `NOTICE` naming the only
third-party material and stating the absence of affiliation; a first
`GENAI.md`; a `.gitignore` for a standalone crate.

**What was verified.** No code change.

**Counters, re-run at this commit.** `cargo fmt --check`: clean · `cargo clippy --all-targets`: 0 warnings · `cargo test --release`: 48/0 (passed/failed) · without `ml-dsa`: 40/0.

**What it does not close.** The `GENAI.md` of this commit was written in the assistant's own words about
the method; §11 replaces it with Arqueo's method.

**Lesson.** A statement that speaks for the author is the author's to word.

## §9 · The start-up check consults the journal in every state, and a test deletes the real counter

**Commit** `cad4c00` · 2026-09-30

**What changed.** Arqueo's ECST report found, by reading, that the node's start-up policy
consulted the journal only in one branch of the reconciliation, so a deleted
signature-counter file reopened at zero and would have re-signed used XMSS
leaves. `guard::startup_check(guard, journal_last)` maps the four `hbs-state`
states to Start or Refuse and looks at the journal whatever the pair says.

**What was verified.** `tests/guard_startup.rs` reproduces the finding on the real `IndexGuard`
(delete the file, reopen, `current() == 0`) and checks that the start-up check
refuses in both directions: counter behind the journal, journal missing while
the counter is ahead.

**Counters, re-run at this commit.** `cargo fmt --check`: clean · `cargo clippy --all-targets`: 0 warnings · `cargo test --release`: 50/0 (passed/failed) · without `ml-dsa`: 42/0.

**What it does not close.** Phase 1 still has to write the start-up path that calls it, with the log
persisted with `fsync` before the number is reserved.

**Lesson.** The datum outside the reconciled pair has to be consulted always; a policy
that consults it in one branch is a policy that reuses resources in the
others.

## §10 · Everything in English, with the name-and-provenance section and a standalone README

**Commit** `270495d` · 2026-09-30

**What changed.** Seven translators (one per file group) and seven independent verifiers. For
the six code groups the verifier stripped comments and string contents from the
committed and the working copies and found the code byte-identical; the
README's verifier read its whole diff and noted three placeholder identifiers
renamed inside its code fence and diagrams (`ruta` to `path`, `izq, der` to
`left, right`, the journal placeholder), none of them a compiled identifier.
All grepped for leftover Spanish and compared the changed comments against the
originals. The README opens as
the README of its own repository, with a section on the name (`mtc-core`,
descriptive, endorsed by no one, free on crates.io on 2026-09-30) and on where
each piece comes from.

**What was verified.** All seven verdicts clean; the crate-wide greps agree; the example prints
5,098 and 274 DER bytes as before.

**Counters, re-run at this commit.** `cargo fmt --check`: clean · `cargo clippy --all-targets`: 0 warnings · `cargo test --release`: 50/0 (passed/failed) · without `ml-dsa`: 42/0.

**What it does not close.** Seven of the nine commit messages before this one remain in Spanish (the two
written after the translation was decided, §8 and §9, are in English): they are
history and were not rewritten.

**Lesson.** Translation is a change like any other: it needs a verifier that is not the
translator, and a mechanical check that the code did not move.

## §11 · GENAI.md in Arqueo's method, and this record

**Commit** `28df509` · 2026-09-30

**What changed.** `GENAI.md` follows the structure and the commitments of
Arqueo's statement: what is used, the four steps of the method, the two
consequences, where the record is, scope, authorship and accountability. It
states the one place where the commits before the author's push, this one
included, departed from step 4 (the assistant ran the gates and pushed to a
review branch; the author's acceptance is the review of that branch and the
push of its split history to this repository) instead of glossing over it.
This `AUDIT.md` is the record the statement points to.

**What was verified.** The counters of the table above: each of the ten commits
checked out in its own worktree, `cargo fmt --check`, `cargo clippy
--all-targets`, `cargo test --release` with and without `ml-dsa`, on
2026-09-30.

**Counters.** Not re-run: no file outside `GENAI.md` and `AUDIT.md` changes, so
the tree under test is that of §10 (50/0, 42/0 without `ml-dsa`, clippy 0, fmt
clean).

**What it does not close.** The counters were re-run in the assistant's
environment, not on the author's machine; the first run on the author's machine
is his to record. And this entry, as first written, carried overclaims that §12
records and corrects.

**Lesson.** A method that requires a per-change record is not adopted by
citing it; the record has to exist, with the numbers re-derived.

## §12 · What two independent readers found in §11 and in GENAI.md, corrected

**Commit** the one that adds this entry · 2026-09-30

**What changed.** A first reading of `GENAI.md` and `AUDIT.md` by two
separate agent instances did not run (the session's usage limit had been
reached); a second attempt ran on the same day, one instance on the facts
against the history and the numbers, one on the method and the wording, and
found what this commit corrects: `GENAI.md` said the gate results were in each
commit message (two of ten mention them, none with numbers); it counted two
independent reviews where the record has three; it said nothing of the one
commit that entered with a silenced formatting gate; it spoke of "this
repository" where only `main` is under the author's push; §10 said ten Spanish
commit messages where there are seven of nine; §5 said one minor finding was
left as is where two were, and the review table added 15, 9 and 17 to 51
without the ten duplicates that de-duplication removed and the cap of 24
sceptics. The second minor finding, the missing test of the decoder's own
rejection of unsorted or duplicate cosigner IDs, is fixed here: `src/proof.rs`
gains `decoder_enforces_canonical_order_and_tolerates_unknown_ids`, which also
checks that a GREASE identifier of any shape decodes.

**What was verified.** The two readers' 27 findings, each with its evidence
(a git command, a file and line, a number in the measurement log), applied or
answered; then the gates on this tree.

**Counters, re-run at this commit.** `cargo fmt --check`: clean · `cargo clippy --all-targets`: 0 warnings · `cargo test --release`: 51/0 (passed/failed) · without `ml-dsa`: 43/0.

**What it does not close.** The author's own reading of the branch, before he
pushes it, is still the acceptance; nothing here replaces it.

**Lesson.** The document that claims a method is the first thing the method
has to be applied to. The first version of this record overclaimed in six
places, and one "fixed" finding was not fixed: a patch that finds no anchor
fails silently, and only a test, or a reader, notices.
