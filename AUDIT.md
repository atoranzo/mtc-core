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
| 1 | `17103f8` | 2026-09-30 | clean | 0 | 35/0 | 31/0 |
| 2 | `ccdabff` | 2026-09-30 | DIFF | 0 | 37/0 | 33/0 |
| 3 | `46de090` | 2026-09-30 | clean | 0 | 37/0 | 33/0 |
| 4 | `4971648` | 2026-09-30 | clean | 0 | 37/0 | 33/0 |
| 5 | `bd84dff` | 2026-09-30 | clean | 0 | 48/0 | 40/0 |
| 6 | `a136dcf` | 2026-09-30 | clean | 0 | 48/0 | 40/0 |
| 7 | `294c640` | 2026-09-30 | clean | 0 | 48/0 | 40/0 |
| 8 | `4a81a71` | 2026-09-30 | clean | 0 | 48/0 | 40/0 |
| 9 | `0aef4d9` | 2026-09-30 | clean | 0 | 50/0 | 42/0 |
| 10 | `645ab5f` | 2026-09-30 | clean | 0 | 50/0 | 42/0 |

---

## §1 · The seed: a verified core for a Merkle Tree Certificates CA

**Commit** `17103f8` · 2026-09-30

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

**Commit** `ccdabff` · 2026-09-30

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

**Commit** `46de090` · 2026-09-30

**What changed.** Format only.

**What was verified.** The previous commit had entered without passing rustfmt: its message says so,
and in the session the non-zero exit of `cargo fmt --check` had been masked by
a `tail` in the same pipeline, which the history does not show.

**Counters, re-run at this commit.** `cargo fmt --check`: clean · `cargo clippy --all-targets`: 0 warnings · `cargo test --release`: 37/0 (passed/failed) · without `ml-dsa`: 33/0.

**What it does not close.** Nothing.

**Lesson.** A gate that is piped into `tail` does not fail the chain; the formatting
gate now runs on its own and its exit code is the one that decides.

## §4 · The verified chronology of the post-quantum transition in the plan

**Commit** `4971648` · 2026-09-30

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

**Commit** `bd84dff` · 2026-09-30

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

**Commit** `a136dcf` · 2026-09-30

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

**Commit** `294c640` · 2026-09-30

**What changed.** The two JSON files under `tests/vectors/` are code components of an IETF
contribution: Simplified BSD License of the IETF Trust, with its notice next to
the crate's MIT OR Apache-2.0.

**What was verified.** Arqueo's citation and figure gates green; no code change.

**Counters, re-run at this commit.** `cargo fmt --check`: clean · `cargo clippy --all-targets`: 0 warnings · `cargo test --release`: 48/0 (passed/failed) · without `ml-dsa`: 40/0.

**What it does not close.** Nothing.

**Lesson.** Third-party material, however small, carries its licence text with it.

## §8 · The files the extracted repository needs

**Commit** `4a81a71` · 2026-09-30

**What changed.** Copies of `LICENSE-MIT` and `LICENSE-APACHE`; a `NOTICE` naming the only
third-party material and stating the absence of affiliation; a first
`GENAI.md`; a `.gitignore` for a standalone crate.

**What was verified.** No code change.

**Counters, re-run at this commit.** `cargo fmt --check`: clean · `cargo clippy --all-targets`: 0 warnings · `cargo test --release`: 48/0 (passed/failed) · without `ml-dsa`: 40/0.

**What it does not close.** The `GENAI.md` of this commit was written in the assistant's own words about
the method; §11 replaces it with Arqueo's method.

**Lesson.** A statement that speaks for the author is the author's to word.

## §9 · The start-up check consults the journal in every state, and a test deletes the real counter

**Commit** `0aef4d9` · 2026-09-30

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

**Commit** `645ab5f` · 2026-09-30

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

**Commit** `48f24bc` · 2026-09-30

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

## §13 · The first run on the author's machine

**Commit** the one that adds this entry · 2026-09-30

**What changed.** Nothing in the code: this entry records the first execution
of the gates on the author's own machine, which §11 and §12 left as his to
record. From here on, step 4 of GENAI.md applies as written.

**Counters, run on this machine.** `cargo fmt --check`: clean · `cargo clippy
--all-targets`: 0 warnings · `cargo test --release`: 51/0 (passed/failed) ·
without `ml-dsa`: 43/0. Toolchain: rustc 1.97.1 (8bab26f4f 2026-07-14). Machine: Linux 6.18.33.2-microsoft-standard-WSL2 x86_64,
WSL2.

**What it does not close.** Nothing new; the open items are those of the
README, section 7.

**Lesson.** A record that says "the author's machine" has to have the
author's machine in it.

## §14 · Interoperability with the draft's reference implementation, measured in both directions

**Commit** the one that adds this entry · 2026-09-30 · branch `interop`, for the author's review; not `main`

**Where it departs from the method, declared.** This entry is written by
the assistant, in a session that ran the gates and pushes a review branch,
as GENAI.md says such a departure is to be declared. The author's own run of
`interop/run.sh` on his machine is not here; when he runs it, it is its own
entry, as §13 was for the gates.

**What changed.** Three library modules, one example, one test corpus and
one directory:

- `src/pem.rs`: PEM (RFC 7468) and base64, strict, no dependency. Needed
  because the reference tool speaks files, not bytes.
- `src/spki.rs`: `SubjectPublicKeyInfo` parse and compose; the ML-DSA OIDs
  of RFC 9881. Needed to read a cosigner's key from a CA certificate or a
  policy line and to publish ours.
- `src/cacert.rs`: `CaCertificate`, the certificate of the section
  "Representing Certification Authorities": written unsigned (RFC 9925) as
  the tool writes it, read from any implementation, and fail-closed on
  what the draft states as MUST (critical MTC extension, `keyCertSign`,
  `cA = TRUE`, serials within `mtcMinSerial..mtcMaxSerial`). Under
  `ml-dsa`, its key becomes a relying party's `CosignerEntry`.
- `src/cosign.rs`: the tlog key ID computation moved into
  `tlog_key_id_for`, one definition for the cosigner and for whoever checks
  a checkpoint line; `MlDsaVerifier::verifying_key_bytes`.
- `examples/interop.rs`: `generate`, `verify` and `checkpoint`, in the
  shape of the tool's own `generate` and `verify`, reading and writing its
  policy vocabulary. Its CA uses the tool's public ML-DSA-44 test seed for
  `32473.1`, so that the two CAs share one key.
- `tests/vectors/interop-plants-07/`: the tool's output over its own
  `mtc.json` with `"Version": "plants-07"` (26 certificates, five deliberate
  negatives; the log of 2122 entries as tiles; its signed checkpoint) and
  the verdicts its verifier gave; `tests/interop_corpus.rs` requires the
  same verdicts here and reproduces the checkpoint from the tiles.
- `interop/README.md` and `interop/run.sh`: the procedure, both directions,
  with the comparisons scripted.

**Two corrections to what this crate said of itself.** The README called
its target "`-06` plus the working repository as of 2026-09-29" without
saying that the working copy's `id-alg-mtcProof` OID (`…47.5`) is what the
repository's `draft_oids.md` assigns to `plants-07`; with the tool's default
`-version plants-06` (OID `…47.0`) every certificate from here is rejected
by design. The README now says `plants-07`, and so do the procedure and the
corpus. And the plan's phase 4 listed the CA certificate as future work; it
is done to the extent above.

**What was measured, and with what.** Go 1.27.1 built from the `go1.27.1`
tag of `golang/go` on GitHub (go.dev is not reachable from the session's
container), bootstrapped with the container's Go 1.24.7; the reference tool
at commit `99097c9e0af9641a85311b68f7642978b882d385` (2026-09-29) built with
`golang.org/x/crypto` v0.54.0's `cryptobyte` copied in as an internal
package (the module proxy is not reachable either; the code is unchanged,
only its import path). rustc 1.94.1, cargo 1.94.1. The container is Linux
x86_64. Results, all reproducible with `interop/run.sh`:

1. Go → Rust: 26 of 26 verdicts equal (21 OK, 5 FAIL). The five negatives
   fail here for the reason they were built for: `UnusedBit` at the DER
   (`BadLength`), `BitFlipProof` at the CA's cosignature or at the trusted
   subtree's hash, the two without the CA's cosignature at
   `MissingCosignature`.
2. Rust → Go: 9 of 9 verdicts as expected (5 OK, 4 FAIL), with this crate's
   CA certificate and again with the tool's own CA certificate. The witness
   `32473.3.1`'s SPKI line written here is byte-identical to the tool's
   `policy.txt` line: FIPS 204 key generation from the same seed agrees.
3. The log: 2122 entries read from the tool's tiles rebuild to the
   checkpoint's root; the tool's origin line equals the log ID derived
   here from the CA ID and log number; the CA's signature line carries the
   `tlog-cosignature` key ID computed here.

**Two findings for the working group, not for this crate.** (a) The tool's
signed `checkpoint` line is `key_id || signature` over the subtree
`[0, size)` with timestamp zero: it verifies here in that form and not as a
`tlog-cosignature` line (`key_id || timestamp || signature`, timestamp in
the message). The draft only requires the *signature* format to be
compatible; whether the demo's checkpoint is meant to be consumable by a
tlog witness is a question. (b) The tool's sample `policy.txt` carries six
`trusted-subtree` lines whose hashes match neither its `plants-07` nor its
`plants-06` output over its own `mtc.json` (the landmark hashes are the
same in both, as the entry does not contain the proof OID); with that
sample, the tool rejects its own landmark-relative certificates
("trusted subtree hash mismatch"). The six correct lines are in
`tests/vectors/interop-plants-07/policy.txt`.

**One correction to this entry's own first draft.** The first version of
`generate` put the standalone negatives on entry 9, whose standalone subtree
`[8, 11)` is also landmark 1's second subtree: the Go verifier accepted the
certificate with no cosignatures because the subtree was trusted, as the
procedure says it should. The negatives moved to entry 17, whose subtree no
landmark covers. The expected verdicts were wrong, not the verifier.

**Counters, re-run at this commit.** `cargo fmt --check`: clean · `cargo
clippy --all-targets`: 0 warnings · `cargo test --release`: 66/0
(passed/failed; 51 before, plus 11 unit tests of the three modules and the
4 of `tests/interop_corpus.rs`) · without `ml-dsa`: 53/0 (43 before, plus
10; the corpus test needs ML-DSA).

**What it does not close.** The author's run on his machine (§13's rule).
One implementation only; ECDSA and Ed25519 cosigners are ignored here, not
verified; the tool's cosigner groups are not expressible in this crate's
minimal policy, and `interop verify` says so line by line instead of
pretending. Nothing here is an audit.

**Lesson.** A version name is a format decision: "written against the
working copy" was true and still named the wrong `-version`. The
interoperability run found no format bug in the crate and two in what the
crate said about itself; that is what the run is for.

**Correction, same day, second commit of the branch.** The first push of
this entry's commit (`8e936d7`) did not carry the corpus's 27 `.pem` files:
the repository's `.gitignore` excludes `*.pem` (keys), the assistant's
`git add -A` obeyed it, and the gates reported 66/0 on a tree where the
files existed untracked. The author's first run of the gates on the branch
found it: the four tests of `tests/interop_corpus.rs` failed with "ca_cert.pem:
No such file or directory", while his `interop/run.sh` passed with
`failures: 0` (Go 1.27.1 from go.dev, the demo at the same commit, rustc
1.97.1). The fix is a negation for that directory in `.gitignore` and the
files themselves; the hash tiles `tile/0` and `tile/1`, copied by accident
and not what the README describes, are dropped (the test reads
`tile/entries` only). The counters below are re-run on the tree as pushed,
checked with `git ls-files`. The lesson is §12's again: a gate that passes on
files git does not see has not passed on the commit.

## §15 · The interoperability run on the author's machine

**Commit** the one that adds this entry · 2026-09-30

**What changed.** Nothing in the code: this entry records the author's own
execution of `interop/run.sh` and of the gates on the `interop` branch,
which §14 left as his to record, and the merge of that branch into `main`
(fast-forward, `a4595c7..aa48595`).

**The run.** `interop/run.sh` at commit `8e936d7`, on 2026-09-30 at
12:19:10 UTC, with Go 1.27.1 installed from go.dev, the reference tool at
commit `99097c9e0af9641a85311b68f7642978b882d385` (2026-09-29) built with
`go build` (its `golang.org/x/crypto` v0.54.0 from the module proxy), rustc
1.97.1 (8bab26f4f 2026-07-14), cargo 1.97.1. Its `results.txt`, verbatim in
substance: Go → Rust, the same verdict for all 26 certificates (21 OK, 5
FAIL), and the Go verdicts equal to `tests/vectors/interop-plants-07/
expected.txt`; Rust → Go, the same verdict as `EXPECTED.txt` for all 9
certificates with this crate's CA certificate and again with the Go tool's
CA certificate, and the witness's SPKI line byte-identical to the demo's
`policy.txt`; the log, 2122 entries read from the tiles, the root
`nZNno7jRGtX4cD1s/ZPu8u1Jlh6LyRCFGTfok/n3LM8=` equal to the checkpoint's,
the origin line equal to the derived log ID, the CA's key ID `e5375464`
equal to the one computed here, and the signature line verifying as a bare
subtree signature with timestamp zero. `failures: 0`. The same numbers as
§14's run in the container.

**Counters, run on this machine, at `aa48595`.** `cargo fmt --check`:
clean · `cargo clippy --all-targets`: 0 warnings · `cargo test --release`:
66/0 (passed/failed; `tests/interop_corpus.rs` 4/0) · without `ml-dsa`:
53/0. The first run of the gates, at `8e936d7`, gave 62/4: the four tests
of the corpus, for the reason §14 records. Machine: Linux
6.18.33.2-microsoft-standard-WSL2 x86_64, WSL2.

**What it does not close.** The open items of README section 7: one
implementation, no ECDSA or Ed25519 cosigners, the minimal policy, no
audit. And the two findings for the working group in §14, which are the
next step outside this repository.

**Lesson.** The second machine found what the first had not: a corpus git
had never seen. A run on the author's machine is not a formality of the
method; it is the only run that can find that.

## §16 · The `Co-Authored-By` trailer removed from every commit: the history rewritten, the hashes changed

**Commit** the one that adds this entry · 2026-09-30

**What changed.** Nothing in the files. The author rewrote the 16 commits
of `main` on his machine (`git filter-branch`, 2026-09-30) to drop the
`Co-Authored-By: Claude …` line the tooling appends to every commit message
the assistant makes. GitHub renders that trailer as co-authorship, in the
repository's header and next to each commit; GENAI.md states that an
assistant is not a co-author of this work, and the badge said otherwise. The
`Claude-Session` trailer stays on those commits: it records the session,
produces no badge, and is what GENAI.md now names as the per-commit
provenance. The tree of every commit is unchanged (`git diff main
main-no-coauthor --stat` printed nothing before the forced update); only
the hashes changed, the author's own commit of §13 included, because its
parent did. Forced update of `main`: `8e4badd` → `47983b2`.

**The hashes, before and after.** Every hash this file cited up to §15 has
been replaced by its new value with the table below; whoever holds the old
history can map it back. The pairing was checked by tree and subject, not
by position.

| before | after | subject |
|---|---|---|
| `8e4badd` | `47983b2` | AUDIT §15: the interoperability run and the gates on the author's machine |
| `42e405b` | `aa48595` | The corpus's certificates, which *.pem in .gitignore had kept out of the branch |
| `0129626` | `8e936d7` | Interoperability with the draft's reference implementation, both directions |
| `20c9a45` | `a4595c7` | AUDIT §13: the first run of the gates on the author's machine |
| `a4f9f39` | `21836fb` | mtc: what two independent readers found in GENAI.md and AUDIT.md, corrected; the decoder test that was missing |
| `28df509` | `48f24bc` | mtc: GENAI.md in Arqueo's method, and AUDIT.md, one entry per verified change |
| `270495d` | `645ab5f` | mtc: everything in English, with the name-and-provenance section and a standalone README |
| `cad4c00` | `0aef4d9` | mtc: the start-up check consults the journal in every state, and a test deletes the real counter |
| `923619a` | `4a81a71` | mtc: the files the extracted repository needs (licences, NOTICE, GENAI, gitignore) |
| `d6a3ee8` | `294c640` | mtc: la licencia de los vectores copiados del repositorio del IETF, declarada |
| `55e0546` | `a136dcf` | mtc: una cifra del plan escrita de forma que el cerrojo de cifras no la tome por tests |
| `3d769f3` | `bd84dff` | mtc: correcciones de la revision adversarial contra el borrador y las especificaciones C2SP |
| `022f2ee` | `4971648` | mtc: la cronologia verificada de la transicion poscuantica en el plan |
| `c679eac` | `46de090` | mtc: rustfmt del test de vectores grandes |
| `d3d55d8` | `ccdabff` | mtc: los vectores grandes del borrador, con un lector escrito a mano |
| `853f3a7` | `17103f8` | mtc: semilla de una CA de Merkle Tree Certificates sobre la infraestructura de Arqueo |

**Counters.** Unchanged by construction: the 66/0 and 53/0 of §15 at
`8e4badd` are those of `47983b2`, the same tree.

**What it does not close.** The commits of the branch in Arqueo that
carried the `mtc/` directory still bear the trailer; that repository's
history is the author's to decide. Arqueo's `doc/MTC.md` cites the
pre-rewrite hash and is corrected in that repository.

**Lesson.** A tool's default is a claim. "Co-Authored-By" was never this
project's word for what the assistant did, and a header on GitHub said it
louder than GENAI.md's disclaimer. From this entry on, commits carry
`Claude-Session` only.

## §17 · Outside the repository: the report to the working group, its answers, and the implementations this crate did not know about

**Commit** the one that adds this entry · 2026-10-02 · branch `next`, for the author's review

**What changed.** README section 7 said that `demo/` was "the only other
implementation of the current design". It stopped being true on 2026-09-29,
before this crate said it, and nobody here had looked: Bob Beck (OpenSSL)
rewrote Cloudflare's Go CA and mirror for `-06` that day
(`github.com/bob-beck/cloudflare-mtc`, commits `ba24e24` to `c6cdfe2`), and the
TLS side is OpenSSL's pull request `#33014`; he announced both on the PLANTS
list on 2026-10-01 with an end-to-end demonstration
(`github.com/bob-beck/mtc-update-service`). The sentence is corrected; the
two are named as not yet measured. Nothing in either repository refers to
this crate: they are independent of it, as it is of them.

**The record of what left this repository** between §16 and this entry, all
by the author:

- On the working group's list, `plants@ietf.org`, 2026-09-30 14:06 UTC,
  subject "An independent Rust implementation of the -07 formats,
  interop-tested against demo/": the report of §14 and §15, with the limits of
  README section 7 and the provenance of GENAI.md. Archived at
  `mailarchive.ietf.org/arch/browse/plants/`.
- In `ietf-plants-wg/merkle-tree-certs`, issue #341: the reference tool's
  checkpoint lines are not `tlog-cosignature` lines. David Benjamin, its
  principal author: "nice catch", "I don't believe anyone before you has ever
  tried consuming it", and "fixing this makes sense to me". The author offered
  the pull request for after `draft-07`.
- Issue #342: the six `trusted-subtree` lines of the sample `policy.txt` do not
  match the shipped `mtc.json`. Confirmed ("that diverged a bit"), parked
  until `draft-07` is cut; the author committed to the pull request then.

**Counters.** None move: documentation only.

**What it does not close.** The measurement against the two implementations
named above (§19), and the two pull requests, which wait for `draft-07`.

**Lesson.** "The only other implementation" was a claim about the world, not
about this crate, and the world moved without asking. A limit of the form
"nothing else exists" needs a date next to it, or a reader to check it.


## §18 · The IANA-assigned OIDs: written by default, and the two experimental sets still read

**Commit** the one that adds this entry · 2026-10-02 · branch `next`, for the author's review

**What changed, and why now.** IANA assigned the three OIDs this protocol
needs, and the draft's working copy adopted them on 2026-09-29 in the commit
"We have PKIX OIDs!" (`ad4256b`): `id-alg-mtcProof` = `1.3.6.1.5.5.7.6.67`,
`id-rdna-trustAnchorID` = `1.3.6.1.5.5.7.25.3`,
`id-pe-mtcCertificationAuthority-SHA256` = `1.3.6.1.5.5.7.1.38`. The reference
tool's `-version plants-07` writes them since then; OpenSSL's pull request and
Bob Beck's Go CA accept them (and his CA writes them by default) [wrong: his
CA writes the experimental `-06` set and reads both; measured in §19]. This crate
wrote the experimental `…44363.47.5`, `.47.3` and `.47.4`: a combination no
tool writes any more, and that OpenSSL and the Go CA do not accept for the
signature algorithm. Left as it was, every certificate from here would have
been rejected by every other implementation within weeks.

- `der::OidSet`: the three OIDs an implementation uses together. Three known
  sets: `OIDS_IANA`; `OIDS_EXPERIMENTAL_06` (`.47.0`, `.47.3`, `.47.4`, the
  `plants-06` one); and `OIDS_EXPERIMENTAL_47_5` (`.47.5`, `.47.3`, `.47.4`),
  the interim one that §14's corpus was written with.
- The CA writes the set in `CaConfig::oids`; the examples and the interop tool
  default to IANA, and `interop generate -oids` chooses another.
- A relying party accepts the three sets, **one set per certificate**: the
  certificate's `id-alg-mtcProof` names the set, the TBS must repeat the same
  `AlgorithmIdentifier` byte for byte, and the issuer's attribute must be the
  set's. An IANA signature algorithm over an experimental issuer is
  `UnknownIssuer`. `VerifiedCertificate::oids` reports the set.
- `CaCertificate` carries its set; read, the extension's OID decides it, and
  the subject must use the same set's attribute. The two experimental sets
  share both OIDs and read as `OIDS_EXPERIMENTAL_06`.

**What was measured.** Against the draft repository's `demo/` at
`38014f7fb0086438a78a4b8353607fc4557eba70` (2026-10-01), Go 1.27.1, with
`interop/run.sh` changed to its new corpus: Go → Rust, the same verdict for
all 26 certificates (21 OK, 5 FAIL); Rust → Go, the same verdict as
`EXPECTED.txt` for all 9, with this crate's CA certificate and with the Go
tool's; the log of 2122 entries rebuilt from its tiles to the checkpoint's
root, which is not §14's: the issuer's attribute is part of every entry, so
every leaf changed with the OID. The verdicts are the same as §14's, file by
file. And with `-version plants-06` the Go tool refuses the certificates from
here, naming the attribute it wanted: the OID gate works in both directions.

**The corpus.** `tests/vectors/interop-iana/`, the tool's output at that
commit, joins `tests/vectors/interop-plants-07/`, which is kept and now says
in its README which `plants-07` it is: the interim OIDs, which no tool writes
any more. `tests/interop_corpus.rs` runs its four tests over both corpora and
asserts the OID set of every accepted certificate; hiding the IANA corpus makes
three of them fail, so it is read.

**What else the draft changed since `99097c9e`**, read in its history and
judged against what this crate encodes: `MTCProof.inclusion_proof` is now
`opaque<0..2^16-1>` with the hashes concatenated, the same bytes with SHA-256;
landmark-relative certificates MAY carry cosignatures (GREASE), which a
relying party here already ignores when the subtree is trusted; trust anchor
ID components can be arbitrarily large, and an implementation MAY bound them
and MUST then fail closed, which `TrustAnchorId` does (arbitrary-precision
ASCII; `arcs()` fails past `u64`); `SubtreeSignature` is renamed
`Cosignature`. None changes a byte this crate writes.

**Counters, re-run at this commit.** `cargo fmt --check`: clean · `cargo
clippy --all-targets`: 0 warnings · `cargo test --release`: 68/0 (66 before,
plus the OID-set test in `der` and the experimental round trip in `cacert`) ·
without `ml-dsa`: 55/0 (53 before, plus the same two).

**What it does not close.** The measurement against OpenSSL and the Go CA
(§19). `draft-07` is not tagged yet; when it is, the run is repeated against
its `demo/` and the two pull requests of #341 and #342 go with it.

**Lesson.** A version name inside a tool is not a format: `plants-07` meant
two different OID sets on the same day. The corpus says which commit wrote
it, and that is what made the difference visible.


## §19 · Measured against Bob Beck's Go stack and OpenSSL's pull request: the same verdicts, a TLS handshake, and one difference of policy

**Commit** the one that adds this entry · 2026-10-02 · branch `next`, for the author's review

**What was measured**, with `interop/run-openssl.sh` (new), against OpenSSL
at `ecf0476f6d979ef265a9c311abb5bb1890c7c75b` (pull request
`openssl/openssl#33014`, "Accept the IANA-assigned Merkle Tree Certificate
OIDs", 2026-09-29, built from source as `OpenSSL 4.2.0-dev`) and Bob Beck's
`mtc` at `c6cdfe20db5651a01804f6ee15b1ba323e524a4e` (Go 1.27.1), with this
crate at `33d1d942de78b2b370cc07bb86a0fbe7b78c00fd`. By the assistant, in a
container; the author has not repeated it yet. `failures: 0`. In four parts,
each with negatives:

1. **This crate → `mtc verify`.** The corpus of §14 (nine certificates) plus
   five for TLS, written once with the IANA OIDs and once with the
   experimental `-06` set. `mtc verify`, with this crate's `subtrees.txt` and
   the witness as a cosigner certificate (`cosigners.pem`) and a quorum of
   one, gives every one of the 14 its expected verdict, in both sets (7 OK,
   7 FAIL); this crate, reading the same two files, gives the same.
2. **`mtc`'s CA → this crate.** His CA, with his mirror `32473.2` required,
   issued 20 certificates in three batches (10 standalone, carrying the CA's
   and the mirror's cosignatures; 10 landmark-relative, under three
   landmarks), with the experimental `-06` OIDs, which is what it writes.
   `interop/flip.py` (new, no MTC code: it walks the DER and the MTCProof's
   length prefixes) cut four negatives from them: one bit of the inclusion
   proof of a standalone and of a landmark-relative certificate, of the CA's
   cosignature, and of the mirror's. Same verdict here as from his verifier on
   all 24, in four configurations: the subtrees and the mirror required (22
   OK, 2 FAIL; every certificate the CA issued verifies, and both flipped
   proofs fail); the mirror required (10/14); the CA alone (11/13: the flipped
   mirror cosignature is no longer read); and a subtree file with one wrong
   hash (12/12: a trusted subtree that disagrees refuses even a certificate
   whose cosignatures are good, in both).
3. **This crate → OpenSSL, over TLS 1.3.** `interop generate -tls-key` issues
   certificates for an ML-DSA-44 key that OpenSSL generated; OpenSSL's own
   `generate_tai_chain` gives them their trust anchor IDs and groups (section
   8.2.1); `s_server` holds them and `s_client`, with `-mtc_cas` and this
   crate's CA certificate, judges what it is served, and the run checks which
   certificate was served, not only the result. With the IANA OIDs, nine
   handshakes, all as expected: the standalone certificate (`Verify return
   code: 0`); the landmark-relative one, chosen by the server because the
   client, given this crate's `landmarks.txt` and `subtrees.txt`, advertised
   the landmark's group (0); a quorum of one cosigner with the witness's
   cosigner certificate (0); the CA-only certificate with no quorum (0) and
   with a quorum of one (111, "lacks the required cosignatures"); a flipped
   bit of the proof in each form, a wrong subtree hash and another CA's
   certificate under the same ID (110, "subtree is not trusted"). With the
   experimental `-06` set, the standalone and the landmark-relative
   handshakes (0, 0).
4. **OpenSSL's corpus → this crate.** The 23 certificates of `test/mtc` in the
   pull request (written by the draft's tool at `plants-06`, and derived by
   hand), checked at OpenSSL's test instant (2025-01-01) with its cosigner
   certificates and the union of its subtree files: 22 get the same verdict
   here as from `mtc verify`, 12 OK and 10 FAIL (five signatureless ones
   whose subtree has no hash in those files, one without the CA's
   cosignature, the two malformed proofs and the two unordered cosignature
   lists). One does not.

**The difference.** `mtc-landmark-1-iana-alg.pem` is landmark 1's certificate
with the IANA `id-alg-mtcProof` in both signature fields and the experimental
`…47.3` attribute left in the issuer. OpenSSL's test expects it to verify
(the case "a landmark certificate with the IANA-assigned id-alg-mtcProof"),
`mtc verify` accepts it, and this crate refuses it, `UnknownIssuer`, because
§18 accepts one OID set per certificate. It is not a byte this crate writes;
it is a policy. The certificate conforms to neither text: the draft with the
IANA OIDs names the IANA attribute for the issuer, and `-06` names the
experimental algorithm. No CA writes it; OpenSSL made it by hand, to show
that its verifier recognises each field on its own. The other two are more
permissive during the transition; this crate is the stricter reading. Not
changed: it is the author's decision, and perhaps a question for the list;
accepting it would mean reading the issuer with any known set in `verify.rs`
(its two signature fields are both IANA, so `proof.rs`'s check that they are
equal already passes).

**What the harness had wrong, before the run recorded here.**

- A TLS handshake that does not happen leaves `s_client` printing `Verify
  return code: 0 (ok)`: there was nothing to verify. The first version of the
  TLS check passed nine of nine for that reason, the negatives included: the
  server, started in the background with no input, read end-of-file and
  closed each connection. It now requires the server's certificate in the
  client's output and compares it with the one expected; `-www` keeps the
  server from reading its input.
- The check "every certificate the CA issued verifies" in part 2 filtered on
  file names that do not begin with a digit; all of them do, so it could not
  fail. Rewritten to count the issued certificates and the flipped proofs by
  name.
- Bob's CA allocates a landmark at each issuance, so every standalone subtree
  of this run is also a landmark subtree, and a verifier given the subtrees
  decides there and never reads a cosignature (section 7.2, step 11 before
  step 12): with them, a flipped cosignature passes, here and in his verifier.
  That is correct behaviour; the cosignature negatives are judged in the
  configurations without the subtrees. And entry 9 of that log is alone in its
  subtree `[9, 10)`, with an empty inclusion proof and no bit to flip: the
  negatives use entry 0.
- Part 4's list of certificates left in OpenSSL's two cosigner certificates
  (`mtc-cosigner-32473.0.pem`, `-32473.2.pem`): the filter named
  `mtc-cosigner.pem`, which does not exist. Both verifiers refused them
  (`NotAnMtcCertificate`), so they agreed, and the count said 25 where the
  corpus has 23. Found by reading the verdicts file by file before writing
  them down here; the filter was fixed in the same, unpushed commit, and the
  run repeated.

**Falsified.** With the comparison of the trusted subtree's hash disabled in
`verify.rs` (one line), the script reports five failures: part 1 in both OID
sets, part 2 in two configurations and in the check of every issued
certificate. Part 3 does not move, as it should not: there OpenSSL verifies,
not this crate. The line was restored.

**What was added.** To `examples/interop.rs`: `generate` writes `subtrees.txt`
(the format of OpenSSL's `-mtc_subtrees`) and `cosigners.pem` (the witness as
a cosigner certificate, the unsigned shape OpenSSL's `-mtc_cosigners` and
`mtc verify --cosigner-cert` read; the draft does not define it), and with
`-tls-key` one more entry, a third landmark, five certificates and
`tls_chains.txt`, all after the corpus is written so that none of its
certificates changes; `verify` takes `-subtrees` and `-cosigner-cert` (a
certificate with the MTC CA extension is refused there). New:
`interop/run-openssl.sh`, `interop/flip.py`, and the section of
`interop/README.md` that describes them. Nothing in the library: the cosigner
certificate is configuration for other relying parties, and lives in the
example.

**One correction to §18.** §18 said that Bob Beck's CA writes the IANA OIDs by
default. It writes the experimental `-06` set and reads both: his README says
so, and `mtc inspect` of the certificates of part 2 shows
`1.3.6.1.4.1.44363.47.0`. The sentence in §18 is kept, marked, with a pointer
here. Its conclusion stands: to read his CA this crate needs the `-06` set,
and reads it (part 2).

**Counters, at this commit.** `cargo fmt --check`: clean · `cargo clippy
--all-targets -- -D warnings`: clean · `cargo test`: 68/0 · without `ml-dsa`:
55/0. No test was added: what changed is the example and two scripts,
which `cargo test` does not run, and the measurement is the script.

**What it does not close.**

- The author's run of `interop/run-openssl.sh` on his machine (§15 did that for
  `demo/`).
- The difference above: the author decides whether to keep the stricter
  reading, and whether to ask the list.
- An offline corpus from these two, as `tests/vectors/interop-iana/` is for
  `demo/`: it would carry third-party files under their licences (Apache 2.0
  for OpenSSL's; Bob Beck's repository's own), which is the author's call.
- Client authentication, ACME and the mirror protocol: not measured; this
  crate has no mirror and no TLS.

**Lesson.** A pass that cannot fail is not a measurement. `s_client` reports
success when nothing was verified, a filter can empty the set it was meant to
test, and another can let in what it was meant to leave out. The checks now
look for the thing itself (the certificate served, the file by name), the
script was made to fail on purpose, and its verdicts were read one by one
before the result was written down.

## §20 · The author's first run of `run-openssl.sh`: no `mtc` binary, read as a disagreement

**Commit** the one that adds this entry · 2026-10-02 · branch `next`, for the author's review

**What happened.** The author ran `interop/run-openssl.sh` on his machine (WSL)
at `8803b78`, with OpenSSL built from the same commit as §19 (`ecf0476`) and
Bob Beck's repository at the same commit (`c6cdfe2`). Go was not installed
(`Command 'go' not found`), so `go build -o mtc ./cmd/mtc` did not run and
there was no `mtc` binary at the path given in `MTC`. The script did not say
so. Part 1 printed, in both OID sets, "mtc verify against the expected
verdicts: DIFFERENT verdicts" next to "mtc-core on the same OpenSSL-format
inputs: same verdict for all 14 certificates (7 OK, 7 FAIL)"; part 2 stopped
at its first call to `mtc` ("No such file or directory"), and parts 3 and 4
did not run. The two "DIFFERENT" lines are not a disagreement: `mtc verify`
never ran. The shell's "No such file or directory" went into the same pipe as
a verifier's output, and the `|| true` that keeps a verifier's non-zero exit
(any FAIL verdict) from stopping the script let it pass. Invoked by a relative
path, as the author did, that line does not begin with `/`, so the verdict
file came out empty, and an empty file differs from the expected one
(reproduced here). Invoked by an absolute path, the same line would have been
read as one more FAIL verdict, for a file named `run-openssl.sh`.

**What changed.** `run-openssl.sh` checks, before it writes anything, that
`MTC` is an executable that runs (`mtc --help`) and that `python3` is present,
and says what is missing (exit 2); and a failed `cargo build` of the example,
whose output is silenced, now says so instead of stopping without a word.
Checked: with `MTC` pointing at a path that does not exist, and at a script
that exits 1, the run stops with the message and no `results.txt`; with the
real `mtc`, the full run at this commit gives the result of §19, `failures: 0`.

**The order of things.** `next` was merged into `main` (`8803b78`) after this
run, before parts 2 to 4 had run on the author's machine. Nothing in the
library changed then or here; §19 stands as the assistant's run in a
container, not yet repeated by the author.

**Counters, at this commit.** `cargo fmt --check`: clean · `cargo clippy
--all-targets -- -D warnings`: clean · `cargo test`: 68/0 · without `ml-dsa`:
55/0. Only the script changed.

**What it does not close.** The author's complete run (Go 1.27 or later, then
`mtc` built, then the same command), and his gates, whose output was not in
what he pasted.

**Lesson.** A missing tool must not look like a verifier's answer. A check that
tolerates failure (here, so that a FAIL verdict does not stop the run) needs
the tool's presence checked first, or its silence reads as a result.

## §21 · The run against Bob Beck's Go stack and OpenSSL, on the author's machine

**Commit** the one that adds this entry · 2026-10-02 · branch `next`, for the author's review

**What changed.** Nothing in the code: this entry records the author's own
execution of `interop/run-openssl.sh` and of the gates, which §19 and §20 left
as his to record, and corrects README section 7, which said he had not
repeated the run.

**The run.** `interop/run-openssl.sh` at commit `d2dff18`, on 2026-10-02 at
08:03:47 UTC, on his machine (WSL2), with Go 1.27.1 installed from go.dev;
Bob Beck's `mtc` at `c6cdfe20db5651a01804f6ee15b1ba323e524a4e` built with
`go build` (its `golang.org/x/crypto` v0.56.0 from the module proxy); OpenSSL
at `ecf0476f6d979ef265a9c311abb5bb1890c7c75b` built from source (`OpenSSL
4.2.0-dev`); rustc 1.97.1 (8bab26f4f 2026-07-14), cargo 1.97.1. Its
`results.txt`, in substance:

1. This crate → `mtc verify`: with the IANA OIDs and with the experimental
   `-06` set, `mtc verify` and this crate each give all 14 certificates their
   expected verdict (7 OK, 7 FAIL).
2. `mtc`'s CA → this crate: 20 certificates issued (10 landmark-relative)
   under 3 landmarks, 4 negatives derived; the same verdict as `mtc verify`
   for all 24 in the four configurations (22/2, 10/14, 11/13, 12/12 OK/FAIL);
   every certificate the CA issued verifies, and each flipped proof fails.
3. This crate → OpenSSL over TLS 1.3: the nine handshakes with the IANA OIDs
   and the two with the `-06` set, each serving the expected certificate and
   ending with the expected code (0; 111 for the CA-only certificate under a
   quorum of one; 110 for the flipped proofs, the wrong subtree hash and the
   other CA under the same ID).
4. OpenSSL's corpus → this crate: the same verdict as `mtc verify` for 22
   certificates (12 OK, 10 FAIL); `mtc-landmark-1-iana-alg.pem` reported apart,
   `mtc verify` OK and this crate FAIL, the known difference of §19.

`failures: 0`, exit status 0. The same numbers as §19's run in the container.

**Counters, run on this machine, at `d2dff18`.** `cargo fmt --check`: clean ·
`cargo clippy --all-targets -- -D warnings`: clean · `cargo test`: 68/0 ·
without `ml-dsa`: 55/0.

**What it does not close.** The difference of policy in §19: whether to keep
the stricter reading of mixed OID sets, and whether to ask the list. The
repetition of §18's measurement against `demo/` at `38014f7` on this machine.
An offline corpus from these two implementations (their licences). Client
authentication, ACME and the mirror protocol. And the merge of `next` into
`main`, which is the author's.

**Lesson.** The second machine agreed on every verdict, and its first attempt
found a fault in the script, not in the crate (§20). The run on the author's
machine checks the instrument as well as the thing measured.

## §22 · One OID set per certificate: the stricter reading kept, and a test that holds it

**Commit** the one that adds this entry · 2026-10-02 · branch `next`, for the author's review

**The decision.** The author's, on 2026-10-02: the difference of §19 stays.
A certificate whose `id-alg-mtcProof` names one OID set and whose issuer uses
another set's trust anchor ID attribute is refused (`UnknownIssuer`), as
OpenSSL's `mtc-landmark-1-iana-alg.pem` is here. Whether to ask the working
group he left to the assistant (below).

**Why the stricter reading.** Neither text defines that shape: the draft with
the IANA OIDs names the IANA attribute for the issuer, and `-06` names the
experimental algorithm. No CA measured here writes it: `demo/` writes the IANA
set, Bob Beck's CA the `-06` set, this crate either, each whole. And the log
entry omits the signature algorithm, so the proof does not bind it: read
field by field, the algorithm may say one set and the name another, and
nothing checks that they agree. The stricter reading refuses nothing that any
of these CAs writes. Its cost, if a CA in transition ever writes the mixed
shape, is that this crate refuses certificates that OpenSSL and `mtc` accept;
that is the reason to ask.

**What changed.** Nothing in the library. `tests/end_to_end.rs` gains
`a_certificate_that_mixes_oid_sets_is_refused`: the CA issues with the
experimental `-06` set and then with the IANA set; each certificate verifies
and reports its set; then both signature fields are rewritten to the other
set's algorithm, the issuer untouched (the shape of OpenSSL's file, in both
directions). The result parses as an MTC certificate of the other set with the
same proof, and is refused with `UnknownIssuer`. `world()` becomes
`world_with(oids)`, with `world()` the IANA case as before. README section 7
and `interop/README.md` say that the stricter reading is kept.

**Falsified.** With the issuer read under any known set in `verify.rs` (the
change §19 named), the test fails, and in the useful way: the mixed
certificate verifies, `Ok`, with the CA's and the witness's cosignatures. So
the proof and the cosignatures are good, and the policy is the only thing that
refuses it; and `verify.rs` is the only file that would change, as §19 said.
The line was restored.

**The list.** Asking was the assistant's call, and the call is to ask: three
implementations disagree on a certificate, the draft does not say what a
relying party does with mixed OIDs during the transition, and the draft's
principal author answered both issues of §17. One short question, drafted by
the assistant and sent by the author on 2026-10-02 to `plants@ietf.org`, as a
reply to his own message of 2026-09-30 ("Re: An independent Rust
implementation of the -07 formats, interop-tested against demo/"). If the
answer is to accept, `verify.rs` changes and this test turns over.

**Counters, at this commit.** `cargo fmt --check`: clean · `cargo clippy
--all-targets -- -D warnings`: clean · `cargo test`: 69/0 (68 before, plus this test) · without
`ml-dsa`: 55/0 (`tests/end_to_end.rs` needs `ml-dsa`).

**What it does not close.** The working group's answer.

**Lesson.** A decision not to change the code is still a decision about what
the code does; without a test, the next change could undo it without anyone
deciding.
