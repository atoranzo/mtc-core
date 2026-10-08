# mtc-core: from Arqueo to a Merkle Tree Certificates CA

> Engineering plan and Rust skeleton for reusing Arqueo's tree infrastructure
> and the `hbs-state` state guardian as the *backend* of a certification
> authority (CA) for **Merkle Tree Certificates (MTC)**, the IETF proposal
> (`draft-ietf-plants-merkle-tree-certs`, PLANTS working group) so that
> post-quantum TLS does not pay three ML-DSA signatures per *handshake*.

This crate was born as the `mtc/` directory of
[Arqueo](https://github.com/atoranzo/Arqueo-open-conservation-proofs-for-closed-ledgers)
and was extracted into its own repository with its history. It is a
standalone Cargo workspace with three dependencies (`sha2`, `ml-dsa`,
`hbs-state`) and no zero-knowledge machinery.

```bash
cargo test --release              # draft vectors + end-to-end flow + the reference implementation's corpus
cargo run --release --example demo_ca
DEMO_DIR=/path/to/merkle-tree-certs/demo interop/run.sh /tmp/mtc-interop   # both directions against the Go tool
```

What running that verifies, and what it does not, is in section 7.

---

## Name and provenance

**The name.** `mtc-core` says what this is, the core of a Merkle Tree
Certificates CA, and nothing about who stands behind it. It is not an IETF,
PLANTS, Cloudflare, Google or Let's Encrypt project, and it is not endorsed
by any of them; their names appear because their specifications, code and
announcements are the subject matter. "MTC" is the generic abbreviation the
draft itself uses. The crate name was free on crates.io on 2026-09-30.

**Where it comes from.** This crate was born inside
[Arqueo](https://github.com/atoranzo/Arqueo-open-conservation-proofs-for-closed-ledgers),
the author's engine of open conservation proofs for closed ledgers, as the
directory `mtc/`, and was extracted with `git subtree split` so that the
history travels with the code: the first commits of this repository are the
commits that created it there, with their messages, their gates and their
provenance trailers. What it takes from Arqueo is not the ledger and not the
zero-knowledge layer, but the tree infrastructure and the discipline around
it:

| from Arqueo | here |
|---|---|
| `zk-ssl-verify::mmr` (RFC 6962 `MTH`, `PATH`, `SUBPROOF`) | `subtree`, on SHA-256 and extended to subtrees |
| `zk-ssl-verify::inclusion` (leaf → root → signed head) | `proof` and `verify` |
| `zk-ssl-node::firma_cabeza` (reserve, sign, self-verify) | `cosign::Cosigner` |
| `zk-ssl-guardian`, already extracted as [`hbs-state`](https://github.com/atoranzo/hbs-state) | `guard`, as a dependency |
| the idea of `zk-ssl::sparse_tree` (cached internal nodes) | `log`, on an append-only tree |
| the rule of `zk-ssl-hash`: one definition per format, shared by issuer and verifier | the whole crate |

Nothing from the STARK layer, the winterfell fork or the ledger state machine
travelled with it. Section 2 says, crate by crate, what was left behind and
why.

**How it was made.** With a generative AI assistant, under the author's
direction; [`GENAI.md`](./GENAI.md) states the method, where it differs from
Arqueo's, and what that does and does not claim.

---

## 0. Read this first: three corrections to the starting hypothesis

The hypothesis was: "`Arqueo` builds and updates the tree; `hbs-state` manages
its persistent state; it is enough to remove STARK and sums and change the
leaves". Having read the code of both repositories and the current draft, three
things must be corrected before designing anything:

1. **`hbs-state` does not manage the tree's state.** It is *the index guardian
   for stateful hash-based signatures* (XMSS/XMSS^MT): a monotonic counter
   persisted with `fsync`, a self-check that refuses to operate on `tmpfs`, and
   the four-state reconciliation after a restart. It is `zk-ssl-guardian`
   extracted from Arqueo, with zero dependencies. It has no cache and no tree.
   **What it contributes to an MTC CA is an invariant**, and it contributes it
   twice (section 2.3).

2. **The draft is no longer the 2023 "batches" one.** The design that circulated
   with Cloudflare (`draft-davidben-…-04`: an independent Merkle tree per batch,
   a signed "validity window", `Assertion` leaves in TLS format) was rewritten
   entirely in `-05` and is today a PLANTS working group document. In the
   current design:
   - the CA keeps *append-only* **issuance logs** in the style of RFC 9162, not
     per-batch trees;
   - the leaf is an `MTCLogEntry` wrapping a **DER-encoded X.509**
     `TBSCertificateLogEntry`, where the public key goes **by its hash**;
   - the CA signs **subtrees** `[start, end)` with a cosignature format
     compatible with tlog *witnesses* (`subtree/v1`), and other cosigners
     (witnesses, mirrors) sign the same thing;
   - the certificate **is an ordinary X.509** whose `signatureValue` carries an
     `MTCProof` (inclusion proof + cosignatures) and whose `signatureAlgorithm`
     is `id-alg-mtcProof`;
   - there are two profiles: the *standalone* one (proof + cosignatures,
     immediate issuance) and the *landmark-relative* one (only the proof, with
     no signature at all, for clients that already have the subtree hash
     predistributed).

   The premises of the hypothesis that **do** hold: no ZK, no sums, validity
   and extensions per certificate, inclusion proof under 1 KB.

3. **What is reusable from Arqueo is not the sparse tree, it is what surrounds
   it.** The MTC tree is a dense, grow-only RFC 9162 tree; the fixed-depth
   `SparseTree` of `zk-ssl` does not fit (section 2.1). What does fit, almost
   line by line, is `zk-ssl-verify::mmr` (the `MTH`/`PATH`/`SUBPROOF` algorithms
   of RFC 6962), the inclusion receipt that binds "leaf → root → signed head",
   the head signer that reserves the index before signing and verifies its own
   output, and the discipline that **the issuer and the verifier compile the
   same definition of every format**.

---

## 1. What problem MTC solves, in four lines

With ML-DSA-44, an X.509 chain with two Certificate Transparency SCTs adds
about 7.3 KB of signatures to the *handshake* (the draft's own figure). MTC
inverts the order: the CA **certifies by recording in its log** and signs **one
checkpoint and two subtrees per cycle**, not one certificate per request. A
certificate is then an inclusion proof of `ceil(log2(n))` 32-byte hashes, plus
the cosignatures —or **none**, if the client already has the subtree as a
predistributed *landmark*—. Measured with this directory's example (section
4.4): 5,098 bytes for the *standalone* certificate with two ML-DSA-44
cosignatures, **274 bytes** for the *landmark*-relative one of the same entry.

### 1.1 Verified chronology: where the urgency comes from

The starting note dated the problem with three milestones (NIST, Chrome, the
Spanish press). They were checked against primary sources and corrected where
needed. Method: the NIST, Google, Cloudflare and IETF servers are not reachable
from the working environment, so the dates rest on (a) the git tags of the
draft's repository, read directly, and (b) search snippets of the primary
pages, cross-checked by a second independent reviewer. The "status" column says
so row by row.

| date | milestone | primary source | status |
|---|---|---|---|
| 2023-03-10 | First individual draft `draft-davidben-tls-merkle-tree-certs-00` (Google and Cloudflare): the batch design | git tag `-00` of the draft's repository | confirmed |
| 2023-08-10 | Chromium Blog, "Protecting Chrome Traffic with Hybrid Kyber KEM": X25519Kyber768 in Chrome 116 as an experiment, not a rollout | blog.chromium.org/2023/08 | confirmed (day from snippets) |
| 2024-04-16 | Chrome 124 stable: X25519Kyber768Draft00 (code point 0x6399) by default **on desktop only** | chromereleases.googleblog.com, `net/base/features.cc` at tag 124.0.6367.60 | confirmed |
| 2024-05-23 | Chromium Blog, "Advancing Our Amazing Bet on Asymmetric Cryptography" | blog.chromium.org/2024/05 | day unverified |
| 2024-08-13 | NIST publishes FIPS 203 (ML-KEM), FIPS 204 (ML-DSA) and FIPS 205 (SLH-DSA); effective on the 14th | nist.gov, Federal Register 2024-17956 | confirmed |
| 2024-09-13 | Google Security Blog, "A new path for Kyber on the web": Chrome 131 will move to X25519MLKEM768 (0x11EC) | security.googleblog.com | confirmed |
| 2024-11-12 | Chrome 131 stable: hybrid ML-KEM by default on desktop; on mobile from the 2024-12-04 commit | chromereleases.googleblog.com, `kUseMLKEM` at the 131.x tags | confirmed |
| 2025-03-03 | `draft-davidben-…-04`, the last of the batch design | git tag `-04` | confirmed |
| 2025-06-20 | `draft-davidben-…-05`: the redesign (issuance logs, subtrees, landmarks); Cloudflare and Geomys join as authors | git tag `-05` | confirmed |
| 2025-10-28 | Cloudflare, "Keeping the Internet fast and secure: introducing Merkle Tree Certificates": intent to experiment with Chrome | blog.cloudflare.com | confirmed (day from snippets) |
| 2025-11 | PLANTS BoF at IETF 124 (Montreal) | datatracker, `bofreq-westerbaan-…-plants` | day unverified |
| 2026-01 | The IESG charters the PLANTS working group (PKI, Logs, And Tree Signatures) | ietf-announce | day unverified |
| 2026-02-18 | Adoption: `draft-ietf-plants-merkle-tree-certs-00` | git tag | confirmed |
| 2026-02-27 | Google Security Blog, "Cultivating a robust and efficient quantum-safe HTTPS": MTC *bootstrapping* in the first quarter of 2027 and the *Chrome Quantum-resistant Root Store* in the third; no post-quantum X.509 in Chrome's root store | security.googleblog.com | confirmed |
| 2026-06-03 | Let's Encrypt, "A Post-Quantum Future for Let's Encrypt": MTC in *staging* at the end of 2026, production in 2027 | letsencrypt.org | confirmed |
| 2026-09-21 | `draft-ietf-plants-merkle-tree-certs-06`; this crate is written against the working repository as of 2026-09-29; first with its interim experimental OIDs (`…47.5` for `id-alg-mtcProof`), and since AUDIT.md §18 with the IANA-assigned ones the working copy adopted that day (`1.3.6.1.5.5.7.6.67`, `.25.3`, `.1.38`), which are what the reference tool's `-version plants-07` writes now | git tag | confirmed |
| 2026-09-29 | Cloudflare announces its public CA and "Building a post-quantum certificate authority with Merkle Tree Certificates": experiment with 50 % of Chrome Beta 146, first MTCs in the first quarter of 2027 | blog.cloudflare.com | confirmed (day from snippets) |
| 2026-09-29 | Spanish press coverage of the Cloudflare announcement; the 20minutos headline matches that hook | infobae.com (same day) | unverified |
| 2026-10-07 | `draft-ietf-plants-merkle-tree-certs-07`, with the IANA-assigned OIDs; its `demo/` is the one measured in AUDIT.md §18, and this crate measures against it and stops reading the interim set (§26) | git tag `-07` (`6c5896d`) | confirmed |

**Corrections to the starting note:**

- The 2023 Chromium post is titled "Protecting Chrome Traffic with Hybrid
  Kyber KEM", and Chrome 116 shipped it as an experiment to 1 % of Stable, not
  as a rollout.
- Chrome 124 came out on April 16, 2024, not the 17th, and enabled
  X25519Kyber768Draft00, a pre-standard draft: ML-KEM did not exist as a FIPS
  until August. The move to ML-KEM (X25519MLKEM768) was Chrome 131, in
  November. And on desktop only until December 2024.
- The NIST press release does not name RSA or ECC: it "urges starting the
  transition as soon as possible". The explicit deprecation of RSA/ECDSA/ECDH
  (2030 and 2035) is in the draft NIST IR 8547, of November 2024.
- The Chrome + Cloudflare experiment was announced by Cloudflare (October 2025)
  and ran in 2026 with Chrome Beta 146; there is no Chromium Blog post about
  MTC. The PLANTS group is from 2026, not 2025.
- The 20minutos piece does not appear to adapt NIST or Chrome press releases:
  the hook that matches its headline and its date is the Cloudflare
  announcement of September 29, 2026.

**Unverified:** the headline, the date and the byline (Portaltic/Europa Press,
EFE or in-house staff) of the 20minutos article; no search returned its
identifier and the domain is unreachable from here. The attribution to a news
agency is plausible and not evidenced.

---

## 2. Refactoring analysis

### 2.1 Arqueo: what is removed, what is kept, what is adapted

| Arqueo crate / module | destination | why |
|---|---|---|
| `stark-experiment`, `zk-ssl-air`, `winter-air` / `winter-prover` / `winter-verifier` (the fork), `zk-core`, `halo2-experiment`, `plonk-experiment`, `nova-experiment`, `ceremony`, `settlement-prover`, `settlement-layer`, `iso-bridge` | **remove** | The whole zero-knowledge proof layer and the five-backend comparison. MTC proves nothing in-circuit: privacy against the operator is not a goal (the log is public on purpose). |
| `zk-ssl` (the layer: `accounts`, `mint`, `burn`, `pending`, `freeze`, `governance`, `recovery`, `two_phase`, `instrumento_*`, `prueba_*`, `consumo`, `iso`) | **remove** | It is the accounting state machine. There are no balances, no two-phase payments, no conservation to prove. |
| `zk-ssl::sparse_tree::SparseTree` | **adapt → `log`** | The idea (internal nodes cached, O(log n) per write, level-by-level rebuild on startup) is kept; the structure is not: MTC needs a dense, *append-only* RFC 9162 tree, where the cache is "one vector per level holding the complete nodes". |
| `zk-ssl-hash` (`native_merge`, `path_root`, `mmr_hoja`/`mmr_nodo`, `epoch_digest_*`) | **replace → `hash` + `cosign`** | Rescue Prime over Goldilocks only made sense inside a STARK. The hash becomes SHA-256 with the `0x00`/`0x01` prefixes of RFC 6962. **The rule is kept whole**: one format decision, one single definition, shared by issuer and verifier. |
| `zk-ssl-verify::mmr` (`cima`, `prueba_de_inclusion`, `prueba_de_consistencia` and their verifications) | **translate → `subtree`** | They are `MTH`, `PATH` and `SUBPROOF` of RFC 6962. They are translated to SHA-256 and **extended to subtrees `[start, end)`**, which is what the draft adds. The property that verification is the mirror recursion of generation is kept. |
| `zk-ssl-verify::inclusion::ReciboInclusion` | **translate → `proof` + `verify`** | The receipt "leaf → path → root → signed head" is exactly `MTCProof`: a bare root proves nothing; what proves is the cosignature over the subtree (or the predistributed subtree). |
| `zk-ssl-node::firma_cabeza::FirmanteCabeza` | **translate → `cosign::Cosigner`** | Reserve the index, sign, verify one's own output with the same verifier a third party will use. With ML-DSA there is no index; with XMSS there is, and the interface (`&mut self`) allows it. |
| `zk-ssl-guardian` | **already is `hbs-state`** | `hbs-state` is used whole as a dependency, not reimplemented (section 2.3). |
| `zk-ssl-node::latido` (the epoch close) | **adapt → `ca::run_checkpoint_job`** | The `latido` (heartbeat) composes the head and signs it; the checkpoint job signs the checkpoint, covers what is new with two subtrees, collects cosignatures and issues. |
| `zk-ssl::persistence` / `snapshot` (`sled`, encryption at rest) | **later** | A CA's log lives on disk; the form (sled, *append-only* file, tlog-tiles) is decided in phase 1. Here `IssuanceLog::from_entries` leaves the hook. |
| `zk-ssl-wire` (JSON-RPC DTOs, OpenRPC generated from the code) | **redo** | MTC's wire is HTTP: ACME towards the requester, tlog-tiles towards monitors and mirrors. The discipline "the wire is generated from the code and frozen in vectors" is kept. |
| `zk-ssl-cli`, `zk-ssl-sdk` | **redo** | A CA operator's CLI looks nothing like a ledger's. |
| `tools/canon.sh`, `tools/conformidad.sh`, the practice of vectors per version | **keep the methodology** | The four accumulated vectors of the draft play here the role of `spec/vectors/`. |

Dependencies that leave: `winterfell` and its subcrates, `sled`,
`chacha20poly1305`, `xmss` (until phase 4). Dependencies that enter: `sha2`,
`ml-dsa` (optional, enabled by default) and `hbs-state`.

### 2.2 What is lost on purpose, and is worth stating

- **Privacy against the operator.** Arqueo hid the proof's witness; in MTC the
  log is public by design (transparency). There is nothing to hide and that is
  why there is no STARK.
- **Conservation.** Arqueo's invariant was "supply = balances + in flight". A
  CA's is "everything I issued is in my log and everything in my log I
  certified", and it is enforced by the cosigners and the monitors, not by a
  circuit.
- **The epoch head as the unit of trust.** In Arqueo every head travels signed.
  In MTC the *landmark*-relative certificate carries no signature at all: the
  trust is predistributed by the client's update channel.

### 2.3 `hbs-state`: what is kept and what for

It is kept **whole and as a dependency**, not as a copy. Its invariant is:

> no signature may exist with an index greater than the persisted counter.

Applied to an MTC CA in two places:

| where | what it keeps | why it is the same invariant |
|---|---|---|
| `ca::run_checkpoint_job`, step 0 | **the checkpoint number**, reserved with `IndexGuard::reserve` (persisted with `fsync`) **before** signing | What it gives, stated precisely: a counter that survives a crash and a diagnosis at startup. If the process dies between reserving and signing, the number is orphaned (`CounterAhead`, the normal case); if at startup the log's journal is ahead of the counter (`KeyAhead`), someone signed without going through the guardian and the CA does not start. **What it does not give:** the number does not enter the `CosignedMessage` (the draft has no place for it), so the guardian by itself does not prevent a CA from publishing two views of the log; that is detected by witnesses with consistency proofs. Avoiding a split view by accident requires the full order of phase 1: persist the entries with `fsync`, reserve, sign. |
| the CA's cosigner, if it is XMSS/LMS | **the signature index**, as in `FirmanteCabeza` | The CA signs one checkpoint and two subtrees per cycle, not one certificate per request: that is the rate at which a stateful signature is viable. |

`IndexGuard::open` measures its own `fsync` and refuses on `tmpfs`; the
end-to-end test opens it in `CARGO_TARGET_TMPDIR` and, if the guardian refuses,
says so and does not measure, instead of pretending it measured.

---

## 3. Design of leaves and proofs (the `struct`s)

The names follow the draft, not the hypothesis: where the latter said
`MTCLeaf`, here there is a working structure `MtcLeaf` **and** the entry that
is actually hashed, `MtcLogEntry`, because they are two different things that
have to agree.

### 3.1 The leaf: `MtcLeaf` and `MtcLogEntry` (`src/entry.rs`)

```rust
/// What the CA certifies about a requester (working structure).
pub struct MtcLeaf {
    pub version: u8,                        // 2 = v3
    pub issuer: Vec<u8>,                    // Name DER: ALWAYS the CA ID
    pub validity: Validity,                 // { not_before, not_after } POSIX
    pub subject: Vec<u8>,                   // subject Name DER
    pub spki: Vec<u8>,                      // SubjectPublicKeyInfo DER, whole
    pub issuer_unique_id: Option<Vec<u8>>,
    pub subject_unique_id: Option<Vec<u8>>,
    pub extensions: Option<Vec<u8>>,        // Extensions DER (SAN, key usage…)
}

/// What is recorded in the log (the draft's TLS serialization).
pub enum MtcLogEntry {
    Null    { extensions: Vec<LogEntryExtension> },
    TbsCert { extensions: Vec<LogEntryExtension>, tbs_cert_entry_data: Vec<u8> },
}
```

Compared with the sketch `(public_key, subject, validity, extensions)`:

- `public_key` **does not go in the leaf**: what goes is
  `subjectPublicKeyAlgorithm` plus the **hash** of the SPKI
  (`subjectPublicKeyInfoHash`, with the log's hash). It is the reason the log
  does not grow with ML-DSA. The whole key goes in the certificate.
- `validity` and `extensions` are ordinary X.509 fields, per certificate.
- There are **two** sets of extensions: the X.509 ones (inside the TBS) and the
  log entry's (`LogEntryExtension`, TLV, normally empty), which also travel in
  the `MTCProof`.

From an `MtcLeaf` come two encodings that a test cross-checks byte by byte:
`tbs_cert_entry_data()` (the fields of the `TBSCertificateLogEntry`
concatenated, without header, so that the verifier hashes in a single step) and
`tbs_certificate(serial)` (the `TBSCertificate` with `serialNumber = (log << 48)
| index` and `signature = id-alg-mtcProof`).

### 3.2 The subtree and the inclusion proof (`src/subtree.rs`, `src/proof.rs`)

```rust
/// A subtree [start, end): start is a multiple of BIT_CEIL(end - start).
pub struct Subtree { pub start: u64, pub end: u64 }

/// MTCProof: what goes in the certificate's signatureValue.
pub struct MtcProof {
    pub extensions: Vec<LogEntryExtension>,   // the entry's, copied
    pub subtree: Subtree,                     // uint48 start, uint48 end
    pub inclusion_proof: Vec<HashValue>,      // at most ceil(log2(size)) hashes
    pub signatures: Vec<SubtreeSignature>,    // empty in a landmark-relative cert.
}

pub struct SubtreeSignature { pub cosigner_id: TrustAnchorId, pub signature: Vec<u8> }

/// The certificate: a DER-encoded X.509 TBSCertificate and its proof.
pub struct MtcCertificate { pub tbs_certificate: Vec<u8>, pub proof: MtcProof }
```

Cosignatures go in canonical order by `cosigner_id` (shortest first, then
lexicographic) and the decoder rejects duplicates and misordering, as the draft
requires.

### 3.3 What is signed (`src/cosign.rs`)

```rust
pub struct CosignedMessage {
    pub cosigner_id: TrustAnchorId,   // "oid/1.3.6.1.4.1.32473.1"
    pub timestamp: u64,               // 0 inside a certificate
    pub log_id: TrustAnchorId,        // caID.0.N
    pub subtree: Subtree,
    pub subtree_hash: HashValue,
}
// fixed label "subtree/v1\n\0" in front: compatible with tlog-witness
```

### 3.4 What the relying party needs (`src/verify.rs`)

```rust
pub struct RelyingPartyConfig {
    pub ca_id: TrustAnchorId,
    pub ca_oids: OidSet,                          // the CA certificate's; its name attribute is compared
    pub cosigners: Vec<(TrustAnchorId, Box<dyn CosignatureVerifier>)>,
    pub required_cosigners: Vec<TrustAnchorId>,   // witnesses/mirrors; the CA is always required
    pub trusted_subtrees: Vec<TrustedSubtree>,    // predistributed landmarks
    pub revoked_ranges: Vec<(u64, u64)>,          // [min, max] inclusive, like minSerial/maxSerial
}
```

The CA's cosignature is always required (it is the certificate's signature);
those from cosigners the configuration does not recognize —GREASE included— are
ignored, as the draft mandates, and an ID of any shape is decoded without
interpreting it.

---

## 4. Workflow, step by step

### 4.1 From the request to the certificate (the CA)

```text
 CSR (PKCS#10)            ┐
 ACME challenge / validation ├─ upper layer: x509-cert + ACME (phase 2)
 proof of possession      ┘
        │
        ▼  CertificateRequest { subject, spki, validity, extensions }   already validated
 ┌──────────────────────────────────────────────────────────────────────┐
 │ CertificationAuthority::submit                                       │
 │   MtcLeaf { issuer = Name(caID), … }                                 │
 │   → MtcLogEntry::TbsCert { tbs_cert_entry_data }                     │
 │   → IssuanceLog::append   (leaf = SHA256(0x00 || entry))             │
 │   → index i                                                          │
 └──────────────────────────────────────────────────────────────────────┘
        │  … every few seconds, the checkpoint job …
        ▼
 ┌──────────────────────────────────────────────────────────────────────┐
 │ CertificationAuthority::run_checkpoint_job(now)                      │
 │  0. guard.reserve()               ← fsync BEFORE signing (hbs-state) │
 │  1. CA signs [0, tree_size) with timestamp = now   (checkpoint)      │
 │  2. (left, right) = covering_subtrees(last_checkpoint, tree_size)    │
 │  3. CA signs each subtree with timestamp = 0                         │
 │  4. each external cosigner signs each subtree                        │
 │  5. → SignedSubtree { subtree, hash, ordered signatures }            │
 └──────────────────────────────────────────────────────────────────────┘
        │
        ├─▶ standalone_certificate(i): TBSCertificate(serial) +
        │     MTCProof { subtree containing i, PATH(i), cosignatures }
        │
        └─▶ (hourly) allocate_landmark(now) → landmark L = current tree_size
            landmark_relative_certificate(i): same TBS +
              MTCProof { landmark's subtree containing i, PATH(i), ∅ }
```

In code, the full cycle fits on one screen (`examples/demo_ca.rs`):

```rust
let mut ca = CertificationAuthority::new(cfg, Box::new(ca_signer), IndexGuard::open(path)?)?;
ca.add_cosigner(Box::new(witness))?;

let i = ca.submit(request)?;                      // 3a · check and record in the log
let cp = ca.run_checkpoint_job(now)?;             // 0-4 · reserve, sign, cover, cosign
let standalone = ca.standalone_certificate(i)?;   // 5  · proof + cosignatures
let der = standalone.to_der()?;                   // X.509 with id-alg-mtcProof

ca.allocate_landmark(now)?;                       // hourly
let relative = ca.landmark_relative_certificate(i)?;   // proof alone, no signatures
```

### 4.2 The "Top Hash" and why it need not be recomputed

The checkpoint hash is `MTH(D[0:tree_size])`. `IssuanceLog` keeps one vector
per level with the **complete nodes**, so `append` closes the pairs that become
complete (amortized O(log n)) and `root()` or `subtree_hash([start, end))` walk
down the right edge in O(log n) lookups. Memory is `2n` hashes. A test walks
every subtree of every tree up to 130 leaves and demands the same hash and the
same proofs as the literal RFC 9162 recursion.

### 4.3 The way back: the relying party (`verify::verify_certificate`)

1. `signatureAlgorithm` is `id-alg-mtcProof`; decode the `MTCProof` with no
   trailing bytes.
2. Non-negative 64-bit `serial`; reject if it falls in a revoked range.
3. `index = serial & (2^48-1)`, `log_number = serial >> 48` (zero: reject).
4. `issuer` must be the `Name` of the configured CA: its CA ID (`ca_id`)
   under the trust anchor ID attribute of the set `signatureAlgorithm` names
   (one set per certificate), and that attribute must be the CA's
   (`ca_oids`, from its CA certificate); otherwise `UnknownIssuer`.
   `log_id = caID.0.N`.
5. Rebuild the entry **from the `TBSCertificate`** (version, issuer, validity,
   subject, key algorithm, `OCTET STRING(SHA256(SPKI))`, the rest) and hash it
   with `0x00` in front.
6. Evaluate the inclusion proof → *expected* subtree hash.
7. If `(log_number, start, end)` is a trusted subtree, compare hashes and
   finish. Otherwise, require a valid cosignature from **each** required
   cosigner over `CosignedMessage { …, subtree_hash = expected }`.
8. Continue with the rest of X.509 validation (here, expiry).

### 4.4 Figures from the example (`cargo run --release --example demo_ca`)

| | subtree | hashes | cosignatures | DER bytes |
|---|---|---|---|---|
| *standalone* for entry 6 | `[6, 8)` | 1 | 2 (CA + witness, ML-DSA-44) | 5,098 |
| relative to *landmark* 1 for the same entry | `[4, 8)` | 2 | 0 | **274** |

An ML-DSA-44 public key is 1,312 bytes and a signature 2,420: the *standalone*
is almost all signatures, and that is why the draft insists that relying
parties negotiate cosigners instead of requiring them all. The signatures are
salted (the *hedged* variant FIPS 204 recommends), so two runs of the example
give different bytes that verify the same.

---

## 5. Code skeleton: module map

| module | contents | comes from |
|---|---|---|
| `hash` | RFC 9162 `MTH` over SHA-256: `hash_empty`, `hash_leaf`, `hash_node` | replaces `zk-ssl-hash` |
| `subtree` | `Subtree`, `is_valid_subtree`, `covering_subtrees`, `inclusion_proof` / `evaluate_inclusion_proof` / `verify_inclusion_proof`, `consistency_proof` / `verify_consistency_proof`, the `TreeHashes` trait and the `LeafHashes` reference | `zk-ssl-verify::mmr` |
| `log` | `IssuanceLog`: *append-only*, complete nodes cached, `from_entries` for startup | the idea of `zk-ssl::sparse_tree` |
| `entry` | `MtcLeaf`, `MtcLogEntry`, `LogEntryExtension`, `Validity`, `entry_bytes_from_tbs` | new |
| `der` | the bare minimum of DER/X.509: TLV, INTEGER, OID, times, the CA ID's `Name`, `parse_tbs`, `parse_certificate` | new |
| `cacert` | `CaCertificate`: the CA's own certificate (subject = CA ID, the cosigner's key, the critical `MTCCertificationAuthority` extension, key usage and basic constraints), written unsigned (RFC 9925) and read from any implementation | new |
| `spki` | `SubjectPublicKeyInfo` of cosigner keys: parse, compose, the ML-DSA OIDs of RFC 9881 | new |
| `pem` | PEM (RFC 7468) and strict base64, without dependencies | new |
| `tai` | `TrustAnchorId`: stores the binary form, tolerates any well-formed ID on the wire (GREASE, up to the 255 bytes `MTCProof` allows), strict with what an operator types; arbitrary-precision ASCII, `oid/…`, log/landmark/group IDs, canonical order. A CA, log, landmark, group or cosigner ID is a trust anchor ID, at most 32 bytes (draft-ietf-tls-trust-anchor-ids-06): held to it where a CA or a relying party is configured, where a CA certificate is written or read, and where an ID is derived, not where one is parsed (AUDIT.md §27) | new |
| `cosign` | `CosignedMessage` (with its rules: timestamp only on checkpoints), `Cosigner`, `CosignatureVerifier`, `SignedSubtree`; `mldsa::{MlDsaCosigner, MlDsaVerifier}` with salted signing by default, seed zeroization and the `tlog-cosignature` *key ID* | `firma_cabeza` |
| `guard` | `SequenceGuard` over `hbs_state::IndexGuard`; `MemoryGuard` for tests only | `hbs-state` |
| `landmark` | `LandmarkSequence`: allocate, each landmark's subtrees, active ones, publish | new |
| `proof` | `MtcProof` (TLS encoding) and `MtcCertificate` (DER) | `zk-ssl-verify::inclusion` |
| `ca` | `CertificationAuthority`: `submit`, `run_checkpoint_job`, `standalone_certificate`, `allocate_landmark`, `landmark_relative_certificate`, `active_landmark_subtrees` | `zk-ssl-node` |
| `verify` | `verify_certificate` for the relying party, without compiling the CA | `zk-ssl-verify` |

How it is tested, in three layers:

- **Against the draft**: `tests/vectors.rs` reproduces the four accumulated
  vectors of the test appendix (712 subtree hashes, 12,807 inclusion paths,
  42,893 consistency paths and 8,646 coverings: every subtree of every tree up
  to 130 leaves), plus the validity and covering cases up to `2^64-1`; and
  `tests/large_vectors.rs` evaluates the 24 inclusion and 21 consistency
  vectors the draft's repository publishes for trees of `2^48-1`, `2^63-1` and
  `2^64-1` leaves, with a hand-written JSON and base64 reader. It includes the
  exercise the draft asks of the verifier: every proof evaluated, and rejected
  when shortened or lengthened by one hash (and by one byte, at the `MTCProof`
  level), and with one bit flipped in the path or in the subtree and tree
  hashes.
- **Against itself**: the `IssuanceLog` cache against the reference recursion;
  the entry the CA records against the one the verifier rebuilds; the encoded
  `MTCProof` against the decoded one, with canonical order also enforced on
  decoding; malformed DER (overflowing, indefinite, non-minimal lengths,
  impossible dates) rejected without panicking.
- **End to end**: `tests/end_to_end.rs` issues with ML-DSA-44 at the CA and at
  a witness, verifies *standalone* and *landmark*-relative, and checks that the
  following fail: SAN tampering, a missing cosignature (from the CA or the
  witness), the proof of another index, revocation by range, expiry and an
  unknown issuer; that a GREASE cosignature is ignored; that the CA rejects
  out-of-bounds validity, malformed DER, unknown entry extensions and
  duplicate cosigners; and that a landmark does not expire before its entries;
  and it opens a real `IndexGuard` on disk to check that the checkpoint number
  survives the process and reconciles (if the file system does not persist,
  the test says so and skips; any other error makes it fail).
- **Against the reference implementation**: `tests/interop_corpus.rs` hands
  this crate's verifier the corpus that `demo/` in the draft's repository
  (Go) generated, 26 certificates with five deliberate negatives, and requires
  the 26 verdicts the Go verifier gave; it also rebuilds the Go tool's log of
  2122 entries from its tiles and reproduces its checkpoint. The other
  direction (certificates from here through the Go verifier) needs Go and runs
  from `interop/run.sh` (section 7 says what was measured and where).

---

## 6. Implementation plan by phases

**Phase 0 — this directory.** The verifiable core: tree, subtrees, proofs,
entries, cosignatures, landmarks, in-memory CA and verifier. Done.

**Phase 1 — persistence and startup.** An *append-only* store of entries (a
file with `fsync` per checkpoint, or `sled` as in `zk-ssl::persistence`), with
the order that avoids a split view: **entries persisted with `fsync`, number
reserved, signature**. `IssuanceLog::from_entries` at startup, a CA constructor
from the store (leaves, size of the last checkpoint, landmarks) and the
reconciliation `guard.reconcile(last_checkpoint_in_journal)` with Arqueo's
policy: only `KeyAhead` prevents startup. Pruning of `signed_subtrees` with
`prune_signed_subtrees_below` when a landmark covers what was signed. Measure
startup with a million entries, as Arqueo's benchmark B.4 did.

**Phase 2 — the real input.** PKCS#10 CSR parsing and construction of
`Name`/`Extensions` with `x509-cert`; domain validation and proof of possession
via ACME (RFC 8555) with the draft's extension (the `mtc-landmark-relative`
link to later collect the relative certificate). This crate does not change: it
receives `CertificateRequest`.

**Phase 3 — the log outward.** Serve the log with tlog-tiles according to
C2SP's `mtc-tlog` profile (checkpoint signed by the CA as a note, `landmarks`
in text, URL prefix per log), and request cosignatures from real witnesses with
the tlog-witness protocol. The `CosignedMessage` here is byte for byte the
`cosigned_message` of `tlog-cosignature` for ML-DSA-44, and `MlDsaCosigner`
already computes the *key ID* and the `timestamped_signature` of the note line
(`examples/interop.rs checkpoint` reads the reference tool's note and tiles,
and finds that today the tool signs its checkpoint with timestamp zero and no
timestamp bytes on the line, which is not the `tlog-cosignature` line format;
a question for the working group, recorded in AUDIT.md §14); what remains is
the full note format (`signed-note`), the witness's HTTP client
(`add-checkpoint`, `sign-subtree`) and the check of the consistency proofs the
witness requires, which `subtree` already knows how to generate and verify.

**Phase 4 — the CA as trust anchor.** The CA's certificate with the
`MTCCertificationAuthority { sigAlg, minSerial, maxSerial }` extension is
`cacert::CaCertificate` (written unsigned, read from the reference tool and
by it); what remains is an XMSS/LMS cosigner with `hbs-state` in front (the
same `Cosigner`, `&mut self` already allows it) and the TLS side: `trust_anchors` with the landmark groups
(`caID.2.N.L`) in `rustls`, so that the server chooses between the *standalone*
and the relative one.

**Phase 5 — the fork.** New repository with this directory as root; from
Arqueo the methodology is carried over (test canon per crate, vectors frozen
per version, one ledger entry per change) and none of the STARK code.

---

## 7. What this skeleton does not claim

- **It is not audited.** Neither this code, nor `ml-dsa` (its own crate says
  so), nor `hbs-state`. The OIDs are the IANA-assigned ones by default
  (`CaConfig::oids`), and a relying party here also accepts the
  experimental set of `plants-06` (`1.3.6.1.4.1.44363.47` arc, AUDIT.md §18;
  the interim `.47.5` set was retired at `draft-07`, §26), one set per
  certificate and each under a CA whose name uses the same attribute (§22,
  §25). The version read is `draft-07` (2026-10-07), and the draft may still
  change before it is an RFC. It did pass an internal adversarial review (six
  reviewers per dimension, one skeptic per finding) against the draft, the
  reference implementation and the C2SP specifications; what was confirmed is
  corrected and covered by tests, and that is no substitute for an audit.
- **Interoperability is measured against three implementations.** The
  `demo/` directory of the draft's repository (a generator and a verifier in
  Go, commit `99097c9e`,
  `-version plants-07`) was the first measured. Since 2026-09-29 there are two
  more, announced on the working group's list with an end-to-end
  demonstration (AUDIT.md §17): OpenSSL's (pull request
  `openssl/openssl#33014`, the TLS client and server side in C) and Bob Beck's
  rewrite of Cloudflare's Go CA and mirror for `-06`
  (`github.com/bob-beck/cloudflare-mtc`). Against those two, at `ecf0476` and
  `c6cdfe2` (§19) and again at `7bd37b7` and `0fe8a6e` (§28), with
  `interop/run-openssl.sh`: his verifier gives every
  certificate from here, with either OID set, the verdict expected of it; his
  CA's 20 certificates, issued through his mirror with either OID set (the
  IANA one since his `31f118e`, §28), and four negatives cut from
  them byte by byte get the same verdict here as from his verifier, in four
  configurations; OpenSSL's `s_client` accepts this crate's standalone and
  landmark-relative certificates in a TLS 1.3 handshake with its `s_server`,
  which picks between them by trust anchor ID, and refuses the five negatives;
  and OpenSSL's own test corpus gets the same verdicts here as from his
  verifier, except one certificate that mixes the IANA signature algorithm
  with the experimental issuer, which both accept and this crate refuses (a
  policy difference, recorded in §19; the stricter reading is kept, and a test
  holds it, §22; the draft's principal author answered on the list that a CA
  is one draft and a draft one set of OIDs, §24). The run at `ecf0476` and
  `c6cdfe2` was made by the assistant in a container and repeated by the
  author on his machine, with the same result (§21); the one at `7bd37b7`
  and `0fe8a6e`, with his CA's IANA certificates, likewise (§28). The OIDs
  changed meanwhile: `demo/` writes
  the IANA-assigned ones
  since `ad4256b`, and the measurement was repeated against it at `38014f7`,
  with the same verdicts (§18; repeated by the author on his machine, §23).
  Cloudflare's own `bwesterb/mtc` still follows the earlier batch
  design. Against `demo/`, in both directions
  and with negatives, everything measured agrees: its 26 verdicts are
  reproduced here (`tests/interop_corpus.rs`, offline), its log of 2122
  entries is rebuilt from its tiles to the same root, and the Go verifier
  accepts the certificates from here, with this crate's CA certificate and
  with its own (the two CAs share a test key, so the ML-DSA-44 key derivation
  and signatures agree byte for byte). The run is recorded in AUDIT.md §14: it
  was made by the assistant in a container with Go 1.27.1 built from source,
  and repeated by the author on his machine with the same result (§15).
  Not measured: any other implementation, cosigners with ECDSA or Ed25519
  keys (their cosignatures are ignored here), the Go tool's cosigner groups
  (this crate's policy is "the CA and all of these"), the witness and mirror
  protocols (this crate has neither), and anything of TLS beyond the
  certificate: both ends of the handshake are OpenSSL's.
- **There is no request validation**: `CertificateRequest` arrives validated.
  Certifying what arrives is this crate's job; that it is true, the operator's.
- **The log is not persisted**, only the guardian's counter. And `MemoryGuard`
  exists to be able to measure without disk: a CA that starts with it reuses
  checkpoint numbers after every crash.
- **The cosigner policy is the minimal one** ("the CA and all of these").
  Quorums, cosigner negotiation in TLS and mirrors are left for phase 3.
- **It is not measured at scale.** The cache is O(log n) by construction, but
  the timings with millions of entries have not been measured, and in Arqueo
  that measurement changed the design twice.
