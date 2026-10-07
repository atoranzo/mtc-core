# The reference implementation's corpus (`plants-07` formats, interim OIDs)

⚠️ **Which `plants-07`.** This corpus is the reference tool's `-version
plants-07` at commit `99097c9e`, which wrote the interim experimental OID set:
`id-alg-mtcProof` `…44363.47.5` with `…47.3` and `…47.4`. The same day, commit
`ad4256b` ("We have PKIX OIDs!") switched `plants-07` to the IANA-assigned OIDs,
and no tool writes this set any more; no published draft ever used it. It
is kept because it is what AUDIT.md §14 and §15 measured, and as a record.
Since `draft-07` this crate no longer reads its OIDs (AUDIT.md §26): its
`id-alg-mtcProof` names no known set, so every certificate here is refused
(`NotAnMtcCertificate`), and `tests/interop_corpus.rs` checks exactly that.
Its CA certificate (which reads as the `plants-06` set, the two sharing
their CA-level OIDs) and its log and checkpoint are still read and checked.
The IANA corpus is `../interop-iana/`.

Everything in this directory except this file and `expected.txt` is the
output of the draft's reference implementation, unchanged:

- Repository: <https://github.com/ietf-plants-wg/merkle-tree-certs>, directory
  `demo/`, commit `99097c9e0af9641a85311b68f7642978b882d385` (2026-09-29,
  "Merge pull request #335 from ietf-plants-wg/registries").
- Toolchain: Go 1.27.1 (the demo's `go.mod` requires 1.27; it uses the
  standard library's `crypto/mldsa`), `golang.org/x/crypto` v0.54.0.
- Configuration: `mtc.json` is the demo's own `mtc.json` with one change,
  `"Version": "plants-06"` → `"plants-07"`. In the demo, the only difference
  between the two is the `id-alg-mtcProof` OID (`…47.0` for plants-06,
  `…47.5` from plants-07; see `draft_oids.md` in that repository). This
  crate encoded `…47.5` then, so `plants-07` was the version it
  interoperated with (until §18; retired in §26).
- Command: `./demo generate -config mtc.json -out .`
- `ca_cert.pem`: the CA certificate (unsigned, RFC 9925), CA ID `32473.1`,
  ML-DSA-44.
- `cert_<entry>_<num>.pem`: the certificates the configuration asks for,
  each preceded by a `MTC CERTIFICATE PROPERTIES` block this crate skips.
  The configuration includes deliberate negatives: `cert_10_1` (`UnusedBit`),
  `cert_10_2` and `cert_2035_2` (`BitFlipProof`), `cert_10_8` (cosigned by
  everyone but the CA) and `cert_10_10` (no cosignatures, not a landmark).
- `checkpoint` and `tile/entries/…`: the issuance log in tlog-tiles form,
  2122 entries.
- `policy.txt`: the `cosigner` lines of the demo's sample `policy.txt` (its
  public keys) plus the six `trusted-subtree` lines printed by `generate`
  for the three landmarks. The demo's sample file also carries
  `trusted-subtree` lines, but their hashes belong to an older run and do
  not match this corpus (nor a `plants-06` one; see AUDIT.md §14).
- `expected.txt`: the verdict of `./demo verify -version plants-07 -ca-cert
  ca_cert.pem -policy policy.txt cert_*.pem`, one line per file, `OK` or
  `FAIL`.

`tests/interop_corpus.rs` required this crate's verifier to give the same
26 verdicts until §26; now it requires every certificate here to be refused,
the 21 the Go verifier accepted as `NotAnMtcCertificate`, under this
corpus's CA certificate and the IANA corpus's. It still reads the CA
certificate, rebuilds the log from the tiles and checks the checkpoint's
root and the CA's signature line.
