# The reference implementation's corpus (`plants-07` formats, interim OIDs)

⚠️ **Which `plants-07`.** This corpus is the reference tool's `-version
plants-07` at commit `99097c9e`, which wrote the interim experimental OID set:
`id-alg-mtcProof` `…44363.47.5` with `…47.3` and `…47.4`. The same day, commit
`ad4256b` ("We have PKIX OIDs!") switched `plants-07` to the IANA-assigned OIDs,
and no tool writes this set any more. It is kept because it is what AUDIT.md
§14 and §15 measured, and because a relying party here still accepts it
(`der::OIDS_EXPERIMENTAL_47_5`) under a CA certificate of the experimental
OIDs, such as this corpus's own; under the IANA corpus's, with the same CA ID
and key, it refuses every certificate (AUDIT.md §25). The IANA corpus is
`../interop-iana/`.

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
  crate encodes `…47.5`, so `plants-07` is the version it interoperates with.
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

`tests/interop_corpus.rs` requires this crate's verifier to give the same
26 verdicts, checks the negatives fail for the reason they were built for,
checks that each corpus is refused under the other's CA certificate,
rebuilds the log from the tiles and checks the checkpoint's root and the
CA's signature line.
