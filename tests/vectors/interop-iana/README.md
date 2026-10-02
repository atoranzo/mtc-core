# The reference implementation's corpus, with the IANA OIDs

The same configuration as `../interop-plants-07/`, generated again after the
reference tool switched `-version plants-07` to the IANA-assigned OIDs
(commit "We have PKIX OIDs!", `ad4256b`, 2026-09-29):

- Repository: <https://github.com/ietf-plants-wg/merkle-tree-certs>, directory
  `demo/`, commit `38014f7fb0086438a78a4b8353607fc4557eba70` (2026-10-01).
- Toolchain: Go 1.27.1, `golang.org/x/crypto` v0.54.0.
- Configuration: `mtc.json` is the demo's own `mtc.json` at that commit with
  `"Version": "plants-06"` → `"plants-07"`, the only change.
- Command: `./demo generate -config mtc.json -out .`
- OIDs: `id-alg-mtcProof` `1.3.6.1.5.5.7.6.67`, `id-rdna-trustAnchorID`
  `1.3.6.1.5.5.7.25.3`, `id-pe-mtcCertificationAuthority-SHA256`
  `1.3.6.1.5.5.7.1.38`.
- `policy.txt`: the `cosigner` lines of the demo's sample `policy.txt` plus the
  six `trusted-subtree` lines `generate` printed for this run.
- `expected.txt`: the verdict of `./demo verify -version plants-07 -ca-cert
  ca_cert.pem -policy policy.txt cert_*.pem`.

The landmark subtree hashes and the checkpoint root differ from the older
corpus: the issuer's attribute OID is part of every log entry, so every leaf
hash changed with it. The verdicts are the same, file by file.
