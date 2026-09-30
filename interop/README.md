# Interoperability with the draft's reference implementation

The natural interoperability target of this crate is `demo/` in the PLANTS
working group's repository, <https://github.com/ietf-plants-wg/merkle-tree-certs>:
a generator and a verifier in Go for the current design. This directory
holds the procedure; `AUDIT.md` holds the record of each run, and
`tests/vectors/interop-plants-07/` holds the Go tool's corpus with its
verdicts so that one direction runs offline in `cargo test`.

## What is measured

Three things, each with negatives:

1. **Go → Rust.** The Go tool generates a CA certificate, a log of 2122
   entries and 26 certificates (five of them deliberately broken). This
   crate's verifier, configured only from `ca_cert.pem` and the Go tool's own
   `policy.txt` vocabulary, must give the same 26 verdicts as `demo verify`.
2. **Rust → Go.** This crate's CA (`examples/interop.rs generate`) writes
   its CA certificate, nine certificates (four of them deliberately broken)
   and a `policy.txt`; `demo verify` must give the verdicts written in
   `EXPECTED.txt`. The Rust CA uses the same ML-DSA-44 test seed as the Go
   tool's CA `32473.1`, so `demo verify` is also run with the **Go** CA
   certificate against the **Rust** certificates: that passes only if FIPS
   204 key generation and the signatures agree byte for byte.
3. **The log itself.** The Go tool writes its log as tlog-tiles and a
   signed `checkpoint`. This crate rebuilds the tree from the entry tiles
   and must reproduce the checkpoint's root; then it checks the CA's
   signature line.

## Versions

The tool's `-version` flag takes names such as `plants-06` or `plants-07`.
This crate encodes `id-alg-mtcProof` as `1.3.6.1.4.1.44363.47.5`, which the
draft repository's `draft_oids.md` assigns "starting draft plants-07"
(`plants-06` used `…47.0`; in the demo that OID is the only difference
between the two). So every command below says `-version plants-07`, and the
generator's configuration says `"Version": "plants-07"`. With the default
`plants-06` the Go verifier rejects every certificate from here with
"signature algorithm was not an mtcProof", by design.

## Requirements

- Go 1.27 or later (the demo's `go.mod`; it uses the standard library's
  `crypto/mldsa`). Ubuntu's packaged Go is older: install from go.dev.
- A checkout of the draft repository with `demo` built:

  ```sh
  git clone https://github.com/ietf-plants-wg/merkle-tree-certs
  cd merkle-tree-certs/demo && go build -o demo .
  ```

- This crate built with the `ml-dsa` feature (the default).

## Procedure

`run.sh` does all of it and writes `results.txt`; `DEMO_DIR` is the
`demo/` directory above with the built binary in it:

```sh
DEMO_DIR=/path/to/merkle-tree-certs/demo interop/run.sh /tmp/mtc-interop
```

By hand, the same steps:

```sh
# 0. This crate's tool.
cargo build --release --example interop
INTEROP=target/release/examples/interop

# 1. Go → Rust.
$DEMO_DIR/demo generate -config tests/vectors/interop-plants-07/mtc.json -out go > go-generate.log
{ grep '^cosigner ' $DEMO_DIR/policy.txt
  grep 'Landmark subtree' go-generate.log |
    sed -E 's/.*\[([0-9]+), ([0-9]+)\) with hash (.*)/trusted-subtree 32473.1 1 \1 \2 \3/'; } > go/policy.txt
$DEMO_DIR/demo verify -version plants-07 -ca-cert go/ca_cert.pem -policy go/policy.txt go/cert_*.pem
$INTEROP verify -ca-cert go/ca_cert.pem -policy go/policy.txt go/cert_*.pem
# Same OK/FAIL per file. Rust reports the reason; `cert_10_1` fails at the
# DER (a declared unused bit), `cert_10_2` at the CA's cosignature,
# `cert_10_8` and `cert_10_10` for lack of the CA's cosignature,
# `cert_2035_2` at the trusted subtree's hash.

# 2. Rust → Go.
$INTEROP generate -out rust
$DEMO_DIR/demo verify -version plants-07 -ca-cert rust/ca_cert.pem -policy rust/policy.txt rust/cert_*.pem
$DEMO_DIR/demo verify -version plants-07 -ca-cert go/ca_cert.pem   -policy rust/policy.txt rust/cert_*.pem
# Compare with rust/EXPECTED.txt.

# 3. The log.
$INTEROP checkpoint -dir go -ca-cert go/ca_cert.pem
```

## What the tool cannot express

`demo verify` has cosigner **groups** (`group`, `require-cosigners`); this
crate's policy is "the CA and all of `-require`". The `verify` subcommand
says so for each such line instead of ignoring it silently. Cosigners with
ECDSA or Ed25519 keys are reported and their cosignatures ignored (the Go
corpus has one, `32473.2.1`); this build verifies ML-DSA-44, -65 and -87.
`verify` holds one CA per run, because `RelyingPartyConfig` does.

## Test keys

`examples/interop.rs` carries two ML-DSA-44 seeds copied from the demo's
`mtc.json` (the CA `32473.1`, seed `00 01 … 1f`, and the cosigner
`32473.3.1`). They are the draft repository's public test keys. They exist
so that the two CAs share a key; they must never sign anything real.
