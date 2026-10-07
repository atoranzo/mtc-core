# Interoperability with the draft's reference implementation

The natural interoperability target of this crate is `demo/` in the PLANTS
working group's repository, <https://github.com/ietf-plants-wg/merkle-tree-certs>:
a generator and a verifier in Go for the current design. This directory
holds the procedure; `AUDIT.md` holds the record of each run, and
`tests/vectors/interop-iana/` holds the Go tool's corpus with its verdicts
so that one direction runs offline in `cargo test` (the corpus of the
interim OIDs of §14, `tests/vectors/interop-plants-07/`, is kept, and since
§26 it must be refused whole).

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
Since the draft repository's commit `ad4256b` ("We have PKIX OIDs!",
2026-09-29), `plants-07` writes and reads the IANA-assigned OIDs
(`id-alg-mtcProof` `1.3.6.1.5.5.7.6.67`, `id-rdna-trustAnchorID`
`1.3.6.1.5.5.7.25.3`, `id-pe-mtcCertificationAuthority-SHA256`
`1.3.6.1.5.5.7.1.38`), which is what this crate's CA writes by default. So
every command below says `-version plants-07`, the generator's configuration
says `"Version": "plants-07"`, and the demo has to be at `ad4256b` or later;
the tag `draft-ietf-plants-merkle-tree-certs-07` (`6c5896d`, 2026-10-07) is
such a commit. Before `ad4256b` the same version string meant the interim
experimental set (`…44363.47.5`, `.47.3`, `.47.4`), which this crate no
longer reads (AUDIT.md §26); a demo of that time can be measured only with
a commit of this crate from before §26. With `plants-06` the Go verifier
rejects every certificate from here by design: its OIDs are another set.

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
`demo/` directory above. The script builds the demo itself from that checkout,
into the output directory, so that the binary measured is the commit recorded
(one built earlier, from another commit, once was not: AUDIT.md §23); it needs
`go` on `PATH`:

```sh
DEMO_DIR=/path/to/merkle-tree-certs/demo interop/run.sh /tmp/mtc-interop
```

By hand, the same steps:

```sh
# 0. This crate's tool.
cargo build --release --example interop
INTEROP=target/release/examples/interop

# 1. Go → Rust.
$DEMO_DIR/demo generate -config tests/vectors/interop-iana/mtc.json -out go > go-generate.log
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

## Against OpenSSL and Bob Beck's Go stack

Two more implementations of the current design appeared on 2026-09-29 (AUDIT.md
§17): OpenSSL's pull request `openssl/openssl#33014` (the TLS client and server
in C) and Bob Beck's `mtc` command (`github.com/bob-beck/cloudflare-mtc`: a CA,
a mirror and a verifier in Go). `run-openssl.sh` measures this crate against
both, in four parts, each with negatives:

1. **This crate → `mtc verify`.** `interop generate` writes, besides its
   corpus, the same configuration in the files OpenSSL's options read and
   `mtc verify` reads too: `subtrees.txt` (`-mtc_subtrees`) and
   `cosigners.pem` (`-mtc_cosigners`, the witness as a cosigner certificate).
   `mtc verify` with a quorum of one must give every certificate its expected
   verdict, with the IANA OIDs and with the experimental `-06` set; this
   crate, given the same two files, must give the same.
2. **`mtc`'s CA → this crate.** A CA and a mirror are created, the CA issues
   three batches through the mirror (so its standalone certificates carry the
   mirror's cosignature) and allocates a landmark with each, and
   `export-openssl` writes its configuration. `flip.py` derives four negatives
   at the byte level, without any MTC code: a bit of the inclusion proof of a
   standalone and of a landmark-relative certificate, of the CA's cosignature,
   and of the mirror's. This crate and `mtc verify` must agree on every
   certificate in four configurations: subtrees and the mirror required; the
   mirror required; the CA alone; and a subtree file with one wrong hash.
3. **This crate → OpenSSL, over TLS 1.3.** With `-tls-key`, `interop
   generate` issues certificates for a key OpenSSL generated (ML-DSA-44, the
   DNS name `localhost`): standalone, landmark-relative under a third
   landmark, and three negatives. OpenSSL's own `generate_tai_chain` gives each
   its trust anchor ID and groups (section 8.2.1 of the draft, from
   `tls_chains.txt`); `s_server` holds them, and `s_client` must verify what it
   is served, or refuse it, with the certificate served checked as well:
   standalone; landmark-relative when the client has the landmarks; a quorum of
   one cosigner, met and not met; a flipped bit in each form; a wrong subtree
   hash; and another CA under the same ID.
4. **OpenSSL's corpus → this crate.** The certificates of `test/mtc` in the
   pull request (generated by the draft's tool at `plants-06`, and derived
   ones) must get the same verdict here as from `mtc verify`. One known
   difference is reported apart: `mtc-landmark-1-iana-alg.pem` mixes the IANA
   signature algorithm with the experimental issuer; OpenSSL and `mtc` accept
   it field by field, this crate refuses it (one OID set per certificate, §18;
   kept by the author's decision, §22, and in line with the answer on the
   list: one CA, one draft, one set of OIDs, §24).

It needs OpenSSL built from the pull request, its source tree (for
`test/mtc`), `mtc` built with Go 1.27 or later, and `python3`:

```sh
git clone https://github.com/openssl/openssl && cd openssl
git fetch origin pull/33014/head && git checkout FETCH_HEAD
./Configure --prefix=$HOME/openssl-mtc && make -j"$(nproc)" && make install_sw
cd .. && git clone https://github.com/bob-beck/cloudflare-mtc
(cd cloudflare-mtc && go build -o mtc ./cmd/mtc)

export LD_LIBRARY_PATH=$HOME/openssl-mtc/lib64:$HOME/openssl-mtc/lib
OPENSSL=$HOME/openssl-mtc/bin/openssl OPENSSL_SRC=$PWD/openssl \
MTC=$PWD/cloudflare-mtc/mtc MTC_SRC=$PWD/cloudflare-mtc \
  mtc-core/interop/run-openssl.sh /tmp/mtc-openssl
```

`results.txt` in the output directory has the record; `failures: 0` is the
pass. The commit recorded for `mtc` is the one Go wrote into the binary when it
was built; if it is not `MTC_SRC`'s, the script stops and asks for a rebuild. The mirror listens on a free local port while the CA issues, and is
stopped after.

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
