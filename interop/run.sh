#!/usr/bin/env bash
# The interoperability run against the draft's reference implementation.
# Usage: DEMO_DIR=/path/to/merkle-tree-certs/demo interop/run.sh OUTDIR
# Requires: the `demo` binary built in DEMO_DIR (Go 1.27+), cargo.
# Writes OUTDIR/results.txt and exits non-zero if any comparison differs.
set -euo pipefail

OUT="${1:?usage: DEMO_DIR=... interop/run.sh OUTDIR}"
DEMO_DIR="${DEMO_DIR:?set DEMO_DIR to the demo/ directory of the draft repository}"
DEMO="$DEMO_DIR/demo"
[ -x "$DEMO" ] || { echo "no demo binary at $DEMO (run: cd $DEMO_DIR && go build -o demo .)" >&2; exit 2; }
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VECTORS="$ROOT/tests/vectors/interop-plants-07"
mkdir -p "$OUT"
RESULTS="$OUT/results.txt"
: > "$RESULTS"
FAILURES=0

say() { echo "$*" | tee -a "$RESULTS"; }
verdict() { sed -E 's/^([^:]*): OK$/\1 OK/; t; s/^([^:]*): .*$/\1 FAIL/' | sed -E 's#^.*/##' | sort -V; }

say "# mtc-core interoperability run, $(date -u +%Y-%m-%dT%H:%M:%SZ)"
say "demo: $(git -C "$DEMO_DIR" rev-parse HEAD 2>/dev/null || echo unknown) ($(git -C "$DEMO_DIR" log -1 --format=%cd --date=short 2>/dev/null || echo unknown))"
say "go: $(cd "$DEMO_DIR" && go version)"
say "rust: $(rustc --version), $(cargo --version)"
say "mtc-core: $(git -C "$ROOT" rev-parse HEAD 2>/dev/null || echo unknown)"

(cd "$ROOT" && cargo build --release --example interop >/dev/null 2>&1)
INTEROP="$ROOT/target/release/examples/interop"

# ── 1. Go → Rust ──
say ""
say "## 1. Go -> Rust"
GO="$OUT/go"; rm -rf "$GO"; mkdir -p "$GO"
"$DEMO" generate -config "$VECTORS/mtc.json" -out "$GO" > "$OUT/go-generate.log"
{ grep '^cosigner ' "$DEMO_DIR/policy.txt"
  grep 'Landmark subtree' "$OUT/go-generate.log" |
    sed -E 's/.*\[([0-9]+), ([0-9]+)\) with hash (.*)/trusted-subtree 32473.1 1 \1 \2 \3/'; } > "$GO/policy.txt"
"$DEMO" verify -version plants-07 -ca-cert "$GO/ca_cert.pem" -policy "$GO/policy.txt" "$GO"/cert_*.pem 2>&1 | grep "^$GO" | verdict > "$OUT/go-verdicts.txt" || true
"$INTEROP" verify -ca-cert "$GO/ca_cert.pem" -policy "$GO/policy.txt" "$GO"/cert_*.pem 2> "$OUT/rust-verify.err" | grep "^$GO" | verdict > "$OUT/rust-verdicts.txt" || true
N=$(wc -l < "$OUT/go-verdicts.txt")
if diff -u "$OUT/go-verdicts.txt" "$OUT/rust-verdicts.txt" > "$OUT/go-to-rust.diff"; then
  say "same verdict for all $N certificates ($(grep -c ' OK$' "$OUT/go-verdicts.txt") OK, $(grep -c ' FAIL$' "$OUT/go-verdicts.txt") FAIL)"
else
  say "DIFFERENT verdicts, see go-to-rust.diff"; FAILURES=$((FAILURES+1))
fi
if diff -q "$OUT/go-verdicts.txt" "$VECTORS/expected.txt" >/dev/null; then
  say "the Go verdicts equal tests/vectors/interop-plants-07/expected.txt"
else
  say "note: the Go verdicts differ from the recorded expected.txt (a newer demo?)"
fi

# ── 2. Rust → Go ──
say ""
say "## 2. Rust -> Go"
RUST="$OUT/rust"; rm -rf "$RUST"
"$INTEROP" generate -out "$RUST" > "$OUT/rust-generate.log"
grep -v '^#' "$RUST/EXPECTED.txt" | awk '{print $1, $2}' | sort -V > "$OUT/rust-expected.txt"
for CA in "$RUST/ca_cert.pem" "$GO/ca_cert.pem"; do
  LABEL=$([ "$CA" = "$RUST/ca_cert.pem" ] && echo "with the Rust CA certificate" || echo "with the GO CA certificate (same key)")
  "$DEMO" verify -version plants-07 -ca-cert "$CA" -policy "$RUST/policy.txt" "$RUST"/cert_*.pem 2>&1 | grep "^$RUST" | verdict > "$OUT/go-on-rust.txt" || true
  if diff -u "$OUT/rust-expected.txt" "$OUT/go-on-rust.txt" > "$OUT/rust-to-go.diff"; then
    say "$LABEL: same verdict as EXPECTED.txt for all $(wc -l < "$OUT/rust-expected.txt") certificates"
  else
    say "$LABEL: DIFFERENT verdicts, see rust-to-go.diff"; FAILURES=$((FAILURES+1))
  fi
done
if diff -q <(grep '^cosigner 32473.3.1 ' "$DEMO_DIR/policy.txt") <(grep '^cosigner 32473.3.1 ' "$RUST/policy.txt") >/dev/null; then
  say "the witness's SPKI line is byte-identical to the demo's policy.txt (same seed, same key)"
else
  say "the witness's SPKI line DIFFERS from the demo's policy.txt"; FAILURES=$((FAILURES+1))
fi

# ── 3. The log ──
say ""
say "## 3. The Go tool's log and checkpoint, rebuilt here"
if "$INTEROP" checkpoint -dir "$GO" -ca-cert "$GO/ca_cert.pem" > "$OUT/checkpoint.txt" 2>&1; then
  grep -v "skipped" "$OUT/checkpoint.txt" | while read -r l; do say "$l"; done
else
  say "checkpoint check FAILED:"; cat "$OUT/checkpoint.txt" | tee -a "$RESULTS"; FAILURES=$((FAILURES+1))
fi

say ""
say "failures: $FAILURES"
exit $FAILURES
