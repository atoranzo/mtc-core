# Generative AI in mtc-core

This document states, for anyone using or reviewing this repository, to what
extent a generative AI assistant was used to produce it, and by what method.
It is not a footnote: the history and the record of this repository are as
much the project's documentation as the code is, and whoever reads them is
entitled to know how they were produced. The method is the one
[Arqueo](https://github.com/atoranzo/Arqueo-open-conservation-proofs-for-closed-ledgers)
states for itself, and this document says where the first commits of this
crate departed from it, because they did.

## What is used

- **Model:** Anthropic's Claude, through Claude Code (cloud sessions started
  from `claude.ai/code`). The specific version may change over the course of
  the project; the commit trailers name the one that made each commit.
- **Since when:** since this crate's first session, on 2026-09-30. It was
  born inside the Arqueo repository, whose own statement covers that
  repository since 2026-07-29, and was extracted with its history.

## How it is used, exactly

The method is Arqueo's, and it explains everything else:

1. **Measure first.** A pure reading over the tree, or over the
   specification's own test vectors, produces the numbers; a remembered
   summary is not a source.
2. Those numbers are discussed, and **the author decides**.
3. The assistant proposes a **block**: a change that brings its own gates,
   its red path included. Here the gates are `cargo fmt --check`,
   `cargo clippy --all-targets`, `cargo test --release` with and without the
   `ml-dsa` feature, and, while the crate lived inside Arqueo, Arqueo's own
   document gates (the citation and figure checkers under `tools/`).
4. **The author runs it on his own machine** and **commits only what comes
   out green**.

Two things follow from that method, and the record sustains them:

- **Nothing gets in without passing the gates.** What is proposed and the
  gates reject never reaches `main`.
- **No claim in this repository rests on the model's knowledge.** What is
  claimed about the present is verified against the tree or against the
  specification's published vectors; what has not been measured is declared
  as not measured; what was measured and came out false is written down as
  false. The README's chronology carries a status per row for that reason.

**Where the first commits departed from step 4, stated rather than glossed
over.** The commits that created this crate were proposed *and executed* by
the assistant, in a cloud session, on a review branch of the Arqueo
repository: the gates ran in that session, their results are in each commit
message and were re-derived commit by commit for [`AUDIT.md`](./AUDIT.md),
and the author's acceptance is the review of that branch and its push to
this repository as its `main`. Nothing reaches this repository that the
author does not push. From that push on, step 4 applies as written.

## Where the record is

Per-commit marking is the tooling's, not the project's method: the trailers
`Co-Authored-By` and `Claude-Session` on each commit record which assistant
took part and in which session. They are provenance, not authorship (see
below).

The per-change record is [`AUDIT.md`](./AUDIT.md): one entry per verified
change, with its commit, its counters (tests, lint, format, re-run at that
commit), what the change does **not** close and the lessons it left. It also
records the two independent reviews that shaped the crate, the adversarial
review against the draft and the verification of the chronology, with what
each confirmed and refuted. It is substantially more detailed than a commit
message, and it is the place to look.

## Scope

It has been used as assistance for **code, prose and the reading of the
specification** (the draft, its reference implementation and the C2SP
specifications it cites). No part of this repository is a model's output
without measurement, execution and the author's acceptance.

## Authorship and accountability

The author of mtc-core is **Ángel José Toranzo Portela**, and he is the only
one. An assistant is not listed as an author or a co-author: in the European
Union, what a machine generates without substantial human intellectual
contribution does not give rise to copyright, and here the decision, the
measurement and the acceptance are the author's. The `Co-Authored-By` trailer
that the tooling adds to commits records participation, not authorship, and
the licence under which the code is offered is the author's to grant. Anyone
who wants to argue about a design or code decision has a person in front of
them who explains it.
