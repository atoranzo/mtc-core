# Generative AI in mtc-core

This document states, for anyone using or reviewing this repository, to what
extent a generative AI assistant was used to produce it, and by what method.
It follows the statement Arqueo makes for itself, and it says where the method
here was different, because it was.

## What is used

- **Model:** Anthropic's Claude (Claude Fable 5.1 at the time of writing),
  through Claude Code running in a cloud session connected to the author's
  GitHub account.
- **Since when:** since this crate's first session, on 2026-09-30. The crate
  was started inside the Arqueo repository and extracted from it; the git
  history carries that origin.

## How it was used, exactly

The method differs from Arqueo's in one point, and it is stated here rather
than glossed over: **in this crate the assistant ran the tests and pushed the
commits itself**, to a review branch, under the author's direction and for
the author's review. In Arqueo the author runs every gate on his own machine
and commits only what comes out green; here the gates ran in the assistant's
cloud session, and the author reviews the branch afterwards. The record of
what ran, and what came out, is in the commit messages.

What the method kept:

1. **Measure first.** Every claim about the code was checked against the tree
   or against the specification's own test vectors, never against a
   remembered summary. What was not measured is declared as not measured.
2. **The author decides.** The scope, the name, the language, the licensing
   choices and what to publish were the author's decisions, taken in the
   conversation and recorded there.
3. **Gates before the commit.** `cargo fmt --check`, `cargo clippy
   --all-targets`, `cargo test --release` with and without the `ml-dsa`
   feature, and Arqueo's own document gates (citation and figure checkers)
   ran green before every push.
4. **Independent review.** After the first version, the assistant ran an
   adversarial review of the crate against the draft, its reference Go
   implementation and the C2SP specifications, using independent agent
   instances: six reviewers by dimension and one sceptic per finding. The
   confirmed findings were fixed and covered by tests; the refuted ones are
   recorded in the commit message that applied the fixes. The same approach
   verified the chronology in the README against primary sources.

## What this does not claim

- Independent review by agents is not an audit. Nothing here has been
  audited by a third party; the README says so.
- The commit trailers (`Co-Authored-By: Claude …`, `Claude-Session: …`) are
  added by the tooling to record the assistant's participation and the
  session in which each commit was made. They are a record of provenance,
  not a claim of authorship (see below).

## Authorship and accountability

The author of mtc-core is **Ángel José Toranzo Portela**, and he is the only
one. In the European Union, what a machine generates without substantial
human intellectual contribution does not give rise to copyright; here the
decision, the direction, the review and the acceptance are the author's, and
the licence under which the code is offered is his to grant. Anyone who wants
to argue about a design or code decision has a person in front of them who
explains it.
