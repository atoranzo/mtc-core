# The draft's large vectors

`large_inclusion_proofs.json` and `large_consistency_proofs.json` are the
files that the appendix "Large Subtree Test Vectors" of
`draft-ietf-plants-merkle-tree-certs` references, copied verbatim from the
`demo/` directory of the PLANTS working group's repository
(`ietf-plants-wg/merkle-tree-certs`, commit `99097c9`, 2026-09-29). They are
proofs over trees of `2^48-1`, `2^63-1` and `2^64-1` leaves, which no
implementation can build: they exercise the **verifier**, which has to
evaluate them with 64-bit integers without overflowing.

`tests/large_vectors.rs` reads them with a hand-written JSON and base64
reader, so that `serde` does not sneak in through the back door.

## License of these two files

The repository they come from declares that all of its material consists of
contributions to the IETF standardization process (BCP 78, BCP 79 and the
*IETF Trust Legal Provisions*), and that its code components, including the
test vectors, are under the IETF Trust's **Simplified BSD License**. They are
kept here under that license and with this attribution, separate from the
MIT OR Apache-2.0 license of the rest of the crate:

> Copyright (c) IETF Trust and the persons identified as authors of the
> code. All rights reserved. Redistribution and use in source and binary
> forms, with or without modification, is permitted pursuant to, and
> subject to the license terms contained in, the Simplified BSD License
> set forth in Section 4.c of the IETF Trust's Legal Provisions Relating
> to IETF Documents (https://trustee.ietf.org/license-info).
