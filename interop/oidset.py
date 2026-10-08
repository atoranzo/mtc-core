#!/usr/bin/env python3
"""Says which MTC OID set each PEM file is written with, by searching the
DER of its CERTIFICATE blocks for the encoded OIDs, without any MTC
implementation: "iana" (id-alg-mtcProof 1.3.6.1.5.5.7.6.67,
id-rdna-trustAnchorID 1.3.6.1.5.5.7.25.3,
id-pe-mtcCertificationAuthority-SHA256 1.3.6.1.5.5.7.1.38), "experimental"
(1.3.6.1.4.1.44363.47.N with N below 128, which covers every set of that
arc so far), "mixed" or "none". One line per file: "NAME SET".

    oidset.py FILE.pem...
"""
import base64
import os
import sys

IANA = [bytes.fromhex(h) for h in (
    "06082b06010505070643",  # 1.3.6.1.5.5.7.6.67
    "06082b06010505071903",  # 1.3.6.1.5.5.7.25.3
    "06082b06010505070126",  # 1.3.6.1.5.5.7.1.38
)]
EXPERIMENTAL = bytes.fromhex("060a2b0601040182da4b2f")  # 1.3.6.1.4.1.44363.47.N, N < 128


def certificates(path):
    der, block = [], None
    for line in open(path):
        line = line.strip()
        if line == "-----BEGIN CERTIFICATE-----":
            block = []
        elif line == "-----END CERTIFICATE-----" and block is not None:
            der.append(base64.b64decode("".join(block)))
            block = None
        elif block is not None:
            block.append(line)
    return der


for path in sys.argv[1:]:
    blobs = certificates(path)
    iana = any(o in d for d in blobs for o in IANA)
    experimental = any(EXPERIMENTAL in d for d in blobs)
    name = "mixed" if iana and experimental else "iana" if iana else \
        "experimental" if experimental else "none"
    print(os.path.basename(path), name)
