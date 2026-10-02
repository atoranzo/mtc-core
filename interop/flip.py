#!/usr/bin/env python3
"""Derives a negative from an MTC certificate by flipping one bit, at the
byte level, without any MTC implementation: the first byte of the first
inclusion-proof hash ("proof"), or of the signature of cosigner N
("sig N", from 0). Reads the first CERTIFICATE block of a PEM file (a
CERTIFICATE PROPERTIES block before it is dropped) and writes one.

    flip.py proof IN.pem OUT.pem
    flip.py sig N IN.pem OUT.pem

The MTCProof (draft-ietf-plants-merkle-tree-certs, section 6.1):
extensions<0..2^16-1>, start and end uint48, inclusion_proof<0..2^16-1>,
signatures<0..2^24-1> of Cosignature { cosigner_id<1..2^8-1>,
signature<0..2^16-1> }.
"""
import base64
import sys


def der_len(b, i):
    """The length at b[i] and the offset of the content."""
    n = b[i]
    if n < 0x80:
        return n, i + 1
    k = n & 0x7F
    return int.from_bytes(b[i + 1:i + 1 + k], "big"), i + 1 + k


def tlv(b, i):
    """(content start, content end) of the TLV at b[i]."""
    n, c = der_len(b, i + 1)
    return c, c + n


def main(argv):
    if argv[:1] == ["proof"] and len(argv) == 3:
        what, src, dst = ("proof", None), argv[1], argv[2]
    elif argv[:1] == ["sig"] and len(argv) == 4:
        what, src, dst = ("sig", int(argv[1])), argv[2], argv[3]
    else:
        sys.exit(__doc__)
    text = open(src).read()
    begin = "-----BEGIN CERTIFICATE-----"
    body = text[text.index(begin) + len(begin):text.index("-----END CERTIFICATE-----")]
    cert = bytearray(base64.b64decode("".join(body.split())))

    c, _ = tlv(cert, 0)                 # Certificate
    _, c = tlv(cert, c)                 # tbsCertificate, skipped
    _, c = tlv(cert, c)                 # signatureAlgorithm, skipped
    if cert[c] != 0x03:
        sys.exit("no BIT STRING")
    s, e = tlv(cert, c)
    if cert[s] != 0:
        sys.exit("BIT STRING with unused bits")
    p = s + 1                           # the MTCProof
    p += 2 + int.from_bytes(cert[p:p + 2], "big")   # extensions
    p += 12                             # start, end
    n = int.from_bytes(cert[p:p + 2], "big")
    proof_at, p = p + 2, p + 2 + n      # inclusion_proof
    sigs_end = p + 3 + int.from_bytes(cert[p:p + 3], "big")
    p += 3
    sigs = []
    while p < sigs_end:
        p += 1 + cert[p]                # cosigner_id
        n = int.from_bytes(cert[p:p + 2], "big")
        sigs.append((p + 2, n))
        p += 2 + n
    if p != e or sigs_end != e:
        sys.exit("MTCProof does not fill the BIT STRING")

    if what[0] == "proof":
        if int.from_bytes(cert[proof_at - 2:proof_at], "big") == 0:
            sys.exit("empty inclusion proof")
        cert[proof_at] ^= 1
    else:
        if what[1] >= len(sigs) or sigs[what[1]][1] == 0:
            sys.exit("no such signature")
        cert[sigs[what[1]][0]] ^= 1

    b64 = base64.b64encode(bytes(cert)).decode()
    lines = [b64[i:i + 64] for i in range(0, len(b64), 64)]
    with open(dst, "w") as f:
        f.write(begin + "\n" + "\n".join(lines) + "\n-----END CERTIFICATE-----\n")


if __name__ == "__main__":
    main(sys.argv[1:])
