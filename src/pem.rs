//! # PEM and base64, the minimum needed to exchange files
//!
//! RFC 7468 textual encoding over RFC 4648 base64, so that a certificate
//! from here can be handed to another implementation and one of theirs can
//! be read back. There is no dependency: the alphabet fits in a page and
//! the two decoders are strict (fail closed on a wrong character, a wrong
//! padding or non-zero trailing bits), as everything else in this crate.
//!
//! [`decode_all`] is tolerant with what surrounds the blocks (the draft's
//! reference implementation writes a `MTC CERTIFICATE PROPERTIES` block
//! before each certificate, and a trust store may carry comments), and
//! strict with what is inside them.

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PemError {
    /// A character outside the alphabet, a wrong length, a wrong padding
    /// or non-zero bits after the last symbol.
    BadBase64,
    /// A `-----BEGIN X-----` line with no matching `-----END X-----`.
    UnterminatedBlock(String),
    /// The `END` label is not the `BEGIN` label.
    LabelMismatch { begin: String, end: String },
}

impl core::fmt::Display for PemError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            PemError::BadBase64 => write!(f, "invalid base64"),
            PemError::UnterminatedBlock(l) => write!(f, "PEM block {l:?} has no END line"),
            PemError::LabelMismatch { begin, end } => {
                write!(f, "PEM block begins as {begin:?} and ends as {end:?}")
            }
        }
    }
}

impl std::error::Error for PemError {}

/// Standard base64 with padding, no line breaks.
pub fn base64_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(ALPHABET[(n >> 18) as usize & 63] as char);
        out.push(ALPHABET[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

fn value(c: u8) -> Option<u32> {
    match c {
        b'A'..=b'Z' => Some(u32::from(c - b'A')),
        b'a'..=b'z' => Some(u32::from(c - b'a') + 26),
        b'0'..=b'9' => Some(u32::from(c - b'0') + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// Strict standard base64: padding required, canonical trailing bits,
/// ASCII whitespace ignored (PEM wraps lines at 64 columns).
pub fn base64_decode(s: &str) -> Result<Vec<u8>, PemError> {
    let symbols: Vec<u8> = s
        .bytes()
        .filter(|b| !matches!(b, b' ' | b'\t' | b'\r' | b'\n'))
        .collect();
    if !symbols.len().is_multiple_of(4) {
        return Err(PemError::BadBase64);
    }
    let mut out = Vec::with_capacity(symbols.len() / 4 * 3);
    for (i, quad) in symbols.chunks(4).enumerate() {
        let last = i == symbols.len() / 4 - 1;
        let pad = quad.iter().rev().take_while(|c| **c == b'=').count();
        if pad > 2 || (pad > 0 && !last) {
            return Err(PemError::BadBase64);
        }
        let mut n = 0u32;
        for c in &quad[..4 - pad] {
            n = (n << 6) | value(*c).ok_or(PemError::BadBase64)?;
        }
        n <<= 6 * pad as u32;
        let bytes = n.to_be_bytes();
        match pad {
            0 => out.extend_from_slice(&bytes[1..4]),
            1 => {
                if n & 0xff != 0 {
                    return Err(PemError::BadBase64);
                }
                out.extend_from_slice(&bytes[1..3]);
            }
            _ => {
                if n & 0xffff != 0 {
                    return Err(PemError::BadBase64);
                }
                out.push(bytes[1]);
            }
        }
    }
    Ok(out)
}

/// One decoded block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PemBlock {
    pub label: String,
    pub der: Vec<u8>,
}

/// `-----BEGIN label-----`, base64 in 64-column lines, `-----END label-----`.
pub fn encode(label: &str, der: &[u8]) -> String {
    let b64 = base64_encode(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for line in b64.as_bytes().chunks(64) {
        out.push_str(core::str::from_utf8(line).expect("base64 is ASCII"));
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

/// Every block in the text, in order. Text outside the blocks is ignored.
pub fn decode_all(text: &str) -> Result<Vec<PemBlock>, PemError> {
    let mut blocks = Vec::new();
    let mut current: Option<(String, String)> = None; // (label, base64 so far)
    for line in text.lines() {
        let line = line.trim_end_matches('\r');
        match &mut current {
            None => {
                if let Some(label) = line
                    .strip_prefix("-----BEGIN ")
                    .and_then(|l| l.strip_suffix("-----"))
                {
                    current = Some((label.to_string(), String::new()));
                }
            }
            Some((label, body)) => {
                if let Some(end) = line
                    .strip_prefix("-----END ")
                    .and_then(|l| l.strip_suffix("-----"))
                {
                    if end != label {
                        return Err(PemError::LabelMismatch {
                            begin: label.clone(),
                            end: end.to_string(),
                        });
                    }
                    let der = base64_decode(body)?;
                    blocks.push(PemBlock {
                        label: label.clone(),
                        der,
                    });
                    current = None;
                } else {
                    body.push_str(line.trim());
                }
            }
        }
    }
    if let Some((label, _)) = current {
        return Err(PemError::UnterminatedBlock(label));
    }
    Ok(blocks)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_round_trips_every_length_modulo_three() {
        for len in 0..40usize {
            let data: Vec<u8> = (0..len as u8).map(|i| i.wrapping_mul(37)).collect();
            let enc = base64_encode(&data);
            assert_eq!(enc.len(), len.div_ceil(3) * 4);
            assert_eq!(base64_decode(&enc).unwrap(), data);
        }
        // RFC 4648 §10 test vectors.
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foob"), "Zm9vYg==");
        assert_eq!(base64_encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn base64_decoder_fails_closed() {
        assert_eq!(base64_decode("Zg"), Err(PemError::BadBase64)); // no padding
        assert_eq!(base64_decode("Zh=="), Err(PemError::BadBase64)); // trailing bits
        assert_eq!(base64_decode("Zm9v!A=="), Err(PemError::BadBase64)); // alphabet
        assert_eq!(base64_decode("Zg==Zg=="), Err(PemError::BadBase64)); // padding inside
        assert_eq!(base64_decode("Z==="), Err(PemError::BadBase64)); // too much padding
        assert_eq!(base64_decode("Zm9v\nYmFy\n").unwrap(), b"foobar"); // whitespace ok
    }

    #[test]
    fn pem_round_trip_and_tolerance_to_other_blocks() {
        let der: Vec<u8> = (0..100u8).collect();
        let text = format!(
            "# a comment\n{}{}",
            encode("MTC CERTIFICATE PROPERTIES", &[1, 2, 3]),
            encode("CERTIFICATE", &der)
        );
        let blocks = decode_all(&text).unwrap();
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0].label, "MTC CERTIFICATE PROPERTIES");
        assert_eq!(blocks[1].label, "CERTIFICATE");
        assert_eq!(blocks[1].der, der);
        // 64-column lines.
        for line in encode("CERTIFICATE", &der).lines() {
            assert!(line.len() <= 64);
        }
    }

    #[test]
    fn pem_decoder_rejects_broken_blocks() {
        assert_eq!(
            decode_all("-----BEGIN A-----\nAAAA\n"),
            Err(PemError::UnterminatedBlock("A".into()))
        );
        assert_eq!(
            decode_all("-----BEGIN A-----\nAAAA\n-----END B-----\n"),
            Err(PemError::LabelMismatch {
                begin: "A".into(),
                end: "B".into()
            })
        );
        assert_eq!(
            decode_all("-----BEGIN A-----\nAAA\n-----END A-----\n"),
            Err(PemError::BadBase64)
        );
    }
}
