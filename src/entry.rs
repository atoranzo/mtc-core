//! # La hoja: `MTCLogEntry` y `TBSCertificateLogEntry`
//!
//! En Arqueo la hoja era `native_leaf(public_id, saldo, nonce)`, un
//! compromiso de tres elementos de campo. En MTC la hoja es lo que la CA
//! **certifica**: los campos del certificado que no dependen del tamano
//! de la clave. La clave publica entra **por su hash** (`subjectPublicKey-
//! InfoHash`) y no hay firma dentro de la entrada: por eso el log no
//! crece con ML-DSA, que es toda la razon de ser de MTC.
//!
//! [`MtcLeaf`] es la estructura de trabajo de la CA (lo que el usuario
//! pidio como `MTCLeaf`: clave, sujeto, validez, extensiones); de ella
//! salen **dos** codificaciones que tienen que cuadrar byte a byte:
//!
//! - [`MtcLeaf::tbs_cert_entry_data`], los campos de un
//!   `TBSCertificateLogEntry` concatenados (sin la cabecera del SEQUENCE,
//!   para que el verificador hashee en un solo paso), que va dentro del
//!   [`MtcLogEntry`] que se anota en el log;
//! - [`MtcLeaf::tbs_certificate`], el `TBSCertificate` X.509 que viaja en
//!   el certificado, con el numero de serie `(log << 48) | index` y la
//!   clave entera.
//!
//! ⚠️ El verificador reconstruye la primera a partir de la segunda. Si las
//! dos divergen, ningun certificado verifica: hay un test que las cruza.

use crate::der::{self, DerError, Tlv};
use crate::hash::{hash_leaf, sha256, HashValue, HASH_SIZE};

/// `null_entry(0)`.
pub const NULL_ENTRY: u16 = 0;
/// `tbs_cert_entry(1)`.
pub const TBS_CERT_ENTRY: u16 = 1;
/// Un `MTCLogEntry` no supera los 65535 bytes (compatibilidad tlog).
pub const MAX_ENTRY_SIZE: usize = 65_535;

/// Los tipos de extension de entrada que esta CA reconoce. **Hoy, ninguno**:
/// el registro del borrador esta vacio, y «una CA MUST NOT firmar un
/// subarbol que contenga una entrada con un `extension_type` que no
/// reconoce». Cuando se defina uno, entra aqui con su semantica.
pub const RECOGNIZED_EXTENSION_TYPES: &[u16] = &[];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryError {
    /// Las extensiones no van en orden estrictamente creciente de tipo.
    ExtensionsNotSorted,
    /// Un campo supera el maximo de su prefijo de longitud.
    TooLong(&'static str, usize),
    /// Tipo de entrada no reconocido: una CA NO debe firmar lo que no entiende.
    UnknownType(u16),
    /// Tipo de extension de entrada no reconocido: idem.
    UnknownExtension(u16),
    Truncated,
    Der(DerError),
}

impl core::fmt::Display for EntryError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for EntryError {}

impl From<DerError> for EntryError {
    fn from(e: DerError) -> Self {
        EntryError::Der(e)
    }
}

/// `MTCLogEntryExtension { extension_type, extension_data<0..2^16-1> }`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogEntryExtension {
    pub extension_type: u16,
    pub extension_data: Vec<u8>,
}

/// `MTCLogEntryExtension extensions<0..2^16-1>`, con su prefijo de dos
/// bytes; exige orden estrictamente creciente por tipo.
pub fn encode_extensions(exts: &[LogEntryExtension]) -> Result<Vec<u8>, EntryError> {
    let mut body = Vec::new();
    let mut last: Option<u16> = None;
    for e in exts {
        if last.is_some_and(|l| e.extension_type <= l) {
            return Err(EntryError::ExtensionsNotSorted);
        }
        last = Some(e.extension_type);
        if e.extension_data.len() > 0xffff {
            return Err(EntryError::TooLong(
                "extension_data",
                e.extension_data.len(),
            ));
        }
        body.extend_from_slice(&e.extension_type.to_be_bytes());
        body.extend_from_slice(&(e.extension_data.len() as u16).to_be_bytes());
        body.extend_from_slice(&e.extension_data);
    }
    if body.len() > 0xffff {
        return Err(EntryError::TooLong("extensions", body.len()));
    }
    let mut out = Vec::with_capacity(body.len() + 2);
    out.extend_from_slice(&(body.len() as u16).to_be_bytes());
    out.extend(body);
    Ok(out)
}

/// Lee `extensions<0..2^16-1>` y devuelve el resto.
pub fn decode_extensions(input: &[u8]) -> Result<(Vec<LogEntryExtension>, &[u8]), EntryError> {
    if input.len() < 2 {
        return Err(EntryError::Truncated);
    }
    let len = u16::from_be_bytes([input[0], input[1]]) as usize;
    let (mut body, rest) = input[2..]
        .split_at_checked(len)
        .ok_or(EntryError::Truncated)?;
    let mut out = Vec::new();
    let mut last: Option<u16> = None;
    while !body.is_empty() {
        if body.len() < 4 {
            return Err(EntryError::Truncated);
        }
        let typ = u16::from_be_bytes([body[0], body[1]]);
        let dlen = u16::from_be_bytes([body[2], body[3]]) as usize;
        let (data, next) = body[4..]
            .split_at_checked(dlen)
            .ok_or(EntryError::Truncated)?;
        if last.is_some_and(|l| typ <= l) {
            return Err(EntryError::ExtensionsNotSorted);
        }
        last = Some(typ);
        out.push(LogEntryExtension {
            extension_type: typ,
            extension_data: data.to_vec(),
        });
        body = next;
    }
    Ok((out, rest))
}

/// `MTCLogEntry`: lo que se anota en el log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MtcLogEntry {
    /// `null_entry`: no afirma nada; una CA lo certifica sin responsabilidad.
    Null { extensions: Vec<LogEntryExtension> },
    /// `tbs_cert_entry`: los campos del `TBSCertificateLogEntry` concatenados.
    TbsCert {
        extensions: Vec<LogEntryExtension>,
        tbs_cert_entry_data: Vec<u8>,
    },
}

impl MtcLogEntry {
    pub fn extensions(&self) -> &[LogEntryExtension] {
        match self {
            MtcLogEntry::Null { extensions } | MtcLogEntry::TbsCert { extensions, .. } => {
                extensions
            }
        }
    }

    /// La serializacion TLS de la entrada.
    pub fn encode(&self) -> Result<Vec<u8>, EntryError> {
        let mut out = encode_extensions(self.extensions())?;
        match self {
            MtcLogEntry::Null { .. } => out.extend_from_slice(&NULL_ENTRY.to_be_bytes()),
            MtcLogEntry::TbsCert {
                tbs_cert_entry_data,
                ..
            } => {
                out.extend_from_slice(&TBS_CERT_ENTRY.to_be_bytes());
                out.extend_from_slice(tbs_cert_entry_data);
            }
        }
        if out.len() > MAX_ENTRY_SIZE {
            return Err(EntryError::TooLong("MTCLogEntry", out.len()));
        }
        Ok(out)
    }

    /// Lee una entrada cuya longitud total se conoce.
    pub fn decode(input: &[u8]) -> Result<Self, EntryError> {
        if input.len() > MAX_ENTRY_SIZE {
            return Err(EntryError::TooLong("MTCLogEntry", input.len()));
        }
        let (extensions, rest) = decode_extensions(input)?;
        if rest.len() < 2 {
            return Err(EntryError::Truncated);
        }
        let typ = u16::from_be_bytes([rest[0], rest[1]]);
        let data = &rest[2..];
        match typ {
            NULL_ENTRY if data.is_empty() => Ok(MtcLogEntry::Null { extensions }),
            NULL_ENTRY => Err(EntryError::Truncated),
            TBS_CERT_ENTRY => Ok(MtcLogEntry::TbsCert {
                extensions,
                tbs_cert_entry_data: data.to_vec(),
            }),
            other => Err(EntryError::UnknownType(other)),
        }
    }

    /// `MTH({entry}) = HASH(0x00 || entry)`.
    pub fn leaf_hash(&self) -> Result<HashValue, EntryError> {
        Ok(hash_leaf(&self.encode()?))
    }
}

/// `Validity { notBefore, notAfter }` en segundos POSIX.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Validity {
    pub not_before: u64,
    pub not_after: u64,
}

impl Validity {
    pub fn to_der(&self) -> Vec<u8> {
        let mut c = der::time(self.not_before);
        c.extend(der::time(self.not_after));
        der::sequence(&c)
    }

    /// Lee un `Validity` (el TLV entero).
    pub fn from_der(validity: &Tlv<'_>) -> Result<Self, DerError> {
        if validity.tag != der::TAG_SEQUENCE {
            return Err(DerError::UnexpectedTag {
                expected: der::TAG_SEQUENCE,
                found: validity.tag,
            });
        }
        let (nb, rest) = der::read_tlv(validity.content)?;
        let (na, rest) = der::read_tlv(rest)?;
        if !rest.is_empty() {
            return Err(DerError::TrailingData);
        }
        Ok(Validity {
            not_before: der::decode_time(&nb)?,
            not_after: der::decode_time(&na)?,
        })
    }

    pub fn contains(&self, now: u64) -> bool {
        self.not_before <= now && now <= self.not_after
    }
}

/// **La hoja de trabajo de la CA**: lo que certifica de un solicitante.
///
/// Los campos DER (`issuer`, `subject`, `spki`, `extensions`) se aceptan
/// ya codificados: los produce la capa de validacion (ACME + `x509-cert`),
/// no este crate. `issuer` lo pone la CA con [`der::name_from_ca_id`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MtcLeaf {
    /// `Version`: 2 = v3 (obligatorio con extensiones). 0 (v1) se omite.
    pub version: u8,
    /// `Name` DER del emisor: **el CA ID**, siempre.
    pub issuer: Vec<u8>,
    pub validity: Validity,
    /// `Name` DER del sujeto (puede ser vacio, `30 00`, si todo va en el SAN).
    pub subject: Vec<u8>,
    /// `SubjectPublicKeyInfo` DER **entero**: en la entrada va su hash, en
    /// el certificado va completo.
    pub spki: Vec<u8>,
    /// `issuerUniqueID [1] IMPLICIT` (contenido del BIT STRING), rara vez.
    pub issuer_unique_id: Option<Vec<u8>>,
    /// `subjectUniqueID [2] IMPLICIT`, rara vez.
    pub subject_unique_id: Option<Vec<u8>>,
    /// `Extensions` DER (el SEQUENCE OF Extension, sin el `[3]`).
    pub extensions: Option<Vec<u8>>,
}

impl MtcLeaf {
    /// El `algorithm` del `SubjectPublicKeyInfo`, como TLV entero.
    pub fn spki_algorithm(&self) -> Result<&[u8], EntryError> {
        Ok(der::spki_algorithm(&self.spki)?)
    }

    /// `subjectPublicKeyInfoHash`: el hash del log sobre el SPKI en DER.
    pub fn spki_hash(&self) -> HashValue {
        sha256(&self.spki)
    }

    fn version_der(&self) -> Vec<u8> {
        if self.version == 0 {
            Vec::new()
        } else {
            der::explicit(0, &der::integer_u64(self.version as u64))
        }
    }

    fn tail_der(&self) -> Vec<u8> {
        let mut out = Vec::new();
        if let Some(id) = &self.issuer_unique_id {
            out.extend(der::implicit_primitive(1, id));
        }
        if let Some(id) = &self.subject_unique_id {
            out.extend(der::implicit_primitive(2, id));
        }
        if let Some(ext) = &self.extensions {
            out.extend(der::explicit(3, ext));
        }
        out
    }

    /// Los campos del `TBSCertificateLogEntry`, concatenados.
    pub fn tbs_cert_entry_data(&self) -> Result<Vec<u8>, EntryError> {
        let mut out = self.version_der();
        out.extend_from_slice(&self.issuer);
        out.extend(self.validity.to_der());
        out.extend_from_slice(&self.subject);
        out.extend_from_slice(self.spki_algorithm()?);
        out.extend(der::octet_string(&self.spki_hash()));
        out.extend(self.tail_der());
        Ok(out)
    }

    /// La entrada del log para esta hoja. Rechaza extensiones que no esten
    /// en [`RECOGNIZED_EXTENSION_TYPES`]: la CA no las firmaria.
    pub fn log_entry(&self, extensions: Vec<LogEntryExtension>) -> Result<MtcLogEntry, EntryError> {
        if let Some(e) = extensions
            .iter()
            .find(|e| !RECOGNIZED_EXTENSION_TYPES.contains(&e.extension_type))
        {
            return Err(EntryError::UnknownExtension(e.extension_type));
        }
        Ok(MtcLogEntry::TbsCert {
            extensions,
            tbs_cert_entry_data: self.tbs_cert_entry_data()?,
        })
    }

    /// El `TBSCertificate` X.509 con `serialNumber = (log << 48) | index` y
    /// `signature = id-alg-mtcProof`.
    pub fn tbs_certificate(&self, serial: u64) -> Result<Vec<u8>, EntryError> {
        let mut c = self.version_der();
        c.extend(der::integer_u64(serial));
        c.extend(der::alg_id_mtc_proof());
        c.extend_from_slice(&self.issuer);
        c.extend(self.validity.to_der());
        c.extend_from_slice(&self.subject);
        c.extend_from_slice(&self.spki);
        c.extend(self.tail_der());
        Ok(der::sequence(&c))
    }
}

/// **La entrada reconstruida desde un `TBSCertificate`** (seccion
/// «Verifying Certificate Signatures», el hash en un solo paso): lo que
/// el verificador hashea sin haber visto nunca la hoja de la CA.
pub fn entry_bytes_from_tbs(
    tbs: &der::TbsFields<'_>,
    extensions: &[LogEntryExtension],
) -> Result<Vec<u8>, EntryError> {
    let mut out = encode_extensions(extensions)?;
    out.extend_from_slice(&TBS_CERT_ENTRY.to_be_bytes());
    if let Some(v) = tbs.version {
        out.extend_from_slice(v.raw);
    }
    out.extend_from_slice(tbs.issuer.raw);
    out.extend_from_slice(tbs.validity.raw);
    out.extend_from_slice(tbs.subject.raw);
    out.extend_from_slice(der::spki_algorithm(tbs.spki.raw)?);
    out.push(der::TAG_OCTET_STRING);
    out.push(HASH_SIZE as u8);
    out.extend_from_slice(&sha256(tbs.spki.raw));
    out.extend_from_slice(tbs.after_spki);
    Ok(out)
}

#[cfg(test)]
pub(crate) mod fixtures {
    use super::*;
    use crate::tai::TrustAnchorId;

    /// Un SPKI de juguete: `SEQUENCE { AlgorithmIdentifier { OID }, BIT STRING key }`.
    pub fn toy_spki(key: &[u8]) -> Vec<u8> {
        let mut c = der::algorithm_identifier(&[1, 3, 101, 112]); // id-Ed25519, por nombrar uno
        c.extend(der::bit_string(key));
        der::sequence(&c)
    }

    pub fn leaf(ca: &TrustAnchorId, dns: &str, key: &[u8]) -> MtcLeaf {
        MtcLeaf {
            version: 2,
            issuer: der::name_from_ca_id(ca),
            validity: Validity {
                not_before: 1_800_000_000,
                not_after: 1_800_000_000 + 7 * 86_400,
            },
            subject: der::sequence(&[]),
            spki: toy_spki(key),
            issuer_unique_id: None,
            subject_unique_id: None,
            extensions: Some(der::san_dns_extensions(&[dns])),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tai::TrustAnchorId;

    #[test]
    fn the_entry_the_ca_logs_is_the_entry_the_verifier_rebuilds() {
        let ca = TrustAnchorId::from_ascii("32473.1").unwrap();
        let leaf = fixtures::leaf(&ca, "example.com", &[7u8; 32]);
        let entry = leaf.log_entry(vec![]).unwrap();
        assert_eq!(
            leaf.log_entry(vec![LogEntryExtension {
                extension_type: 9,
                extension_data: vec![]
            }])
            .err(),
            Some(EntryError::UnknownExtension(9))
        );
        let tbs = leaf.tbs_certificate((1u64 << 48) | 5).unwrap();
        let fields = der::parse_tbs(&tbs).unwrap();
        assert_eq!(
            entry_bytes_from_tbs(&fields, &[]).unwrap(),
            entry.encode().unwrap()
        );
        assert_eq!(
            der::decode_integer_u64(fields.serial.content).unwrap(),
            (1u64 << 48) | 5
        );
        assert_eq!(fields.signature.raw, der::alg_id_mtc_proof().as_slice());
        assert_eq!(Validity::from_der(&fields.validity).unwrap(), leaf.validity);
    }

    #[test]
    fn entries_round_trip_and_reject_disorder() {
        let e = MtcLogEntry::TbsCert {
            extensions: vec![
                LogEntryExtension {
                    extension_type: 1,
                    extension_data: vec![9],
                },
                LogEntryExtension {
                    extension_type: 7,
                    extension_data: vec![],
                },
            ],
            tbs_cert_entry_data: vec![1, 2, 3],
        };
        assert_eq!(MtcLogEntry::decode(&e.encode().unwrap()).unwrap(), e);
        let bad = MtcLogEntry::Null {
            extensions: vec![
                LogEntryExtension {
                    extension_type: 7,
                    extension_data: vec![],
                },
                LogEntryExtension {
                    extension_type: 7,
                    extension_data: vec![],
                },
            ],
        };
        assert_eq!(bad.encode(), Err(EntryError::ExtensionsNotSorted));
        assert_eq!(
            MtcLogEntry::decode(&[0, 0, 0, 2]),
            Err(EntryError::UnknownType(2))
        );
        assert_eq!(
            MtcLogEntry::decode(&[0, 0, 0, 0]).unwrap(),
            MtcLogEntry::Null { extensions: vec![] }
        );
    }
}
