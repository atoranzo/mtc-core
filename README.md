# MTC — de Arqueo a una CA de Merkle Tree Certificates

> Plan de ingeniería y esqueleto en Rust para reutilizar la infraestructura de
> árbol de Arqueo y el guardián de estado de `hbs-state` como *backend* de una
> autoridad de certificación (CA) de **Merkle Tree Certificates (MTC)**, la
> propuesta del IETF (`draft-ietf-plants-merkle-tree-certs`, grupo PLANTS) para
> que el TLS poscuántico no pague tres firmas ML-DSA por *handshake*.

Este directorio es **un workspace de Cargo independiente**: no es miembro del
workspace de Arqueo, no arrastra `winterfell` ni el fork de `winter-*`, y su
`Cargo.lock` es suyo. Es la semilla del *fork*: lo que se llevaría a un
repositorio nuevo es este directorio entero.

```bash
cd mtc
cargo test --release              # vectores del borrador + flujo de extremo a extremo
cargo run --release --example demo_ca
```

Lo que se verifica al correr eso, y lo que no, está en la sección 7.

---

## 0. Leer antes de nada: tres correcciones a la hipótesis de partida

La hipótesis era: «`Arqueo` construye y actualiza el árbol; `hbs-state` gestiona
su estado persistente; basta quitar STARK y sumas y cambiar las hojas». Leído el
código de los dos repositorios y el borrador vigente, hay que corregir tres
cosas antes de diseñar nada:

1. **`hbs-state` no gestiona el estado del árbol.** Es *el guardián del índice
   de las firmas basadas en hashes con estado* (XMSS/XMSS^MT): un contador
   monótono persistido con `fsync`, una autocomprobación que se niega a operar
   en `tmpfs`, y la reconciliación en cuatro estados tras un reinicio. Es
   `zk-ssl-guardian` extraído de Arqueo, con cero dependencias. No tiene caché
   ni árbol. **Lo que aporta a una CA de MTC es un invariante**, y lo aporta
   dos veces (sección 2.3).

2. **El borrador ya no es el de los «lotes» de 2023.** El diseño que circuló
   con Cloudflare (`draft-davidben-…-04`: un árbol de Merkle independiente por
   lote, una «ventana de validez» firmada, hojas `Assertion` en formato TLS)
   se reescribió entero en `-05` y hoy es un documento del grupo de trabajo
   PLANTS. En el diseño vigente:
   - la CA lleva **logs de emisión** *append-only* al estilo RFC 9162, no
     árboles por lote;
   - la hoja es un `MTCLogEntry` que envuelve un `TBSCertificateLogEntry`
     **X.509 en DER**, donde la clave pública va **por su hash**;
   - la CA firma **subárboles** `[start, end)` con un formato de cofirma
     compatible con los *witnesses* de tlog (`subtree/v1`), y otros
     cofirmantes (testigos, espejos) firman lo mismo;
   - el certificado **es un X.509 corriente** cuyo `signatureValue` lleva un
     `MTCProof` (prueba de inclusión + cofirmas) y cuyo `signatureAlgorithm` es
     `id-alg-mtcProof`;
   - hay dos perfiles: el *standalone* (prueba + cofirmas, emisión inmediata)
     y el *relativo a landmark* (solo la prueba, sin ninguna firma, para
     clientes que ya tienen predistribuido el hash del subárbol).

   Las premisas de la hipótesis que **sí** se mantienen: sin ZK, sin sumas,
   validez y extensiones por certificado, prueba de inclusión de menos de 1 KB.

3. **Lo reutilizable de Arqueo no es el árbol disperso, es lo que hay
   alrededor.** El árbol de MTC es un árbol RFC 9162 denso y solo creciente; el
   `SparseTree` de profundidad fija de `zk-ssl` no encaja (sección 2.1). Lo que
   sí encaja, y casi línea a línea, es `zk-ssl-verify::mmr` (los algoritmos
   `MTH`/`PATH`/`SUBPROOF` de RFC 6962), el recibo de inclusión que ata «hoja →
   raíz → cabeza firmada», el firmante de cabeza que reserva el índice antes de
   firmar y verifica su propia salida, y la disciplina de que **el emisor y el
   verificador compilen la misma definición de cada formato**.

---

## 1. Qué problema resuelve MTC, en cuatro líneas

Con ML-DSA-44, una cadena X.509 con dos SCT de Certificate Transparency añade
unos 7,3 KB de firmas al *handshake* (cifra del propio borrador). MTC invierte
el orden: la CA **certifica anotando en su log** y firma **un checkpoint y dos
subárboles por ciclo**, no un certificado por solicitud. Un certificado es
entonces una prueba de inclusión de `ceil(log2(n))` hashes de 32 bytes, más las
cofirmas —o **ninguna**, si el cliente ya tiene el subárbol como *landmark*
predistribuido—. Medido con el ejemplo de este directorio (sección 4.4): 5.095
bytes el certificado *standalone* con dos cofirmas ML-DSA-44, **271 bytes** el
relativo a *landmark* de la misma entrada.

---

## 2. Análisis de refactorización

### 2.1 Arqueo: qué se elimina, qué se conserva, qué se adapta

| crate / módulo de Arqueo | destino | por qué |
|---|---|---|
| `stark-experiment`, `zk-ssl-air`, `winter-air` / `winter-prover` / `winter-verifier` (el fork), `zk-core`, `halo2-experiment`, `plonk-experiment`, `nova-experiment`, `ceremony`, `settlement-prover`, `settlement-layer`, `iso-bridge` | **eliminar** | Toda la capa de pruebas de conocimiento cero y la comparativa de cinco backends. MTC no prueba nada en circuito: la privacidad frente al operador no es un objetivo (el log es público a propósito). |
| `zk-ssl` (la capa: `accounts`, `mint`, `burn`, `pending`, `freeze`, `governance`, `recovery`, `two_phase`, `instrumento_*`, `prueba_*`, `consumo`, `iso`) | **eliminar** | Es la máquina de estados contable. No hay saldos, ni pagos en dos fases, ni conservación que probar. |
| `zk-ssl::sparse_tree::SparseTree` | **adaptar → `log`** | La idea (nodos internos en caché, O(log n) por escritura, reconstrucción por niveles al arrancar) se conserva; la estructura no: MTC necesita un árbol RFC 9162 denso y *append-only*, donde la caché es «un vector por nivel con los nodos completos». |
| `zk-ssl-hash` (`native_merge`, `path_root`, `mmr_hoja`/`mmr_nodo`, `epoch_digest_*`) | **sustituir → `hash` + `cosign`** | Rescue Prime sobre Goldilocks solo tenía sentido dentro de un STARK. El hash pasa a SHA-256 con los prefijos `0x00`/`0x01` de RFC 6962. **La regla se conserva entera**: una decisión de formato, una sola definición, compartida por emisor y verificador. |
| `zk-ssl-verify::mmr` (`cima`, `prueba_de_inclusion`, `prueba_de_consistencia` y sus verificaciones) | **traducir → `subtree`** | Son `MTH`, `PATH` y `SUBPROOF` de RFC 6962. Se traducen a SHA-256 y se **extienden a subárboles `[start, end)`**, que es lo que el borrador añade. Se conserva la propiedad de que la verificación es la recursión espejo de la generación. |
| `zk-ssl-verify::inclusion::ReciboInclusion` | **traducir → `proof` + `verify`** | El recibo «hoja → camino → raíz → cabeza firmada» es exactamente `MTCProof`: la raíz suelta no prueba nada, lo que prueba es la cofirma sobre el subárbol (o el subárbol predistribuido). |
| `zk-ssl-node::firma_cabeza::FirmanteCabeza` | **traducir → `cosign::Cosigner`** | Reservar el índice, firmar, verificar la propia salida con el mismo verificador que usará un tercero. Con ML-DSA no hay índice; con XMSS sí, y la interfaz (`&mut self`) lo admite. |
| `zk-ssl-guardian` | **ya es `hbs-state`** | Se usa `hbs-state` entero como dependencia, no se reimplementa (sección 2.3). |
| `zk-ssl-node::latido` (el cierre de época) | **adaptar → `ca::run_checkpoint_job`** | El latido compone la cabeza y la firma; el trabajo de checkpoint firma el checkpoint, cubre lo nuevo con dos subárboles, recoge cofirmas y emite. |
| `zk-ssl::persistence` / `snapshot` (`sled`, cifrado en reposo) | **más adelante** | El log de una CA vive en disco; la forma (sled, fichero *append-only*, tlog-tiles) se decide en la fase 1. Aquí `IssuanceLog::from_entries` deja el enganche. |
| `zk-ssl-wire` (DTOs JSON-RPC, OpenRPC generado del código) | **rehacer** | El cable de MTC es HTTP: ACME hacia el solicitante, tlog-tiles hacia monitores y espejos. La disciplina «el cable se genera del código y se congela en vectores» sí se conserva. |
| `zk-ssl-cli`, `zk-ssl-sdk` | **rehacer** | La CLI de un operador de CA no se parece a la de un libro. |
| `tools/canon.sh`, `tools/conformidad.sh`, la práctica de vectores por versión | **conservar la metodología** | Los cuatro vectores acumulados del borrador hacen aquí el papel de `spec/vectors/`. |

Dependencias que salen: `winterfell` y sus subcrates, `sled`,
`chacha20poly1305`, `xmss` (hasta la fase 4). Dependencias que entran: `sha2`,
`ml-dsa` (opcional, activada por defecto) y `hbs-state`.

### 2.2 Lo que se pierde a propósito, y conviene decir

- **La privacidad frente al operador.** Arqueo ocultaba el testigo de la
  prueba; en MTC el log es público por diseño (transparencia). No hay nada que
  ocultar y por eso no hay STARK.
- **La conservación.** El invariante de Arqueo era «suministro = saldos + en
  vuelo». El de una CA es «todo lo que emití está en mi log y todo lo que hay
  en mi log lo certifiqué», y lo hacen cumplir los cofirmantes y los monitores,
  no un circuito.
- **La cabeza de época como unidad de confianza.** En Arqueo cada cabeza viaja
  firmada. En MTC el certificado relativo a *landmark* no lleva firma alguna: la
  confianza la predistribuye el canal de actualización del cliente.

### 2.3 `hbs-state`: qué se conserva y para qué

Se conserva **entero y como dependencia**, no como copia. Su invariante es:

> ninguna firma puede existir con un índice mayor que el contador persistido.

Aplicado a una CA de MTC en dos sitios:

| dónde | qué guarda | por qué es el mismo invariante |
|---|---|---|
| `ca::run_checkpoint_job`, paso 0 | **el número de checkpoint**, reservado con `IndexGuard::reserve` (persistido con `fsync`) **antes** de firmar | Si el proceso muere entre firmar un checkpoint y persistir el log, al reiniciar existiría en el mundo una vista firmada que el log ya no puede reproducir: es una *split view*, y los testigos la detectan. Persistir antes de firmar convierte ese caso en un número huérfano (`CounterAhead`, el caso normal tras una caída) en vez de en una firma inconsistente. Al arrancar, `SequenceGuard::reconcile` compara con el diario: solo `KeyAhead` es fatal. |
| el cofirmante de la CA, si es XMSS/LMS | **el índice de firma**, como en `FirmanteCabeza` | La CA firma un checkpoint y dos subárboles por ciclo, no un certificado por solicitud: es el ritmo al que una firma con estado es viable. |

`IndexGuard::open` mide su propio `fsync` y se niega en `tmpfs`; el test de
extremo a extremo lo abre en `CARGO_TARGET_TMPDIR` y, si el guardián se niega,
lo dice y no mide, en vez de fingir que midió.

---

## 3. Diseño de hojas y pruebas (los `struct`)

Los nombres siguen al borrador, no a la hipótesis: donde ésta decía `MTCLeaf`,
aquí hay una estructura de trabajo `MtcLeaf` **y** la entrada que de verdad se
hashea, `MtcLogEntry`, porque son dos cosas distintas que tienen que cuadrar.

### 3.1 La hoja: `MtcLeaf` y `MtcLogEntry` (`src/entry.rs`)

```rust
/// Lo que la CA certifica de un solicitante (estructura de trabajo).
pub struct MtcLeaf {
    pub version: u8,                        // 2 = v3
    pub issuer: Vec<u8>,                    // Name DER: SIEMPRE el CA ID
    pub validity: Validity,                 // { not_before, not_after } POSIX
    pub subject: Vec<u8>,                   // Name DER del sujeto
    pub spki: Vec<u8>,                      // SubjectPublicKeyInfo DER, entero
    pub issuer_unique_id: Option<Vec<u8>>,
    pub subject_unique_id: Option<Vec<u8>>,
    pub extensions: Option<Vec<u8>>,        // Extensions DER (SAN, key usage…)
}

/// Lo que se anota en el log (serialización TLS del borrador).
pub enum MtcLogEntry {
    Null    { extensions: Vec<LogEntryExtension> },
    TbsCert { extensions: Vec<LogEntryExtension>, tbs_cert_entry_data: Vec<u8> },
}
```

Frente al boceto `(public_key, subject, validity, extensions)`:

- `public_key` **no va en la hoja**: va `subjectPublicKeyAlgorithm` más el
  **hash** del SPKI (`subjectPublicKeyInfoHash`, con el hash del log). Es la
  razón por la que el log no crece con ML-DSA. La clave entera va en el
  certificado.
- `validity` y `extensions` son campos X.509 normales, por certificado.
- Hay **dos** juegos de extensiones: las X.509 (dentro del TBS) y las de la
  entrada del log (`LogEntryExtension`, TLV, normalmente vacías), que también
  viajan en el `MTCProof`.

De una `MtcLeaf` salen dos codificaciones que un test cruza byte a byte:
`tbs_cert_entry_data()` (los campos del `TBSCertificateLogEntry` concatenados,
sin cabecera, para que el verificador hashee en un solo paso) y
`tbs_certificate(serial)` (el `TBSCertificate` con `serialNumber = (log << 48)
| index` y `signature = id-alg-mtcProof`).

### 3.2 El subárbol y la prueba de inclusión (`src/subtree.rs`, `src/proof.rs`)

```rust
/// Un subárbol [start, end): start múltiplo de BIT_CEIL(end - start).
pub struct Subtree { pub start: u64, pub end: u64 }

/// MTCProof: lo que va en el signatureValue del certificado.
pub struct MtcProof {
    pub extensions: Vec<LogEntryExtension>,   // las de la entrada, copiadas
    pub subtree: Subtree,                     // uint48 start, uint48 end
    pub inclusion_proof: Vec<HashValue>,      // ceil(log2(size)) hashes como mucho
    pub signatures: Vec<SubtreeSignature>,    // vacío en un cert. relativo a landmark
}

pub struct SubtreeSignature { pub cosigner_id: TrustAnchorId, pub signature: Vec<u8> }

/// El certificado: un TBSCertificate X.509 en DER y su prueba.
pub struct MtcCertificate { pub tbs_certificate: Vec<u8>, pub proof: MtcProof }
```

Las cofirmas van en orden canónico por `cosigner_id` (primero las más cortas,
luego lexicográfico) y el decodificador rechaza repetidos y desorden, como
exige el borrador.

### 3.3 Lo que se firma (`src/cosign.rs`)

```rust
pub struct CosignedMessage {
    pub cosigner_id: TrustAnchorId,   // "oid/1.3.6.1.4.1.32473.1"
    pub timestamp: u64,               // 0 dentro de un certificado
    pub log_id: TrustAnchorId,        // caID.0.N
    pub subtree: Subtree,
    pub subtree_hash: HashValue,
}
// etiqueta fija "subtree/v1\n\0" delante: compatible con tlog-witness
```

### 3.4 Lo que la parte que confía necesita (`src/verify.rs`)

```rust
pub struct RelyingPartyConfig {
    pub ca_id: TrustAnchorId,
    pub cosigners: Vec<(TrustAnchorId, Box<dyn CosignatureVerifier>)>,
    pub required_cosigners: Vec<TrustAnchorId>,   // la CA + un quórum de testigos
    pub trusted_subtrees: Vec<TrustedSubtree>,    // landmarks predistribuidos
    pub revoked_ranges: Vec<(u64, u64)>,          // por número de serie
}
```

---

## 4. Flujo de trabajo, paso a paso

### 4.1 De la solicitud al certificado (la CA)

```text
 CSR (PKCS#10)            ┐
 reto ACME / validación   ├─ capa de arriba: x509-cert + ACME (fase 2)
 prueba de posesión       ┘
        │
        ▼  CertificateRequest { subject, spki, validity, extensions }   ya validada
 ┌──────────────────────────────────────────────────────────────────────┐
 │ CertificationAuthority::submit                                       │
 │   MtcLeaf { issuer = Name(caID), … }                                 │
 │   → MtcLogEntry::TbsCert { tbs_cert_entry_data }                     │
 │   → IssuanceLog::append   (hoja = SHA256(0x00 || entrada))           │
 │   → índice i                                                         │
 └──────────────────────────────────────────────────────────────────────┘
        │  … cada pocos segundos, el trabajo de checkpoint …
        ▼
 ┌──────────────────────────────────────────────────────────────────────┐
 │ CertificationAuthority::run_checkpoint_job(now)                      │
 │  0. guard.reserve()               ← fsync ANTES de firmar (hbs-state)│
 │  1. CA firma [0, tree_size) con timestamp = now   (checkpoint)       │
 │  2. (izq, der) = covering_subtrees(último_checkpoint, tree_size)     │
 │  3. CA firma cada subárbol con timestamp = 0                         │
 │  4. cada cofirmante externo firma cada subárbol                      │
 │  5. → SignedSubtree { subtree, hash, signatures ordenadas }          │
 └──────────────────────────────────────────────────────────────────────┘
        │
        ├─▶ standalone_certificate(i): TBSCertificate(serial) +
        │     MTCProof { subárbol que contiene i, PATH(i), cofirmas }
        │
        └─▶ (cada hora) allocate_landmark(now) → landmark L = tree_size actual
            landmark_relative_certificate(i): mismo TBS +
              MTCProof { subárbol del landmark que contiene i, PATH(i), ∅ }
```

En código, el ciclo completo cabe en una pantalla (`examples/demo_ca.rs`):

```rust
let mut ca = CertificationAuthority::new(cfg, Box::new(ca_signer), IndexGuard::open(ruta)?)?;
ca.add_cosigner(Box::new(witness));

let i = ca.submit(request)?;                      // 3a · al log
let cp = ca.run_checkpoint_job(now)?;             // 0-4 · reservar, firmar, cubrir, cofirmar
let standalone = ca.standalone_certificate(i)?;   // 5  · prueba + cofirmas
let der = standalone.to_der()?;                   // X.509 con id-alg-mtcProof

ca.allocate_landmark(now)?;                       // cada hora
let relative = ca.landmark_relative_certificate(i)?;   // prueba sola, sin firmas
```

### 4.2 El «Top Hash» y por qué no hay que recalcularlo

El hash del checkpoint es `MTH(D[0:tree_size])`. `IssuanceLog` guarda un vector
por nivel con los **nodos completos**, así que `append` cierra los pares que se
completan (O(log n) amortizado) y `root()` o `subtree_hash([start, end))` bajan
por el borde derecho en O(log n) consultas. La memoria es `2n` hashes. Un test
recorre todos los subárboles de todos los árboles hasta 130 hojas y exige el
mismo hash y las mismas pruebas que la recursión literal de RFC 9162.

### 4.3 De vuelta: la parte que confía (`verify::verify_certificate`)

1. `signatureAlgorithm` e `id-alg-mtcProof`; decodificar el `MTCProof` sin restos.
2. `serial` no negativo de 64 bits; rechazar si cae en un rango revocado.
3. `index = serial & (2^48-1)`, `log_number = serial >> 48` (cero: rechazar).
4. `issuer` ha de ser el `Name` del CA ID configurado; `log_id = caID.0.N`.
5. Reconstruir la entrada **desde el `TBSCertificate`** (versión, emisor,
   validez, sujeto, algoritmo de la clave, `OCTET STRING(SHA256(SPKI))`, el
   resto) y hashearla con `0x00` delante.
6. Evaluar la prueba de inclusión → hash de subárbol *esperado*.
7. Si `(log_number, start, end)` es un subárbol de confianza, comparar hashes
   y terminar. Si no, exigir una cofirma válida de **cada** cofirmante
   requerido sobre `CosignedMessage { …, subtree_hash = esperado }`.
8. Seguir con el resto de la validación X.509 (aquí, la caducidad).

### 4.4 Cifras del ejemplo (`cargo run --release --example demo_ca`)

| | subárbol | hashes | cofirmas | bytes DER |
|---|---|---|---|---|
| *standalone* de la entrada 6 | `[6, 8)` | 1 | 2 (CA + testigo, ML-DSA-44) | 5.095 |
| relativo al *landmark* 1 de la misma entrada | `[4, 8)` | 2 | 0 | **271** |

Una clave pública ML-DSA-44 mide 1.312 bytes y una firma 2.420: el
*standalone* es casi todo firmas, y por eso el borrador insiste en que las
partes que confían negocien cofirmantes en vez de exigirlos todos.

---

## 5. Esqueleto de código: mapa de módulos

| módulo | contenido | viene de |
|---|---|---|
| `hash` | `MTH` de RFC 9162 sobre SHA-256: `hash_empty`, `hash_leaf`, `hash_node` | sustituye a `zk-ssl-hash` |
| `subtree` | `Subtree`, `is_valid_subtree`, `covering_subtrees`, `inclusion_proof` / `evaluate_inclusion_proof` / `verify_inclusion_proof`, `consistency_proof` / `verify_consistency_proof`, el trait `TreeHashes` y la referencia `LeafHashes` | `zk-ssl-verify::mmr` |
| `log` | `IssuanceLog`: *append-only*, nodos completos en caché, `from_entries` para arrancar | la idea de `zk-ssl::sparse_tree` |
| `entry` | `MtcLeaf`, `MtcLogEntry`, `LogEntryExtension`, `Validity`, `entry_bytes_from_tbs` | nuevo |
| `der` | lo mínimo de DER/X.509: TLV, INTEGER, OID, tiempos, el `Name` del CA ID, `parse_tbs`, `parse_certificate` | nuevo |
| `tai` | `TrustAnchorId`: ASCII, binario, `oid/…`, IDs de log/landmark/grupo, orden canónico | nuevo |
| `cosign` | `CosignedMessage`, `Cosigner`, `CosignatureVerifier`, `SignedSubtree`; `mldsa::{MlDsaCosigner, MlDsaVerifier}` | `firma_cabeza` |
| `guard` | `SequenceGuard` sobre `hbs_state::IndexGuard`; `MemoryGuard` solo para tests | `hbs-state` |
| `landmark` | `LandmarkSequence`: asignar, subárboles de cada landmark, activos, publicar | nuevo |
| `proof` | `MtcProof` (codificación TLS) y `MtcCertificate` (DER) | `zk-ssl-verify::inclusion` |
| `ca` | `CertificationAuthority`: `submit`, `run_checkpoint_job`, `standalone_certificate`, `allocate_landmark`, `landmark_relative_certificate`, `active_landmark_subtrees` | `zk-ssl-node` |
| `verify` | `verify_certificate` para la parte que confía, sin compilar la CA | `zk-ssl-verify` |

Cómo se prueba, en tres capas:

- **Contra el borrador**: `tests/vectors.rs` reproduce los cuatro vectores
  acumulados del apéndice de test (hashes de subárbol, pruebas de inclusión,
  pruebas de consistencia, subárboles de cobertura), que cubren todos los
  subárboles de todos los árboles hasta 130 hojas, más los casos grandes de
  validez y cobertura hasta `2^64-1`. Incluye el ejercicio que el borrador
  pide al verificador: cada prueba evaluada, y rechazada al recortarla,
  alargarla o cambiar un bit.
- **Contra sí mismo**: la caché de `IssuanceLog` frente a la recursión de
  referencia; la entrada que la CA anota frente a la que el verificador
  reconstruye; el `MTCProof` codificado frente al decodificado.
- **De extremo a extremo**: `tests/end_to_end.rs` emite con ML-DSA-44 en la CA
  y en un testigo, verifica *standalone* y relativo a *landmark*, y comprueba
  que fallan la manipulación del SAN, la cofirma ausente, la prueba de otro
  índice, la revocación por rango, la caducidad y el emisor desconocido; y
  abre un `IndexGuard` real en disco para comprobar que el número de checkpoint
  sobrevive al proceso y se reconcilia.

---

## 6. Plan de implementación por fases

**Fase 0 — este directorio.** El núcleo verificable: árbol, subárboles,
pruebas, entradas, cofirmas, landmarks, CA en memoria y verificador. Hecho.

**Fase 1 — persistencia y arranque.** Un almacén *append-only* de entradas
(fichero con `fsync` por checkpoint, o `sled` como en `zk-ssl::persistence`),
`IssuanceLog::from_entries` al arrancar, y la reconciliación
`guard.reconcile(último_checkpoint_del_diario)` con la política de Arqueo: solo
`KeyAhead` impide arrancar. Medir el arranque con un millón de entradas, como
hizo el banco B.4 de Arqueo.

**Fase 2 — la entrada real.** Parseo de CSR PKCS#10 y construcción de
`Name`/`Extensions` con `x509-cert`; validación de dominio y prueba de posesión
por ACME (RFC 8555) con la extensión del borrador (el enlace
`mtc-landmark-relative` para recoger después el certificado relativo). Este
crate no cambia: recibe `CertificateRequest`.

**Fase 3 — el log hacia fuera.** Servir el log con tlog-tiles según el perfil
MTC de C2SP, y pedir cofirmas a testigos reales con el protocolo tlog-witness:
el `CosignedMessage` de aquí ya lleva la etiqueta y el `log_origin` que ese
protocolo espera; queda alinear el nombre de clave y el *key id* de
TLOG-COSIGNATURE para ML-DSA-44. Los `consistency_proof` de `subtree` son lo
que un testigo comprueba antes de cofirmar.

**Fase 4 — la CA como ancla de confianza.** El certificado de la CA con la
extensión `MTCCertificationAuthority { sigAlg, minSerial, maxSerial }`; un
cofirmante XMSS/LMS con `hbs-state` delante (el mismo `Cosigner`, `&mut self`
ya lo admite); y el lado TLS: `trust_anchors` con los grupos de landmark
(`caID.2.N.L`) en `rustls`, para que el servidor elija entre el *standalone* y
el relativo.

**Fase 5 — el fork.** Repositorio nuevo con este directorio como raíz; de
Arqueo se llevan la metodología (canon de tests por crate, vectores congelados
por versión, un asiento por cambio) y nada del código STARK.

---

## 7. Lo que este esqueleto no afirma

- **No está auditado.** Ni este código, ni `ml-dsa` (lo declara su propio
  crate), ni `hbs-state`. Los OID son los experimentales del arco
  `1.3.6.1.4.1.44363.47` que el borrador reserva para eso, y el borrador puede
  cambiar: la versión leída es la del repositorio de trabajo del grupo PLANTS
  a 29 de septiembre de 2026.
- **No hay interoperabilidad medida** con otra implementación. La
  implementación pública en Go de Cloudflare avisa de que sigue el diseño
  anterior de lotes; los cuatro vectores acumulados del borrador son la única
  referencia externa que este código pasa.
- **No hay validación de solicitudes**: `CertificateRequest` llega validada.
  Certificar lo que llega es de este crate; que sea verdad, del operador.
- **No persiste el log**, solo el contador del guardián. Y `MemoryGuard`
  existe para poder medir sin disco: una CA que arranque con él reutiliza
  números de checkpoint tras cada caída.
- **La política de cofirmantes es la mínima** («todos estos»). Quórums,
  negociación de cofirmantes en TLS y espejos quedan para la fase 3.
- **No está medido a escala.** La caché es O(log n) por construcción, pero
  los tiempos con millones de entradas no se han medido, y en Arqueo esa
  medición cambió el diseño dos veces.
