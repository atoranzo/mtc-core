# Vectores grandes del borrador

`large_inclusion_proofs.json` y `large_consistency_proofs.json` son los
ficheros que el apendice «Large Subtree Test Vectors» de
`draft-ietf-plants-merkle-tree-certs` referencia, copiados tal cual del
directorio `demo/` del repositorio de trabajo del grupo PLANTS
(`ietf-plants-wg/merkle-tree-certs`, commit `99097c9`, 29-09-2026). Son
pruebas sobre arboles de `2^48-1`, `2^63-1` y `2^64-1` hojas, que ninguna
implementacion puede construir: ejercitan al **verificador**, que ha de
evaluarlas con enteros de 64 bits sin desbordar.

Los lee `tests/large_vectors.rs` con un lector de JSON y base64 escrito a
mano, para que `serde` no entre por la puerta de atras.

## Licencia de estos dos ficheros

El repositorio del que proceden declara que todo su material son
contribuciones al proceso de estandarizacion del IETF (BCP 78, BCP 79 y las
*IETF Trust Legal Provisions*), y que sus componentes de codigo, incluidos
los vectores de prueba, quedan bajo la **Simplified BSD License** del IETF
Trust. Se conservan aqui con esa licencia y esta atribucion, aparte de la
licencia MIT OR Apache-2.0 del resto del crate:

> Copyright (c) IETF Trust and the persons identified as authors of the
> code. All rights reserved. Redistribution and use in source and binary
> forms, with or without modification, is permitted pursuant to, and
> subject to the license terms contained in, the Simplified BSD License
> set forth in Section 4.c of the IETF Trust's Legal Provisions Relating
> to IETF Documents (https://trustee.ietf.org/license-info).
