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
