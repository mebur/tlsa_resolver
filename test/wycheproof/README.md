# Project Wycheproof test vectors

The `*_test.json` files are signature verification vectors from
[C2SP/wycheproof](https://github.com/C2SP/wycheproof) (`testvectors_v1/`)
at commit `d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9`, unchanged. Licensed
under the Apache License 2.0 (`LICENSE`).

`test/wycheproof_test.dart` runs them through `verifySignature`, and
`test/ed25519_test.dart` runs the Ed25519 ones against `ed25519_edwards`
directly as well.
