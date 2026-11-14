# ed25519-speccheck test vectors

`cases.json` holds the 12 Ed25519 edge cases from
[novifinancial/ed25519-speccheck](https://github.com/novifinancial/ed25519-speccheck)
at commit `65519336fda78a3d016e947df6d82848aca0c9da`, unchanged. They come
from "Taming the many EdDSAs" (Chalkias, Garillot and Nikolaenko, SSR 2020,
https://eprint.iacr.org/2020/1244) and test small-order and mixed-order
points, cofactored against cofactorless verification, S out of range and
non-canonical encodings. The upstream README has the table of what each case
tests and how libraries handle it.

Licensed under the Apache License 2.0 (`LICENSE`). `test/ed25519_test.dart`
runs them.
