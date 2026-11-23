# X.509 fixtures

Certificates for `test/spki_fuzz_test.dart`, chosen for the shapes the
SubjectPublicKeyInfo extractor has to walk past:

| File | Why |
| --- | --- |
| `rsa2048-v1.der` | Version 1: no `[0]` version field |
| `rsa4096-sans.der` | 41 subjectAltNames and a long subject: 2-byte lengths |
| `p384.der`, `ed25519.der` | EC and EdDSA keys |
| `isrg-root-x1.der` | A real root (ISRG Root X1), RSA-4096 |
| `gts-root-r4.der` | A real root (GTS Root R4), P-384 |

The test-only certificates are self-signed, made with OpenSSL 4.1:

```sh
openssl req -x509 -x509v1 -newkey rsa:2048 -nodes -keyout /dev/null \
  -subj /CN=v1.example.test -days 3650 -outform DER -out rsa2048-v1.der
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-384 -nodes \
  -keyout /dev/null -subj /CN=p384.example.test -days 3650 -outform DER -out p384.der
# and so on; rsa4096-sans.der adds -addext subjectAltName=DNS:host1.example.test,...
```

The two roots come from the macOS system store.

`spki_sha256.json` has the SHA-256 of each certificate's
SubjectPublicKeyInfo as OpenSSL extracts it:

```sh
openssl x509 -inform DER -in f.der -noout -pubkey \
  | openssl pkey -pubin -outform DER | openssl dgst -sha256
```
