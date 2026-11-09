# tlsa_resolver

Resolve DNS TLSA records with **local DNSSEC validation**, and match TLS
certificates against them (DANE, RFC 6698 / RFC 7671).

Queries go through the operating system's resolver, so they follow the
device's DNS settings (DHCP, VPN, Android Private DNS). The answers are not
trusted as they come: the library fetches the RRSIG, DNSKEY, DS, NSEC and
NSEC3 records and checks the whole chain of trust itself, from the IANA root
trust anchors down to the TLSA record.

```dart
import 'package:tlsa_resolver/tlsa_resolver.dart';

final resolver = TlsaResolver(); // reuse it: validated zone keys are cached

final result = await resolver.lookup('mail.example.com', port: 25);

switch (result.status) {
  case SecurityStatus.secure:
    // result.usableRecords holds authenticated TLSA records (may be empty:
    // the absence of TLSA is proven too).
  case SecurityStatus.insecure:
    // The name is in an unsigned zone: DANE does not apply.
  case SecurityStatus.bogus:
  case SecurityStatus.indeterminate:
    // Validation failed or no answer: do not fall back to plain TLS
    // silently; defer or refuse the connection (result.reason says why).
}

// After the TLS handshake, check the server's chain (DER, leaf first):
final verdict = DaneVerifier.verify(result, chain, pkixValidated: platformSaidOk);
if (verdict.outcome == DaneOutcome.mismatch ||
    verdict.outcome == DaneOutcome.lookupFailed) {
  // reject
}
```

## Platforms

| Platform | System resolver API | Notes |
|---|---|---|
| Android 10+ (API 29) | `android_res_nsend` (NDK), default network | Needs the `INTERNET` permission. Looked up at run time, so the library loads on older versions but throws `DnsTransportException`. |
| iOS, macOS | `res_nsend` (libresolv) | Sandboxed macOS apps need `com.apple.security.network.client`. |
| Linux | `res_nsend` (glibc libresolv) | |
| Windows, Android < 10 | — | Use `DirectDnsTransport`. |
| Web | — | Not supported (no raw DNS). |

Any `DnsTransport` can be plugged in. `DirectDnsTransport` talks UDP/TCP
straight to a resolver of your choice:

```dart
final resolver = TlsaResolver(
  transport: DirectDnsTransport(InternetAddress('9.9.9.9')),
);
```

The native code is compiled by the package's build hook (`hook/build.dart`,
`package:native_toolchain_c`); there are no platform plugin classes.

The system resolver only has to pass DNSSEC records through (EDNS0 with the
DO bit). Most public and ISP resolvers do. Ones that strip them make every
signed name come back `bogus`, which is the safe failure.

## What gets validated

* RRSIG verification for RSA/SHA-1, RSA/SHA-256, RSA/SHA-512, ECDSA P-256 and
  P-384, and Ed25519 (algorithms 5, 7, 8, 10, 13, 14, 15). Zones signed only
  with unsupported algorithms are treated as insecure (RFC 4035 §5.2).
* DS digests SHA-1, SHA-256 and SHA-384. A SHA-1 DS is ignored when the
  same DS set has a stronger digest (RFC 4509 §3).
* `sha1:` sets how the SHA-1 based algorithms (RSASHA1, RSASHA1-NSEC3-SHA1
  and SHA-1 DS digests) are treated: `Sha1Policy.accept` (default) validates
  them, `unsupported` makes zones that depend on them `insecure`, and
  `reject` makes them `bogus`.
* Chain of trust from the root KSKs 20326 (KSK-2017) and 38696 (KSK-2024).
  Pass `trustAnchors:` to `DnssecValidator` to use others.
* Authenticated denial of existence with NSEC (RFC 4035) and NSEC3
  (RFC 5155), including NXDOMAIN, NODATA, empty non-terminals, wildcard
  answers and wildcard NODATA.
* Insecure delegations must be proven: an NSEC/NSEC3 record from the signed
  parent showing NS without DS (or an NSEC3 opt-out span). A resolver that
  strips signatures therefore yields `bogus`, never `insecure`.
* CNAME chains (every link is validated; the result is the weakest link) and
  CNAMEs synthesised from signed DNAMEs.
* NSEC3 with more than 150 iterations is treated as insecure (RFC 9276).
* Each lookup is capped at `maxQueries` DNS queries (default 64) and
  `timeout` (default 20 s), including the queries for zone keys and proofs;
  past either it is `indeterminate`. A resolver cannot keep a lookup busy
  with long delegation chains or slow answers.

```dart
final resolver = TlsaResolver(
  validator: DnssecValidator(
    const NativeDnsTransport(),
    sha1: Sha1Policy.unsupported,
    maxQueries: 32,
    timeout: const Duration(seconds: 10),
  ),
);
```

## DANE matching

`DaneVerifier.verify` follows RFC 7671:

* **DANE-EE (3)** matches the leaf certificate only; no PKIX or name checks.
* **DANE-TA (2)** matches any certificate in the presented chain. When it
  matches one other than the leaf, `verdict.requiresChainCheck` is true: you
  still need to check that the leaf chains to it and the name matches. This
  library does not build X.509 paths.
* **PKIX-TA (0) / PKIX-EE (1)** only count when `pkixValidated` is true.
* Records with unknown parameters or wrong digest lengths are ignored.

`DaneVerifier.recordFor(certDer)` computes the record to publish (default
`3 1 1`).

## Development

```sh
dart test                 # unit tests + live DNS tests
dart test -x network      # offline only
dart run tool/probe.dart _25._tcp.mail.ietf.org
```

`device_test/` is a Flutter app that runs a live test suite on a phone or
tablet; see its README.

The offline tests run the validator against a fake resolver serving an
Ed25519-signed test hierarchy, covering both the success paths and the
tampering cases.
