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

// Reuse it: validated zone keys are cached. In a Flutter app, validate on
// a background isolate so signature checks never stall the UI.
final resolver = TlsaResolver.inBackground();

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

`TlsaResolver.inBackground()` runs the validator, its transport and its key
cache on a long-lived background isolate (`IsolateValidator`); call
`resolver.close()` when done, as the isolate keeps the program alive. Plain
`TlsaResolver()` validates on the calling isolate, which suits command-line
tools and servers.

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

`DohTransport` sends queries over DNS over HTTPS (RFC 8484), for networks
whose resolver strips DNSSEC records or should not see the queries. The
answers are still validated locally:

```dart
final resolver = TlsaResolver.inBackground(transport: DohTransport.cloudflare());
```

It uses `dart:io`'s HTTP/1.1 client, so the server must accept HTTP/1.1;
Cloudflare and Google do, Quad9's DoH service requires HTTP/2.

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
* Bounded work per lookup against KeyTrap-style attacks (CVE-2023-50387):
  at most 4 keys tried per signature, 8 signatures per RRset and
  `maxSignatureChecks` (default 64) verifications per lookup. RSA keys must
  be 512–4096 bits (RFC 3110) with an exponent of at most 8 bytes, and
  ECDSA keys must be points on the curve.
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
    maxCachedZones: 200,
    timeout: const Duration(seconds: 10),
  ),
);
```

## Why an answer is not secure

`result.reason` explains a non-secure answer in words; `result.error` gives a
`ValidationError` for programs to act on (`signatureExpired`,
`signatureNotYetValid`, `dnskeyMissing`, `rrsigsMissing`, `nsecMissing`,
`networkError`, ...). Each carries `edeCode`, the closest Extended DNS Error
code (RFC 8914). Plainly unsigned zones and NSEC3 opt-out are insecure
without an error.

```dart
if (result.error == ValidationError.signatureNotYetValid) {
  // Probably the device clock: tell the user rather than blame the server.
}
```

## Where TLSA records are looked up

`lookup(host, port: …)` follows RFC 7671 §7. When `host` is an alias whose
CNAME chain validates, the records are looked up at the chain's final target
first and at `host` only if the target has none; with an insecure chain,
`host` alone is used. `result.answer.name` says which name answered. A bogus
or unanswered address lookup is returned as a failure rather than a
fallback. `followCname: false` skips the address lookup, and `lookupName`
takes an explicit owner name such as `_25._tcp.mail.example.com`.

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

### Differential testing against Unbound

`tool/differential.dart` looks up about 750 names with this validator and
with Unbound's `unbound-host`, which recurses and validates independently,
using the same root trust anchors, and lists every answer they disagree on.
The corpus covers signed and unsigned domains across many TLDs, denial
proofs for missing names, DANE for SMTP at each domain's mail servers, and
RootCanary's test zones for every algorithm, DS digest and NSEC type, each
with a validly and an invalidly signed name.

```sh
brew install unbound            # or: apt-get install unbound-host
dart run tool/differential.dart               # validator via 9.9.9.9
dart run tool/differential.dart --system      # via the system resolver
```

It exits with 1 when the two disagree on whether an answer is secure, on the
status, or on the data of a secure answer. Expected differences are listed
in the tool with their reason; currently that is only Ed448 (algorithm 16),
which this package does not support. CI runs it on every push and weekly.

* Signatures count up to `clockSkew` (default one hour) outside their
  validity period, since phone clocks are often a few minutes off;
  `Duration.zero` is strict. A signature that is still outside reports
  `signatureExpired` or `signatureNotYetValid`.
* `negativeTrustAnchors` (RFC 7646) maps domains whose DNSSEC is known to be
  broken to the time the exception ends; until then, answers at or below
  them are insecure instead of bogus. Use them briefly: meanwhile a forged
  answer there is accepted as merely insecure.
* Zone keys are cached for their TTL, for at most `maxCachedZones` zones
  (default 1000); past that the least recently used zone is dropped.

### Native code

The C shim checks its arguments (null buffers, non-positive lengths and
timeouts) before calling the platform API, and the build hook compiles it
with `-Wall -Wextra -Wformat=2 -fstack-protector-strong -D_FORTIFY_SOURCE=2`
for clang and gcc. CI also builds it with `-Werror`, `-Wconversion` and
friends, and runs `test/native/shim_test.c` under AddressSanitizer and
UndefinedBehaviorSanitizer on Linux and macOS:

```sh
mkdir -p build && cc -std=gnu11 -Wall -Wextra -Werror -g -fsanitize=address,undefined \
  -Isrc src/tlsa_resolver.c test/native/shim_test.c -lresolv -o build/shim_test && build/shim_test
```

### Crypto test vectors and fuzzing

`test/wycheproof_test.dart` runs Project Wycheproof's Ed25519, ECDSA and
RSA PKCS#1 signature vectors (vendored in `test/wycheproof/`) through the
signature checks. `test/fuzz_test.dart` corrupts responses on the way to
the validator (bit flips, truncation, dropped, duplicated and moved records,
replayed signed records, forged denials) and checks that a lookup never
throws and never comes out secure with anything but the untampered answer.

```sh
FUZZ_ITERATIONS=100000 dart test test/fuzz_test.dart   # longer run
FUZZ_SEED=1234 dart test test/fuzz_test.dart           # replay a failure
```

`device_test/` is a Flutter app that runs a live test suite on a phone or
tablet; see its README.

The offline tests run the validator against a fake resolver serving an
Ed25519-signed test hierarchy, covering both the success paths and the
tampering cases.
