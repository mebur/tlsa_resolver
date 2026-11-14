## 0.1.2

Fixes from a security review.

* **Breaking:** a DANE-TA (usage 2) match is now
  `DaneOutcome.needsChainCheck` instead of `DaneOutcome.verified`, so
  `isVerified` is false until the caller has checked the chain and the
  name. Before, a server could send any leaf followed by a copy of the
  real anchor certificate and get `verified`. A DANE-TA match on the leaf
  itself is reported the same way, since the name check still applies, and
  a match that needs no further checks is preferred over a DANE-TA match.
* An answer expanded from an NSEC-signed wildcard now has to prove that the
  wildcard's parent is the closest encloser (RFC 4035 §5.3.4). Before, a
  wildcard answer could be replayed as secure for a name below an existing
  name, which the wildcard does not cover.
* Responses are grouped into RRsets in linear time. A 64 KiB response of
  thousands of records took about 430 ms to process before and about
  85 ms now, so a hostile resolver can no longer keep a lookup busy for
  long.
* Zone keys are cached no longer than the DNSKEY signature's remaining
  lifetime and original TTL, or the DS TTL, and not at all when the
  signature only counted because of `clockSkew`.
* Unsigned data whose zone could not be looked up (no answer, malformed
  response, or a spent budget) is now indeterminate with that error,
  instead of bogus with `rrsigsMissing`.
* Ed25519 public keys and signature R values of small order are refused,
  as libsodium does. `ed25519_edwards` accepts them, and with such a key
  (the identity key, say) a signature verifies for any message. No honestly
  made key or signature has one. A new test suite pins the package's
  outcome on all 210 Wycheproof Ed25519 vectors and the 12
  ed25519-speccheck edge cases, so an update that changes its behaviour is
  caught.
* NSEC3 records whose owner or next hash is not 20 bytes (SHA-1) are
  ignored: a short next hash would cover far more than the zone meant.
* `lookup` throws an `ArgumentError` for a non-ASCII host or protocol
  instead of looking up raw UTF-8, which never exists and made DANE quietly
  not apply. Pass internationalised names in A-label (`xn--`) form.

## 0.1.1

* Allows code_assets 2.x (now `^2.2.0`) and requires native_toolchain_c
  0.19.6 or later for the build hook. No change at run time.

## 0.1.0

* TLSA lookups through the system resolver (Android 10+, iOS, macOS, Linux)
  or directly to a chosen resolver.
* Local DNSSEC validation from the root trust anchors, with NSEC/NSEC3
  denial of existence.
* DANE certificate matching (RFC 6698 / RFC 7671).
* `Sha1Policy` chooses whether RSASHA1 and SHA-1 DS digests are accepted,
  treated as unsupported (insecure) or rejected (bogus).
* SHA-1 DS records are ignored when a stronger digest is present
  (RFC 4509 §3).
* Each lookup is bounded by `maxQueries` (default 64) and `timeout`
  (default 20 s).
* Bounded signature work per lookup against KeyTrap (CVE-2023-50387):
  `maxSignatureChecks`, and caps on keys per signature and signatures per
  RRset.
* RSA keys limited to 512–4096 bits with exponents of at most 8 bytes;
  ECDSA keys must lie on the curve.
* Duplicate records are removed from RRsets (RFC 2181 §5).
* `TlsaResolver.inBackground` and `IsolateValidator` validate on a
  long-lived background isolate, keeping signature checks off the UI
  isolate. `TlsaResolver.validator` is now a `DnssecLookup`.
* The zone key cache holds at most `maxCachedZones` zones (default 1000),
  dropping the least recently used.
* The native shim rejects invalid arguments, and is built with warnings and
  stack protection, `_FORTIFY_SOURCE` and, in CI, sanitizers.
* A root key set that matches no trust anchor is reported as likely stale
  anchors, with the key tags involved.
* `lookup` uses the CNAME-expanded host name as TLSA base domain first when
  the chain is secure (RFC 7671 §7); `followCname: false` turns this off.
* Queries advertise a 1232-byte EDNS0 UDP payload (RFC 9715) instead of
  4096, so large answers come back truncated and are fetched over TCP
  rather than fragmented.
* `DohTransport`: DNS over HTTPS (RFC 8484), with presets for Cloudflare
  and Google. Servers must accept HTTP/1.1.
* `ValidatedAnswer.error` / `TlsaResult.error`: a `ValidationError` with the
  closest Extended DNS Error code (RFC 8914) for every non-secure answer
  that is a failure, alongside the `reason` text. Expired and not yet valid
  signatures, and NSEC3 opt-out and iteration limits, are told apart.
* `clockSkew` (default one hour) lets signatures count slightly outside
  their validity period, for devices with a wrong clock.
* `negativeTrustAnchors` (RFC 7646): time-limited exceptions for domains
  whose DNSSEC is known to be broken.
