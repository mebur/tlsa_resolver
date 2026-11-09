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
