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
