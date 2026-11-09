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
