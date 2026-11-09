import 'dart:typed_data';

import '../wire/rdata.dart';

Uint8List _hex(String s) => Uint8List.fromList([
      for (var i = 0; i < s.length; i += 2) int.parse(s.substring(i, i + 2), radix: 16),
    ]);

/// The IANA root zone trust anchors (https://data.iana.org/root-anchors/),
/// as DS records for the root KSKs:
///
/// * KSK-2017 (key tag 20326), in use since 2018.
/// * KSK-2024 (key tag 38696), published in the root zone in January 2025
///   and taking over signing from October 2026.
///
/// Both are trusted so validation works across the rollover. Pass your own
/// list to [DnssecValidator] to pin a different set.
final List<Ds> rootTrustAnchors = List.unmodifiable([
  Ds(20326, 8, 2,
      _hex('e06d44b80b8f1d39a95c0b0d7c65d08458e880409bbc683457104237c7f8ec8d')),
  Ds(38696, 8, 2,
      _hex('683d2d0acb8c9b712a1948b27f741219298d0a450d612c483af444a4c0fb2b16')),
]);
