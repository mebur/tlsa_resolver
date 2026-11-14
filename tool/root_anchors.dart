// Compares the built-in root trust anchors with IANA's published list
// (https://data.iana.org/root-anchors/root-anchors.xml), so a root key
// rollover or revocation shows up as a failing CI job instead of as users'
// lookups turning bogus.
//
//   dart run tool/root_anchors.dart [--file root-anchors.xml]
//
// Exit codes: 0 in step, 1 out of step (the built-in list needs a change),
// 2 the list could not be fetched or read.
//
// This only raises an alarm: the file is fetched over HTTPS and not checked
// against IANA's detached signature, and any change to the anchors is made
// and reviewed by hand.

// ignore_for_file: avoid_print

import 'dart:io';

import 'package:tlsa_resolver/src/dnssec/trust_anchors.dart';

final _url = Uri.https('data.iana.org', '/root-anchors/root-anchors.xml');

Future<void> main(List<String> args) async {
  final String xml;
  try {
    final file = args.indexOf('--file');
    xml = file >= 0 ? await File(args[file + 1]).readAsString() : await _fetch();
  } catch (e) {
    print('Could not get the root anchors: $e');
    exit(2);
  }

  final List<_Anchor> published;
  try {
    published = _parse(xml);
  } on FormatException catch (e) {
    print('Could not read the root anchors: ${e.message}');
    exit(2);
  }

  final now = DateTime.now().toUtc();
  final builtIn = {for (final ds in rootTrustAnchors) _key(ds.keyTag, ds.algorithm, ds.digestType, ds.digest)};
  final problems = <String>[];

  for (final a in published) {
    final key = _key(a.keyTag, a.algorithm, a.digestType, a.digest);
    final retired = a.validUntil != null && !a.validUntil!.isAfter(now);
    if (retired && builtIn.remove(key)) {
      problems.add('Key tag ${a.keyTag} is built in but IANA ended it on ${a.validUntil}: remove it.');
    } else if (!retired && !builtIn.remove(key)) {
      problems.add('Key tag ${a.keyTag} (valid from ${a.validFrom}) is published by IANA '
          'but not built in: add it.');
    } else if (!retired) {
      print('Key tag ${a.keyTag}: built in, valid from ${a.validFrom}.');
    }
  }
  for (final key in builtIn) {
    problems.add('Built-in anchor $key is not in IANA\'s list: remove it.');
  }

  if (problems.isEmpty) {
    print('The built-in root trust anchors match IANA\'s list.');
    return;
  }
  problems.forEach(print);
  print('Update lib/src/dnssec/trust_anchors.dart (and its documentation).');
  exit(1);
}

Future<String> _fetch() async {
  final client = HttpClient()..connectionTimeout = const Duration(seconds: 20);
  try {
    final request = await client.getUrl(_url);
    final response = await request.close().timeout(const Duration(seconds: 30));
    if (response.statusCode != HttpStatus.ok) {
      throw HttpException('HTTP ${response.statusCode}', uri: _url);
    }
    return await response.transform(const SystemEncoding().decoder).join();
  } finally {
    client.close(force: true);
  }
}

class _Anchor {
  _Anchor(this.keyTag, this.algorithm, this.digestType, this.digest, this.validFrom, this.validUntil);
  final int keyTag;
  final int algorithm;
  final int digestType;
  final List<int> digest;
  final DateTime validFrom;
  final DateTime? validUntil;
}

/// Reads the KeyDigest elements of a TrustAnchor document (RFC 9718 §2).
List<_Anchor> _parse(String xml) {
  if (!RegExp(r'<Zone>\s*\.\s*</Zone>').hasMatch(xml)) {
    throw const FormatException('Not the root zone\'s trust anchors');
  }
  final anchors = <_Anchor>[];
  for (final m in RegExp(r'<KeyDigest\b([^>]*)>(.*?)</KeyDigest>', dotAll: true).allMatches(xml)) {
    final attributes = m[1]!, body = m[2]!;
    String element(String name) {
      final e = RegExp('<$name>\\s*([^<]*?)\\s*</$name>').firstMatch(body);
      if (e == null) throw FormatException('KeyDigest without $name');
      return e[1]!;
    }

    DateTime? attribute(String name) {
      final a = RegExp('$name="([^"]*)"').firstMatch(attributes);
      return a == null ? null : DateTime.parse(a[1]!).toUtc();
    }

    final hex = element('Digest');
    anchors.add(_Anchor(
      int.parse(element('KeyTag')),
      int.parse(element('Algorithm')),
      int.parse(element('DigestType')),
      [for (var i = 0; i < hex.length; i += 2) int.parse(hex.substring(i, i + 2), radix: 16)],
      attribute('validFrom') ?? (throw const FormatException('KeyDigest without validFrom')),
      attribute('validUntil'),
    ));
  }
  if (anchors.isEmpty) throw const FormatException('No KeyDigest elements');
  return anchors;
}

String _key(int keyTag, int algorithm, int digestType, List<int> digest) =>
    '$keyTag/$algorithm/$digestType/${digest.map((b) => b.toRadixString(16).padLeft(2, '0')).join()}';
