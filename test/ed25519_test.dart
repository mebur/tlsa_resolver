import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:ed25519_edwards/ed25519_edwards.dart' as ed25519;
import 'package:test/test.dart';
import 'package:tlsa_resolver/src/dnssec/crypto.dart';

/// ed25519_edwards is a small pure-Dart port and the least reviewed of the
/// crypto dependencies, so its behaviour is pinned here against Project
/// Wycheproof's Ed25519 vectors (test/wycheproof/ed25519_test.json), all
/// of them, including the "acceptable" ones whose outcome RFC 8032 leaves
/// open, and against the 12 edge cases of ed25519-speccheck
/// (test/ed25519_speccheck/cases.json, from "Taming the many EdDSAs",
/// Chalkias, Garillot and Nikolaenko, SSR 2020), on which implementations
/// disagree. A dependency update that changes any outcome fails these
/// tests, so it can be looked at before it ships.
void main() {
  final vectors = [
    for (final group in _groups())
      for (final t in (group['tests'] as List).cast<Map<String, dynamic>>())
        _Vector(_hex(group['publicKey']['pk'] as String), t),
  ];

  test('the vectors are all there', () {
    expect(vectors, hasLength(210));
  });

  group('ed25519_edwards itself', () {
    test('verifies every valid vector and refuses every invalid one', () {
      final wrong = [
        for (final v in vectors)
          if (v.result != 'acceptable' && v.libraryVerifies != (v.result == 'valid')) v,
      ];
      expect(wrong, isEmpty, reason: wrong.join('\n'));
    });

    test('accepts the small-order and mixed-order keys Wycheproof leaves open', () {
      // RFC 8032 neither requires nor forbids these keys. The library
      // accepts them all; tlsa_resolver refuses the small-order ones
      // itself (below). If this changes, check what else the update did.
      final acceptable = [for (final v in vectors) if (v.result == 'acceptable') v];
      expect(acceptable, hasLength(29));
      expect({for (final v in acceptable) ...v.flags},
          {'SmallOrderPublicKey', 'MixedOrderPublicKey'});
      final refused = [for (final v in acceptable) if (!v.libraryVerifies) v];
      expect(refused, isEmpty, reason: refused.join('\n'));
    });
  });

  group('verifySignature', () {
    test('refuses every small-order key, in every encoding', () {
      final smallOrder = [for (final v in vectors) if (v.flags.contains('SmallOrderPublicKey')) v];
      expect(smallOrder, hasLength(8));
      for (final v in smallOrder) {
        expect(v.weVerify, isFalse, reason: '$v');
      }
    });

    test('the identity key cannot forge a signature over any message', () {
      // R = identity, S = 0: the library accepts this for any message.
      final identity = _hex('01${'00' * 31}');
      final signature = Uint8List.fromList([...identity, ...List.filled(32, 0)]);
      for (final message in ['', 'a', 'any message at all']) {
        final data = Uint8List.fromList(utf8.encode(message));
        expect(ed25519.verify(ed25519.PublicKey(identity), data, signature), isTrue);
        expect(verifySignature(DnssecAlgorithm.ed25519, identity, data, signature), isFalse);
        // With the sign bit set, and in the non-canonical encoding of 1.
        final signed = Uint8List.fromList(identity)..[31] |= 0x80;
        expect(verifySignature(DnssecAlgorithm.ed25519, signed, data, signature), isFalse);
        final pPlus1 = _hex('ee${'ff' * 30}7f');
        expect(verifySignature(DnssecAlgorithm.ed25519, pPlus1, data, signature), isFalse);
      }
    });

    test('still accepts mixed-order keys, as libsodium does', () {
      final mixed = [
        for (final v in vectors)
          if (v.flags.contains('MixedOrderPublicKey') && v.result == 'acceptable') v,
      ];
      expect(mixed, hasLength(21));
      for (final v in mixed) {
        expect(v.weVerify, isTrue, reason: '$v');
      }
    });

    test('agrees with the library on every other vector', () {
      final other = [
        for (final v in vectors)
          if (!v.flags.contains('SmallOrderPublicKey') && v.weVerify != v.libraryVerifies) v,
      ];
      expect(other, isEmpty, reason: other.join('\n'));
    });
  });

  group('ed25519-speccheck', () {
    // What each case tests, from the speccheck README (A is the public key,
    // R and S the halves of the signature).
    const what = [
      'small A and R, S = 0',
      'small A',
      'small R',
      'mixed-order A and R; passes either equation',
      'mixed-order A and R; passes only the cofactored equation',
      'passes the cofactored equation only if 8h is pre-reduced',
      'S > L',
      'S >> L, beyond a canonical encoding',
      'non-canonical R, reduced for the hash',
      'non-canonical R, not reduced for the hash',
      'non-canonical small A, reduced for the hash',
      'non-canonical small A, not reduced for the hash',
    ];
    final cases = [
      for (final c in (jsonDecode(File('test/ed25519_speccheck/cases.json').readAsStringSync())
              as List)
          .cast<Map<String, dynamic>>())
        (
          key: _hex(c['pub_key'] as String),
          message: _hex(c['message'] as String),
          signature: _hex(c['signature'] as String),
        ),
    ];

    String outcomes(bool Function(Uint8List key, Uint8List message, Uint8List signature) verify) =>
        [
          for (final c in cases)
            () {
              try {
                return verify(c.key, c.message, c.signature) ? 'V' : 'X';
              } catch (_) {
                return 'X';
              }
            }(),
        ].join();

    String explain(String got, String want) => [
          for (var i = 0; i < cases.length; i++)
            if (got[i] != want[i]) 'case $i (${what[i]}): got ${got[i]}, expected ${want[i]}',
        ].join('\n');

    test('the cases are all there', () => expect(cases, hasLength(what.length)));

    test('ed25519_edwards behaves like Go, BoringSSL and OpenSSL 3', () {
      // Cofactorless, refuses S >= L and non-canonical R, accepts small
      // and mixed-order points. The row those libraries share in the
      // speccheck results table.
      const want = 'VVVVXXXXXXXV';
      final got = outcomes((k, m, s) => ed25519.verify(ed25519.PublicKey(k), m, s));
      expect(got, want, reason: explain(got, want));
    });

    test('verifySignature behaves like libsodium', () {
      // The same, but small-order A or R is refused too, which also covers
      // case 11's non-canonical encoding of a small A.
      const want = 'XXXVXXXXXXXX';
      final got = outcomes((k, m, s) => verifySignature(DnssecAlgorithm.ed25519, k, m, s));
      expect(got, want, reason: explain(got, want));
    });
  });
}

class _Vector {
  _Vector(this.publicKey, Map<String, dynamic> t)
      : id = t['tcId'] as int,
        result = t['result'] as String,
        comment = t['comment'] as String,
        flags = (t['flags'] as List).cast<String>(),
        message = _hex(t['msg'] as String),
        signature = _hex(t['sig'] as String);

  final Uint8List publicKey;
  final int id;
  final String result;
  final String comment;
  final List<String> flags;
  final Uint8List message;
  final Uint8List signature;

  bool get libraryVerifies {
    try {
      return ed25519.verify(ed25519.PublicKey(publicKey), message, signature);
    } catch (_) {
      return false;
    }
  }

  bool get weVerify => verifySignature(DnssecAlgorithm.ed25519, publicKey, message, signature);

  @override
  String toString() => 'tcId $id ($result, $comment, $flags)';
}

List<Map<String, dynamic>> _groups() {
  final json = jsonDecode(File('test/wycheproof/ed25519_test.json').readAsStringSync());
  return ((json as Map<String, dynamic>)['testGroups'] as List).cast<Map<String, dynamic>>();
}

Uint8List _hex(String s) => Uint8List.fromList([
      for (var i = 0; i < s.length; i += 2) int.parse(s.substring(i, i + 2), radix: 16),
    ]);
