import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:tlsa_resolver/src/dnssec/crypto.dart';

/// Runs Project Wycheproof's signature test vectors (test/wycheproof/, see
/// its README) through [verifySignature], with keys and signatures in the
/// DNSKEY and RRSIG formats. Every "valid" vector must verify and every
/// "invalid" one must not; "acceptable" ones may go either way.
void main() {
  group('Ed25519', () {
    _run('ed25519_test', (group) => (
          DnssecAlgorithm.ed25519,
          _hex(group['publicKey']['pk'] as String),
        ));
  });

  group('ECDSA', () {
    _run('ecdsa_secp256r1_sha256_p1363_test', (group) => (
          DnssecAlgorithm.ecdsaP256Sha256,
          _ecKey(group, 32),
        ));
    _run('ecdsa_secp384r1_sha384_p1363_test', (group) => (
          DnssecAlgorithm.ecdsaP384Sha384,
          _ecKey(group, 48),
        ));
  });

  test('an ECDSA key that is not on the curve is refused', () {
    final group = _load('ecdsa_secp256r1_sha256_p1363_test').first;
    final key = _ecKey(group, 32);
    final t = (group['tests'] as List).cast<Map<String, dynamic>>()
        .firstWhere((t) => t['result'] == 'valid');
    final msg = _hex(t['msg'] as String), sig = _hex(t['sig'] as String);
    expect(verifySignature(DnssecAlgorithm.ecdsaP256Sha256, key, msg, sig), isTrue);
    key[63] ^= 1; // y no longer matches x
    expect(verifySignature(DnssecAlgorithm.ecdsaP256Sha256, key, msg, sig), isFalse);
  });

  group('RSA PKCS#1 v1.5', () {
    for (final (file, algorithm) in [
      ('rsa_signature_2048_sha256_test', DnssecAlgorithm.rsaSha256),
      ('rsa_signature_2048_sha512_test', DnssecAlgorithm.rsaSha512),
      ('rsa_signature_3072_sha256_test', DnssecAlgorithm.rsaSha256),
      ('rsa_signature_4096_sha256_test', DnssecAlgorithm.rsaSha256),
      ('rsa_signature_4096_sha512_test', DnssecAlgorithm.rsaSha512),
    ]) {
      _run(file, (group) => (algorithm, _rsaKey(group)));
    }

    test('keys over 4096 bits are refused (RFC 3110)', () {
      final vectors = _load('rsa_signature_8192_sha256_test');
      var valid = 0;
      for (final group in vectors) {
        final key = _rsaKey(group);
        for (final t in (group['tests'] as List).cast<Map<String, dynamic>>()) {
          if (t['result'] != 'valid') continue;
          valid++;
          expect(
              verifySignature(DnssecAlgorithm.rsaSha256, key, _hex(t['msg'] as String),
                  _hex(t['sig'] as String)),
              isFalse,
              reason: 'tcId ${t['tcId']}');
        }
      }
      expect(valid, greaterThan(0));
    });

    test('public exponents over 8 bytes are refused', () {
      final group = _load('rsa_signature_2048_sha256_test').first;
      final key = _rsaKey(group);
      // Same key with the exponent 65537 padded to 9 bytes: numerically
      // equal, but over the limit.
      final padded = Uint8List.fromList([9, 0, 0, 0, 0, 0, 0, ...key.sublist(1)]);
      final t = (group['tests'] as List).cast<Map<String, dynamic>>()
          .firstWhere((t) => t['result'] == 'valid');
      final msg = _hex(t['msg'] as String), sig = _hex(t['sig'] as String);
      expect(verifySignature(DnssecAlgorithm.rsaSha256, key, msg, sig), isTrue);
      expect(verifySignature(DnssecAlgorithm.rsaSha256, padded, msg, sig), isFalse);
    });
  });
}

typedef _KeyFor = (int algorithm, Uint8List key) Function(Map<String, dynamic> group);

void _run(String file, _KeyFor keyFor) {
  test(file, () {
    final failures = <String>[];
    var count = 0;
    for (final group in _load(file)) {
      final (algorithm, key) = keyFor(group);
      for (final t in (group['tests'] as List).cast<Map<String, dynamic>>()) {
        final result = t['result'] as String;
        if (result == 'acceptable') continue;
        count++;
        final verified = verifySignature(
            algorithm, key, _hex(t['msg'] as String), _hex(t['sig'] as String));
        if (verified != (result == 'valid')) {
          failures.add('tcId ${t['tcId']} ($result, ${t['comment']}, ${t['flags']}): '
              '${verified ? 'verified' : 'rejected'}');
        }
      }
    }
    expect(count, greaterThan(0));
    expect(failures, isEmpty, reason: '${failures.length} of $count vectors:\n${failures.join('\n')}');
  });
}

List<Map<String, dynamic>> _load(String file) {
  final json = jsonDecode(File('test/wycheproof/$file.json').readAsStringSync());
  return ((json as Map<String, dynamic>)['testGroups'] as List).cast<Map<String, dynamic>>();
}

/// DNSKEY format for ECDSA (RFC 6605): X || Y, each [size] bytes.
Uint8List _ecKey(Map<String, dynamic> group, int size) {
  final key = group['publicKey'] as Map<String, dynamic>;
  return Uint8List.fromList([
    ..._fixed(_hex(key['wx'] as String), size),
    ..._fixed(_hex(key['wy'] as String), size),
  ]);
}

/// DNSKEY format for RSA (RFC 3110): exponent length, exponent, modulus.
Uint8List _rsaKey(Map<String, dynamic> group) {
  final key = group['publicKey'] as Map<String, dynamic>;
  final exponent = _strip(_hex(key['publicExponent'] as String));
  final modulus = _strip(_hex(key['modulus'] as String));
  return Uint8List.fromList([
    if (exponent.length < 256) exponent.length else ...[0, exponent.length >> 8, exponent.length & 0xff],
    ...exponent,
    ...modulus,
  ]);
}

Uint8List _strip(Uint8List bytes) {
  var i = 0;
  while (i < bytes.length - 1 && bytes[i] == 0) {
    i++;
  }
  return Uint8List.sublistView(bytes, i);
}

/// Left-pads or strips leading zeros to exactly [size] bytes.
Uint8List _fixed(Uint8List bytes, int size) {
  final stripped = _strip(bytes);
  if (stripped.length > size) return stripped; // let verification reject it
  return Uint8List(size)..setAll(size - stripped.length, stripped);
}

Uint8List _hex(String s) => Uint8List.fromList([
      for (var i = 0; i < s.length; i += 2) int.parse(s.substring(i, i + 2), radix: 16),
    ]);
