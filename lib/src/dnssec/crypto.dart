import 'dart:typed_data';

import 'package:crypto/crypto.dart' as hash;
import 'package:ed25519_edwards/ed25519_edwards.dart' as ed25519;
import 'package:pointycastle/ecc/ecc_fp.dart' as fp;
import 'package:pointycastle/export.dart';

import '../wire/name.dart';
import '../wire/rdata.dart';

/// DNSSEC algorithm numbers (IANA "DNS Security Algorithm Numbers").
abstract final class DnssecAlgorithm {
  static const rsaSha1 = 5;
  static const rsaSha1Nsec3Sha1 = 7;
  static const rsaSha256 = 8;
  static const rsaSha512 = 10;
  static const ecdsaP256Sha256 = 13;
  static const ecdsaP384Sha384 = 14;
  static const ed25519 = 15;

  static const supported = {
    rsaSha1,
    rsaSha1Nsec3Sha1,
    rsaSha256,
    rsaSha512,
    ecdsaP256Sha256,
    ecdsaP384Sha384,
    ed25519,
  };
}

/// DS digest types.
abstract final class DigestType {
  static const sha1 = 1;
  static const sha256 = 2;
  static const sha384 = 4;

  static const supported = {sha1, sha256, sha384};
}

Uint8List? _digest(int digestType, List<int> data) => switch (digestType) {
      DigestType.sha1 => Uint8List.fromList(hash.sha1.convert(data).bytes),
      DigestType.sha256 => Uint8List.fromList(hash.sha256.convert(data).bytes),
      DigestType.sha384 => Uint8List.fromList(hash.sha384.convert(data).bytes),
      _ => null,
    };

bool bytesEqual(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  var diff = 0;
  for (var i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff == 0;
}

/// Whether [ds] is a digest of [key] owned by [owner] (RFC 4034 §5.1.4).
bool dsMatchesKey(Ds ds, Dnskey key, DnsName owner) {
  if (ds.algorithm != key.algorithm || ds.keyTag != key.keyTag) return false;
  final digest = _digest(ds.digestType, [
    ...owner.toCanonicalWire(),
    ...key.record.rdata,
  ]);
  return digest != null && bytesEqual(digest, ds.digest);
}

/// Verifies [signature] over [data] with a DNSKEY public key in DNS wire
/// format. Returns false for malformed keys or signatures and for
/// unsupported algorithms.
bool verifySignature(int algorithm, Uint8List publicKey, Uint8List data,
    Uint8List signature) {
  try {
    return switch (algorithm) {
      DnssecAlgorithm.rsaSha1 || DnssecAlgorithm.rsaSha1Nsec3Sha1 =>
        _rsa(SHA1Digest(), '06052b0e03021a', publicKey, data, signature),
      DnssecAlgorithm.rsaSha256 =>
        _rsa(SHA256Digest(), '0609608648016503040201', publicKey, data, signature),
      DnssecAlgorithm.rsaSha512 =>
        _rsa(SHA512Digest(), '0609608648016503040203', publicKey, data, signature),
      DnssecAlgorithm.ecdsaP256Sha256 =>
        _ecdsa(ECCurve_secp256r1(), SHA256Digest(), 32, publicKey, data, signature),
      DnssecAlgorithm.ecdsaP384Sha384 =>
        _ecdsa(ECCurve_secp384r1(), SHA384Digest(), 48, publicKey, data, signature),
      DnssecAlgorithm.ed25519 => publicKey.length == 32 &&
          signature.length == 64 &&
          !_ed25519SmallOrder(publicKey) &&
          ed25519.verify(ed25519.PublicKey(publicKey), data, signature),
      _ => false,
    };
  } catch (_) {
    return false;
  }
}

/// Encodings of the eight Ed25519 points of small order (the y coordinate,
/// sign bit cleared), including y = p and y = p + 1, which decode to 0 and
/// 1. The same list as libsodium's. With such a key, signatures verify for
/// any message (the identity key accepts R = identity, S = 0 for all), and
/// ed25519_edwards does not refuse them, so they are refused here. No
/// honestly made key has small order.
final _ed25519SmallOrderKeys = [
  for (final hex in const [
    '0000000000000000000000000000000000000000000000000000000000000000', // 0, order 4
    '0100000000000000000000000000000000000000000000000000000000000000', // 1, identity
    '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05', // order 8
    'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a', // order 8
    'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f', // p - 1, order 2
    'edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f', // p, i.e. 0
    'eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f', // p + 1, i.e. 1
  ])
    [for (var i = 0; i < 64; i += 2) int.parse(hex.substring(i, i + 2), radix: 16)],
];

bool _ed25519SmallOrder(Uint8List key) {
  final y = [...key.sublist(0, 31), key[31] & 0x7f];
  return _ed25519SmallOrderKeys.any((k) => bytesEqual(k, y));
}

BigInt _unsigned(List<int> bytes) {
  var v = BigInt.zero;
  for (final b in bytes) {
    v = (v << 8) | BigInt.from(b);
  }
  return v;
}

/// RFC 3110 §2 limits DNSSEC RSA moduli to 512–4096 bits. Larger keys
/// would only make each verification slower.
const _maxRsaModulusBits = 4096;
const _minRsaModulusBits = 512;

/// Public exponents in use are 3 and 65537; a huge one makes verification
/// as slow as a private-key operation.
const _maxRsaExponentBytes = 8;

/// RSA/SHA-x PKCS#1 v1.5 with the RFC 3110 key format: exponent length (one
/// byte, or zero followed by two bytes), exponent, modulus.
bool _rsa(Digest digest, String digestInfo, Uint8List key, Uint8List data,
    Uint8List signature) {
  if (key.isEmpty) return false;
  var pos = 1;
  var expLength = key[0];
  if (expLength == 0) {
    if (key.length < 3) return false;
    expLength = (key[1] << 8) | key[2];
    pos = 3;
  }
  if (expLength == 0 || expLength > _maxRsaExponentBytes || pos + expLength >= key.length) {
    return false;
  }
  final exponent = _unsigned(key.sublist(pos, pos + expLength));
  final modulus = _unsigned(key.sublist(pos + expLength));
  if (modulus.bitLength > _maxRsaModulusBits || modulus.bitLength < _minRsaModulusBits) {
    return false;
  }
  final signer = RSASigner(digest, digestInfo)
    ..init(false, PublicKeyParameter<RSAPublicKey>(RSAPublicKey(modulus, exponent)));
  return signer.verifySignature(data, RSASignature(signature));
}

/// ECDSA (RFC 6605): key is X || Y, signature is r || s.
bool _ecdsa(ECDomainParameters curve, Digest digest, int size, Uint8List key,
    Uint8List data, Uint8List signature) {
  if (key.length != size * 2 || signature.length != size * 2) return false;
  final x = _unsigned(key.sublist(0, size)), y = _unsigned(key.sublist(size));
  if (!_onCurve(curve, x, y)) return false;
  final point = curve.curve.createPoint(x, y);
  final signer = ECDSASigner(digest)
    ..init(false, PublicKeyParameter<ECPublicKey>(ECPublicKey(point, curve)));
  return signer.verifySignature(
      data,
      ECSignature(_unsigned(signature.sublist(0, size)),
          _unsigned(signature.sublist(size))));
}

/// Whether (x, y) is a point of [curve]: y² = x³ + ax + b (mod p). The
/// library does not check this when it builds a public key.
bool _onCurve(ECDomainParameters curve, BigInt x, BigInt y) {
  final c = curve.curve as fp.ECCurve;
  final p = c.q!;
  if (x >= p || y >= p) return false;
  final a = c.a!.toBigInteger()!, b = c.b!.toBigInteger()!;
  return (y * y - (x * x * x + a * x + b)) % p == BigInt.zero;
}

/// NSEC3 owner hash (RFC 5155 §5): iterated SHA-1 over the canonical name.
Uint8List nsec3Hash(DnsName name, Uint8List salt, int iterations) {
  var h = hash.sha1.convert([...name.toCanonicalWire(), ...salt]).bytes;
  for (var i = 0; i < iterations; i++) {
    h = hash.sha1.convert([...h, ...salt]).bytes;
  }
  return Uint8List.fromList(h);
}

int compareBytes(List<int> a, List<int> b) {
  final n = a.length < b.length ? a.length : b.length;
  for (var i = 0; i < n; i++) {
    if (a[i] != b[i]) return a[i] - b[i];
  }
  return a.length - b.length;
}
