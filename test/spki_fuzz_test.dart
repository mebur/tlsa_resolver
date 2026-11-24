import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:test/test.dart';
import 'package:tlsa_resolver/tlsa_resolver.dart';

/// Fuzzes [DaneVerifier.subjectPublicKeyInfo], the hand-written DER walk
/// that finds the public key a DANE selector-1 record is matched against.
/// If it found a different key in a certificate than the TLS stack does, a
/// TLSA record could match a key the server never proved it holds.
///
/// Each run takes a certificate from test/x509, changes it, and compares the
/// extractor with a separate reader in this file that parses the whole
/// certificate into a tree and checks its shape. For every input:
///
/// * the extractor returns a SEQUENCE inside the input or throws a
///   [FormatException], nothing else;
/// * when the reference reads a certificate, the extractor returns the same
///   bytes. The reference also accepts long-form lengths that are longer
///   than they need to be, which DER forbids but the extractor reads.
///
/// Changes are structural (fields removed, duplicated, swapped, added,
/// resized across length boundaries, lengths re-encoded in long form), then
/// often bytes on top: bit flips, special byte values, truncation,
/// insertion, deletion, trailing bytes.
///
/// FUZZ_ITERATIONS sets the scale as for test/fuzz_test.dart (this test
/// runs 5 times as many, as each is cheap) and FUZZ_SEED the seed.
void main() {
  final iterations = 5 * int.parse(Platform.environment['FUZZ_ITERATIONS'] ?? '400');
  final seed = int.parse(Platform.environment['FUZZ_SEED'] ?? '${Random().nextInt(1 << 32)}');

  final manifest =
      (jsonDecode(File('test/x509/spki_sha256.json').readAsStringSync()) as Map).cast<String, String>();
  final fixtures = {
    for (final name in manifest.keys) name: Uint8List.fromList(File('test/x509/$name').readAsBytesSync()),
  };

  test('extracts the key OpenSSL extracts', () {
    expect(fixtures, hasLength(greaterThanOrEqualTo(6)));
    for (final MapEntry(key: name, value: der) in fixtures.entries) {
      final spki = DaneVerifier.subjectPublicKeyInfo(der);
      expect(sha256.convert(spki).toString(), manifest[name], reason: name);
      expect(_referenceSpki(der), spki, reason: name);
    }
  });

  test('the reference reader is strict where it should be', () {
    final der = fixtures['p384.der']!;
    expect(_referenceSpki(Uint8List.fromList([...der, 0])), isNull, reason: 'trailing byte');
    expect(_referenceSpki(Uint8List.sublistView(der, 0, der.length - 1)), isNull, reason: 'truncated');
    final longForm = _encode(_toTlv(der), longForm: () => true, rnd: Random(1));
    expect(_referenceSpki(longForm), isNull, reason: 'non-minimal lengths are not DER');
    expect(_referenceSpki(longForm, allowLongForm: true), DaneVerifier.subjectPublicKeyInfo(longForm));
    final v1 = fixtures['rsa2048-v1.der']!;
    expect(_referenceSpki(v1), isNotNull, reason: 'version 1 has no version field');
  });

  test('$iterations changed certificates (seed $seed)', () {
    final rnd = Random(seed);
    final names = fixtures.keys.toList();
    final failures = <String>[];
    final counts = <String, int>{};
    for (var i = 0; i < iterations && failures.length < 5; i++) {
      final name = names[rnd.nextInt(names.length)];
      final applied = <String>[];
      final der = _mutate(fixtures[name]!, rnd, applied);
      final (:failure, :outcome) = _check(der);
      counts[outcome] = (counts[outcome] ?? 0) + 1;
      if (failure != null) {
        failures.add('run $i $name after ${applied.join(', ')}: $failure\n  input: ${base64.encode(der)}');
      }
    }
    // ignore: avoid_print
    print('Outcomes: $counts');
    expect(failures, isEmpty, reason: 'seed $seed\n${failures.join('\n')}');
    // The structural changes are meant to produce certificates the
    // reference reads; if almost none do, the comparison tests nothing.
    expect(counts['certificate'] ?? 0, greaterThan(iterations ~/ 20), reason: '$counts');
  }, timeout: const Timeout(Duration(minutes: 30)));
}

({String? failure, String outcome}) _check(Uint8List der) {
  Uint8List? ours;
  try {
    ours = DaneVerifier.subjectPublicKeyInfo(der);
  } on FormatException {
    ours = null;
  } catch (e) {
    return (failure: 'threw ${e.runtimeType}: $e', outcome: 'threw');
  }
  final strict = _referenceSpki(der);
  final lenient = strict ?? _referenceSpki(der, allowLongForm: true);
  final outcome = strict != null
      ? 'certificate'
      : lenient != null
          ? 'certificate with long-form lengths'
          : ours != null
              ? 'malformed, key found'
              : 'malformed, rejected';
  if (ours != null) {
    final offset = ours.offsetInBytes - der.offsetInBytes;
    final inside = ours.buffer == der.buffer &&
        offset >= 0 &&
        offset + ours.length <= der.length &&
        _same(ours, Uint8List.sublistView(der, offset, offset + ours.length));
    if (!inside) return (failure: 'result is not part of the input', outcome: outcome);
    if (ours.length < 2 || ours[0] != 0x30) return (failure: 'result is not a SEQUENCE', outcome: outcome);
  }
  if (lenient != null) {
    if (ours == null) return (failure: 'rejects a certificate the reference reads', outcome: outcome);
    if (!_same(ours, lenient)) {
      return (
        failure: 'found ${_hex(ours.take(16))}... (${ours.length} bytes), '
            'reference ${_hex(lenient.take(16))}... (${lenient.length} bytes)',
        outcome: outcome,
      );
    }
  }
  return (failure: null, outcome: outcome);
}

bool _same(Uint8List a, Uint8List b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}

String _hex(Iterable<int> b) => b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();

// ---------------------------------------------------------------------------
// Reference reader: the whole input as one tree, every length checked.

class _Node {
  _Node(this.tag, this.start, this.contentStart, this.end, this.children);
  final int tag;
  final int start;
  final int contentStart;
  final int end;

  /// Null for a primitive.
  final List<_Node>? children;
}

/// Parses [d] as exactly one TLV. Tags must use the low-tag-number form
/// (all X.509 tags up to the key do) and lengths must be definite; with
/// [allowLongForm], lengths may use more bytes than DER allows.
_Node? _parse(Uint8List d, {bool allowLongForm = false}) {
  final node = _read(d, 0, d.length, allowLongForm, 0);
  return node != null && node.end == d.length ? node : null;
}

_Node? _read(Uint8List d, int start, int limit, bool allowLongForm, int depth) {
  if (depth > 64 || start + 2 > limit) return null;
  final tag = d[start];
  if (tag & 0x1f == 0x1f) return null;
  var pos = start + 1;
  var length = d[pos++];
  if (length & 0x80 != 0) {
    final n = length & 0x7f;
    if (n == 0 || n > 4 || pos + n > limit) return null;
    if (!allowLongForm && d[pos] == 0) return null;
    length = 0;
    for (var i = 0; i < n; i++) {
      length = (length << 8) | d[pos++];
    }
    if (!allowLongForm && length < 0x80) return null;
  }
  final end = pos + length;
  if (end > limit) return null;
  if (tag & 0x20 == 0) return _Node(tag, start, pos, end, null);
  final children = <_Node>[];
  for (var p = pos; p < end;) {
    final child = _read(d, p, end, allowLongForm, depth + 1);
    if (child == null) return null;
    children.add(child);
    p = child.end;
  }
  return _Node(tag, start, pos, end, children);
}

/// The SubjectPublicKeyInfo of a certificate shaped as RFC 5280 §4.1 says,
/// up to and including that field.
Uint8List? _referenceSpki(Uint8List der, {bool allowLongForm = false}) {
  final cert = _parse(der, allowLongForm: allowLongForm);
  if (cert == null || cert.tag != 0x30 || cert.children!.length != 3) return null;
  final [tbs, algorithm, signature] = cert.children!;
  if (tbs.tag != 0x30 || algorithm.tag != 0x30 || signature.tag != 0x03) return null;
  var fields = tbs.children!;
  if (fields.isNotEmpty && fields.first.tag == 0xa0) {
    final version = fields.first.children!;
    if (version.length != 1 || version.single.tag != 0x02) return null;
    fields = fields.sublist(1);
  }
  // serialNumber, signature, issuer, validity, subject, subjectPublicKeyInfo
  const tags = [0x02, 0x30, 0x30, 0x30, 0x30, 0x30];
  if (fields.length < tags.length) return null;
  for (var i = 0; i < tags.length; i++) {
    if (fields[i].tag != tags[i]) return null;
  }
  return Uint8List.sublistView(der, fields[5].start, fields[5].end);
}

// ---------------------------------------------------------------------------
// Mutations

class _Tlv {
  _Tlv(this.tag, {this.value, this.children});
  int tag;
  Uint8List? value;
  List<_Tlv>? children;

  _Tlv copy() => _Tlv(tag, value: value, children: children?.map((c) => c.copy()).toList());
}

_Tlv _toTlv(Uint8List der) {
  _Tlv convert(_Node n) => n.children == null
      ? _Tlv(n.tag, value: Uint8List.sublistView(der, n.contentStart, n.end))
      : _Tlv(n.tag, children: [for (final c in n.children!) convert(c)]);
  return convert(_parse(der)!);
}

/// Encodes [t] in DER, except that a length is written in long form,
/// possibly with leading zeros, wherever [longForm] says so.
Uint8List _encode(_Tlv t, {bool Function()? longForm, Random? rnd}) {
  final content = t.children == null
      ? t.value!
      : Uint8List.fromList([for (final c in t.children!) ..._encode(c, longForm: longForm, rnd: rnd)]);
  final length = content.length;
  final minimal = length == 0 ? 1 : (length.bitLength + 7) ~/ 8;
  final List<int> header;
  if (longForm != null && longForm()) {
    final n = minimal + (rnd?.nextInt(5 - minimal) ?? 0);
    header = [0x80 | n, for (var i = n - 1; i >= 0; i--) (length >> (8 * i)) & 0xff];
  } else if (length < 0x80) {
    header = [length];
  } else {
    header = [0x80 | minimal, for (var i = minimal - 1; i >= 0; i--) (length >> (8 * i)) & 0xff];
  }
  return Uint8List.fromList([t.tag, ...header, ...content]);
}

/// Content sizes on both sides of each length-encoding boundary.
const _sizes = [0, 1, 2, 126, 127, 128, 129, 254, 255, 256, 257, 4000, 65535, 65536];

Uint8List _mutate(Uint8List original, Random rnd, List<String> applied) {
  var der = original;
  if (rnd.nextInt(4) != 0) der = _mutateTree(original, rnd, applied);
  if (applied.isEmpty || rnd.nextBool()) der = _mutateBytes(der, rnd, applied);
  return der;
}

Uint8List _mutateTree(Uint8List der, Random rnd, List<String> applied) {
  final cert = _toTlv(der);
  final tbs = cert.children![0].children!;
  final hasVersion = tbs.first.tag == 0xa0;
  final spkiIndex = hasVersion ? 6 : 5;
  int beforeKey() => rnd.nextInt(spkiIndex);
  bool Function()? longForm;
  switch (rnd.nextInt(8)) {
    case 0:
      if (hasVersion) {
        tbs.removeAt(0);
        applied.add('version dropped');
      } else {
        tbs.insert(0, _Tlv(0xa0, children: [_Tlv(0x02, value: Uint8List.fromList([2]))]));
        applied.add('version added');
      }
    case 1:
      final i = beforeKey();
      tbs.removeAt(i);
      applied.add('field $i removed');
    case 2:
      final i = beforeKey();
      tbs.insert(i, tbs[i].copy());
      applied.add('field $i duplicated');
    case 3:
      final i = beforeKey(), j = rnd.nextInt(tbs.length);
      final t = tbs[i];
      tbs[i] = tbs[j];
      tbs[j] = t;
      applied.add('fields $i and $j swapped');
    case 4:
      const tags = [0x02, 0x04, 0x05, 0x30, 0x31, 0xa0, 0xa1, 0xa3, 0x80, 0x0c];
      final tag = tags[rnd.nextInt(tags.length)];
      final i = rnd.nextInt(spkiIndex + 1);
      final size = _sizes[rnd.nextInt(_sizes.length)];
      tbs.insert(i, tag & 0x20 != 0 ? _Tlv(tag, children: [_Tlv(0x04, value: _random(rnd, size))]) : _Tlv(tag, value: _random(rnd, size)));
      applied.add('element ${tag.toRadixString(16)} of $size bytes inserted at $i');
    case 5 || 6:
      // Resize a value inside a field before the key (a name, a serial
      // number), so that lengths up the tree change their encoding.
      final i = beforeKey();
      final leaves = <_Tlv>[];
      void collect(_Tlv t) => t.children == null ? leaves.add(t) : t.children!.forEach(collect);
      collect(tbs[i]);
      final leaf = leaves[rnd.nextInt(leaves.length)];
      final size = _sizes[rnd.nextInt(_sizes.length)];
      leaf.value = _random(rnd, size);
      applied.add('value in field $i resized to $size bytes');
    case _:
      final share = rnd.nextDouble();
      longForm = () => rnd.nextDouble() < share;
      applied.add('long-form lengths (${(share * 100).round()}%)');
  }
  return _encode(cert, longForm: longForm, rnd: rnd);
}

Uint8List _mutateBytes(Uint8List der, Random rnd, List<String> applied) {
  final d = Uint8List.fromList(der);
  // Half the edits land in the first 64 bytes, where the headers the
  // extractor reads are dense.
  int position() => rnd.nextBool() ? rnd.nextInt(min(64, d.length)) : rnd.nextInt(d.length);
  switch (rnd.nextInt(6)) {
    case 0:
      final flips = 1 + rnd.nextInt(4);
      for (var i = 0; i < flips; i++) {
        d[position()] ^= 1 << rnd.nextInt(8);
      }
      applied.add('$flips bit flips');
      return d;
    case 1:
      const values = [0x00, 0x01, 0x02, 0x1f, 0x30, 0x7f, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x8f, 0xa0, 0xff];
      final p = position();
      d[p] = values[rnd.nextInt(values.length)];
      applied.add('byte $p set to ${d[p].toRadixString(16)}');
      return d;
    case 2:
      final length = rnd.nextInt(d.length);
      applied.add('truncated to $length bytes');
      return Uint8List.sublistView(d, 0, length);
    case 3:
      final p = position(), n = 1 + rnd.nextInt(4);
      applied.add('$n bytes inserted at $p');
      return Uint8List.fromList([...d.take(p), ..._random(rnd, n), ...d.skip(p)]);
    case 4:
      final p = position(), n = 1 + rnd.nextInt(min(4, d.length - p));
      applied.add('$n bytes deleted at $p');
      return Uint8List.fromList([...d.take(p), ...d.skip(p + n)]);
    case _:
      final n = 1 + rnd.nextInt(8);
      applied.add('$n bytes appended');
      return Uint8List.fromList([...d, ..._random(rnd, n)]);
  }
}

Uint8List _random(Random rnd, int n) => Uint8List.fromList([for (var i = 0; i < n; i++) rnd.nextInt(256)]);
