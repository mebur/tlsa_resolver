import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:tlsa_resolver/src/wire/message.dart';
import 'package:tlsa_resolver/src/wire/rdata.dart';
import 'package:tlsa_resolver/tlsa_resolver.dart';

import 'support/fake_dns.dart';

/// Fuzzes the DNS wire parser on its own, below the validator:
///
/// * the corpus messages, re-encoded with name compression by a separate
///   encoder in this file, parse to the same message as without it;
/// * any input, however corrupted, either parses or throws a
///   [FormatException], nothing else;
/// * whatever parses can be encoded again, with or without compression,
///   and parses back to the same message;
/// * the RDATA readers (RRSIG, DNSKEY, DS, NSEC, NSEC3, TLSA) and the
///   canonical form of every parsed record only throw [FormatException],
///   also on RDATA of another type;
/// * every parsed name survives presentation format: printing and parsing
///   it again gives the same name.
///
/// Corruptions: bit flips, special bytes (compression pointers, reserved
/// label types, length extremes), truncation, insertion, deletion, header
/// counts, and pointers planted at name positions.
///
/// FUZZ_ITERATIONS sets the scale as for test/fuzz_test.dart (this test
/// runs 5 times as many, as each is cheap) and FUZZ_SEED the seed.
void main() {
  final iterations = 5 * int.parse(Platform.environment['FUZZ_ITERATIONS'] ?? '400');
  final seed = int.parse(Platform.environment['FUZZ_SEED'] ?? '${Random().nextInt(1 << 32)}');
  final corpus = _corpus();

  test('compression does not change what a message says', () {
    final rnd = Random(1);
    for (final message in corpus) {
      final plain = _encode(message, compress: false);
      final compressed = _encode(message, compress: true);
      expect(compressed.length, lessThan(plain.length));
      expect(_describe(DnsMessage.parse(compressed)), _describe(DnsMessage.parse(plain)));
      final partly = _encode(message, compress: true, rnd: rnd);
      expect(_describe(DnsMessage.parse(partly)), _describe(DnsMessage.parse(plain)));
    }
  });

  test('$iterations corrupted messages (seed $seed)', () {
    final rnd = Random(seed);
    final failures = <String>[];
    var parsed = 0;
    for (var i = 0; i < iterations && failures.length < 5; i++) {
      final message = corpus[rnd.nextInt(corpus.length)];
      final applied = <String>[];
      final bytes = _mutate(_encode(message, compress: rnd.nextBool(), rnd: rnd), rnd, applied);
      final problem = _check(bytes, rnd);
      if (problem == 'parsed') {
        parsed++;
      } else if (problem != null) {
        failures.add(
          'run $i after ${applied.join(', ')}: $problem\n'
          '  input: ${bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join()}',
        );
      }
    }
    // ignore: avoid_print
    print('Parsed $parsed of $iterations');
    expect(failures, isEmpty, reason: 'seed $seed\n${failures.join('\n')}');
    // Most corruptions must still parse, or the checks on parsed messages
    // test little.
    expect(parsed, greaterThan(iterations ~/ 5));
  }, timeout: const Timeout(Duration(minutes: 30)));
}

/// Null if all is well but the input did not parse, 'parsed' if it did and
/// all checks passed, otherwise what went wrong.
String? _check(Uint8List bytes, Random rnd) {
  final DnsMessage message;
  try {
    message = DnsMessage.parse(bytes);
  } on FormatException {
    return null;
  } catch (e, st) {
    return 'parse threw ${e.runtimeType}: $e\n$st';
  }
  final records = [...message.answers, ...message.authority, ...message.additional];
  for (final name in [for (final q in message.questions) q.name, for (final r in records) r.name]) {
    final problem = _checkName(name);
    if (problem != null) return problem;
  }
  for (final r in records) {
    try {
      r.canonicalRdata;
    } catch (e) {
      return 'canonicalRdata of $r threw ${e.runtimeType}: $e';
    }
    // The record's own type, and the RDATA read as another type.
    final problem = _readRdata(r, r.type) ?? _readRdata(r, _rdataTypes[rnd.nextInt(_rdataTypes.length)]);
    if (problem != null) return problem;
  }
  if (records.every((r) => r.rdata.length <= 0xffff)) {
    final again = _describe(message);
    for (final compress in [false, true]) {
      final DnsMessage reparsed;
      try {
        reparsed = DnsMessage.parse(_encode(message, compress: compress));
      } catch (e) {
        return 're-encoded (compress: $compress) message does not parse: $e';
      }
      if (_describe(reparsed) != again) return 're-encoded (compress: $compress) message differs';
    }
  }
  return 'parsed';
}

String? _checkName(DnsName name) {
  final DnsName back;
  try {
    back = DnsName.parse('$name');
  } catch (e) {
    return 'presentation form "$name" does not parse: $e';
  }
  if (back != name || !_same(back.toWire(), name.toWire())) return 'presentation form "$name" changes the name';
  return null;
}

const _rdataTypes = [RRType.rrsig, RRType.dnskey, RRType.ds, RRType.nsec, RRType.nsec3, RRType.tlsa];

String? _readRdata(ResourceRecord r, int type) {
  final typed = ResourceRecord(r.name, type, r.cls, r.ttl, r.rdata);
  try {
    switch (type) {
      case RRType.rrsig:
        final sig = Rrsig.fromRecord(typed);
        sig.signedPrefix;
        sig.isValidAt(1 << 31, skew: 3600);
        return _checkName(sig.signer);
      case RRType.dnskey:
        Dnskey.fromRecord(typed).keyTag;
      case RRType.ds:
        Ds.fromRecord(typed);
      case RRType.nsec:
        final nsec = Nsec.fromRecord(typed);
        nsec.covers(r.name);
        return _checkName(nsec.next);
      case RRType.nsec3:
        final nsec3 = Nsec3.fromRecord(typed);
        nsec3.ownerHash;
        nsec3.optOut;
      case RRType.tlsa:
        TlsaRecord.fromRdata(typed.rdata).toString();
    }
  } on FormatException {
    return null;
  } catch (e, st) {
    return 'reading ${typed.rdata.length} bytes of RDATA as ${RRType.name(type)} threw ${e.runtimeType}: $e\n$st';
  }
  return null;
}

bool _same(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}

/// Everything a parsed message says, for comparing two parses.
String _describe(DnsMessage m) {
  String hex(List<int> b) => b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();
  String record(ResourceRecord r) => '${hex(r.name.toWire())} ${r.type} ${r.cls} ${r.ttl} ${hex(r.rdata)}';
  return [
    'id ${m.id} flags ${m.flags} rcode ${m.rcode}',
    for (final q in m.questions) 'q ${hex(q.name.toWire())} ${q.type} ${q.cls}',
    for (final r in m.answers) 'an ${record(r)}',
    for (final r in m.authority) 'ns ${record(r)}',
    for (final r in m.additional) 'ar ${record(r)}',
  ].join('\n');
}

// ---------------------------------------------------------------------------
// Encoder, written apart from the library's parser

/// Where names sit in RDATA: positive entries are fixed byte runs, 0 a name.
/// Kept separate from the library's table on purpose.
const _layouts = <int, List<int>>{
  RRType.ns: [0],
  RRType.cname: [0],
  RRType.ptr: [0],
  RRType.dname: [0],
  RRType.md: [0],
  RRType.mf: [0],
  RRType.mb: [0],
  RRType.mg: [0],
  RRType.mr: [0],
  RRType.mx: [2, 0],
  RRType.afsdb: [2, 0],
  RRType.rt: [2, 0],
  RRType.kx: [2, 0],
  RRType.soa: [0, 0],
  RRType.rp: [0, 0],
  RRType.minfo: [0, 0],
  RRType.srv: [6, 0],
  RRType.rrsig: [18, 0],
};

/// Encodes [m]. With [compress], names are written as pointers to earlier
/// copies of their longest known suffix, as servers do; with [rnd] as well,
/// each name is compressed or not at random.
Uint8List _encode(DnsMessage m, {required bool compress, Random? rnd}) {
  final out = BytesBuilder();
  final offsets = <String, int>{};
  void u16(int v) => out.add([v >> 8 & 0xff, v & 0xff]);
  void u32(int v) => out.add([v >> 24 & 0xff, v >> 16 & 0xff, v >> 8 & 0xff, v & 0xff]);

  void name(DnsName n, BytesBuilder into, int base) {
    final useCompression = compress && (rnd?.nextBool() ?? true);
    final labels = n.labels;
    for (var i = 0; i < labels.length; i++) {
      // Exact bytes: compressing across case would change the name's case.
      final key = DnsName(labels.sublist(i)).toWire().join(',');
      final earlier = offsets[key];
      if (useCompression && earlier != null) {
        into.add([0xc0 | earlier >> 8, earlier & 0xff]);
        return;
      }
      final here = base + into.length;
      if (here < 0x4000) offsets.putIfAbsent(key, () => here);
      into
        ..addByte(labels[i].length)
        ..add(labels[i]);
    }
    into.addByte(0);
  }

  out.add([m.id >> 8, m.id & 0xff]);
  u16(m.flags);
  u16(m.questions.length);
  u16(m.answers.length);
  u16(m.authority.length);
  u16(m.additional.length);
  for (final q in m.questions) {
    name(q.name, out, 0);
    u16(q.type);
    u16(q.cls);
  }
  for (final r in [...m.answers, ...m.authority, ...m.additional]) {
    name(r.name, out, 0);
    u16(r.type);
    u16(r.cls);
    u32(r.ttl);
    final rdataStart = out.length + 2;
    final rdata = BytesBuilder();
    final layout = _layouts[r.type];
    var p = 0;
    if (layout != null) {
      for (final step in layout) {
        if (step > 0) {
          rdata.add(r.rdata.sublist(p, p + step));
          p += step;
        } else {
          final (n, end) = readRdataName(r.rdata, p);
          name(n, rdata, rdataStart);
          p = end;
        }
      }
    }
    rdata.add(r.rdata.sublist(p));
    u16(rdata.length);
    out.add(rdata.takeBytes());
  }
  return out.toBytes();
}

// ---------------------------------------------------------------------------
// Corpus

List<DnsMessage> _corpus() {
  final h = TestHierarchy();
  final ex = h.example, n3 = h.nsec3, t = h.test;
  DnsMessage message(
    List<ResourceRecord> answers, {
    List<ResourceRecord> authority = const [],
    List<ResourceRecord> additional = const [],
    int rcode = 0,
  }) => DnsMessage(
    id: 0x1234,
    flags: 0x8180 | rcode,
    rcode: rcode,
    questions: [Question(answers.isEmpty ? authority.first.name : answers.first.name, RRType.a)],
    answers: answers,
    authority: authority,
    additional: additional,
  );
  ResourceRecord named(
    String owner,
    int type,
    List<String> names, {
    List<int> before = const [],
    List<int> after = const [],
  }) => rr(n(owner), type, [...before, for (final x in names) ...n(x).toWire(), ...after]);
  // EDNS OPT with extended rcode bits and the DO flag.
  final opt = ResourceRecord(DnsName.root, RRType.opt, 1232, 0x01008000, Uint8List(0));
  // A name with bytes that need escaping in presentation format.
  final odd = DnsName([
    Uint8List.fromList('a.b'.codeUnits),
    Uint8List.fromList([0x5c, 0x20, 0x00, 0xff, 0x41]),
    Uint8List.fromList('example'.codeUnits),
    Uint8List.fromList('test'.codeUnits),
  ]);
  final chain = n3.nsec3Chain({
    'nsec3.test.': {RRType.soa, RRType.ns, RRType.dnskey},
    'www.nsec3.test.': {RRType.a},
    '_tcp.www.nsec3.test.': {},
  });

  return [
    message([
      ex.dnskey,
      ex.sign([ex.dnskey]),
    ]),
    message(
      [
        ex.ds,
        t.sign([ex.ds]),
      ],
      additional: [opt],
    ),
    message(ex.signed_([tlsaRecord('_443._tcp.www.example.test.', 3, 1, 1, List.generate(32, (i) => i))])),
    message(
      [],
      authority: [
        ...ex.signed_([ex.soa]),
        ...ex.signed_([
          ex.nsec('example.test.', 'www.example.test.', {RRType.soa, RRType.ns, RRType.dnskey}),
        ]),
      ],
      rcode: Rcode.nxDomain,
    ),
    message(
      [],
      authority: [
        ...n3.signed_([n3.soa]),
        for (final r in chain) ...n3.signed_([r]),
      ],
    ),
    message(
      [
        named('alias.example.test.', RRType.cname, ['www.example.test.']),
        named('www.example.test.', RRType.cname, ['host.example.test.']),
        named('example.test.', RRType.mx, ['mail.example.test.'], before: [0, 10]),
        named('_sip._tcp.example.test.', RRType.srv, ['sip.example.test.'], before: [0, 1, 0, 2, 0x13, 0xc4]),
        named('example.test.', RRType.ns, ['ns1.example.test.']),
        named('example.test.', RRType.ns, ['ns2.example.test.']),
        named('sub.example.test.', RRType.dname, ['other.test.']),
        named('4.3.2.1.in-addr.arpa.', RRType.ptr, ['www.example.test.']),
        rr(n('www.example.test.'), RRType.txt, [5, ...'hello'.codeUnits]),
      ],
      additional: [
        rr(n('ns1.example.test.'), RRType.a, [192, 0, 2, 1]),
        opt,
      ],
    ),
    message([
      rr(odd, RRType.txt, [0]),
      rr(n('x.example.test.'), RRType.cname, odd.toWire()),
    ]),
    message([], authority: [h.unsigned.soa]),
  ];
}

// ---------------------------------------------------------------------------
// Mutations

Uint8List _mutate(Uint8List original, Random rnd, List<String> applied) {
  var d = Uint8List.fromList(original);
  final rounds = 1 + rnd.nextInt(2);
  for (var round = 0; round < rounds && d.length > 12; round++) {
    // Most edits past the header, where names and records are.
    int position() => rnd.nextInt(4) == 0 ? rnd.nextInt(d.length) : 12 + rnd.nextInt(d.length - 12);
    switch (rnd.nextInt(7)) {
      case 0:
        final flips = 1 + rnd.nextInt(3);
        for (var i = 0; i < flips; i++) {
          d[position()] ^= 1 << rnd.nextInt(8);
        }
        applied.add('$flips bit flips');
      case 1:
        const values = [0x00, 0x01, 0x3f, 0x40, 0x80, 0xc0, 0xc1, 0xff];
        final p = position();
        d[p] = values[rnd.nextInt(values.length)];
        applied.add('byte $p set to ${d[p].toRadixString(16)}');
      case 2:
        // A compression pointer, back or forward, where a name may start.
        final p = position();
        if (p + 1 >= d.length) break;
        final target = rnd.nextInt(min(d.length + 20, 0x3fff));
        d[p] = 0xc0 | target >> 8;
        d[p + 1] = target & 0xff;
        applied.add('pointer to $target at $p');
      case 3:
        final length = 12 + rnd.nextInt(d.length - 12);
        d = Uint8List.sublistView(d, 0, length);
        applied.add('truncated to $length bytes');
      case 4:
        final p = position(), n = 1 + rnd.nextInt(4);
        d = Uint8List.fromList([...d.take(p), for (var i = 0; i < n; i++) rnd.nextInt(256), ...d.skip(p)]);
        applied.add('$n bytes inserted at $p');
      case 5:
        final p = position(), n = 1 + rnd.nextInt(min(4, d.length - p));
        d = Uint8List.fromList([...d.take(p), ...d.skip(p + n)]);
        applied.add('$n bytes deleted at $p');
      case _:
        // A section count: one more, one less, zero or huge.
        final at = 4 + 2 * rnd.nextInt(4);
        final count = (d[at] << 8) | d[at + 1];
        final value = [count + 1, max(0, count - 1), 0, 0xffff][rnd.nextInt(4)];
        d[at] = value >> 8 & 0xff;
        d[at + 1] = value & 0xff;
        applied.add('count at $at set to $value');
    }
  }
  return d;
}
