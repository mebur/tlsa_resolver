import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:ed25519_edwards/ed25519_edwards.dart' as ed;
import 'package:tlsa_resolver/src/wire/message.dart';
import 'package:tlsa_resolver/tlsa_resolver.dart';

/// Fixed "now" for the fake hierarchy: signatures are valid around it.
final testNow = DateTime.utc(2026, 6, 1);
final _nowSecs = testNow.millisecondsSinceEpoch ~/ 1000;

DnsName n(String s) => DnsName.parse(s);

Uint8List _u16(int v) => Uint8List.fromList([v >> 8, v & 0xff]);
Uint8List _u32(int v) =>
    Uint8List.fromList([v >> 24 & 0xff, v >> 16 & 0xff, v >> 8 & 0xff, v & 0xff]);

ResourceRecord rr(DnsName name, int type, List<int> rdata, {int ttl = 3600}) =>
    ResourceRecord(name, type, DnsClass.internet, ttl, Uint8List.fromList(rdata));

ResourceRecord tlsaRecord(String name, int usage, int selector, int mtype, List<int> data) =>
    rr(n(name), RRType.tlsa, [usage, selector, mtype, ...data]);

/// Type bitmap encoding for NSEC/NSEC3.
List<int> typeBitmap(Iterable<int> types) {
  final windows = <int, List<int>>{};
  for (final t in types) {
    final w = windows.putIfAbsent(t >> 8, () => List.filled(32, 0));
    w[(t & 0xff) >> 3] |= 0x80 >> (t & 7);
  }
  final out = <int>[];
  for (final w in (windows.keys.toList()..sort())) {
    final bytes = windows[w]!;
    var len = 32;
    while (len > 1 && bytes[len - 1] == 0) {
      len--;
    }
    out..add(w)..add(len)..addAll(bytes.sublist(0, len));
  }
  return out;
}

/// A signed (or unsigned) zone with one Ed25519 key.
class Zone {
  Zone(String apex, {this.signed = true}) : apex = n(apex) {
    final pair = ed.generateKey();
    _private = pair.privateKey;
    final pub = Uint8List.fromList(pair.publicKey.bytes);
    dnskey = rr(this.apex, RRType.dnskey, [0x01, 0x01, 3, 15, ...pub]); // 257 = ZONE|SEP
  }

  final DnsName apex;
  final bool signed;
  late final ed.PrivateKey _private;
  late final ResourceRecord dnskey;

  int get keyTag {
    final d = dnskey.rdata;
    var ac = 0;
    for (var i = 0; i < d.length; i++) {
      ac += i.isOdd ? d[i] : d[i] << 8;
    }
    return (ac + ((ac >> 16) & 0xffff)) & 0xffff;
  }

  /// DS RRset (SHA-256) for this zone's key, owned by the apex.
  ResourceRecord get ds => dsWith();

  /// DS for this zone's key with another digest type, or claiming another
  /// algorithm.
  ResourceRecord dsWith({int digestType = 2, int algorithm = 15}) {
    final data = [...apex.toCanonicalWire(), ...dnskey.rdata];
    final digest = digestType == 1 ? sha1.convert(data).bytes : sha256.convert(data).bytes;
    return rr(apex, RRType.ds, [..._u16(keyTag), algorithm, digestType, ...digest]);
  }

  Ds get dsValue => Ds.fromRecord(ds);

  ResourceRecord get soa => rr(apex, RRType.soa, [
        ...n('ns.${apex.isRoot ? '' : apex}').toWire(),
        ...n('admin.${apex.isRoot ? '' : apex}').toWire(),
        ..._u32(1), ..._u32(3600), ..._u32(600), ..._u32(86400), ..._u32(300),
      ]);

  /// RRSIG over [rrset]. [labels] overrides the label count (wildcards).
  ResourceRecord sign(List<ResourceRecord> rrset,
      {int? labels, int inceptionOffset = -86400, int expirationOffset = 86400 * 30}) {
    final owner = rrset.first.name;
    final type = rrset.first.type;
    final l = labels ?? owner.rrsigLabelCount;
    final prefix = [
      ..._u16(type), 15, l, ..._u32(rrset.first.ttl),
      ..._u32(_nowSecs + expirationOffset), ..._u32(_nowSecs + inceptionOffset),
      ..._u16(keyTag), ...apex.toCanonicalWire(),
    ];
    var signedOwner = owner;
    if (l < owner.rrsigLabelCount) signedOwner = owner.suffix(l).prependString('*');
    final rdatas = [for (final r in rrset) r.canonicalRdata]
      ..sort((a, b) {
        for (var i = 0; i < a.length && i < b.length; i++) {
          if (a[i] != b[i]) return a[i] - b[i];
        }
        return a.length - b.length;
      });
    final data = <int>[...prefix];
    for (final rd in rdatas) {
      data
        ..addAll(signedOwner.toCanonicalWire())
        ..addAll(_u16(type))
        ..addAll(_u16(DnsClass.internet))
        ..addAll(_u32(rrset.first.ttl))
        ..addAll(_u16(rd.length))
        ..addAll(rd);
    }
    final sig = ed.sign(_private, Uint8List.fromList(data));
    return rr(owner, RRType.rrsig, [...prefix, ...sig], ttl: rrset.first.ttl);
  }

  /// [rrset] followed by its signature (if the zone is signed).
  List<ResourceRecord> signed_(List<ResourceRecord> rrset, {int? labels}) =>
      [...rrset, if (signed) sign(rrset, labels: labels)];

  ResourceRecord nsec(String owner, String next, Iterable<int> types) =>
      rr(n(owner), RRType.nsec,
          [...n(next).toWire(), ...typeBitmap({...types, RRType.rrsig, RRType.nsec})]);

  static final salt = [0xab, 0xcd];
  static const iterations = 1;

  Uint8List nsec3HashOf(String name, {int rounds = iterations}) {
    var h = sha1.convert([...n(name).toCanonicalWire(), ...salt]).bytes;
    for (var i = 0; i < rounds; i++) {
      h = sha1.convert([...h, ...salt]).bytes;
    }
    return Uint8List.fromList(h);
  }

  /// NSEC3 chain for the given names (with their types), sorted by hash.
  List<ResourceRecord> nsec3Chain(Map<String, Set<int>> names,
      {bool optOut = false, int rounds = iterations}) {
    final entries = [
      for (final e in names.entries) (nsec3HashOf(e.key, rounds: rounds), e.value),
    ]..sort((a, b) => _cmp(a.$1, b.$1));
    return [
      for (var i = 0; i < entries.length; i++)
        rr(n('${_b32(entries[i].$1)}.$apex'), RRType.nsec3, [
          1, optOut ? 1 : 0, ..._u16(rounds), salt.length, ...salt,
          20, ...entries[(i + 1) % entries.length].$1,
          ...typeBitmap(entries[i].$2.isEmpty ? <int>{} : {...entries[i].$2, RRType.rrsig}),
        ]),
    ];
  }

  static int _cmp(List<int> a, List<int> b) {
    for (var i = 0; i < a.length; i++) {
      if (a[i] != b[i]) return a[i] - b[i];
    }
    return 0;
  }

  static String _b32(List<int> data) {
    const alphabet = '0123456789abcdefghijklmnopqrstuv';
    final sb = StringBuffer();
    var buffer = 0, bits = 0;
    for (final b in data) {
      buffer = (buffer << 8) | b;
      bits += 8;
      while (bits >= 5) {
        bits -= 5;
        sb.write(alphabet[(buffer >> bits) & 0x1f]);
      }
    }
    if (bits > 0) sb.write(alphabet[(buffer << (5 - bits)) & 0x1f]);
    return sb.toString();
  }
}

class FakeResponse {
  FakeResponse({this.rcode = 0, this.answers = const [], this.authority = const []});
  final int rcode;
  final List<ResourceRecord> answers;
  final List<ResourceRecord> authority;
}

/// A transport that answers from a table, like a recursive resolver that
/// passes DNSSEC records through. Unknown questions get SERVFAIL.
class FakeResolver implements DnsTransport {
  final _table = <(DnsName, int), FakeResponse>{};
  final queries = <(DnsName, int)>[];

  void on(String name, int type, FakeResponse response) => _table[(n(name), type)] = response;

  @override
  Future<Uint8List> send(Uint8List query) async {
    final q = DnsMessage.parse(query);
    final question = q.questions.single;
    queries.add((question.name, question.type));
    final response = _table[(question.name, question.type)] ?? FakeResponse(rcode: 2);
    return encodeResponse(q.id, question, response);
  }

  static Uint8List encodeResponse(int id, Question question, FakeResponse r) {
    final out = BytesBuilder()
      ..add(_u16(id))
      ..add(_u16(0x8180 | r.rcode)) // QR RD RA
      ..add(_u16(1))
      ..add(_u16(r.answers.length))
      ..add(_u16(r.authority.length))
      ..add(_u16(0))
      ..add(question.name.toWire())
      ..add(_u16(question.type))
      ..add(_u16(question.cls));
    for (final record in [...r.answers, ...r.authority]) {
      out
        ..add(record.name.toWire())
        ..add(_u16(record.type))
        ..add(_u16(record.cls))
        ..add(_u32(record.ttl))
        ..add(_u16(record.rdata.length))
        ..add(record.rdata);
    }
    return out.toBytes();
  }
}

/// A hierarchy: . → test. → {example.test. (NSEC), nsec3.test. (NSEC3),
/// unsigned.test. (no DS), broken.test. (DS for the wrong key)}.
class TestHierarchy {
  TestHierarchy() {
    _publishZone(root, null);
    _publishZone(test, root);
    _publishZone(example, test);
    _publishZone(nsec3, test);
    _publishZone(unsigned, test);
    _publishZone(broken, test);
  }

  final dns = FakeResolver();
  final root = Zone('.');
  final test = Zone('test.');
  final example = Zone('example.test.');
  final nsec3 = Zone('nsec3.test.');
  final unsigned = Zone('unsigned.test.', signed: false);
  final broken = Zone('broken.test.');

  DnssecValidator validator() =>
      DnssecValidator(dns, trustAnchors: [root.dsValue], clock: () => testNow);

  TlsaResolver resolver() => TlsaResolver(validator: validator());

  void _publishZone(Zone zone, Zone? parent) {
    final apex = zone.apex.toString();
    dns.on(apex, RRType.soa, FakeResponse(answers: zone.signed_([zone.soa])));
    dns.on(apex, RRType.dnskey, FakeResponse(answers: zone.signed_([zone.dnskey])));
    if (parent == null) return;
    if (!zone.signed) {
      // Parent proves the delegation has NS but no DS.
      final next = '${zone.apex.labels.first.map(String.fromCharCode).join()}0.${parent.apex}';
      dns.on(apex, RRType.ds, FakeResponse(authority: [
        ...parent.signed_([parent.soa]),
        ...parent.signed_([parent.nsec(apex, next, {RRType.ns})]),
      ]));
    } else if (zone == broken) {
      dns.on(apex, RRType.ds, FakeResponse(answers: parent.signed_([Zone(apex).ds])));
    } else {
      dns.on(apex, RRType.ds, FakeResponse(answers: parent.signed_([zone.ds])));
    }
  }
}
