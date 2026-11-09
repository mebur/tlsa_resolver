import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:tlsa_resolver/src/wire/message.dart';
import 'package:tlsa_resolver/tlsa_resolver.dart';

import 'support/fake_dns.dart';

/// Fuzzes the validator: each run looks up one name with one response on
/// the way corrupted, and checks that
///
/// * the lookup completes without throwing, and
/// * a secure result is exactly the untampered result: same records, same
///   NXDOMAIN flag, same CNAME target.
///
/// Corruptions are byte flips, truncation, and record-level edits: dropping,
/// duplicating or moving records, flipping the rcode, and splicing in
/// validly signed records from other answers (replay). The zones are
/// consistent with each other, so no spliced record can prove anything the
/// zones do not say.
///
/// FUZZ_ITERATIONS sets the number of runs (default 400) and FUZZ_SEED the
/// seed (default: random, printed so a failure can be replayed).
void main() {
  final iterations = int.parse(Platform.environment['FUZZ_ITERATIONS'] ?? '400');
  final seed = int.parse(Platform.environment['FUZZ_SEED'] ?? '${Random().nextInt(1 << 32)}');

  late _World world;
  setUpAll(() async {
    world = _World();
    for (final s in world.scenarios) {
      world.baselines[s.name] = await world.validator(world.h.dns).resolve(n(s.name), RRType.tlsa);
    }
  });

  test('untampered lookups give the expected results', () {
    for (final s in world.scenarios) {
      final answer = world.baselines[s.name]!;
      expect(answer.status, s.expected, reason: '${s.name}: ${answer.reason}');
    }
  });

  test('$iterations corrupted lookups (seed $seed)', () async {
    final rnd = Random(seed);
    final failures = <String>[];
    final counts = <SecurityStatus, int>{};
    for (var i = 0; i < iterations && failures.length < 5; i++) {
      final s = world.scenarios[rnd.nextInt(world.scenarios.length)];
      final mutator = _Mutator(world.h.dns, rnd, world.pool, world.denials, target: rnd.nextInt(8));
      final ValidatedAnswer answer;
      try {
        answer = await world.validator(mutator).resolve(n(s.name), RRType.tlsa);
      } catch (e, st) {
        failures.add('run $i ${s.name} after ${mutator.applied}: threw $e\n$st');
        continue;
      }
      counts[answer.status] = (counts[answer.status] ?? 0) + 1;
      if (answer.status != SecurityStatus.secure) continue;
      final base = world.baselines[s.name]!;
      final diffs = [
        if (base.status != SecurityStatus.secure) 'status (untampered: ${base.status.name})',
        if (base.nxDomain != answer.nxDomain) 'NXDOMAIN',
        if (base.canonicalName != answer.canonicalName) 'CNAME target',
        if (!_sameRdata(base.records, answer.records)) 'records',
      ];
      if (diffs.isNotEmpty) {
        failures.add('run $i ${s.name} after ${mutator.applied}: secure with different ${diffs.join(', ')}');
      }
    }
    // ignore: avoid_print
    print('Outcomes: ${{for (final e in counts.entries) e.key.name: e.value}}');
    expect(failures, isEmpty, reason: 'seed $seed\n${failures.join('\n')}');
  }, timeout: const Timeout(Duration(minutes: 30)));
}

bool _sameRdata(List<ResourceRecord> a, List<ResourceRecord> b) {
  String key(List<ResourceRecord> rs) =>
      ([for (final r in rs) r.canonicalRdata.join(',')]..sort()).join('|');
  return key(a) == key(b);
}

class _Scenario {
  const _Scenario(this.name, this.expected);
  final String name;
  final SecurityStatus expected;
}

/// The test hierarchy with one consistent set of names per zone.
///
/// example.test (NSEC): example.test, *.example.test (TLSA),
///   _443._tcp.alias.example.test (CNAME), _443._tcp.nodata.example.test
///   (TXT), _443._tcp.www.example.test (TLSA).
/// nsec3.test (NSEC3): nsec3.test, www, _tcp.www (empty), _443._tcp.www
///   (TXT), mail, _tcp.mail (empty), _25._tcp.mail (TLSA).
/// test.: delegations only, plus NXDOMAIN for anything else.
class _World {
  _World() {
    final ex = h.example, n3 = h.nsec3, t = h.test;
    final digest = List.generate(32, (i) => i);
    ResourceRecord tlsa(String owner) => tlsaRecord(owner, 3, 1, 1, digest);

    // example.test, NSEC chain in canonical order.
    const apex = 'example.test.', wild = '*.example.test.';
    const alias = '_443._tcp.alias.example.test.', nodata = '_443._tcp.nodata.example.test.';
    const www = '_443._tcp.www.example.test.';
    final nsecApex = ex.signed_([ex.nsec(apex, wild, {RRType.soa, RRType.ns, RRType.dnskey})]);
    final nsecWild = ex.signed_([ex.nsec(wild, alias, {RRType.tlsa})]);
    final nsecAlias = ex.signed_([ex.nsec(alias, nodata, {RRType.cname})]);
    final nsecNodata = ex.signed_([ex.nsec(nodata, www, {RRType.txt})]);
    final soaEx = ex.signed_([ex.soa]);

    on(www, FakeResponse(answers: ex.signed_([tlsa(www)])));
    on(nodata, FakeResponse(authority: [...soaEx, ...nsecNodata]));
    // Wildcard expansion: proof that the name itself does not exist.
    const expanded = '_443._tcp.wild.example.test.';
    on(expanded, FakeResponse(
        answers: [tlsa(expanded), ex.sign([tlsa(expanded)], labels: 2)],
        authority: nsecNodata));

    // nsec3.test, one NSEC3 chain for every answer.
    const target = '_25._tcp.mail.nsec3.test.';
    final chain = n3.nsec3Chain({
      'nsec3.test.': {RRType.soa, RRType.ns, RRType.dnskey},
      'www.nsec3.test.': {RRType.a},
      '_tcp.www.nsec3.test.': {},
      '_443._tcp.www.nsec3.test.': {RRType.txt},
      'mail.nsec3.test.': {RRType.a},
      '_tcp.mail.nsec3.test.': {},
      target: {RRType.tlsa},
    });
    final denial = [...n3.signed_([n3.soa]), for (final r in chain) ...n3.signed_([r])];
    on(target, FakeResponse(answers: n3.signed_([tlsa(target)])));
    on('_443._tcp.www.nsec3.test.', FakeResponse(authority: denial));
    on('_443._tcp.gone.nsec3.test.', FakeResponse(rcode: Rcode.nxDomain, authority: denial));
    on(alias, FakeResponse(answers: ex.signed_([rr(n(alias), RRType.cname, n(target).toWire())])));

    // test.: NXDOMAIN between example.test and nsec3.test; *.test is
    // covered by test. -> broken.test.
    on('_443._tcp.gone.test.', FakeResponse(rcode: Rcode.nxDomain, authority: [
      ...t.signed_([t.soa]),
      ...t.signed_([t.nsec('test.', 'broken.test.', {RRType.soa, RRType.ns, RRType.dnskey})]),
      ...t.signed_([t.nsec('example.test.', 'nsec3.test.', {RRType.ns, RRType.ds})]),
    ]));

    // Unsigned zone.
    const unsigned = '_443._tcp.www.unsigned.test.';
    on(unsigned, FakeResponse(answers: [tlsa(unsigned)]));
    h.dns.on(unsigned, RRType.soa, FakeResponse(authority: [h.unsigned.soa]));

    // Signed records that splicing may replay anywhere.
    pool.addAll([...nsecApex, ...nsecWild, ...nsecAlias, ...nsecNodata, ...soaEx, ...denial]);

    // Each zone's complete signed denial records, for forging denials.
    denials[ex.apex] = [...soaEx, ...nsecApex, ...nsecWild, ...nsecAlias, ...nsecNodata];
    denials[n3.apex] = denial;
    denials[t.apex] = [
      ...t.signed_([t.soa]),
      ...t.signed_([t.nsec('test.', 'broken.test.', {RRType.soa, RRType.ns, RRType.dnskey})]),
      ...t.signed_([t.nsec('example.test.', 'nsec3.test.', {RRType.ns, RRType.ds})]),
    ];
  }

  final h = TestHierarchy();
  final pool = <ResourceRecord>[];
  final denials = <DnsName, List<ResourceRecord>>{};
  final baselines = <String, ValidatedAnswer>{};

  final scenarios = const [
    _Scenario('_443._tcp.www.example.test.', SecurityStatus.secure),
    _Scenario('_443._tcp.nodata.example.test.', SecurityStatus.secure),
    _Scenario('_443._tcp.wild.example.test.', SecurityStatus.secure),
    _Scenario('_443._tcp.alias.example.test.', SecurityStatus.secure),
    _Scenario('_25._tcp.mail.nsec3.test.', SecurityStatus.secure),
    _Scenario('_443._tcp.www.nsec3.test.', SecurityStatus.secure),
    _Scenario('_443._tcp.gone.nsec3.test.', SecurityStatus.secure),
    _Scenario('_443._tcp.gone.test.', SecurityStatus.secure),
    _Scenario('_443._tcp.www.unsigned.test.', SecurityStatus.insecure),
  ];

  void on(String name, FakeResponse response) {
    h.dns.on(name, RRType.tlsa, response);
    pool.addAll([...response.answers, ...response.authority]);
  }

  /// A fresh validator per run, so corrupted zone keys cannot leak from one
  /// run into the next and every run walks the whole chain.
  DnssecValidator validator(DnsTransport transport) =>
      DnssecValidator(transport, trustAnchors: [h.root.dsValue], clock: () => testNow);
}

/// Passes queries through to [inner] and corrupts the response to the
/// [target]th query.
class _Mutator implements DnsTransport {
  _Mutator(this.inner, this.rnd, this.pool, this.denials, {required this.target});

  final FakeResolver inner;
  final Random rnd;
  final List<ResourceRecord> pool;
  final Map<DnsName, List<ResourceRecord>> denials;
  final int target;
  var _count = 0;
  String applied = 'nothing';

  @override
  Future<Uint8List> send(Uint8List query) async {
    final bytes = await inner.send(query);
    if (_count++ != target) return bytes;
    return rnd.nextInt(3) == 0 ? _bytes(bytes) : _records(bytes);
  }

  Uint8List _bytes(Uint8List bytes) {
    final out = Uint8List.fromList(bytes);
    if (rnd.nextInt(4) == 0) {
      final length = 12 + rnd.nextInt(out.length - 12);
      applied = 'truncation to $length bytes';
      return Uint8List.sublistView(out, 0, length);
    }
    final flips = 1 + rnd.nextInt(4);
    // Leave the header alone: a broken ID or question just fails the match.
    for (var i = 0; i < flips; i++) {
      out[12 + rnd.nextInt(out.length - 12)] ^= 1 << rnd.nextInt(8);
    }
    applied = '$flips bit flips';
    return out;
  }

  Uint8List _records(Uint8List bytes) {
    final msg = DnsMessage.parse(bytes);
    final answers = [...msg.answers], authority = [...msg.authority];
    var rcode = msg.rcode;
    final edits = <String>[];
    for (var k = 1 + rnd.nextInt(3); k > 0; k--) {
      rcode = _edit(msg.questions.single.name, answers, authority, rcode);
      edits.add(applied);
    }
    applied = edits.join('; ');
    return FakeResolver.encodeResponse(msg.id, msg.questions.single,
        FakeResponse(rcode: rcode, answers: answers, authority: authority));
  }

  /// Applies one random edit and returns the new rcode.
  int _edit(DnsName qname, List<ResourceRecord> answers, List<ResourceRecord> authority, int rcode) {
    List<ResourceRecord> section() => rnd.nextBool() ? answers : authority;
    List<ResourceRecord> nonEmpty() => answers.isEmpty ? authority : (authority.isEmpty ? answers : section());
    final all = [...answers, ...authority];
    switch (rnd.nextInt(7)) {
      case 0 when all.isNotEmpty:
        final s = nonEmpty();
        final r = s.removeAt(rnd.nextInt(s.length));
        applied = 'dropping ${_describe(r)}';
      case 1 when all.isNotEmpty:
        final r = all[rnd.nextInt(all.length)];
        section().add(r);
        applied = 'duplicating ${_describe(r)}';
      case 2 when all.isNotEmpty:
        final from = nonEmpty();
        final r = from.removeAt(rnd.nextInt(from.length));
        (identical(from, answers) ? authority : answers).add(r);
        applied = 'moving ${_describe(r)} to the other section';
      case 3:
        rcode = rcode == Rcode.nxDomain ? Rcode.noError : Rcode.nxDomain;
        applied = 'flipping the rcode';
      case 4 when all.isNotEmpty:
        final s = nonEmpty();
        final i = rnd.nextInt(s.length);
        final r = s[i];
        final rdata = Uint8List.fromList(r.rdata);
        if (rdata.isNotEmpty) rdata[rnd.nextInt(rdata.length)] ^= 1 << rnd.nextInt(8);
        s[i] = ResourceRecord(r.name, r.type, r.cls, r.ttl, rdata);
        applied = 'corrupting the RDATA of ${_describe(r)}';
      case 5:
        // Forged denial: the answer replaced by the zone's own signed SOA
        // and NSEC/NSEC3 records, with one NSEC/NSEC3 tampered with.
        final zone = denials.keys
            .where(qname.isSubdomainOf)
            .fold<DnsName?>(null, (best, z) => best == null || z.labelCount > best.labelCount ? z : best);
        final records = [...denials[zone] ?? denials.values.first];
        final forgeable = [
          for (var i = 0; i < records.length; i++)
            if (records[i].type == RRType.nsec || records[i].type == RRType.nsec3) i,
        ];
        final i = forgeable[rnd.nextInt(forgeable.length)];
        final rdata = Uint8List.fromList(records[i].rdata);
        rdata[rnd.nextInt(rdata.length)] ^= 1 << rnd.nextInt(8);
        records[i] = ResourceRecord(records[i].name, records[i].type, records[i].cls, records[i].ttl, rdata);
        answers.clear();
        authority
          ..clear()
          ..addAll(records);
        rcode = rnd.nextBool() ? Rcode.nxDomain : Rcode.noError;
        applied = 'forging a denial with a tampered ${_describe(records[i])}';
      default:
        final spliced = [for (var i = 0, k = 1 + rnd.nextInt(3); i < k; i++) pool[rnd.nextInt(pool.length)]];
        if (rnd.nextBool()) answers.clear();
        section().addAll(spliced);
        applied = 'splicing in ${spliced.map(_describe).join(', ')}';
    }
    return rcode;
  }

  static String _describe(ResourceRecord r) => '${r.name} ${RRType.name(r.type)}';
}
