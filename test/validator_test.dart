import 'dart:async';
import 'dart:math';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:tlsa_resolver/src/dnssec/crypto.dart';
import 'package:tlsa_resolver/src/wire/message.dart';
import 'package:tlsa_resolver/src/wire/rdata.dart';
import 'package:tlsa_resolver/tlsa_resolver.dart';

import 'support/fake_dns.dart';

void main() {
  late TestHierarchy h;
  final digest = List.generate(32, (i) => i);

  setUp(() => h = TestHierarchy());

  ResourceRecord tlsa(String name) => tlsaRecord(name, 3, 1, 1, digest);

  group('positive answers', () {
    test('signed TLSA is secure', () async {
      const name = '_443._tcp.www.example.test.';
      h.dns.on(name, RRType.tlsa, FakeResponse(answers: h.example.signed_([tlsa(name)])));
      final result = await h.resolver().lookup('www.example.test', port: 443);
      expect(result.status, SecurityStatus.secure, reason: result.reason);
      expect(result.daneApplies, isTrue);
      expect(result.records.single.toString(), startsWith('3 1 1 000102'));
    });

    test('tampered data is bogus', () async {
      const name = '_443._tcp.www.example.test.';
      final sig = h.example.sign([tlsa(name)]);
      h.dns.on(name, RRType.tlsa, FakeResponse(answers: [
        tlsaRecord(name, 3, 1, 1, List.filled(32, 0xee)), sig,
      ]));
      final result = await h.resolver().lookupName(n(name));
      expect(result.status, SecurityStatus.bogus);
      expect(result.reason, contains('No valid signature'));
      expect(result.daneApplies, isFalse);
      expect(result.isFailure, isTrue);
    });

    test('stripped signatures in a signed zone are bogus', () async {
      const name = '_443._tcp.www.example.test.';
      h.dns.on(name, RRType.tlsa, FakeResponse(answers: [tlsa(name)]));
      h.dns.on(name, RRType.soa, FakeResponse(authority: h.example.signed_([h.example.soa])));
      final result = await h.resolver().lookupName(n(name));
      expect(result.status, SecurityStatus.bogus);
      expect(result.reason, contains('Missing signatures'));
    });

    test('expired signatures are bogus', () async {
      const name = '_443._tcp.www.example.test.';
      h.dns.on(name, RRType.tlsa, FakeResponse(answers: [
        tlsa(name), h.example.sign([tlsa(name)], inceptionOffset: -100, expirationOffset: -10),
      ]));
      expect((await h.resolver().lookupName(n(name))).reason, contains('No valid signature'));
    });

    test('a signature by a key outside the chain is bogus', () async {
      const name = '_443._tcp.www.example.test.';
      final impostor = Zone('example.test.');
      h.dns.on(name, RRType.tlsa, FakeResponse(answers: impostor.signed_([tlsa(name)])));
      expect((await h.resolver().lookupName(n(name))).reason, contains('No valid signature'));
    });

    test('DS that matches no DNSKEY makes the zone bogus', () async {
      const name = '_443._tcp.www.broken.test.';
      h.dns.on(name, RRType.tlsa, FakeResponse(answers: h.broken.signed_([tlsa(name)])));
      final result = await h.resolver().lookupName(n(name));
      expect(result.status, SecurityStatus.bogus);
      expect(result.reason, contains('matches its DS'));
    });

    test('wrong trust anchor makes everything bogus', () async {
      const name = '_443._tcp.www.example.test.';
      h.dns.on(name, RRType.tlsa, FakeResponse(answers: h.example.signed_([tlsa(name)])));
      final validator = DnssecValidator(h.dns,
          trustAnchors: [Zone('.').dsValue], clock: () => testNow);
      final result = await TlsaResolver(validator: validator).lookupName(n(name));
      expect(result.status, SecurityStatus.bogus);
      expect(result.reason, contains('No DNSKEY of .'));
    });
  });

  group('unsigned zones', () {
    test('answer from an unsigned delegation is insecure', () async {
      const name = '_443._tcp.www.unsigned.test.';
      h.dns.on(name, RRType.tlsa, FakeResponse(answers: [tlsa(name)]));
      h.dns.on(name, RRType.soa, FakeResponse(authority: [h.unsigned.soa]));
      final result = await h.resolver().lookupName(n(name));
      expect(result.status, SecurityStatus.insecure, reason: result.reason);
      expect(result.records, hasLength(1));
      expect(result.usableRecords, isEmpty);
      expect(result.isFailure, isFalse);
    });

    test('claiming a zone cut that the parent does not delegate is bogus', () async {
      // Attacker strips signatures and claims www.example.test is an
      // unsigned zone; example.test's NSEC shows no delegation there.
      const name = '_443._tcp.www.example.test.';
      h.dns.on(name, RRType.tlsa, FakeResponse(answers: [tlsa(name)]));
      h.dns.on(name, RRType.soa, FakeResponse(authority: [
        rr(n('www.example.test.'), RRType.soa, Zone('www.example.test.').soa.rdata),
      ]));
      h.dns.on('www.example.test.', RRType.ds, FakeResponse(authority: [
        ...h.example.signed_([h.example.soa]),
        ...h.example.signed_([h.example.nsec('www.example.test.', 'zzz.example.test.', {RRType.a})]),
      ]));
      final result = await h.resolver().lookupName(n(name));
      expect(result.status, SecurityStatus.bogus);
      expect(result.reason, contains('www.example.test. DS does not exist'));
    });
  });

  group('NSEC denial', () {
    const name = '_443._tcp.www.example.test.';

    test('NODATA is secure with no records', () async {
      h.dns.on(name, RRType.tlsa, FakeResponse(authority: [
        ...h.example.signed_([h.example.soa]),
        ...h.example.signed_([h.example.nsec(name, 'a.www.example.test.', {RRType.txt})]),
      ]));
      final result = await h.resolver().lookupName(n(name));
      expect(result.status, SecurityStatus.secure, reason: result.reason);
      expect(result.records, isEmpty);
      expect(result.daneApplies, isFalse);
      expect(result.isFailure, isFalse);
    });

    test('NODATA whose NSEC lists the type is bogus', () async {
      h.dns.on(name, RRType.tlsa, FakeResponse(authority: [
        ...h.example.signed_([h.example.soa]),
        ...h.example.signed_([h.example.nsec(name, 'a.www.example.test.', {RRType.tlsa})]),
      ]));
      expect((await h.resolver().lookupName(n(name))).reason, contains('No valid proof'));
    });

    test('NXDOMAIN with name and wildcard covered is secure', () async {
      h.dns.on(name, RRType.tlsa, FakeResponse(rcode: Rcode.nxDomain, authority: [
        ...h.example.signed_([h.example.soa]),
        // example.test. < *.example.test. < _443._tcp.www... < zzz.example.test.
        ...h.example.signed_([h.example.nsec('example.test.', 'zzz.example.test.', {RRType.soa, RRType.ns, RRType.dnskey})]),
      ]));
      final result = await h.resolver().lookupName(n(name));
      expect(result.status, SecurityStatus.secure, reason: result.reason);
      expect(result.answer.nxDomain, isTrue);
    });

    test('NXDOMAIN without wildcard proof is bogus', () async {
      h.dns.on(name, RRType.tlsa, FakeResponse(rcode: Rcode.nxDomain, authority: [
        ...h.example.signed_([h.example.soa]),
        // Covers the name but not *.example.test (owner sorts after it).
        ...h.example.signed_([h.example.nsec('_1.www.example.test.', 'zzz.example.test.', {RRType.a})]),
      ]));
      expect((await h.resolver().lookupName(n(name))).reason, contains('No valid proof'));
    });

    test('unsigned NSEC records do not count', () async {
      h.dns.on(name, RRType.tlsa, FakeResponse(authority: [
        ...h.example.signed_([h.example.soa]),
        h.example.nsec(name, 'a.www.example.test.', {RRType.txt}),
      ]));
      expect((await h.resolver().lookupName(n(name))).reason, contains('No valid proof'));
    });

    test('wildcard expansion needs a proof the name does not exist', () async {
      final expanded = tlsa(name);
      final sig = h.example.sign([expanded], labels: 2); // from *.example.test.
      h.dns.on(name, RRType.tlsa, FakeResponse(answers: [expanded, sig]));
      expect((await h.resolver().lookupName(n(name))).reason, contains('Wildcard answer'));

      h.dns.on(name, RRType.tlsa, FakeResponse(answers: [expanded, sig], authority: [
        ...h.example.signed_([h.example.nsec('*.example.test.', 'zzz.example.test.', {RRType.tlsa})]),
      ]));
      final result = await h.resolver().lookupName(n(name));
      expect(result.status, SecurityStatus.secure, reason: result.reason);
    });
  });

  group('NSEC3 denial', () {
    const name = '_443._tcp.www.nsec3.test.';

    test('NODATA with a matching NSEC3 is secure', () async {
      final chain = h.nsec3.nsec3Chain({
        'nsec3.test.': {RRType.soa, RRType.ns, RRType.dnskey},
        name: {RRType.txt},
        '_tcp.www.nsec3.test.': {},
        'www.nsec3.test.': {RRType.a},
      });
      h.dns.on(name, RRType.tlsa, FakeResponse(authority: [
        ...h.nsec3.signed_([h.nsec3.soa]),
        for (final r in chain) ...h.nsec3.signed_([r]),
      ]));
      final result = await h.resolver().lookupName(n(name));
      expect(result.status, SecurityStatus.secure, reason: result.reason);
      expect(result.records, isEmpty);
    });

    test('NXDOMAIN with closest encloser proof is secure', () async {
      final chain = h.nsec3.nsec3Chain({
        'nsec3.test.': {RRType.soa, RRType.ns, RRType.dnskey},
        'www.nsec3.test.': {RRType.a},
        'mail.nsec3.test.': {RRType.a},
      });
      h.dns.on(name, RRType.tlsa, FakeResponse(rcode: Rcode.nxDomain, authority: [
        ...h.nsec3.signed_([h.nsec3.soa]),
        for (final r in chain) ...h.nsec3.signed_([r]),
      ]));
      final result = await h.resolver().lookupName(n(name));
      expect(result.status, SecurityStatus.secure, reason: result.reason);
      expect(result.answer.nxDomain, isTrue);
    });

    test('NXDOMAIN for a name the NSEC3 chain shows exists is bogus', () async {
      final chain = h.nsec3.nsec3Chain({
        'nsec3.test.': {RRType.soa, RRType.ns, RRType.dnskey},
        'www.nsec3.test.': {RRType.a},
        name: {RRType.tlsa},
      });
      h.dns.on(name, RRType.tlsa, FakeResponse(rcode: Rcode.nxDomain, authority: [
        ...h.nsec3.signed_([h.nsec3.soa]),
        for (final r in chain) ...h.nsec3.signed_([r]),
      ]));
      expect((await h.resolver().lookupName(n(name))).reason, contains('No valid proof'));
    });
  });

  group('CNAME', () {
    test('secure chain to a secure answer', () async {
      const alias = '_443._tcp.alias.example.test.';
      const target = '_443._tcp.www.nsec3.test.';
      final cname = rr(n(alias), RRType.cname, n(target).toWire());
      h.dns.on(alias, RRType.tlsa, FakeResponse(answers: h.example.signed_([cname])));
      h.dns.on(target, RRType.tlsa, FakeResponse(answers: h.nsec3.signed_([tlsa(target)])));
      final result = await h.resolver().lookupName(n(alias));
      expect(result.status, SecurityStatus.secure, reason: result.reason);
      expect(result.answer.canonicalName, n(target));
      expect(result.records, hasLength(1));
    });

    test('secure CNAME into an unsigned zone is insecure', () async {
      const alias = '_443._tcp.alias.example.test.';
      const target = '_443._tcp.www.unsigned.test.';
      h.dns.on(alias, RRType.tlsa, FakeResponse(
          answers: h.example.signed_([rr(n(alias), RRType.cname, n(target).toWire())])));
      h.dns.on(target, RRType.tlsa, FakeResponse(answers: [tlsa(target)]));
      h.dns.on(target, RRType.soa, FakeResponse(authority: [h.unsigned.soa]));
      expect((await h.resolver().lookupName(n(alias))).status, SecurityStatus.insecure);
    });

    test('CNAME loop is bogus', () async {
      const a = '_443._tcp.a.example.test.', b = '_443._tcp.b.example.test.';
      h.dns.on(a, RRType.tlsa, FakeResponse(answers: h.example.signed_([rr(n(a), RRType.cname, n(b).toWire())])));
      h.dns.on(b, RRType.tlsa, FakeResponse(answers: h.example.signed_([rr(n(b), RRType.cname, n(a).toWire())])));
      final result = await h.resolver().lookupName(n(a));
      expect(result.status, SecurityStatus.bogus);
      expect(result.reason, contains('CNAME loop'));
    });
  });

  test('transport failure is indeterminate', () async {
    final result = await h.resolver().lookupName(n('_443._tcp.nothing.example.test.'));
    expect(result.status, SecurityStatus.indeterminate);
    expect(result.isFailure, isTrue);
  });

  test('zone keys are cached across lookups', () async {
    for (final host in ['a', 'b']) {
      final name = '_443._tcp.$host.example.test.';
      h.dns.on(name, RRType.tlsa, FakeResponse(answers: h.example.signed_([tlsa(name)])));
    }
    final resolver = h.resolver();
    await resolver.lookup('a.example.test', port: 443);
    final before = h.dns.queries.length;
    await resolver.lookup('b.example.test', port: 443);
    expect(h.dns.queries.length - before, 1);
  });

  group('SHA-1 policy', () {
    const name = '_443._tcp.www.example.test.';

    Future<TlsaResult> lookupWithDs(List<ResourceRecord> dsSet, Sha1Policy policy) {
      h.dns.on(name, RRType.tlsa, FakeResponse(answers: h.example.signed_([tlsa(name)])));
      h.dns.on('example.test.', RRType.ds, FakeResponse(answers: h.test.signed_(dsSet)));
      final validator = DnssecValidator(h.dns,
          trustAnchors: [h.root.dsValue], clock: () => testNow, sha1: policy);
      return TlsaResolver(validator: validator).lookupName(n(name));
    }

    test('a SHA-1 DS digest validates when accepted', () async {
      final result = await lookupWithDs([h.example.dsWith(digestType: 1)], Sha1Policy.accept);
      expect(result.status, SecurityStatus.secure, reason: result.reason);
    });

    test('a zone reachable only through a SHA-1 DS is insecure when unsupported', () async {
      final result =
          await lookupWithDs([h.example.dsWith(digestType: 1)], Sha1Policy.unsupported);
      expect(result.status, SecurityStatus.insecure);
      expect(result.reason, contains('only be validated with SHA-1'));
      expect(result.daneApplies, isFalse);
    });

    test('a zone reachable only through a SHA-1 DS is bogus when rejected', () async {
      final result = await lookupWithDs([h.example.dsWith(digestType: 1)], Sha1Policy.reject);
      expect(result.status, SecurityStatus.bogus);
      expect(result.reason, contains('only be validated with SHA-1'));
    });

    test('a zone signed only with RSASHA1 follows the policy', () async {
      // The DS claims algorithm 5; the policy decides before any key is
      // looked at.
      ResourceRecord ds() => h.example.dsWith(algorithm: DnssecAlgorithm.rsaSha1);
      expect((await lookupWithDs([ds()], Sha1Policy.unsupported)).status, SecurityStatus.insecure);
      h = TestHierarchy();
      expect((await lookupWithDs([ds()], Sha1Policy.reject)).status, SecurityStatus.bogus);
    });

    test('SHA-1 alongside SHA-256 does not change the outcome', () async {
      for (final policy in Sha1Policy.values) {
        h = TestHierarchy();
        final result = await lookupWithDs([h.example.dsWith(digestType: 1), h.example.ds], policy);
        expect(result.status, SecurityStatus.secure, reason: '$policy: ${result.reason}');
      }
    });

    test('a SHA-1 DS is ignored when a SHA-256 DS is present (RFC 4509)', () async {
      // The SHA-256 digest is for another key, so only the SHA-1 one
      // matches; it must not be used.
      final ds = [h.example.dsWith(digestType: 1), Zone('example.test.').ds];
      final result = await lookupWithDs(ds, Sha1Policy.accept);
      expect(result.status, SecurityStatus.bogus);
      expect(result.reason, contains('matches its DS'));
    });
  });

  group('lookup budget', () {
    const name = '_443._tcp.www.example.test.';

    setUp(() => h.dns.on(name, RRType.tlsa, FakeResponse(answers: h.example.signed_([tlsa(name)]))));

    test('a lookup stops after maxQueries', () async {
      final validator = DnssecValidator(h.dns,
          trustAnchors: [h.root.dsValue], clock: () => testNow, maxQueries: 2);
      final result = await TlsaResolver(validator: validator).lookupName(n(name));
      expect(result.status, SecurityStatus.indeterminate);
      expect(result.reason, contains('more than 2 DNS queries'));
      expect(h.dns.queries, hasLength(2));
    });

    test('the default budget is enough for a cold lookup', () async {
      final result = await h.resolver().lookupName(n(name));
      expect(result.status, SecurityStatus.secure, reason: result.reason);
    });

    test('a slow resolver runs into the timeout', () async {
      final validator = DnssecValidator(_SlowTransport(h.dns, const Duration(milliseconds: 40)),
          trustAnchors: [h.root.dsValue], clock: () => testNow,
          timeout: const Duration(milliseconds: 100));
      final result = await TlsaResolver(validator: validator).lookupName(n(name));
      expect(result.status, SecurityStatus.indeterminate);
      expect(result.reason, contains('took longer than 100 ms'));
    });

    test('a resolver that never answers cannot hold a lookup past the timeout', () async {
      final validator = DnssecValidator(_HangingTransport(),
          trustAnchors: [h.root.dsValue], clock: () => testNow,
          timeout: const Duration(milliseconds: 100));
      final watch = Stopwatch()..start();
      final result = await validator.resolve(n(name), RRType.tlsa);
      expect(result.status, SecurityStatus.indeterminate);
      expect(watch.elapsed, lessThan(const Duration(seconds: 1)));
    });
  });

  group('KeyTrap limits', () {
    const name = '_443._tcp.www.example.test.';

    /// A DNSKEY of example.test with key tag [tag]: random key bytes with
    /// the last two chosen to hit the tag.
    ResourceRecord collidingKey(int tag, Random rnd) {
      final rdata = [0x01, 0x00, 3, 15, for (var i = 0; i < 32; i++) rnd.nextInt(256)];
      for (var last = 0; last < 0x10000; last++) {
        rdata[34] = last >> 8;
        rdata[35] = last & 0xff;
        final key = rr(n('example.test.'), RRType.dnskey, rdata);
        if (Dnskey.fromRecord(key).keyTag == tag) return key;
      }
      throw StateError('unreachable');
    }

    /// example.test publishes [keys] keys sharing its real key's tag, and
    /// the TLSA RRset carries [sigs] signatures claiming that tag, none
    /// valid. Unbounded, that is keys × sigs verifications.
    void publishTrap({required int keys, required int sigs}) {
      final rnd = Random(7);
      final tag = h.example.keyTag;
      final fakes = [for (var i = 0; i < keys; i++) collidingKey(tag, rnd)];
      h.dns.on('example.test.', RRType.dnskey,
          FakeResponse(answers: h.example.signed_([...fakes, h.example.dnskey])));
      final real = h.example.sign([tlsa(name)]);
      h.dns.on(name, RRType.tlsa, FakeResponse(answers: [
        tlsa(name),
        for (var i = 0; i < sigs; i++)
          rr(real.name, RRType.rrsig, [...real.rdata.sublist(0, real.rdata.length - 1), i]),
      ]));
    }

    TlsaResolver resolver({required int maxSignatureChecks}) => TlsaResolver(
        validator: DnssecValidator(h.dns,
            trustAnchors: [h.root.dsValue], clock: () => testNow,
            maxSignatureChecks: maxSignatureChecks));

    test('colliding key tags and piles of signatures cost a bounded number of checks', () async {
      publishTrap(keys: 30, sigs: 30);
      // 900 checks unbounded; at most 8 signatures × 4 keys plus the chain.
      final result = await resolver(maxSignatureChecks: 40).lookupName(n(name));
      expect(result.status, SecurityStatus.bogus, reason: result.reason);
      expect(result.reason, contains('No valid signature'));
    });

    test('running out of signature checks is indeterminate', () async {
      publishTrap(keys: 30, sigs: 30);
      final result = await resolver(maxSignatureChecks: 3).lookupName(n(name));
      expect(result.status, SecurityStatus.indeterminate);
      expect(result.reason, contains('more than 3 signature checks'));
    });

    test('a key-tag collision with the real key still validates', () async {
      // One honest collision: the real key comes after a colliding one.
      final fake = collidingKey(h.example.keyTag, Random(3));
      h.dns.on('example.test.', RRType.dnskey,
          FakeResponse(answers: h.example.signed_([fake, h.example.dnskey])));
      h.dns.on(name, RRType.tlsa, FakeResponse(answers: h.example.signed_([tlsa(name)])));
      final result = await h.resolver().lookupName(n(name));
      expect(result.status, SecurityStatus.secure, reason: result.reason);
    });
  });
}

class _SlowTransport implements DnsTransport {
  _SlowTransport(this.inner, this.delay);
  final DnsTransport inner;
  final Duration delay;

  @override
  Future<Uint8List> send(Uint8List query) async {
    await Future<void>.delayed(delay);
    return inner.send(query);
  }
}

class _HangingTransport implements DnsTransport {
  @override
  Future<Uint8List> send(Uint8List query) => Completer<Uint8List>().future;
}
