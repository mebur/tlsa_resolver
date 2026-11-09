import 'package:test/test.dart';
import 'package:tlsa_resolver/src/wire/message.dart';
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
}
