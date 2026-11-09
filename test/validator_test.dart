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
      final result = await h.resolver().lookup('www.example.test', port: 443, followCname: false);
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
        tlsa(name), h.example.sign([tlsa(name)], inceptionOffset: -86400, expirationOffset: -7200),
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
      expect(result.reason, contains('No root key matches the configured trust anchors'));
      expect(result.reason, contains('key tags ${h.root.keyTag}'));
      expect(result.reason, contains('out of date'));
    });
  });

  test('stale built-in anchors are named as such', () async {
    // The fake root is signed by a key the real IANA anchors do not match,
    // which is what the built-in anchors look like after a root rollover.
    const name = '_443._tcp.www.example.test.';
    h.dns.on(name, RRType.tlsa, FakeResponse(answers: h.example.signed_([tlsa(name)])));
    final result = await TlsaResolver(transport: h.dns).lookupName(n(name));
    expect(result.status, SecurityStatus.bogus);
    expect(result.reason, contains('the root trust anchors built into tlsa_resolver (key tags 20326, 38696'));
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

  group('TLSA base domain (RFC 7671 §7)', () {
    const alias = 'alias.example.test.', target = 'host.example.test.';
    const atAlias = '_443._tcp.alias.example.test.', atTarget = '_443._tcp.host.example.test.';
    final address = [192, 0, 2, 1];

    void aliasTo(String to) => h.dns.on(alias, RRType.a,
        FakeResponse(answers: h.example.signed_([rr(n(alias), RRType.cname, n(to).toWire())])));

    setUp(() {
      aliasTo(target);
      h.dns.on(target, RRType.a, FakeResponse(answers: h.example.signed_([rr(n(target), RRType.a, address)])));
      h.dns.on(atAlias, RRType.tlsa, FakeResponse(answers: h.example.signed_([tlsa(atAlias)])));
    });

    test('a secure alias is looked up at its target first', () async {
      h.dns.on(atTarget, RRType.tlsa, FakeResponse(answers: h.example.signed_([tlsaRecord(atTarget, 3, 1, 1, List.filled(32, 9))])));
      final result = await h.resolver().lookup('alias.example.test', port: 443);
      expect(result.status, SecurityStatus.secure, reason: result.reason);
      expect(result.answer.name, n(atTarget));
      expect(result.records.single.toString(), endsWith('0909'));
    });

    test('with no TLSA at the target, the alias itself is used', () async {
      h.dns.on(atTarget, RRType.tlsa, FakeResponse(authority: [
        ...h.example.signed_([h.example.soa]),
        ...h.example.signed_([h.example.nsec(atTarget, 'a.$atTarget', {RRType.txt})]),
      ]));
      final result = await h.resolver().lookup('alias.example.test', port: 443);
      expect(result.status, SecurityStatus.secure, reason: result.reason);
      expect(result.answer.name, n(atAlias));
      expect(result.daneApplies, isTrue);
    });

    test('a bogus TLSA RRset at the target is not skipped', () async {
      h.dns.on(atTarget, RRType.tlsa, FakeResponse(answers: [
        tlsa(atTarget), Zone('example.test.').sign([tlsa(atTarget)]),
      ]));
      final result = await h.resolver().lookup('alias.example.test', port: 443);
      expect(result.status, SecurityStatus.bogus);
      expect(result.answer.name, n(atTarget));
    });

    test('an alias into an unsigned zone uses the alias only', () async {
      const unsignedTarget = 'host.unsigned.test.';
      aliasTo(unsignedTarget);
      h.dns.on(unsignedTarget, RRType.a, FakeResponse(answers: [rr(n(unsignedTarget), RRType.a, address)]));
      h.dns.on(unsignedTarget, RRType.soa, FakeResponse(authority: [h.unsigned.soa]));
      final result = await h.resolver().lookup('alias.example.test', port: 443);
      expect(result.status, SecurityStatus.secure, reason: result.reason);
      expect(result.answer.name, n(atAlias));
      expect(h.dns.queries.any((q) => q.$1 == n('_443._tcp.host.unsigned.test.')), isFalse);
    });

    test('a bogus address lookup is a failure, not a fallback', () async {
      h.dns.on(alias, RRType.a, FakeResponse(answers: [
        rr(n(alias), RRType.cname, n(target).toWire()),
        Zone('example.test.').sign([rr(n(alias), RRType.cname, n(target).toWire())]),
      ]));
      final result = await h.resolver().lookup('alias.example.test', port: 443);
      expect(result.status, SecurityStatus.bogus);
      expect(result.reason, startsWith('Address lookup for alias.example.test. failed'));
      expect(result.isFailure, isTrue);
    });

    test('a host that is not an alias is looked up directly', () async {
      h.dns.on(target, RRType.tlsa, FakeResponse());
      h.dns.on(atTarget, RRType.tlsa, FakeResponse(answers: h.example.signed_([tlsa(atTarget)])));
      final result = await h.resolver().lookup('host.example.test', port: 443);
      expect(result.status, SecurityStatus.secure, reason: result.reason);
      expect(result.answer.name, n(atTarget));
    });
  });

  group('error codes (RFC 8914)', () {
    const name = '_443._tcp.www.example.test.';

    Future<TlsaResult> lookup([DnssecValidator? v]) =>
        TlsaResolver(validator: v ?? h.validator()).lookupName(n(name));

    test('secure answers have none', () async {
      h.dns.on(name, RRType.tlsa, FakeResponse(answers: h.example.signed_([tlsa(name)])));
      expect((await lookup()).error, isNull);
    });

    test('a signature that does not verify is bogus (6)', () async {
      h.dns.on(name, RRType.tlsa, FakeResponse(answers: [
        tlsaRecord(name, 3, 1, 1, List.filled(32, 0xee)), h.example.sign([tlsa(name)]),
      ]));
      final result = await lookup();
      expect(result.error, ValidationError.bogus);
      expect(result.error!.edeCode, 6);
    });

    test('expired signatures are signatureExpired (7)', () async {
      h.dns.on(name, RRType.tlsa, FakeResponse(answers: [
        tlsa(name), h.example.sign([tlsa(name)], inceptionOffset: -86400, expirationOffset: -7200),
      ]));
      final result = await lookup();
      expect(result.error, ValidationError.signatureExpired);
      expect(result.reason, contains('signatures expired'));
    });

    test('signatures from the future are signatureNotYetValid (8)', () async {
      h.dns.on(name, RRType.tlsa, FakeResponse(answers: [
        tlsa(name), h.example.sign([tlsa(name)], inceptionOffset: 7200, expirationOffset: 86400),
      ]));
      final result = await lookup();
      expect(result.error, ValidationError.signatureNotYetValid);
      expect(result.reason, contains('check the clock'));
    });

    test('a DS matching no key is dnskeyMissing (9)', () async {
      const broken = '_443._tcp.www.broken.test.';
      h.dns.on(broken, RRType.tlsa, FakeResponse(answers: h.broken.signed_([tlsa(broken)])));
      final result = await TlsaResolver(validator: h.validator()).lookupName(n(broken));
      expect(result.error, ValidationError.dnskeyMissing);
    });

    test('stripped signatures are rrsigsMissing (10)', () async {
      h.dns.on(name, RRType.tlsa, FakeResponse(answers: [tlsa(name)]));
      h.dns.on(name, RRType.soa, FakeResponse(authority: h.example.signed_([h.example.soa])));
      expect((await lookup()).error, ValidationError.rrsigsMissing);
    });

    test('a denial without a valid proof is nsecMissing (12)', () async {
      h.dns.on(name, RRType.tlsa, FakeResponse(authority: [
        ...h.example.signed_([h.example.soa]),
        ...h.example.signed_([h.example.nsec(name, 'a.www.example.test.', {RRType.tlsa})]),
      ]));
      expect((await lookup()).error, ValidationError.nsecMissing);
    });

    test('a SERVFAIL is resolverError (22)', () async {
      expect((await lookup()).error, ValidationError.resolverError);
    });

    test('a transport failure is networkError (23)', () async {
      final v = DnssecValidator(_FailingTransport(), trustAnchors: [h.root.dsValue], clock: () => testNow);
      expect((await lookup(v)).error, ValidationError.networkError);
    });

    test('a CNAME loop is invalidData (24)', () async {
      const other = '_443._tcp.b.example.test.';
      h.dns.on(name, RRType.tlsa, FakeResponse(answers: h.example.signed_([rr(n(name), RRType.cname, n(other).toWire())])));
      h.dns.on(other, RRType.tlsa, FakeResponse(answers: h.example.signed_([rr(n(other), RRType.cname, n(name).toWire())])));
      expect((await lookup()).error, ValidationError.invalidData);
    });

    test('an unsigned zone has none; a SHA-1-only zone is unsupportedAlgorithm (1)', () async {
      const unsigned = '_443._tcp.www.unsigned.test.';
      h.dns.on(unsigned, RRType.tlsa, FakeResponse(answers: [tlsa(unsigned)]));
      h.dns.on(unsigned, RRType.soa, FakeResponse(authority: [h.unsigned.soa]));
      final plain = await TlsaResolver(validator: h.validator()).lookupName(n(unsigned));
      expect(plain.status, SecurityStatus.insecure);
      expect(plain.error, isNull);

      h.dns.on(name, RRType.tlsa, FakeResponse(answers: h.example.signed_([tlsa(name)])));
      h.dns.on('example.test.', RRType.ds,
          FakeResponse(answers: h.test.signed_([h.example.dsWith(digestType: 1)])));
      final sha1 = await lookup(DnssecValidator(h.dns,
          trustAnchors: [h.root.dsValue], clock: () => testNow, sha1: Sha1Policy.unsupported));
      expect(sha1.status, SecurityStatus.insecure);
      expect(sha1.error, ValidationError.unsupportedAlgorithm);
    });

    test('NSEC3 opt-out is insecure without an error; too many iterations is (27)', () async {
      const missing = '_443._tcp.www.nsec3.test.';
      Future<TlsaResult> nxWith({bool optOut = false, int rounds = 1}) async {
        final chain = h.nsec3.nsec3Chain({
          'nsec3.test.': {RRType.soa, RRType.ns, RRType.dnskey},
          'mail.nsec3.test.': {RRType.a},
        }, optOut: optOut, rounds: rounds);
        h.dns.on(missing, RRType.tlsa, FakeResponse(rcode: Rcode.nxDomain, authority: [
          ...h.nsec3.signed_([h.nsec3.soa]),
          for (final r in chain) ...h.nsec3.signed_([r]),
        ]));
        return TlsaResolver(validator: h.validator()).lookupName(n(missing));
      }

      final optOut = await nxWith(optOut: true);
      expect(optOut.status, SecurityStatus.insecure, reason: optOut.reason);
      expect(optOut.error, isNull);
      expect(optOut.reason, contains('opt-out'));

      final heavy = await nxWith(rounds: 151);
      expect(heavy.status, SecurityStatus.insecure, reason: heavy.reason);
      expect(heavy.error, ValidationError.unsupportedNsec3Iterations);
      expect(heavy.error!.edeCode, 27);
    });

    test('running out of queries is limitExceeded', () async {
      h.dns.on(name, RRType.tlsa, FakeResponse(answers: h.example.signed_([tlsa(name)])));
      final result = await lookup(DnssecValidator(h.dns,
          trustAnchors: [h.root.dsValue], clock: () => testNow, maxQueries: 1));
      expect(result.error, ValidationError.limitExceeded);
      expect(result.error!.edeCode, 0);
    });
  });

  group('clock tolerance', () {
    const name = '_443._tcp.www.example.test.';

    void signedWith({required int inception, required int expiration}) => h.dns.on(name, RRType.tlsa,
        FakeResponse(answers: [
          tlsa(name), h.example.sign([tlsa(name)], inceptionOffset: inception, expirationOffset: expiration),
        ]));

    test('signatures a few minutes outside their period still count by default', () async {
      signedWith(inception: -86400, expiration: -300); // expired five minutes ago
      expect((await h.resolver().lookupName(n(name))).status, SecurityStatus.secure);
      h = TestHierarchy();
      signedWith(inception: 300, expiration: 86400); // valid in five minutes
      expect((await h.resolver().lookupName(n(name))).status, SecurityStatus.secure);
    });

    test('clockSkew zero is strict', () async {
      signedWith(inception: -86400, expiration: -300);
      final strict = DnssecValidator(h.dns,
          trustAnchors: [h.root.dsValue], clock: () => testNow, clockSkew: Duration.zero);
      final result = await TlsaResolver(validator: strict).lookupName(n(name));
      expect(result.status, SecurityStatus.bogus);
      expect(result.error, ValidationError.signatureExpired);
    });
  });

  group('negative trust anchors (RFC 7646)', () {
    const broken = '_443._tcp.www.broken.test.', fine = '_443._tcp.www.example.test.';

    setUp(() {
      h.dns.on(broken, RRType.tlsa, FakeResponse(answers: h.broken.signed_([tlsa(broken)])));
      h.dns.on(fine, RRType.tlsa, FakeResponse(answers: [tlsa(fine), Zone('example.test.').sign([tlsa(fine)])]));
    });

    TlsaResolver withAnchor(DateTime until) => TlsaResolver(validator: DnssecValidator(h.dns,
        trustAnchors: [h.root.dsValue], clock: () => testNow,
        negativeTrustAnchors: {n('broken.test.'): until}));

    test('turn a broken zone insecure until they expire', () async {
      final result = await withAnchor(testNow.add(const Duration(hours: 1))).lookupName(n(broken));
      expect(result.status, SecurityStatus.insecure, reason: result.reason);
      expect(result.reason, contains('negative trust anchor'));
      expect(result.error, isNull);
      expect(result.records, hasLength(1));
      expect(result.daneApplies, isFalse);
    });

    test('have no effect once expired', () async {
      final result = await withAnchor(testNow.subtract(const Duration(seconds: 1))).lookupName(n(broken));
      expect(result.status, SecurityStatus.bogus);
    });

    test('do not cover other zones', () async {
      final result = await withAnchor(testNow.add(const Duration(hours: 1))).lookupName(n(fine));
      expect(result.status, SecurityStatus.bogus);
    });

    test('end exactly when they expire, even with keys cached', () async {
      var now = testNow;
      final resolver = TlsaResolver(validator: DnssecValidator(h.dns,
          trustAnchors: [h.root.dsValue], clock: () => now,
          negativeTrustAnchors: {n('broken.test.'): testNow.add(const Duration(minutes: 10))}));
      expect((await resolver.lookupName(n(broken))).status, SecurityStatus.insecure);
      now = testNow.add(const Duration(minutes: 11));
      expect((await resolver.lookupName(n(broken))).status, SecurityStatus.bogus);
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
    await resolver.lookup('a.example.test', port: 443, followCname: false);
    final before = h.dns.queries.length;
    await resolver.lookup('b.example.test', port: 443, followCname: false);
    expect(h.dns.queries.length - before, 1);
  });

  test('the key cache drops the least recently used zone past maxCachedZones', () async {
    const inExample = '_443._tcp.a.example.test.', inNsec3 = '_443._tcp.a.nsec3.test.';
    h.dns.on(inExample, RRType.tlsa, FakeResponse(answers: h.example.signed_([tlsa(inExample)])));
    h.dns.on(inNsec3, RRType.tlsa, FakeResponse(answers: h.nsec3.signed_([tlsa(inNsec3)])));
    final resolver = TlsaResolver(validator: DnssecValidator(h.dns,
        trustAnchors: [h.root.dsValue], clock: () => testNow, maxCachedZones: 3));
    // Caches ., test. and example.test.
    await resolver.lookupName(n(inExample));
    // nsec3.test. needs a fourth slot: example.test., used least recently,
    // goes. test. was just used again and stays.
    var before = h.dns.queries.length;
    await resolver.lookupName(n(inNsec3));
    expect(h.dns.queries.length - before, 3); // TLSA, DS, DNSKEY of nsec3.test.
    before = h.dns.queries.length;
    final result = await resolver.lookupName(n(inExample));
    expect(result.status, SecurityStatus.secure, reason: result.reason);
    expect([for (final q in h.dns.queries.skip(before)) '${q.$1} ${RRType.name(q.$2)}'],
        ['$inExample TLSA', 'example.test. DS', 'example.test. DNSKEY']);
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

class _FailingTransport implements DnsTransport {
  @override
  Future<Uint8List> send(Uint8List query) => throw DnsTransportException('unplugged');
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
