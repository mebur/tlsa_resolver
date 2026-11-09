import 'dart:async';
import 'dart:isolate';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:tlsa_resolver/src/wire/message.dart';
import 'package:tlsa_resolver/tlsa_resolver.dart';

import 'support/fake_dns.dart';

void main() {
  late TestHierarchy h;
  const name = '_443._tcp.www.example.test.';

  setUp(() {
    h = TestHierarchy();
    h.dns.on(name, RRType.tlsa,
        FakeResponse(answers: h.example.signed_([tlsaRecord(name, 3, 1, 1, List.filled(32, 7))])));
  });

  IsolateValidator background(DnsTransport transport) {
    final anchor = h.root.dsValue;
    return IsolateValidator(
        () => DnssecValidator(transport, trustAnchors: [anchor], clock: () => testNow));
  }

  test('gives the same answer as validating in place', () async {
    final v = background(h.dns);
    addTearDown(v.close);
    final remote = await TlsaResolver(validator: v).lookupName(n(name));
    final local = await h.resolver().lookupName(n(name));
    expect(remote.status, SecurityStatus.secure, reason: remote.reason);
    expect(remote.records.map((r) => '$r'), local.records.map((r) => '$r'));
  });

  test('the calling isolate keeps running while the background one validates', () async {
    // The transport busies its isolate for 300 ms per query.
    final v = background(_BusyTransport(h.dns, const Duration(milliseconds: 300)));
    addTearDown(v.close);
    var ticks = 0;
    final timer = Timer.periodic(const Duration(milliseconds: 10), (_) => ticks++);
    final result = await v.resolve(n(name), RRType.tlsa);
    timer.cancel();
    expect(result.status, SecurityStatus.secure, reason: result.reason);
    // Several queries at 300 ms each: well over a second of blocking that
    // the calling isolate did not see.
    expect(ticks, greaterThan(50));
  });

  test('concurrent lookups are answered separately', () async {
    final v = background(h.dns);
    addTearDown(v.close);
    final results = await Future.wait([
      v.resolve(n(name), RRType.tlsa),
      v.resolve(n('_443._tcp.nothing.example.test.'), RRType.tlsa),
      v.resolve(n(name), RRType.tlsa),
    ]);
    expect(results.map((r) => r.status),
        [SecurityStatus.secure, SecurityStatus.indeterminate, SecurityStatus.secure]);
    expect(results[1].name, n('_443._tcp.nothing.example.test.'));
  });

  test('clearCache reaches the background validator', () async {
    final v = background(h.dns);
    addTearDown(v.close);
    await v.clearCache(); // before the isolate exists: nothing to do
    await v.resolve(n(name), RRType.tlsa);
    await v.clearCache();
    expect((await v.resolve(n(name), RRType.tlsa)).status, SecurityStatus.secure);
  });

  test('an error in the background isolate is passed back', () async {
    final v = background(_ThrowingTransport());
    addTearDown(v.close);
    await expectLater(v.resolve(n(name), RRType.tlsa),
        throwsA(isA<RemoteError>().having((e) => e.toString(), 'message', contains('transport bug'))));
  });

  test('a new isolate is started after the old one dies', () async {
    final v = background(_KillingTransport(h.dns, n('_443._tcp.kill.example.test.')));
    addTearDown(v.close);
    await expectLater(v.resolve(n('_443._tcp.kill.example.test.'), RRType.tlsa), throwsA(isA<RemoteError>()));
    expect((await v.resolve(n(name), RRType.tlsa)).status, SecurityStatus.secure);
  });

  test('close lets lookups in progress finish and refuses new ones', () async {
    final v = background(_BusyTransport(h.dns, const Duration(milliseconds: 20)));
    final pending = v.resolve(n(name), RRType.tlsa);
    await Future<void>.delayed(const Duration(milliseconds: 50));
    await v.close();
    expect((await pending).status, SecurityStatus.secure);
    expect(() => v.resolve(n(name), RRType.tlsa), throwsStateError);
  });

  test('TlsaResolver.inBackground works with a sendable transport', () async {
    final resolver = TlsaResolver.inBackground(transport: h.dns);
    addTearDown(resolver.close);
    // Real root anchors against the fake root: bogus, but answered.
    final result = await resolver.lookupName(n(name));
    expect(result.status, SecurityStatus.bogus);
  });
}

/// Blocks its isolate for [delay] before each answer.
class _BusyTransport implements DnsTransport {
  _BusyTransport(this.inner, this.delay);
  final DnsTransport inner;
  final Duration delay;

  @override
  Future<Uint8List> send(Uint8List query) {
    final watch = Stopwatch()..start();
    while (watch.elapsed < delay) {}
    return inner.send(query);
  }
}

class _ThrowingTransport implements DnsTransport {
  @override
  Future<Uint8List> send(Uint8List query) => throw StateError('transport bug');
}

/// Kills its isolate when asked about [victim].
class _KillingTransport implements DnsTransport {
  _KillingTransport(this.inner, this.victim);
  final DnsTransport inner;
  final DnsName victim;

  @override
  Future<Uint8List> send(Uint8List query) {
    if (DnsMessage.parse(query).questions.single.name == victim) {
      Isolate.current.kill(priority: Isolate.immediate);
    }
    return inner.send(query);
  }
}
