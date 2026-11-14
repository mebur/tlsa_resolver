@TestOn('vm')
library;

import 'dart:io';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:tlsa_resolver/src/wire/message.dart';
import 'package:tlsa_resolver/tlsa_resolver.dart';

import '../tool/dane_connect.dart';
import 'support/fake_dns.dart';

/// tool/dane_connect.dart against a local TLS server with a self-signed
/// certificate for another name, so ordinary validation always fails and
/// only DANE can let the connection through.
void main() {
  late Directory dir;
  late SecureServerSocket server;
  late Uint8List certDer;
  late TestHierarchy h;
  const host = 'www.example.test';

  setUpAll(() async {
    dir = await Directory.systemTemp.createTemp('dane_connect_test');
    final key = '${dir.path}/key.pem', cert = '${dir.path}/cert.pem', der = '${dir.path}/cert.der';
    for (final args in [
      ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes',
        '-keyout', key, '-out', cert, '-days', '1', '-subj', '/CN=not-the-right-name.invalid'],
      ['x509', '-in', cert, '-outform', 'DER', '-out', der],
    ]) {
      final r = await Process.run('openssl', args);
      if (r.exitCode != 0) throw StateError('openssl ${args.first}: ${r.stderr}');
    }
    certDer = await File(der).readAsBytes();
    server = await SecureServerSocket.bind('localhost', 0,
        SecurityContext()..useCertificateChain(cert)..usePrivateKey(key));
    server.listen((socket) => socket.listen((_) {}, onError: (_) {}, cancelOnError: true),
        onError: (_) {});
  });

  tearDownAll(() async {
    await server.close();
    await dir.delete(recursive: true);
  });

  setUp(() {
    h = TestHierarchy();
    h.dns.on('$host.', RRType.a, FakeResponse(answers: h.example.signed_([
      rr(n('$host.'), RRType.a, [127, 0, 0, 1]),
    ])));
  });

  String owner() => '_${server.port}._tcp.$host.';

  Future<SecureSocket> connect() =>
      connectWithDane(h.resolver(), host, server.port, connectTo: 'localhost');

  test('a DANE-EE match lets a self-signed certificate for another name through', () async {
    final record = DaneVerifier.recordFor(certDer); // 3 1 1
    h.dns.on(owner(), RRType.tlsa, FakeResponse(answers: h.example.signed_([
      rr(n(owner()), RRType.tlsa, [record.usage, record.selector, record.matchingType, ...record.data]),
    ])));
    final socket = await connect();
    expect(socket.peerCertificate!.der, certDer);
    socket.destroy();
  });

  test('a certificate matching no TLSA record is refused', () async {
    h.dns.on(owner(), RRType.tlsa, FakeResponse(answers: h.example.signed_([
      tlsaRecord(owner(), 3, 1, 1, List.filled(32, 7)),
    ])));
    await expectLater(connect(), throwsA(isA<DaneException>()
        .having((e) => e.message, 'message', contains('matches none'))));
  });

  test('without TLSA records, ordinary validation decides (and fails here)', () async {
    h.dns.on(owner(), RRType.tlsa, FakeResponse(authority: [
      ...h.example.signed_([h.example.soa]),
      ...h.example.signed_([h.example.nsec(owner(), 'zzz.example.test.', {RRType.txt})]),
    ]));
    await expectLater(connect(), throwsA(isA<HandshakeException>()));
  });

  test('a bogus TLSA lookup refuses before connecting', () async {
    h.dns.on(owner(), RRType.tlsa, FakeResponse(answers: [tlsaRecord(owner(), 3, 1, 1, List.filled(32, 7))]));
    await expectLater(connect(), throwsA(isA<DaneException>()
        .having((e) => e.message, 'message', contains('bogus'))));
  });
}
