import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:tlsa_resolver/src/wire/message.dart';
import 'package:tlsa_resolver/tlsa_resolver.dart';

import 'support/fake_dns.dart';

void main() {
  late HttpServer server;
  late Future<void> Function(HttpRequest) handler;
  final requests = <HttpRequest>[];

  setUp(() async {
    requests.clear();
    server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    server.listen((request) {
      requests.add(request);
      handler(request);
    });
  });
  tearDown(() => server.close(force: true));

  DohTransport transport({Duration timeout = const Duration(seconds: 5)}) =>
      DohTransport(Uri.http('127.0.0.1:${server.port}', '/dns-query'), timeout: timeout);

  Future<void> answer(HttpRequest request, {int status = 200, String type = 'application/dns-message', List<int>? body}) async {
    final query = Uint8List.fromList(await request.fold<List<int>>([], (a, b) => a..addAll(b)));
    final q = DnsMessage.parse(query);
    request.response
      ..statusCode = status
      ..headers.contentType = ContentType.parse(type)
      ..add(body ?? FakeResolver.encodeResponse(q.id, q.questions.single, FakeResponse()));
    await request.response.close();
  }

  final query = DnsMessage.buildQuery(DnsName.parse('example.test'), RRType.tlsa);

  test('posts the query as application/dns-message and returns the answer', () async {
    handler = (r) => answer(r);
    final t = transport();
    addTearDown(t.close);
    final reply = DnsMessage.parse(await t.send(query));
    expect(reply.id, DnsMessage.queryId(query));
    expect(requests.single.method, 'POST');
    expect(requests.single.headers.contentType?.mimeType, 'application/dns-message');
    expect(requests.single.headers.value('accept'), 'application/dns-message');
  });

  test('reuses one connection for several queries', () async {
    handler = (r) => answer(r);
    final t = transport();
    addTearDown(t.close);
    for (var i = 0; i < 3; i++) {
      await t.send(query);
    }
    expect(requests, hasLength(3));
    expect(requests.map((r) => r.connectionInfo!.remotePort).toSet(), hasLength(1));
  });

  test('an HTTP error is a transport error', () async {
    handler = (r) => answer(r, status: 503);
    expect(transport().send(query),
        throwsA(isA<DnsTransportException>().having((e) => e.message, 'message', contains('HTTP 503'))));
  });

  test('a body of another type is a transport error', () async {
    handler = (r) => answer(r, type: 'text/html', body: '<html>captive portal</html>'.codeUnits);
    expect(transport().send(query),
        throwsA(isA<DnsTransportException>().having((e) => e.message, 'message', contains('text/html'))));
  });

  test('an oversized body is refused', () async {
    handler = (r) => answer(r, body: Uint8List(70000));
    expect(transport().send(query),
        throwsA(isA<DnsTransportException>().having((e) => e.message, 'message', contains('over 65535'))));
  });

  test('a server that never answers runs into the timeout', () async {
    handler = (r) async {}; // never responds
    expect(transport(timeout: const Duration(milliseconds: 200)).send(query),
        throwsA(isA<DnsTransportException>().having((e) => e.message, 'message', contains('No DoH answer'))));
  });

  test('works from a background validator', () async {
    handler = (r) => answer(r);
    final resolver = TlsaResolver.inBackground(transport: transport());
    addTearDown(resolver.close);
    // The fake answer is unsigned and the root is real: not secure, but it
    // proves the transport made the trip to the isolate and back.
    final result = await resolver.lookupName(DnsName.parse('_443._tcp.example.test'));
    expect(result.status, isNot(SecurityStatus.secure));
    expect(requests, isNotEmpty);
  });
}
