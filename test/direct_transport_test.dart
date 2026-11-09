import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:tlsa_resolver/src/wire/message.dart';
import 'package:tlsa_resolver/tlsa_resolver.dart';

import 'support/fake_dns.dart';

/// A resolver on 127.0.0.1 that answers UDP queries with [udpAnswer] and
/// TCP queries with [tcpAnswer], both built from the incoming query.
class _LocalResolver {
  _LocalResolver(this.udpAnswer, this.tcpAnswer);
  final Uint8List Function(Uint8List query) udpAnswer;
  final Uint8List Function(Uint8List query) tcpAnswer;
  late RawDatagramSocket udp;
  late ServerSocket tcp;
  var tcpQueries = 0;

  Future<int> start() async {
    tcp = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
    udp = await RawDatagramSocket.bind(InternetAddress.loopbackIPv4, tcp.port);
    udp.listen((event) {
      if (event != RawSocketEvent.read) return;
      final d = udp.receive();
      if (d != null) udp.send(udpAnswer(d.data), d.address, d.port);
    });
    tcp.listen((client) {
      final buffer = BytesBuilder();
      client.listen((chunk) {
        buffer.add(chunk);
        final bytes = buffer.toBytes();
        if (bytes.length < 2 || bytes.length < ((bytes[0] << 8) | bytes[1]) + 2) return;
        tcpQueries++;
        final answer = tcpAnswer(Uint8List.sublistView(bytes, 2));
        client
          ..add([answer.length >> 8, answer.length & 0xff, ...answer])
          ..close();
      });
    });
    return tcp.port;
  }

  Future<void> stop() async {
    udp.close();
    await tcp.close();
  }
}

Uint8List _answer(Uint8List query, {required bool truncated, int records = 1}) {
  final q = DnsMessage.parse(query);
  final bytes = FakeResolver.encodeResponse(q.id, q.questions.single, FakeResponse(answers: [
    for (var i = 0; i < records; i++) rr(q.questions.single.name, RRType.txt, [5, ...'hello'.codeUnits, i]),
  ]));
  if (truncated) bytes[2] |= 0x02;
  return bytes;
}

void main() {
  final query = DnsMessage.buildQuery(DnsName.parse('example.test'), RRType.txt);

  test('a truncated UDP answer is fetched again over TCP', () async {
    final server = _LocalResolver(
        (q) => _answer(q, truncated: true, records: 0), (q) => _answer(q, truncated: false, records: 3));
    final port = await server.start();
    addTearDown(server.stop);
    final answer = await DirectDnsTransport(InternetAddress.loopbackIPv4, port: port).send(query);
    expect(DnsMessage.parse(answer).answers, hasLength(3));
    expect(server.tcpQueries, 1);
  });

  test('a complete UDP answer needs no TCP', () async {
    final server = _LocalResolver((q) => _answer(q, truncated: false), (q) => _answer(q, truncated: false));
    final port = await server.start();
    addTearDown(server.stop);
    final answer = await DirectDnsTransport(InternetAddress.loopbackIPv4, port: port).send(query);
    expect(DnsMessage.parse(answer).answers, hasLength(1));
    expect(server.tcpQueries, 0);
  });
}
