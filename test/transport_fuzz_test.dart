import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:tlsa_resolver/src/wire/message.dart';
import 'package:tlsa_resolver/tlsa_resolver.dart';

import 'support/fake_dns.dart';

/// Fuzzes [DirectDnsTransport] and [DohTransport] against hostile servers on
/// 127.0.0.1. Each run picks one way to misbehave (garbage, wrong IDs,
/// spoofed source ports, broken TCP framing, bytes dribbled out one at a
/// time, malformed HTTP, oversized bodies, connections held open or reset)
/// and checks that
///
/// * `send` ends within its timeout, plus some slack, however slowly the
///   server sends;
/// * it returns bytes or throws a [DnsTransportException], nothing else,
///   and leaves no uncaught error behind;
/// * a well-behaved answer, however it is split up, comes back intact;
/// * a validator using the transport returns an answer, never secure, and
///   does not throw.
///
/// FUZZ_ITERATIONS sets the scale as for test/fuzz_test.dart (this test
/// runs a tenth as many, between 40 and 2000, as each can take a timeout)
/// and FUZZ_SEED the seed.
void main() {
  final iterations = (int.parse(Platform.environment['FUZZ_ITERATIONS'] ?? '400') ~/ 10).clamp(40, 2000);
  final seed = int.parse(Platform.environment['FUZZ_SEED'] ?? '${Random().nextInt(1 << 32)}');
  const timeout = Duration(milliseconds: 300);
  // The longest `send` may take: the timeout, once for UDP and once for
  // TCP, and scheduling slack on a loaded CI machine.
  const limit = Duration(milliseconds: 2 * 300 + 700);

  test('$iterations hostile DNS servers (seed $seed)', () async {
    final failures = await _runAll(iterations, seed, (i, rnd) async {
      final server = _HostileDns(rnd);
      await server.start();
      try {
        final transport = DirectDnsTransport(InternetAddress.loopbackIPv4, port: server.port, timeout: timeout);
        final problem = await _checkSend(transport, server.query, limit, expected: server.expected);
        if (problem != null || !rnd.nextBool()) return problem == null ? null : '${server.behaviour}: $problem';
        return await _checkValidator(transport, server.behaviour);
      } finally {
        await server.stop();
      }
    });
    expect(failures, isEmpty, reason: 'seed $seed\n${failures.join('\n')}');
  }, timeout: const Timeout(Duration(minutes: 30)));

  test('$iterations hostile DoH servers (seed $seed)', () async {
    final failures = await _runAll(iterations, seed, (i, rnd) async {
      final server = _HostileHttp(rnd);
      await server.start();
      final transport = DohTransport(Uri.http('127.0.0.1:${server.port}', '/dns-query'), timeout: timeout);
      try {
        final problem = await _checkSend(transport, server.query, limit, expected: server.expected);
        if (problem != null || !rnd.nextBool()) return problem == null ? null : '${server.behaviour}: $problem';
        return await _checkValidator(transport, server.behaviour);
      } finally {
        transport.close();
        await server.stop();
      }
    });
    expect(failures, isEmpty, reason: 'seed $seed\n${failures.join('\n')}');
  }, timeout: const Timeout(Duration(minutes: 30)));
}

/// Runs [iterations] cases, eight at a time, each with its own [Random]
/// derived from [seed], and catches errors that escape a case.
Future<List<String>> _runAll(int iterations, int seed, Future<String?> Function(int i, Random rnd) run) async {
  final failures = <String>[];
  var next = 0;
  Future<void> worker() async {
    while (next < iterations && failures.length < 5) {
      final i = next++;
      final done = Completer<void>();
      runZonedGuarded(
        () async {
          final problem = await run(i, Random(seed ^ (i * 0x9e3779b1)));
          if (problem != null) failures.add('run $i: $problem');
          if (!done.isCompleted) done.complete();
        },
        (e, st) {
          failures.add('run $i: uncaught ${e.runtimeType}: $e\n$st');
          if (!done.isCompleted) done.complete();
        },
      );
      await done.future;
    }
  }

  await Future.wait([for (var w = 0; w < 8; w++) worker()]);
  return failures;
}

Future<String?> _checkSend(DnsTransport transport, Uint8List query, Duration limit, {Uint8List? expected}) async {
  final sw = Stopwatch()..start();
  Uint8List? answer;
  try {
    answer = await transport.send(query).timeout(limit * 3);
  } on DnsTransportException {
    answer = null;
  } on TimeoutException {
    return 'send did not end within ${limit * 3}';
  } catch (e) {
    return 'threw ${e.runtimeType}: $e';
  }
  if (sw.elapsed > limit) return 'send took ${sw.elapsedMilliseconds} ms';
  if (expected != null) {
    if (answer == null) return 'a well-formed answer was not returned';
    if (!_same(answer, expected)) return 'the answer came back changed (${answer.length} bytes)';
  }
  return null;
}

Future<String?> _checkValidator(DnsTransport transport, String behaviour) async {
  final validator = DnssecValidator(transport, timeout: const Duration(seconds: 2), maxQueries: 4);
  try {
    final answer = await validator
        .resolve(DnsName.parse('_443._tcp.example.test'), RRType.tlsa)
        .timeout(const Duration(seconds: 6));
    if (answer.status == SecurityStatus.secure) return '$behaviour: validator says secure';
    return null;
  } on TimeoutException {
    return '$behaviour: validator did not end';
  } catch (e) {
    return '$behaviour: validator threw ${e.runtimeType}: $e';
  }
}

bool _same(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}

Uint8List _random(Random rnd, int n) => Uint8List.fromList([for (var i = 0; i < n; i++) rnd.nextInt(256)]);

/// A well-formed answer to [query], with [records] TXT records.
Uint8List _answer(Uint8List query, int records) {
  final q = DnsMessage.parse(query);
  return FakeResolver.encodeResponse(
    q.id,
    q.questions.single,
    FakeResponse(
      answers: [
        for (var i = 0; i < records; i++) rr(q.questions.single.name, RRType.txt, [5, ...'hello'.codeUnits, i & 0xff]),
      ],
    ),
  );
}

Future<void> _pause(Random rnd) => Future.delayed(Duration(milliseconds: rnd.nextInt(20)));

// ---------------------------------------------------------------------------
// UDP and TCP

enum _Udp {
  silent,
  garbage,
  valid,
  truncated,
  idThenGarbageTruncated,
  idOnly,
  wrongIdThenValid,
  otherPort,
  severalThenValid,
  maxDatagram,
  closed,
}

enum _Tcp {
  valid,
  validInPieces,
  shortThenClose,
  shortThenHold,
  dribble,
  garbage,
  closeAtOnce,
  reset,
  empty,
  halfPrefix,
  validWithTrailing,
  refused,
  neverAnswer,
  hugeLength,
}

class _HostileDns {
  _HostileDns(this.rnd)
    : udpMode = _Udp.values[rnd.nextInt(_Udp.values.length)],
      tcpMode = _Tcp.values[rnd.nextInt(_Tcp.values.length)],
      records = rnd.nextInt(3) == 0 ? 300 + rnd.nextInt(1500) : rnd.nextInt(4) {
    query = DnsMessage.buildQuery(DnsName.parse('example.test'), RRType.txt);
  }

  final Random rnd;
  final _Udp udpMode;
  final _Tcp tcpMode;
  final int records;
  late final Uint8List query;
  late RawDatagramSocket udp;
  RawDatagramSocket? other;
  ServerSocket? tcp;
  final _clients = <Socket>[];
  var _stopped = false;

  String get behaviour => 'UDP $udpMode, TCP $tcpMode, $records records';
  int get port => udp.port;

  /// The answer `send` must return, when the server behaves.
  Uint8List? get expected => switch (udpMode) {
    // UDP answers stay small: macOS caps loopback datagrams at 9216 bytes.
    _Udp.valid || _Udp.wrongIdThenValid || _Udp.severalThenValid => _answer(query, min(records, 3)),
    _Udp.truncated || _Udp.idThenGarbageTruncated
        when const [_Tcp.valid, _Tcp.validInPieces, _Tcp.validWithTrailing].contains(tcpMode) =>
      _answer(query, records),
    _ => null,
  };

  Future<void> start() async {
    // UDP and TCP on the same port; retry if another test took it.
    for (var attempt = 0; ; attempt++) {
      final t = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
      try {
        udp = await RawDatagramSocket.bind(InternetAddress.loopbackIPv4, t.port);
        tcp = t;
        break;
      } on SocketException {
        await t.close();
        if (attempt == 10) rethrow;
      }
    }
    other = await RawDatagramSocket.bind(InternetAddress.loopbackIPv4, 0);
    if (tcpMode == _Tcp.refused) {
      await tcp!.close();
      tcp = null;
    } else {
      tcp!.listen(_serveTcp);
    }
    if (udpMode == _Udp.closed) {
      udp.close();
      return;
    }
    udp.listen((event) {
      if (event != RawSocketEvent.read) return;
      final d = udp.receive();
      if (d != null) _serveUdp(d.data, d.address, d.port);
    });
  }

  void _serveUdp(Uint8List q, InternetAddress to, int port) {
    void send(List<int> bytes) => udp.send(bytes, to, port);
    final id = [q[0], q[1]];
    final answer = _answer(q, min(records, 3));
    switch (udpMode) {
      case _Udp.silent || _Udp.closed:
        break;
      case _Udp.garbage:
        send(_random(rnd, rnd.nextInt(600)));
      case _Udp.valid:
        send(answer);
      case _Udp.truncated:
        send(Uint8List.fromList(answer)..[2] |= 0x02);
      case _Udp.idThenGarbageTruncated:
        send([...id, 0x82, ..._random(rnd, rnd.nextInt(20))]);
      case _Udp.idOnly:
        send(id);
      case _Udp.wrongIdThenValid:
        send(Uint8List.fromList(answer)..[0] ^= 0xff);
        send(answer);
      case _Udp.otherPort:
        other!.send(answer, to, port);
      case _Udp.severalThenValid:
        for (var i = 0; i < 3; i++) {
          // Half the ID right, so that only the full comparison rejects it.
          send(
            _random(rnd, 2 + rnd.nextInt(50))
              ..[0] = id[0]
              ..[1] = id[1] ^ (1 + rnd.nextInt(255)),
          );
        }
        send(answer);
      case _Udp.maxDatagram:
        send([...id, ..._random(rnd, 9000)]);
    }
  }

  Future<void> _serveTcp(Socket client) async {
    _clients.add(client);
    final answer = _answer(query, records);
    final framed = [answer.length >> 8, answer.length & 0xff, ...answer];
    // Read the query, without waiting for it in modes that do not care.
    client.listen((_) {}, onError: (_) {}, cancelOnError: true);
    Future<void> write(List<int> bytes) async {
      if (_stopped) return;
      try {
        client.add(bytes);
        await client.flush();
      } on Object {
        // The client went away.
      }
    }

    try {
      switch (tcpMode) {
        case _Tcp.valid:
          await write(framed);
          await client.close();
        case _Tcp.validInPieces:
          for (var p = 0; p < framed.length && !_stopped;) {
            final n = 1 + rnd.nextInt(min(framed.length - p, 1 + framed.length ~/ 4));
            await write(framed.sublist(p, p + n));
            p += n;
            await _pause(rnd);
          }
          await client.close();
        case _Tcp.shortThenClose:
          await write(framed.sublist(0, 2 + rnd.nextInt(answer.length)));
          await client.close();
        case _Tcp.shortThenHold:
          await write(framed.sublist(0, 2 + rnd.nextInt(answer.length)));
        case _Tcp.dribble:
          // One byte every 50 ms: never more than the timeout between
          // bytes, so only a deadline for the whole answer stops it.
          for (var p = 0; p < framed.length && !_stopped; p++) {
            await write([framed[p]]);
            await Future.delayed(const Duration(milliseconds: 50));
          }
        case _Tcp.garbage:
          await write(_random(rnd, rnd.nextInt(100)));
          await client.close();
        case _Tcp.closeAtOnce:
          await client.close();
        case _Tcp.reset:
          client.destroy();
        case _Tcp.empty:
          await write([0, 0]);
          await client.close();
        case _Tcp.halfPrefix:
          await write([framed[0]]);
          await client.close();
        case _Tcp.validWithTrailing:
          await write([...framed, ..._random(rnd, 1 + rnd.nextInt(30))]);
          await client.close();
        case _Tcp.hugeLength:
          await write([0xff, 0xff, ..._random(rnd, 1000)]);
        case _Tcp.refused || _Tcp.neverAnswer:
          break;
      }
    } on Object {
      // The client went away.
    }
  }

  Future<void> stop() async {
    _stopped = true;
    udp.close();
    other?.close();
    for (final c in _clients) {
      c.destroy();
    }
    await tcp?.close();
  }
}

// ---------------------------------------------------------------------------
// DNS over HTTPS (plain HTTP here; TLS is dart:io's)

enum _Http {
  valid,
  validChunked,
  validHttp10,
  continueThenValid,
  garbage,
  statusOnly,
  wrongType,
  badType,
  shortBody,
  longBody,
  badChunk,
  hugeChunked,
  hugeLength,
  slowHeaders,
  slowBody,
  closeAtOnce,
  redirect,
  neverAnswer,
  duplicateType,
  hugeHeader,
  emptyBody,
}

class _HostileHttp {
  _HostileHttp(this.rnd)
    : mode = _Http.values[rnd.nextInt(_Http.values.length)],
      records = rnd.nextInt(3) == 0 ? 300 + rnd.nextInt(1500) : rnd.nextInt(4) {
    query = DnsMessage.buildQuery(DnsName.parse('example.test'), RRType.txt);
  }

  final Random rnd;
  final _Http mode;
  final int records;
  late final Uint8List query;
  late ServerSocket server;
  final _clients = <Socket>[];
  var _stopped = false;

  String get behaviour => 'HTTP $mode, $records records';
  int get port => server.port;

  Uint8List? get expected => switch (mode) {
    _Http.valid || _Http.validChunked || _Http.validHttp10 || _Http.continueThenValid => _answer(query, records),
    _ => null,
  };

  Future<void> start() async {
    server = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
    server.listen(_serve);
  }

  Future<void> _serve(Socket client) async {
    _clients.add(client);
    // Read headers and a Content-Length body.
    final received = BytesBuilder(copy: false);
    final request = Completer<Uint8List?>();
    client.listen(
      (chunk) {
        received.add(chunk);
        final bytes = received.toBytes();
        final end = _indexOf(bytes, const [13, 10, 13, 10]);
        if (end < 0 || request.isCompleted) return;
        final headers = latin1.decode(bytes.sublist(0, end)).toLowerCase();
        final length = int.parse(RegExp(r'content-length:\s*(\d+)').firstMatch(headers)?.group(1) ?? '0');
        if (bytes.length >= end + 4 + length) request.complete(Uint8List.sublistView(bytes, end + 4, end + 4 + length));
      },
      onError: (_) {},
      onDone: () {
        if (!request.isCompleted) request.complete(null);
      },
      cancelOnError: true,
    );
    final q = await request.future;
    if (q == null || _stopped) return;

    Future<void> write(List<int> bytes) async {
      if (_stopped) return;
      try {
        client.add(bytes);
        await client.flush();
      } on Object {
        // The client went away.
      }
    }

    Future<void> close() async {
      try {
        await client.close();
      } on Object {
        // Already gone.
      }
    }

    List<int> ascii(String s) => latin1.encode(s);
    final body = _answer(q, records);
    const type = 'Content-Type: application/dns-message\r\n';
    String length(int n) => 'Content-Length: $n\r\n';
    List<int> chunked(List<int> b) => [...ascii('${b.length.toRadixString(16)}\r\n'), ...b, ...ascii('\r\n0\r\n\r\n')];

    switch (mode) {
      case _Http.valid:
        await write([...ascii('HTTP/1.1 200 OK\r\n$type${length(body.length)}\r\n'), ...body]);
      case _Http.validChunked:
        await write([...ascii('HTTP/1.1 200 OK\r\n${type}Transfer-Encoding: chunked\r\n\r\n'), ...chunked(body)]);
      case _Http.validHttp10:
        await write([...ascii('HTTP/1.0 200 OK\r\n${type}Connection: close\r\n\r\n'), ...body]);
        await close();
      case _Http.continueThenValid:
        await write([
          ...ascii('HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\n$type${length(body.length)}\r\n'),
          ...body,
        ]);
      case _Http.garbage:
        await write(_random(rnd, rnd.nextInt(300)));
        await close();
      case _Http.statusOnly:
        await write(ascii('HTTP/1.1 200 OK\r\n'));
        await close();
      case _Http.wrongType:
        await write([...ascii('HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n${length(body.length)}\r\n'), ...body]);
      case _Http.badType:
        const types = [';;;', 'application/dns-message; =', '/', '"', 'application/', 'a/b; c="'];
        await write([
          ...ascii(
            'HTTP/1.1 200 OK\r\nContent-Type: ${types[rnd.nextInt(types.length)]}\r\n'
            '${length(body.length)}\r\n',
          ),
          ...body,
        ]);
      case _Http.shortBody:
        await write([...ascii('HTTP/1.1 200 OK\r\n$type${length(body.length + 10)}\r\n'), ...body]);
        await close();
      case _Http.longBody:
        await write([...ascii('HTTP/1.1 200 OK\r\n$type${length(max(0, body.length - 3))}\r\n'), ...body]);
      case _Http.badChunk:
        await write([...ascii('HTTP/1.1 200 OK\r\n${type}Transfer-Encoding: chunked\r\n\r\nzz\r\n'), ...body]);
        await close();
      case _Http.hugeChunked:
        await write(ascii('HTTP/1.1 200 OK\r\n${type}Transfer-Encoding: chunked\r\n\r\n'));
        for (var i = 0; i < 20 && !_stopped; i++) {
          await write(chunked(_random(rnd, 8192)).sublist(0, 8192 + 6));
        }
        await close();
      case _Http.hugeLength:
        await write([...ascii('HTTP/1.1 200 OK\r\n${type}Content-Length: 1000000000000\r\n\r\n'), ...body]);
      case _Http.slowHeaders:
        final head = ascii('HTTP/1.1 200 OK\r\n$type${length(body.length)}\r\n');
        for (var p = 0; p < head.length && !_stopped; p++) {
          await write([head[p]]);
          await Future.delayed(const Duration(milliseconds: 50));
        }
      case _Http.slowBody:
        await write(ascii('HTTP/1.1 200 OK\r\n$type${length(body.length)}\r\n'));
        for (var p = 0; p < body.length && !_stopped; p++) {
          await write([body[p]]);
          await Future.delayed(const Duration(milliseconds: 50));
        }
      case _Http.closeAtOnce:
        client.destroy();
      case _Http.redirect:
        await write(
          ascii(
            'HTTP/1.1 307 Temporary Redirect\r\nLocation: http://127.0.0.1:1/dns-query\r\n'
            'Content-Length: 0\r\n\r\n',
          ),
        );
      case _Http.neverAnswer:
        break;
      case _Http.duplicateType:
        await write([
          ...ascii('HTTP/1.1 200 OK\r\n${type}Content-Type: text/plain\r\n${length(body.length)}\r\n'),
          ...body,
        ]);
      case _Http.hugeHeader:
        await write(ascii('HTTP/1.1 200 OK\r\nX-Junk: ${'a' * 200000}\r\n$type${length(body.length)}\r\n'));
        await write(body);
      case _Http.emptyBody:
        await write(ascii('HTTP/1.1 200 OK\r\n$type${length(0)}\r\n'));
    }
  }

  Future<void> stop() async {
    _stopped = true;
    for (final c in _clients) {
      c.destroy();
    }
    await server.close();
  }
}

int _indexOf(List<int> haystack, List<int> needle) {
  outer:
  for (var i = 0; i + needle.length <= haystack.length; i++) {
    for (var j = 0; j < needle.length; j++) {
      if (haystack[i + j] != needle[j]) continue outer;
    }
    return i;
  }
  return -1;
}
