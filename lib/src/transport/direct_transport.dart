import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'transport.dart';

/// Sends queries straight to one recursive resolver over UDP, retrying over
/// TCP when the answer is truncated.
///
/// Useful where [NativeDnsTransport] is unavailable (Windows, Android before
/// 10) or to pin a known DNSSEC-aware resolver such as 1.1.1.1 or 9.9.9.9.
class DirectDnsTransport implements DnsTransport {
  DirectDnsTransport(this.server,
      {this.port = 53, this.timeout = const Duration(seconds: 5)});

  final InternetAddress server;
  final int port;
  final Duration timeout;

  @override
  Future<Uint8List> send(Uint8List query) async {
    final answer = await _udp(query);
    // TC bit: the answer did not fit, ask again over TCP.
    if (answer.length >= 3 && answer[2] & 0x02 != 0) return _tcp(query);
    return answer;
  }

  Future<Uint8List> _udp(Uint8List query) async {
    final socket = await RawDatagramSocket.bind(
        server.type == InternetAddressType.IPv6
            ? InternetAddress.anyIPv6
            : InternetAddress.anyIPv4,
        0);
    try {
      final completer = Completer<Uint8List>();
      socket.listen((event) {
        if (event != RawSocketEvent.read) return;
        final datagram = socket.receive();
        if (datagram == null || datagram.address != server || datagram.port != port) {
          return;
        }
        final data = datagram.data;
        // Ignore anything that does not echo our query ID.
        if (data.length >= 2 && data[0] == query[0] && data[1] == query[1] &&
            !completer.isCompleted) {
          completer.complete(data);
        }
      });
      socket.send(query, server, port);
      return await completer.future.timeout(timeout);
    } on TimeoutException {
      throw DnsTransportException('No UDP answer from ${server.address}');
    } finally {
      socket.close();
    }
  }

  Future<Uint8List> _tcp(Uint8List query) async {
    Socket? socket;
    try {
      socket = await Socket.connect(server, port, timeout: timeout);
      socket.add([query.length >> 8, query.length & 0xff, ...query]);
      final buffer = BytesBuilder();
      await for (final chunk in socket.timeout(timeout)) {
        buffer.add(chunk);
        final bytes = buffer.toBytes();
        if (bytes.length >= 2) {
          final length = (bytes[0] << 8) | bytes[1];
          if (bytes.length >= length + 2) {
            return Uint8List.sublistView(bytes, 2, length + 2);
          }
        }
      }
      throw DnsTransportException('TCP connection closed early');
    } on TimeoutException {
      throw DnsTransportException('No TCP answer from ${server.address}');
    } on SocketException catch (e) {
      throw DnsTransportException(e.message);
    } finally {
      socket?.destroy();
    }
  }
}
