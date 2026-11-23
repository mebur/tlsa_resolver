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
    final RawDatagramSocket socket;
    try {
      socket = await RawDatagramSocket.bind(
          server.type == InternetAddressType.IPv6
              ? InternetAddress.anyIPv6
              : InternetAddress.anyIPv4,
          0);
    } on SocketException catch (e) {
      throw DnsTransportException(e.message);
    }
    try {
      final completer = Completer<Uint8List>();
      socket.listen(onError: (Object e) {
        // Without this handler a socket error would be uncaught.
        if (!completer.isCompleted) {
          completer.completeError(DnsTransportException('UDP socket error: $e'));
        }
      }, (event) {
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
    } on SocketException catch (e) {
      throw DnsTransportException(e.message);
    } finally {
      socket.close();
    }
  }

  Future<Uint8List> _tcp(Uint8List query) async {
    Socket? socket;
    var finished = false;
    Future<Uint8List> exchange() async {
      final s = socket = await Socket.connect(server, port, timeout: timeout);
      // Connected only after the deadline: nobody is waiting any more, and
      // the finally below has already run without a socket to close.
      if (finished) {
        s.destroy();
        throw DnsTransportException('Connected after the deadline');
      }
      // A write that fails (the server resets the connection) reports its
      // error on done; unheard, it would be an uncaught error. The read
      // below sees the failure too.
      s.done.ignore();
      s.add([query.length >> 8, query.length & 0xff, ...query]);
      final buffer = BytesBuilder();
      int? length;
      await for (final chunk in s) {
        buffer.add(chunk);
        if (length == null && buffer.length >= 2) {
          final head = buffer.toBytes();
          length = (head[0] << 8) | head[1];
        }
        if (length != null && buffer.length >= length + 2) {
          return Uint8List.sublistView(buffer.takeBytes(), 2, length + 2);
        }
      }
      throw DnsTransportException('TCP connection closed early');
    }

    try {
      // One deadline for the whole exchange: a server that sends a byte
      // now and then must not hold the query open indefinitely.
      return await exchange().timeout(timeout);
    } on TimeoutException {
      throw DnsTransportException('No TCP answer from ${server.address}');
    } on SocketException catch (e) {
      throw DnsTransportException(e.message);
    } finally {
      finished = true;
      socket?.destroy();
    }
  }
}
