import 'dart:typed_data';

/// Sends one DNS query message and returns the raw response message.
///
/// The validator builds the query (with the DO and CD bits set) and parses
/// the response; a transport only moves bytes. Implementations must throw a
/// [DnsTransportException] when no response arrives.
abstract interface class DnsTransport {
  Future<Uint8List> send(Uint8List query);
}

class DnsTransportException implements Exception {
  DnsTransportException(this.message);
  final String message;

  @override
  String toString() => 'DnsTransportException: $message';
}
