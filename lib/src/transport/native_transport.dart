import 'dart:ffi';
import 'dart:isolate';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import 'transport.dart';

@Native<Int32 Function(Pointer<Uint8>, Int32, Pointer<Uint8>, Int32, Int32)>(
    symbol: 'tlsa_resolver_send')
external int _send(Pointer<Uint8> query, int queryLength, Pointer<Uint8> answer,
    int answerCapacity, int timeoutMs);

const _errors = {
  1: 'no system resolver API on this platform (Android needs API 29+)',
  2: 'the system resolver could not be initialised',
  3: 'the system resolver did not return an answer',
  4: 'the system resolver timed out',
  5: 'the answer was larger than the buffer',
  6: 'invalid arguments to the native resolver call',
};

/// Sends queries through the operating system's resolver, so they follow the
/// device's DNS configuration (DHCP, VPN, Android Private DNS, ...).
///
/// * Android 10+: `android_res_nsend` on the default network.
/// * iOS, macOS, Linux: `res_nsend` from libresolv.
///
/// Each query runs on a short-lived background isolate because the native
/// call blocks. Validation still happens locally: the system resolver only
/// has to pass DNSSEC records through, which it does when the upstream
/// server supports EDNS0 and the DO bit.
class NativeDnsTransport implements DnsTransport {
  const NativeDnsTransport({this.timeout = const Duration(seconds: 10)});

  final Duration timeout;

  @override
  Future<Uint8List> send(Uint8List query) async {
    final timeoutMs = timeout.inMilliseconds;
    final (length, answer) = await Isolate.run(() => _sendBlocking(query, timeoutMs));
    if (length < 0) {
      throw DnsTransportException(_errors[-length] ?? 'native error $length');
    }
    return answer!;
  }

  static (int, Uint8List?) _sendBlocking(Uint8List query, int timeoutMs) {
    const capacity = 65535;
    final q = malloc<Uint8>(query.length);
    final a = malloc<Uint8>(capacity);
    try {
      q.asTypedList(query.length).setAll(0, query);
      final n = _send(q, query.length, a, capacity, timeoutMs);
      if (n < 0) return (n, null);
      return (n, Uint8List.fromList(a.asTypedList(n)));
    } finally {
      malloc.free(q);
      malloc.free(a);
    }
  }
}
