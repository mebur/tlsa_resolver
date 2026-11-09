import 'dnssec/isolate_validator.dart';
import 'dnssec/validator.dart';
import 'tlsa.dart';
import 'transport/native_transport.dart';
import 'transport/transport.dart';
import 'wire/message.dart';
import 'wire/name.dart';

/// Looks up and DNSSEC-validates TLSA records.
///
/// ```dart
/// final resolver = TlsaResolver();
/// final result = await resolver.lookup('mail.example.com', port: 25);
/// if (result.isFailure) { /* defer or refuse the connection */ }
/// if (result.daneApplies) { /* check the certificate with DaneVerifier */ }
/// ```
///
/// Validation runs locally from the root trust anchors, so the only thing
/// asked of the system resolver is that it passes DNSSEC records through.
/// Validated zone keys are cached for their TTL; reuse one instance.
///
/// In a Flutter app, use [TlsaResolver.inBackground] so signature checks
/// run off the UI isolate.
class TlsaResolver {
  TlsaResolver({DnsTransport? transport, DnssecLookup? validator})
      : validator = validator ?? DnssecValidator(transport ?? const NativeDnsTransport());

  /// Validates on a long-lived background isolate (see [IsolateValidator]).
  /// [transport] is copied to that isolate. Call [close] when done.
  factory TlsaResolver.inBackground({DnsTransport? transport}) {
    final t = transport ?? const NativeDnsTransport();
    return TlsaResolver(validator: IsolateValidator(() => DnssecValidator(t)));
  }

  final DnssecLookup validator;

  /// Stops the background isolate, if the validator has one.
  Future<void> close() async {
    final v = validator;
    if (v is IsolateValidator) await v.close();
  }

  /// Looks up the TLSA records for a service at `_port._protocol.host`
  /// (RFC 6698 §3).
  Future<TlsaResult> lookup(String host, {required int port, String protocol = 'tcp'}) {
    if (port < 0 || port > 65535) throw ArgumentError.value(port, 'port');
    final name = DnsName.parse(host).prependString('_$protocol').prependString('_$port');
    return lookupName(name);
  }

  /// Looks up TLSA records at an explicit owner name such as
  /// `_443._tcp.example.com`.
  Future<TlsaResult> lookupName(DnsName name) async =>
      TlsaResult(await validator.resolve(name, RRType.tlsa));
}
