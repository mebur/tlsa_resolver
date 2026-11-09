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
class TlsaResolver {
  TlsaResolver({DnsTransport? transport, DnssecValidator? validator})
      : validator = validator ?? DnssecValidator(transport ?? const NativeDnsTransport());

  final DnssecValidator validator;

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
