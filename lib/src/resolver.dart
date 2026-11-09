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

  /// Looks up the TLSA records for a service on [host], at
  /// `_port._protocol.host` (RFC 6698 §3).
  ///
  /// When [host] is an alias, RFC 7671 §7 applies. If its CNAME chain
  /// validates as secure, the records are looked up at the chain's final
  /// target first and, only if there are none there, at [host] itself. If
  /// the chain is insecure, [host] alone is used. `result.answer.name`
  /// says where the records came from. This costs one address lookup
  /// first; [followCname] false skips it and uses [host] only.
  ///
  /// A bogus or unanswered address lookup is returned as a failure: the
  /// client cannot know where it would connect, and falling back to [host]
  /// would let an attacker steer around DANE.
  Future<TlsaResult> lookup(String host,
      {required int port, String protocol = 'tcp', bool followCname = true}) async {
    if (port < 0 || port > 65535) throw ArgumentError.value(port, 'port');
    final hostName = DnsName.parse(host);
    DnsName owner(DnsName base) => base.prependString('_$protocol').prependString('_$port');
    if (!followCname) return lookupName(owner(hostName));

    final address = await validator.resolve(hostName, RRType.a);
    if (address.status == SecurityStatus.bogus || address.status == SecurityStatus.indeterminate) {
      return TlsaResult(ValidatedAnswer(
          name: owner(hostName), type: RRType.tlsa, status: address.status,
          reason: 'Address lookup for $hostName failed: ${address.reason}', error: address.error));
    }
    if (address.status == SecurityStatus.secure && address.aliases.isNotEmpty) {
      final expanded = await lookupName(owner(address.canonicalName));
      if (expanded.isFailure || (expanded.isSecure && expanded.records.isNotEmpty)) {
        return expanded;
      }
    }
    return lookupName(owner(hostName));
  }

  /// Looks up TLSA records at an explicit owner name such as
  /// `_443._tcp.example.com`.
  Future<TlsaResult> lookupName(DnsName name) async =>
      TlsaResult(await validator.resolve(name, RRType.tlsa));
}
