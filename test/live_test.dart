@Tags(['network'])
library;

import 'dart:io';

import 'package:test/test.dart';
import 'package:tlsa_resolver/tlsa_resolver.dart';

/// Validates against the real DNS. Skip with `dart test -x network`.
void main() {
  final transports = <String, DnsTransport>{
    'system resolver': const NativeDnsTransport(),
    'direct to 9.9.9.9': DirectDnsTransport(InternetAddress('9.9.9.9')),
  };

  for (final MapEntry(key: label, value: transport) in transports.entries) {
    group(label, () {
      final resolver = TlsaResolver(transport: transport);

      test('IETF mail server publishes secure DANE records', () async {
        final result = await resolver.lookup('mail.ietf.org', port: 25);
        expect(result.status, SecurityStatus.secure, reason: result.reason);
        expect(result.daneApplies, isTrue);
      });

      test('signed zone without TLSA is a secure denial', () async {
        final result = await resolver.lookup('example.com', port: 443);
        expect(result.status, SecurityStatus.secure, reason: result.reason);
        expect(result.records, isEmpty);
      });

      test('unsigned zone is insecure', () async {
        final result = await resolver.lookup('google.com', port: 443);
        expect(result.status, SecurityStatus.insecure, reason: result.reason);
      });

      test('broken zone is bogus', () async {
        final result = await resolver.lookup('dnssec-failed.org', port: 443);
        expect(result.status, SecurityStatus.bogus);
      });
    });
  }
}
