// ignore_for_file: avoid_print
import 'dart:io';

import 'package:tlsa_resolver/tlsa_resolver.dart';

/// Looks up TLSA records for the given names (or a default set) and prints
/// the validation result.
///
///   dart run tool/probe.dart [--server 1.1.1.1] [_25._tcp.mail.ietf.org ...]
Future<void> main(List<String> args) async {
  DnsTransport transport = const NativeDnsTransport();
  final names = <String>[];
  for (var i = 0; i < args.length; i++) {
    if (args[i] == '--server') {
      transport = DirectDnsTransport(InternetAddress(args[++i]));
    } else {
      names.add(args[i]);
    }
  }
  if (names.isEmpty) {
    names.addAll([
      '_25._tcp.mail.ietf.org', // DANE for SMTP
      '_443._tcp.example.com', // signed zone, no TLSA
      '_443._tcp.google.com', // unsigned zone
      '_443._tcp.dnssec-failed.org', // deliberately broken signatures
    ]);
  }
  final resolver = TlsaResolver(transport: transport);
  for (final name in names) {
    final sw = Stopwatch()..start();
    final result = await resolver.lookupName(DnsName.parse(name));
    print('$name: ${result.status.name} (${sw.elapsedMilliseconds} ms)'
        '${result.reason == null ? '' : ' - ${result.reason}'}');
    for (final r in result.records) {
      print('    $r');
    }
  }
}
