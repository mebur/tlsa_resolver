// Opens a TLS connection with dart:io and DANE, the way an app would.
//
//   dart run tool/dane_connect.dart www.freebsd.org          # DANE-EE: verified
//   dart run tool/dane_connect.dart www.google.com           # no TLSA: PKIX decides
//   dart run tool/dane_connect.dart www.freebsd.org --connect www.debian.org
//                                                            # wrong server: refused
//
// What dart:io allows: SecureSocket gives the server's leaf certificate and
// nothing else of the chain. That is all DANE-EE (usage 3, by far the most
// published, and what SMTP uses) needs. DANE-TA (2) and PKIX-TA (0) need
// the chain, so a server that publishes only those cannot be verified here
// and the connection is refused rather than let through on PKIX alone.

// ignore_for_file: avoid_print

import 'dart:io';

import 'package:tlsa_resolver/tlsa_resolver.dart';

class DaneException implements IOException {
  DaneException(this.message);
  final String message;

  @override
  String toString() => 'DaneException: $message';
}

/// Connects to [host]:[port] with TLS and, when [host] publishes secure
/// TLSA records, accepts the server only if its certificate matches them.
///
/// * TLSA lookup bogus or failed: throws before connecting. Falling back to
///   plain PKIX would let an attacker who can break the lookup also skip
///   DANE (RFC 7672 §2.2).
/// * No secure TLSA records (insecure zone, or none published): ordinary
///   certificate validation decides, as without DANE.
/// * TLSA records: the server's leaf must match one. A DANE-EE match is
///   enough even if the certificate is self-signed, expired or for another
///   name (RFC 7671 §5.1); PKIX-EE also needs ordinary validation to pass.
///
/// [connectTo] connects to another host while checking [host]'s records,
/// to try a server that should not match.
Future<SecureSocket> connectWithDane(TlsaResolver resolver, String host, int port,
    {String? connectTo}) async {
  final tlsa = await resolver.lookup(host, port: port);
  if (tlsa.isFailure) {
    throw DaneException('TLSA lookup for $host failed (${tlsa.status.name}): ${tlsa.reason}');
  }
  final daneApplies = tlsa.daneApplies;

  var pkixValidated = true;
  final socket = await SecureSocket.connect(connectTo ?? host, port,
      timeout: const Duration(seconds: 10), onBadCertificate: (_) {
    // Called when ordinary validation fails, with whichever certificate
    // failed (not always the leaf). Without DANE that is the end of it;
    // with DANE, finish the handshake and judge the leaf below.
    pkixValidated = false;
    return daneApplies;
  });
  if (!daneApplies) return socket;

  final leaf = socket.peerCertificate;
  final verdict = leaf == null
      ? null
      : DaneVerifier.verify(tlsa, [leaf.der], pkixValidated: pkixValidated);
  if (verdict?.outcome == DaneOutcome.verified) return socket;

  socket.destroy();
  throw DaneException(switch (verdict?.outcome) {
    DaneOutcome.needsChainCheck =>
      'only a DANE-TA record matched, and dart:io does not expose the chain to check it',
    null => 'the server sent no certificate',
    _ => 'the certificate of ${connectTo ?? host} matches none of the TLSA records of $host',
  });
}

Future<void> main(List<String> args) async {
  if (args.isEmpty) {
    print('Usage: dart run tool/dane_connect.dart <host> [port] [--connect <other host>]');
    exit(64);
  }
  final rest = [...args];
  String? connectTo;
  final connect = rest.indexOf('--connect');
  if (connect >= 0) {
    connectTo = rest.removeAt(connect + 1);
    rest.removeAt(connect);
  }
  final host = rest[0];
  final port = rest.length > 1 ? int.parse(rest[1]) : 443;

  final resolver = TlsaResolver();
  final tlsa = await resolver.lookup(host, port: port);
  print('TLSA _$port._tcp.$host: ${tlsa.status.name}, '
      '${tlsa.usableRecords.length} usable record(s)${tlsa.reason == null ? '' : ' (${tlsa.reason})'}');
  try {
    final socket = await connectWithDane(resolver, host, port, connectTo: connectTo);
    print(tlsa.daneApplies
        ? 'Connected: the certificate matches a TLSA record.'
        : 'Connected: no DANE for this host, so ordinary certificate validation decided.');
    socket.destroy();
  } on DaneException catch (e) {
    print('Refused: ${e.message}');
    exitCode = 1;
  } on HandshakeException catch (e) {
    print('Refused by ordinary certificate validation: ${e.message}');
    exitCode = 1;
  }
}
