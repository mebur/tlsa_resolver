import 'dart:async';
import 'dart:io';

import 'package:tlsa_resolver/tlsa_resolver.dart';

/// One live check against the public DNS. Expectations reflect how these
/// zones were set up when the suite was written (November 2026); if a zone
/// operator changes their setup, a case can start failing without a bug.
class TestCase {
  const TestCase(
    this.title,
    this.host,
    this.port, {
    this.type = RRType.tlsa,
    this.connectHost,
    required this.status,
    this.records,
    this.usable,
    this.nxDomain,
    this.viaCname,
    this.dane,
    required this.note,
  });

  final String title;
  final String host;
  final int port;

  /// Record type to look up. For TLSA the owner is `_port._tcp.host`, for
  /// anything else just `host`.
  final int type;

  /// Host to take the TLS certificate from, if not [host]. Used to present
  /// a certificate the TLSA records were not made for.
  final String? connectHost;
  final SecurityStatus status;

  /// Whether TLSA records should be present (null: don't check).
  final bool? records;

  /// Whether any of them should be usable for DANE.
  final bool? usable;
  final bool? nxDomain;
  final bool? viaCname;

  /// When set, also connect with TLS and check the certificate.
  final DaneOutcome? dane;

  final String note;
}

const testCases = [
  // Secure answers
  TestCase('DANE for SMTP', 'mail.ietf.org', 25,
      status: SecurityStatus.secure, records: true, usable: true,
      note: 'Signed TLSA in ietf.org'),
  TestCase('NSEC3-signed TLD', 'www.nic.cz', 443,
      status: SecurityStatus.secure, records: true, usable: true,
      note: '.cz chain'),
  TestCase('TLSA behind a CNAME', 'www.nlnetlabs.nl', 443,
      status: SecurityStatus.secure, records: true, viaCname: true,
      note: 'Alias to _443._tcp.nlnetlabs.nl'),
  TestCase('Unusable parameters', 'badparam.dane.huque.com', 443,
      status: SecurityStatus.secure, records: true, usable: false,
      note: 'Record "7 5 23 …" must be ignored'),

  // Secure denials
  TestCase('No TLSA in signed zone', 'example.com', 443,
      status: SecurityStatus.secure, records: false, nxDomain: false,
      note: 'NODATA proof'),
  TestCase('Name does not exist', 'no-such-host-x7q.nic.cz', 443,
      status: SecurityStatus.secure, records: false, nxDomain: true,
      note: 'NXDOMAIN proof with NSEC3'),
  TestCase('Compact denial', 'no-such-host-x7q.ietf.org', 443,
      status: SecurityStatus.secure, records: false, nxDomain: false,
      note: 'Cloudflare answers missing names with a signed NODATA'),

  // Insecure
  TestCase('Unsigned zone', 'google.com', 443,
      status: SecurityStatus.insecure,
      note: 'Proven unsigned delegation from .com'),
  TestCase('NSEC3 opt-out', 'no-such-host-x7q.com', 443,
      status: SecurityStatus.insecure,
      note: '.com denial covered by an opt-out span'),

  // Bogus
  TestCase('Broken zone keys', 'dnssec-failed.org', 443,
      status: SecurityStatus.bogus, note: 'DS matches no DNSKEY'),
  TestCase('Broken zone keys (.cz)', 'rhybar.cz', 443,
      status: SecurityStatus.bogus, note: 'DS matches no DNSKEY'),
  TestCase('Bad signature', 'sigfail.verteiltesysteme.net', 0, type: RRType.a,
      status: SecurityStatus.bogus, note: 'A record behind a CNAME with a corrupted RRSIG'),
  TestCase('Good signature (control)', 'sigok.verteiltesysteme.net', 0, type: RRType.a,
      status: SecurityStatus.secure, records: true, note: 'Same setup, valid RRSIG'),

  // TLS handshake + DANE matching
  TestCase('Handshake: FreeBSD', 'www.freebsd.org', 443,
      status: SecurityStatus.secure, dane: DaneOutcome.verified,
      note: 'Server key matches its 3 1 1 record'),
  TestCase('Handshake: Debian', 'www.debian.org', 443,
      status: SecurityStatus.secure, dane: DaneOutcome.verified,
      note: 'Server key matches its 3 1 1 record'),
  TestCase('Handshake: wrong server', 'www.freebsd.org', 443, connectHost: 'www.debian.org',
      status: SecurityStatus.secure, dane: DaneOutcome.mismatch,
      note: "Debian's certificate against FreeBSD's TLSA must not match"),
];

class CaseResult {
  CaseResult(this.testCase, this.elapsed, {this.result, this.verdict, this.error, required this.failures});

  final TestCase testCase;
  final Duration elapsed;
  final TlsaResult? result;
  final DaneVerdict? verdict;
  final Object? error;
  final List<String> failures;

  bool get passed => failures.isEmpty;
}

/// A DNS transport choice for the suite.
class TransportOption {
  const TransportOption(this.label, this.create);
  final String label;
  final DnsTransport Function() create;
}

final transportOptions = [
  TransportOption('System resolver', () => const NativeDnsTransport()),
  TransportOption('Quad9 (9.9.9.9)', () => DirectDnsTransport(InternetAddress('9.9.9.9'))),
  TransportOption('Cloudflare (1.1.1.1)', () => DirectDnsTransport(InternetAddress('1.1.1.1'))),
  TransportOption('Cloudflare over HTTPS', DohTransport.cloudflare),
  TransportOption('Google over HTTPS', DohTransport.google),
];

Future<CaseResult> runCase(TlsaResolver resolver, TestCase c) async {
  final sw = Stopwatch()..start();
  final failures = <String>[];
  TlsaResult? result;
  DaneVerdict? verdict;
  try {
    result = c.type == RRType.tlsa
        ? await resolver.lookup(c.host, port: c.port)
        : TlsaResult(await resolver.validator.resolve(DnsName.parse(c.host), c.type));
    if (result.status != c.status) {
      failures.add('status ${result.status.name}, expected ${c.status.name}');
    }
    void check(bool? expected, bool actual, String what) {
      if (expected != null && expected != actual) {
        failures.add(expected ? 'expected $what' : 'unexpected $what');
      }
    }

    check(c.records, result.answer.records.isNotEmpty, 'records');
    check(c.usable, result.usableRecords.isNotEmpty, 'usable records');
    check(c.nxDomain, result.answer.nxDomain, 'NXDOMAIN');
    check(c.viaCname, result.answer.aliases.isNotEmpty, 'CNAME');

    if (c.dane != null) {
      verdict = await _handshake(c.connectHost ?? c.host, c.port, result);
      if (verdict.outcome != c.dane) {
        failures.add('DANE ${verdict.outcome.name}, expected ${c.dane!.name}');
      }
    }
    return CaseResult(c, sw.elapsed, result: result, verdict: verdict, failures: failures);
  } catch (e) {
    return CaseResult(c, sw.elapsed, result: result, verdict: verdict, error: e,
        failures: [...failures, 'error: $e']);
  }
}

/// Connects with TLS, takes the server's leaf certificate and matches it
/// against the TLSA records. PKIX failures are noted, not fatal, so DANE-EE
/// can be judged on its own.
Future<DaneVerdict> _handshake(String host, int port, TlsaResult result) async {
  var pkixValid = true;
  final socket = await SecureSocket.connect(host, port,
      timeout: const Duration(seconds: 10), onBadCertificate: (_) {
    pkixValid = false;
    return true;
  });
  try {
    final cert = socket.peerCertificate;
    if (cert == null) throw StateError('No peer certificate');
    return DaneVerifier.verify(result, [cert.der], pkixValidated: pkixValid);
  } finally {
    socket.destroy();
  }
}

String environmentSummary() =>
    '${Platform.operatingSystem} ${Platform.operatingSystemVersion}\n'
    'Dart ${Platform.version.split(' ').first}';

String formatReport(String transport, List<CaseResult> results) {
  final passed = results.where((r) => r.passed).length;
  final sb = StringBuffer()
    ..writeln('tlsa_resolver device test')
    ..writeln(DateTime.now().toUtc().toIso8601String())
    ..writeln(environmentSummary())
    ..writeln('Transport: $transport')
    ..writeln('Passed $passed/${results.length}')
    ..writeln();
  for (final r in results) {
    final c = r.testCase;
    sb.writeln('${r.passed ? 'PASS' : 'FAIL'}  ${c.title}  '
        '(${describe(c)}, ${r.elapsed.inMilliseconds} ms)');
    for (final line in detailLines(r)) {
      sb.writeln('      $line');
    }
  }
  return sb.toString();
}

/// What a case observed, one fact per line; failures start with `!`.
List<String> detailLines(CaseResult r) {
  final result = r.result;
  return [
    if (result != null) ...[
      'status=${result.status.name} records=${result.answer.records.length}'
          ' usable=${result.usableRecords.length} nx=${result.answer.nxDomain}'
          '${result.answer.aliases.isEmpty ? '' : ' via=${result.answer.aliases.join(',')}'}',
      if (result.reason != null) 'reason: ${result.reason}',
      for (final record in result.records) 'tlsa: $record',
    ],
    if (r.verdict != null) 'dane: ${r.verdict}',
    for (final f in r.failures) '! $f',
  ];
}

/// The name and type a case looks up, e.g. `_443._tcp.example.com TLSA`.
String describe(TestCase c) {
  final lookup = c.type == RRType.tlsa
      ? '_${c.port}._tcp.${c.host} TLSA'
      : '${c.host} ${RRType.name(c.type)}';
  return c.connectHost == null ? lookup : '$lookup, cert from ${c.connectHost}';
}
