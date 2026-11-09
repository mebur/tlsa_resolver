// ignore_for_file: avoid_print
import 'dart:async';
import 'dart:collection';
import 'dart:io';

import 'package:tlsa_resolver/tlsa_resolver.dart';

/// Differential test: looks up a corpus of names with this package's
/// validator and with Unbound (`unbound-host`, which recurses and validates
/// on its own), and reports every answer they disagree on.
///
///   dart run tool/differential.dart [--server 9.9.9.9 | --system | --doh URL]
///       [--unbound-host PATH] [--jobs 8] [--only SUBSTRING] [--strict]
///
/// Both sides use the same root trust anchors. A disagreement is retried
/// once, to rule out a zone changing between the two lookups. Exit code 1
/// means at least one unexplained disagreement (with --strict, also ones
/// where a side got no answer).
Future<void> main(List<String> args) async {
  DnsTransport transport = DirectDnsTransport(InternetAddress('9.9.9.9'));
  var transportLabel = '9.9.9.9';
  var unboundHost = 'unbound-host';
  var jobs = 8;
  var strict = false;
  String? only;
  for (var i = 0; i < args.length; i++) {
    switch (args[i]) {
      case '--server':
        transportLabel = args[++i];
        transport = DirectDnsTransport(InternetAddress(transportLabel));
      case '--system':
        transportLabel = 'system resolver';
        transport = const NativeDnsTransport();
      case '--doh':
        final endpoint = Uri.parse(args[++i]);
        transportLabel = 'DoH ${endpoint.host}';
        transport = DohTransport(endpoint);
      case '--unbound-host':
        unboundHost = args[++i];
      case '--jobs':
        jobs = int.parse(args[++i]);
      case '--only':
        only = args[++i];
      case '--strict':
        strict = true;
      default:
        stderr.writeln('Unknown argument ${args[i]}');
        exit(64);
    }
  }

  final anchors = File('${Directory.systemTemp.createTempSync('differential').path}/root.ds')
    ..writeAsStringSync([
      for (final ds in rootTrustAnchors)
        '. DS ${ds.keyTag} ${ds.algorithm} ${ds.digestType} ${_hex(ds.digest)}',
    ].join('\n'));
  final unbound = _Unbound(unboundHost, anchors.path);
  final ours = _Ours(DnssecValidator(transport));
  final pool = _Pool(jobs);

  Future<_Comparison> compare(_Query q) async {
    var c = _Comparison(q, await pool.run(() => ours.lookup(q)), await pool.run(() => unbound.lookup(q)));
    if (c.verdict != _Verdict.agree) {
      c = _Comparison(q, await pool.run(() => ours.lookup(q)), await pool.run(() => unbound.lookup(q)));
    }
    return c;
  }

  bool selected(_Query q) => only == null || q.name.contains(only);

  final sw = Stopwatch()..start();
  final first = _corpus().where(selected).toList();
  final results = await Future.wait(first.map(compare));

  // Second round: DANE for SMTP at the mail servers Unbound found.
  final mxHosts = {
    for (final r in results)
      if (r.query.type == RRType.mx && r.unbound.status == SecurityStatus.secure) ...r.unbound.mxHosts,
  };
  final second = [
    for (final host in mxHosts) _Query('_25._tcp.$host', RRType.tlsa, 'mx'),
  ].where(selected);
  results.addAll(await Future.wait(second.map(compare)));

  print('Validator via $transportLabel vs ${await unbound.version()}');
  print('${results.length} lookups in ${sw.elapsed.inSeconds} s');
  final statuses = {
    for (final status in SecurityStatus.values)
      status: results.where((r) => r.unbound.status == status).length,
  };
  print('Unbound found ${[for (final e in statuses.entries) '${e.value} ${e.key.name}'].join(', ')}\n');
  final byVerdict = <_Verdict, List<_Comparison>>{};
  for (final r in results) {
    (byVerdict[r.verdict] ??= []).add(r);
  }
  for (final verdict in _Verdict.values) {
    final list = byVerdict[verdict] ?? const [];
    print('${verdict.label.padRight(28)} ${list.length}');
  }
  for (final verdict in _Verdict.values.where((v) => v != _Verdict.agree)) {
    final list = byVerdict[verdict];
    if (list == null) continue;
    print('\n${verdict.label}:');
    for (final r in list) {
      print('  ${r.query}');
      print('    ours:    ${r.ours}');
      print('    unbound: ${r.unbound}');
      if (r.note != null) print('    note:    ${r.note}');
    }
  }

  final failing = results.where((r) => r.verdict.fails || (strict && r.verdict == _Verdict.noAnswer));
  // A run where many lookups got no answer compared too little to pass.
  final unanswered = byVerdict[_Verdict.noAnswer]?.length ?? 0;
  final unreliable = unanswered > results.length * maxUnanswered;
  if (unreliable) {
    print('\nUNRELIABLE RUN: $unanswered of ${results.length} lookups got no answer on one '
        'side (limit ${(maxUnanswered * 100).round()}%). The network or a resolver is failing; '
        'this says nothing about the validator.');
  }
  exit(failing.isEmpty && !unreliable ? 0 : 1);
}

// ---------------------------------------------------------------------------
// Corpus

/// Signed and unsigned domains with a mix of TLDs, DNS hosts, algorithms
/// and denial types. Expectations are not needed: only agreement counts.
const _domains = [
  'ietf.org', 'isc.org', 'nlnetlabs.nl', 'nic.cz', 'sidn.nl', 'internet.nl',
  'debian.org', 'freebsd.org', 'torproject.org', 'cloudflare.com',
  'verisign.com', 'icann.org', 'iana.org', 'ripe.net', 'apnic.net', 'arin.net',
  'denic.de', 'internetstiftelsen.se', 'switch.ch', 'eurid.eu', 'afnic.fr',
  'nic.at', 'registro.br', 'nasa.gov', 'cisa.gov', 'bund.de', 'posteo.de',
  'mailbox.org', 'web.de', 'gmx.net', 'xs4all.nl', 'bit.nl', 'transip.nl',
  'comcast.net', 'paypal.com', 'huque.com', 'dnssec-tools.org',
  'example.com', 'example.org', 'example.net',
  'google.com', 'github.com', 'microsoft.com', 'amazon.com', 'wikipedia.org',
];

const _tlds = [
  'com', 'net', 'org', 'info', 'nl', 'de', 'se', 'cz', 'ch', 'uk', 'fr', 'eu',
  'br', 'jp', 'au', 'ca', 'us', 'gov', 'edu', 'io', 'dev', 'app', 'xyz',
  'nu', 'be', 'at', 'dk', 'no', 'fi', 'pl', 'it', 'es', 'pt', 'ru', 'cn',
];

/// Share of lookups that may go unanswered on one side before the run as a
/// whole is reported as unreliable.
const maxUnanswered = 0.10;

/// A label that should not exist anywhere, to exercise denial proofs.
const _missing = 'x7q-differential';

List<_Query> _corpus() => [
      for (final d in _domains) ...[
        _Query('_443._tcp.$d', RRType.tlsa, 'domain'),
        _Query('_443._tcp.www.$d', RRType.tlsa, 'domain'),
        _Query(d, RRType.a, 'domain'),
        _Query('www.$d', RRType.aaaa, 'domain'),
        _Query(d, RRType.mx, 'domain'),
        _Query(d, RRType.txt, 'domain'),
        _Query(d, RRType.ds, 'domain'),
        _Query(d, RRType.dnskey, 'domain'),
        _Query('$_missing.$d', RRType.a, 'denial'),
        _Query('_443._tcp.$_missing.$d', RRType.tlsa, 'denial'),
      ],
      for (final t in _tlds) ...[
        _Query(t, RRType.soa, 'tld'),
        _Query('$_missing.$t', RRType.a, 'denial'),
      ],
      // RootCanary: one zone per DS digest, algorithm and NSEC type, each
      // with a validly and an invalidly signed name. Missing zones are
      // NXDOMAIN in rootcanary.net, which both sides should agree on.
      for (final digest in [1, 2, 4])
        for (final alg in [5, 7, 8, 10, 13, 14, 15, 16])
          for (final nsec in [1, 3]) ...[
            _Query('secure.d${digest}a${alg}n$nsec.rootcanary.net', RRType.a, 'rootcanary'),
            _Query('bogus.d${digest}a${alg}n$nsec.rootcanary.net', RRType.a, 'rootcanary'),
            _Query('$_missing.d${digest}a${alg}n$nsec.rootcanary.net', RRType.a, 'rootcanary'),
          ],
      for (final name in [
        'dnssec-failed.org', 'rhybar.cz', 'sigfail.verteiltesysteme.net',
        'sigok.verteiltesysteme.net',
      ])
        _Query(name, RRType.a, 'broken'),
    ];

/// Disagreements that follow from a documented difference, not a bug.
_KnownDifference? _knownDifference(_Query q, _Outcome ours, _Outcome unbound) {
  if (RegExp(r'\.d\da16n\d\.rootcanary\.net$').hasMatch(q.name) &&
      ours.status == SecurityStatus.insecure) {
    return const _KnownDifference('Ed448 (algorithm 16) is not supported, so the zone is insecure');
  }
  return null;
}

// ---------------------------------------------------------------------------
// The two sides

class _Query {
  const _Query(this.name, this.type, this.group);
  final String name;
  final int type;
  final String group;

  @override
  String toString() => '$name ${RRType.name(type)}';
}

class _Outcome {
  _Outcome(this.status,
      {this.nxDomain = false, this.records = 0, this.canonicalName, this.tlsa = const {}, this.detail, this.mxHosts = const []});

  final SecurityStatus status;
  final bool nxDomain;
  final int records;

  /// Where the CNAME chain ends, if there is one. `unbound-host` prints only
  /// that, not the steps in between.
  final String? canonicalName;
  final Set<String> tlsa;
  final String? detail;
  final List<String> mxHosts;

  @override
  String toString() => [
        status.name,
        if (nxDomain) 'NXDOMAIN',
        '$records records',
        if (canonicalName != null) 'via $canonicalName',
        if (tlsa.isNotEmpty) 'tlsa=${(tlsa.toList()..sort()).join(',')}',
        if (detail != null) '($detail)',
      ].join(' ');
}

class _Ours {
  _Ours(this.validator);
  final DnssecValidator validator;

  Future<_Outcome> lookup(_Query q) async {
    final answer = await validator.resolve(DnsName.parse(q.name), q.type);
    return _Outcome(
      answer.status,
      nxDomain: answer.nxDomain,
      records: answer.records.length,
      canonicalName: answer.aliases.isEmpty ? null : _bare('${answer.aliases.last}'),
      tlsa: q.type == RRType.tlsa ? {for (final r in TlsaResult(answer).records) '$r'.toLowerCase()} : const {},
      detail: answer.reason,
    );
  }
}

class _Unbound {
  _Unbound(this.executable, this.anchors);
  final String executable;
  final String anchors;
  static const timeout = Duration(seconds: 30);

  Future<String> version() async {
    final r = await Process.run(executable, ['-h']);
    final line = '${r.stdout}${r.stderr}'.split('\n').firstWhere((l) => l.startsWith('Version'), orElse: () => '');
    return 'Unbound ${line.replaceFirst('Version ', '')}'.trim();
  }

  /// Runs `unbound-host -v` and reads its answer lines, which look like
  /// `name has TLSA record 3 1 1 AB… (secure)`,
  /// `name is an alias for target. (secure)` or
  /// `Host name not found: 3(NXDOMAIN). (BOGUS (security failure))`.
  Future<_Outcome> lookup(_Query q) async {
    // unbound-host has no timeout of its own and can hang on an
    // unresponsive server; it is killed after [timeout].
    final process = await Process.start(
        executable, ['-v', '-f', anchors, '-t', RRType.name(q.type), q.name]);
    final stdout = process.stdout.transform(systemEncoding.decoder).join();
    final stderr = process.stderr.transform(systemEncoding.decoder).join();
    final exited = await process.exitCode.then((_) => true).timeout(timeout, onTimeout: () {
      process.kill(ProcessSignal.sigkill);
      return false;
    });
    if (!exited) {
      return _Outcome(SecurityStatus.indeterminate,
          detail: 'unbound-host did not finish within ${timeout.inSeconds} s');
    }
    final lines = '${await stdout}${await stderr}'.split('\n').where((l) => l.trim().isNotEmpty).toList();
    var status = SecurityStatus.secure;
    var tagged = false;
    var nx = false, records = 0;
    String? canonical;
    final tlsa = <String>{};
    final mx = <String>[];
    String? detail;
    for (final line in lines) {
      if (line.startsWith('validation failure')) {
        detail = line;
        continue;
      }
      final SecurityStatus lineStatus;
      if (line.contains('(BOGUS')) {
        lineStatus = SecurityStatus.bogus;
      } else if (line.endsWith('(insecure)')) {
        lineStatus = SecurityStatus.insecure;
      } else if (line.endsWith('(secure)')) {
        lineStatus = SecurityStatus.secure;
      } else {
        lineStatus = SecurityStatus.indeterminate;
        detail ??= line;
      }
      tagged = true;
      if (_rank(lineStatus) > _rank(status)) status = lineStatus;

      final alias = RegExp(r' is an alias for (\S+)').firstMatch(line);
      if (alias != null) {
        canonical = _bare(alias.group(1)!);
      } else if (line.contains('3(NXDOMAIN)')) {
        nx = true;
      } else if (line.contains(' mail is handled by ')) {
        records++;
        // A null MX (RFC 7505) has the root as its target: no mail server.
        final target = RegExp(r'mail is handled by \d+ (\S+) \(').firstMatch(line)?.group(1);
        if (target != null && target != '.') mx.add(_bare(target));
      } else if (line.contains(' has ') && !line.contains(' has no ')) {
        records++;
        final m = RegExp(r' has TLSA record (.*) \((?:secure|insecure|BOGUS)').firstMatch(line);
        if (m != null) tlsa.add(m.group(1)!.toLowerCase());
      }
    }
    if (!tagged) status = SecurityStatus.indeterminate;
    return _Outcome(status, nxDomain: nx, records: records, canonicalName: canonical, tlsa: tlsa, detail: detail, mxHosts: mx);
  }
}

int _rank(SecurityStatus s) => switch (s) {
      SecurityStatus.secure => 0,
      SecurityStatus.insecure => 1,
      SecurityStatus.indeterminate => 2,
      SecurityStatus.bogus => 3,
    };

// ---------------------------------------------------------------------------
// Comparing

enum _Verdict {
  agree('agree', fails: false),
  known('known difference', fails: false),
  noAnswer('one side got no answer', fails: false),
  diverged('different CNAME targets', fails: false),
  security('SECURE ON ONE SIDE ONLY', fails: true),
  status('different status', fails: true),
  data('same status, different data', fails: true);

  const _Verdict(this.label, {required this.fails});
  final String label;
  final bool fails;
}

class _KnownDifference {
  const _KnownDifference(this.reason);
  final String reason;
}

class _Comparison {
  _Comparison(this.query, this.ours, this.unbound);

  final _Query query;
  final _Outcome ours;
  final _Outcome unbound;
  late final (_Verdict, String?) _judged = _judge();
  _Verdict get verdict => _judged.$1;
  String? get note => _judged.$2;

  (_Verdict, String?) _judge() {
    // CDN traffic steering hands out different CNAME targets by location
    // and time (www.paypal.com goes to a signed or an unsigned CDN), so
    // the two sides may have looked up different chains.
    if (ours.canonicalName != null &&
        unbound.canonicalName != null &&
        ours.canonicalName != unbound.canonicalName) {
      return (_Verdict.diverged, 'statuses cannot be compared');
    }
    if (ours.status == unbound.status) {
      // Unauthenticated data may differ between the servers each side
      // reached (zones served by several providers), so only secure
      // answers are compared further. Addresses vary with CDNs and GeoDNS,
      // so for them only the presence of records counts; TLSA data has to
      // match exactly.
      if (ours.status != SecurityStatus.secure) return (_Verdict.agree, null);
      final diffs = [
        if (ours.nxDomain != unbound.nxDomain) 'NXDOMAIN',
        if ((ours.records > 0) != (unbound.records > 0)) 'records',
        if (ours.canonicalName != unbound.canonicalName) 'CNAME target',
        if (query.type == RRType.tlsa && !_sameSet(ours.tlsa, unbound.tlsa)) 'TLSA data',
      ];
      return diffs.isEmpty ? (_Verdict.agree, null) : (_Verdict.data, diffs.join(', '));
    }
    // Without an answer on one side there is nothing to compare.
    if (ours.status == SecurityStatus.indeterminate || unbound.status == SecurityStatus.indeterminate) {
      return (_Verdict.noAnswer, null);
    }
    final known = _knownDifference(query, ours, unbound);
    if (known != null) return (_Verdict.known, known.reason);
    if (ours.status == SecurityStatus.secure || unbound.status == SecurityStatus.secure) {
      return (_Verdict.security, null);
    }
    return (_Verdict.status, null);
  }

  static bool _sameSet(Set<String> a, Set<String> b) => a.length == b.length && a.containsAll(b);
}

/// Runs at most [size] tasks at a time.
class _Pool {
  _Pool(this.size);
  final int size;
  var _running = 0;
  final _waiting = Queue<Completer<void>>();

  Future<T> run<T>(Future<T> Function() task) async {
    if (_running >= size) {
      final turn = Completer<void>();
      _waiting.add(turn);
      await turn.future;
    }
    _running++;
    try {
      return await task();
    } finally {
      _running--;
      if (_waiting.isNotEmpty) _waiting.removeFirst().complete();
    }
  }
}

String _bare(String name) =>
    (name.endsWith('.') && name.length > 1 ? name.substring(0, name.length - 1) : name).toLowerCase();

String _hex(List<int> bytes) => [for (final b in bytes) b.toRadixString(16).padLeft(2, '0')].join();
