import 'dart:async';
import 'dart:collection';
import 'dart:math';
import 'dart:typed_data';

import '../transport/transport.dart';
import '../wire/message.dart';
import '../wire/name.dart';
import '../wire/rdata.dart';
import 'crypto.dart';
import 'denial.dart';
import 'isolate_validator.dart';
import 'trust_anchors.dart';

/// DNSSEC security status of an answer (RFC 4033 §5).
enum SecurityStatus {
  /// Validated through an unbroken chain of signatures from a trust anchor.
  secure,

  /// Provably outside any signed zone (an unsigned delegation sits between
  /// the trust anchor and the name). The data cannot be authenticated.
  insecure,

  /// Should have validated but did not: missing or invalid signatures,
  /// failed proofs, or a resolver that strips DNSSEC records.
  bogus,

  /// No usable answer was obtained (network error, SERVFAIL, timeout).
  indeterminate,
}

/// How the validator treats DNSSEC's SHA-1 based algorithms: RSASHA1 (5),
/// RSASHA1-NSEC3-SHA1 (7) and SHA-1 DS digests (1). NSEC3 name hashing
/// also uses SHA-1 but only hides names, so it is not affected.
enum Sha1Policy {
  /// Validate them like any other algorithm (RFC 8624).
  accept,

  /// Treat them as unsupported: a zone that can only be validated through
  /// SHA-1 is [SecurityStatus.insecure], like an unsigned zone
  /// (RFC 4035 §5.2).
  unsupported,

  /// A zone that can only be validated through SHA-1 is
  /// [SecurityStatus.bogus].
  reject,
}

/// Why an answer is not secure, for programs to act on. Each value carries
/// the closest Extended DNS Error code (RFC 8914), so it can be logged or
/// passed on in those terms. The [ValidatedAnswer.reason] text says more.
enum ValidationError {
  /// The zone is signed only with algorithms or DS digests that are not
  /// supported or are disabled (see [Sha1Policy]). Insecure, or bogus under
  /// [Sha1Policy.reject].
  unsupportedAlgorithm(1),

  /// Other DNSSEC failures: signatures that do not verify, a signer that
  /// is not an ancestor, a zone that the parent says does not exist.
  bogus(6),

  /// The only signatures have expired.
  signatureExpired(7),

  /// The only signatures are not valid yet; often a wrong device clock.
  signatureNotYetValid(8),

  /// No DNSKEY matches the parent's DS records or the trust anchors.
  dnskeyMissing(9),

  /// Data in a signed zone came without signatures.
  rrsigsMissing(10),

  /// A denial of existence or wildcard answer came without a valid
  /// NSEC/NSEC3 proof.
  nsecMissing(12),

  /// The resolver answered with an error (SERVFAIL, REFUSED, ...), or the
  /// zone of a name could not be found.
  resolverError(22),

  /// No answer arrived: the transport failed or timed out.
  networkError(23),

  /// Malformed, mismatched or contradictory responses: a response that does
  /// not match the query, several CNAMEs at a name, CNAME loops.
  invalidData(24),

  /// The zone uses more NSEC3 iterations than are validated (RFC 9276), so
  /// its denials are insecure.
  unsupportedNsec3Iterations(27),

  /// The lookup used up its query, signature check, alias or time budget.
  /// There is no Extended DNS Error code for this; 0 is "Other".
  limitExceeded(0);

  const ValidationError(this.edeCode);

  /// The Extended DNS Error INFO-CODE (RFC 8914 §4) closest to this error.
  final int edeCode;
}

/// A reason an answer is not secure: the code, if it is a failure (plain
/// unsigned zones and NSEC3 opt-out have none), and the text.
typedef _Why = ({ValidationError? error, String text});

_Why _why(ValidationError? error, String text) => (error: error, text: text);

/// The validated outcome of looking up one name and type.
class ValidatedAnswer {
  ValidatedAnswer({
    required this.name,
    required this.type,
    required this.status,
    this.records = const [],
    this.nxDomain = false,
    this.reason,
    this.error,
    this.aliases = const [],
  });

  /// The queried name.
  final DnsName name;
  final int type;
  final SecurityStatus status;

  /// The answer records of [type] at the end of any CNAME chain. Empty for
  /// a denial of existence.
  final List<ResourceRecord> records;

  /// Whether the final name does not exist.
  final bool nxDomain;

  /// Why the answer is not [SecurityStatus.secure], in words.
  final String? reason;

  /// Why the answer is not [SecurityStatus.secure], as a code. Null for
  /// secure answers and for plainly unsigned zones.
  final ValidationError? error;

  /// CNAME targets followed from [name], in order.
  final List<DnsName> aliases;

  /// The name the [records] belong to.
  DnsName get canonicalName => aliases.isEmpty ? name : aliases.last;

  bool get isSecure => status == SecurityStatus.secure;
}

/// Something that looks up and validates DNS data: a [DnssecValidator], or
/// an [IsolateValidator] running one on a background isolate.
abstract interface class DnssecLookup {
  /// Looks up [type] at [name], following CNAMEs, and validates every step.
  Future<ValidatedAnswer> resolve(DnsName name, int type);

  /// Clears cached zone keys.
  Future<void> clearCache();
}

/// A validating stub resolver: it asks a recursive resolver (through a
/// [DnsTransport]) for data plus signatures and checks the whole chain of
/// trust from the root trust anchors itself, following RFC 4033–4035,
/// RFC 5155 and RFC 6840.
///
/// Each [resolve] is bounded by [maxQueries] and [timeout], so a hostile
/// resolver cannot keep it busy with endless delegations or slow answers.
class DnssecValidator implements DnssecLookup {
  DnssecValidator(
    this.transport, {
    List<Ds>? trustAnchors,
    DateTime Function()? clock,
    this.maxAliases = 8,
    this.sha1 = Sha1Policy.accept,
    this.maxQueries = 64,
    this.maxSignatureChecks = 64,
    this.maxCachedZones = 1000,
    this.clockSkew = const Duration(hours: 1),
    Map<DnsName, DateTime> negativeTrustAnchors = const {},
    this.timeout = const Duration(seconds: 20),
  })  : trustAnchors = trustAnchors ?? rootTrustAnchors,
        negativeTrustAnchors = Map.unmodifiable(negativeTrustAnchors),
        _clock = clock ?? DateTime.now {
    if (clockSkew.isNegative) throw ArgumentError.value(clockSkew, 'clockSkew');
    if (maxQueries < 1) throw ArgumentError.value(maxQueries, 'maxQueries');
    if (maxCachedZones < 1) throw ArgumentError.value(maxCachedZones, 'maxCachedZones');
    if (maxSignatureChecks < 1) {
      throw ArgumentError.value(maxSignatureChecks, 'maxSignatureChecks');
    }
    if (timeout <= Duration.zero) throw ArgumentError.value(timeout, 'timeout');
  }

  final DnsTransport transport;
  final List<Ds> trustAnchors;
  final int maxAliases;
  final Sha1Policy sha1;

  /// Most DNS queries one [resolve] may send, including those for zone
  /// keys and denial proofs. Cached zone keys cost nothing.
  final int maxQueries;

  /// Most signature verifications one [resolve] may do. With
  /// [maxKeysPerSignature] and [maxSignaturesPerRRset] this bounds the work
  /// a zone can cause with colliding key tags and piles of signatures
  /// (KeyTrap, CVE-2023-50387). Past it the lookup is
  /// [SecurityStatus.indeterminate].
  final int maxSignatureChecks;

  /// Keys with the signature's key tag and algorithm tried per signature.
  /// Honest zones rarely have two; a zone can publish many on purpose.
  static const maxKeysPerSignature = 4;

  /// Signatures tried per RRset before it counts as unverifiable.
  static const maxSignaturesPerRRset = 8;

  /// Most zones whose keys (or proven unsigned status) are cached. Past it,
  /// the least recently used zone is dropped, so lookups across many zones
  /// cannot grow memory without bound.
  final int maxCachedZones;

  /// How far outside a signature's validity period the clock may be and
  /// the signature still count, in both directions. Phones are often a few
  /// minutes off, and their owners rarely notice. The default allows an
  /// hour; [Duration.zero] is strict.
  final Duration clockSkew;

  /// Domains whose DNSSEC is known to be broken, each with the time its
  /// exception ends (RFC 7646). Until then, answers at or below the domain
  /// are insecure instead of bogus, with a reason that says why. Use them
  /// briefly, while the zone's operator fixes it: during that time a forged
  /// answer for the domain is accepted as merely insecure.
  final Map<DnsName, DateTime> negativeTrustAnchors;

  /// Longest one [resolve] may take; after that it is
  /// [SecurityStatus.indeterminate].
  final Duration timeout;

  final DateTime Function() _clock;

  late final Set<int> _algorithms = sha1 == Sha1Policy.accept
      ? DnssecAlgorithm.supported
      : DnssecAlgorithm.supported
          .difference({DnssecAlgorithm.rsaSha1, DnssecAlgorithm.rsaSha1Nsec3Sha1});
  late final Set<int> _digests = sha1 == Sha1Policy.accept
      ? DigestType.supported
      : DigestType.supported.difference({DigestType.sha1});

  /// Zone keys in least recently used order (oldest first).
  final _keyCache = <DnsName, _CachedKeys>{};

  int get _now => _clock().millisecondsSinceEpoch ~/ 1000;

  @override
  Future<void> clearCache() async => _keyCache.clear();

  /// Looks up [type] at [name], following CNAMEs, and validates every step.
  /// The overall status is the weakest of the steps.
  ///
  /// Signature checks run synchronously on the calling isolate. In a
  /// Flutter app, use an [IsolateValidator] to keep them off the UI isolate.
  @override
  Future<ValidatedAnswer> resolve(DnsName name, int type) {
    // The budget travels in a zone so every query of this lookup draws on
    // it. Zone keys fetched for one lookup and awaited by a concurrent one
    // count against the lookup that started the fetch.
    final budget = _Budget(maxQueries, maxSignatureChecks, timeout);
    return runZoned(() => _resolve(name, type), zoneValues: {_Budget: budget}).then((answer) {
      // Answers reached after running out of signature checks may rest on
      // a verification that was skipped.
      if (budget.checksExhausted) {
        return ValidatedAnswer(
            name: name, type: type, status: SecurityStatus.indeterminate,
            reason: budget.checksReason, error: ValidationError.limitExceeded,
            aliases: answer.aliases);
      }
      return answer;
    }).timeout(timeout, onTimeout: () {
      budget.expire();
      return ValidatedAnswer(
          name: name, type: type, status: SecurityStatus.indeterminate,
          reason: budget.timeoutReason, error: ValidationError.limitExceeded);
    });
  }

  Future<ValidatedAnswer> _resolve(DnsName name, int type) async {
    final aliases = <DnsName>[];
    var current = name;
    var status = SecurityStatus.secure;
    _Why? why;
    while (true) {
      final step = await _resolveStep(current, type);
      if (_rank(step.status) > _rank(status)) {
        status = step.status;
        why = step.why;
      }
      if (step.status == SecurityStatus.bogus ||
          step.status == SecurityStatus.indeterminate ||
          step.cnameTarget == null) {
        return ValidatedAnswer(
          name: name,
          type: type,
          status: status,
          records: step.records,
          nxDomain: step.nxDomain,
          reason: why?.text,
          error: why?.error,
          aliases: aliases,
        );
      }
      current = step.cnameTarget!;
      if (aliases.contains(current) || current == name) {
        return ValidatedAnswer(
            name: name, type: type, status: SecurityStatus.bogus,
            reason: 'CNAME loop at $current', error: ValidationError.invalidData,
            aliases: aliases);
      }
      aliases.add(current);
      if (aliases.length > maxAliases) {
        return ValidatedAnswer(
            name: name, type: type, status: SecurityStatus.indeterminate,
            reason: 'More than $maxAliases CNAMEs', error: ValidationError.limitExceeded,
            aliases: aliases);
      }
    }
  }

  static int _rank(SecurityStatus s) => switch (s) {
        SecurityStatus.secure => 0,
        SecurityStatus.insecure => 1,
        SecurityStatus.indeterminate => 2,
        SecurityStatus.bogus => 3,
      };

  // ---------------------------------------------------------------------
  // Transport

  Future<(DnsMessage?, _Why?)> _query(DnsName name, int type) async {
    final query = DnsMessage.buildQuery(name, type);
    final budget = Zone.current[_Budget] as _Budget?;
    if (budget != null) {
      final refusal = budget.take();
      if (refusal != null) return (null, _why(ValidationError.limitExceeded, refusal));
    }
    try {
      var response = transport.send(query);
      if (budget != null) {
        response = response.timeout(budget.remaining, onTimeout: () => throw _OutOfTime());
      }
      final bytes = await response;
      final msg = DnsMessage.parse(bytes);
      if (!msg.isResponse || msg.id != DnsMessage.queryId(query)) {
        return (null, _why(ValidationError.invalidData, 'Response does not match query for $name'));
      }
      if (msg.questions.length != 1 ||
          msg.questions.first.name != name ||
          msg.questions.first.type != type) {
        return (null, _why(ValidationError.invalidData, 'Response question does not match $name'));
      }
      if (msg.truncated) {
        return (null, _why(ValidationError.invalidData, 'Truncated response for $name'));
      }
      if (msg.rcode != Rcode.noError && msg.rcode != Rcode.nxDomain) {
        return (
          null,
          _why(ValidationError.resolverError,
              'Resolver returned rcode ${msg.rcode} for $name ${RRType.name(type)}')
        );
      }
      return (msg, null);
    } on _OutOfTime {
      return (null, _why(ValidationError.limitExceeded, budget!.timeoutReason));
    } on DnsTransportException catch (e) {
      return (null, _why(ValidationError.networkError, e.message));
    } on FormatException catch (e) {
      return (null, _why(ValidationError.invalidData, 'Malformed response for $name: ${e.message}'));
    }
  }

  /// Each message section's records grouped by owner and type, built the
  /// first time the section is searched. A response can carry thousands of
  /// records; scanning all of them for every owner would take quadratic
  /// time, and a hostile resolver could keep a lookup busy with that.
  static final _sections = Expando<Map<(DnsName, int), List<ResourceRecord>>>();

  static List<ResourceRecord> _recordsAt(List<ResourceRecord> section, DnsName name, int type) {
    final index = _sections[section] ??= () {
      final map = <(DnsName, int), List<ResourceRecord>>{};
      for (final rr in section) {
        (map[(rr.name, rr.type)] ??= []).add(rr);
      }
      return map;
    }();
    return index[(name, type)] ?? const [];
  }

  static Set<Uint8List> _byteSet() =>
      HashSet<Uint8List>(equals: bytesEqual, hashCode: Object.hashAll);

  /// The records of [type] at [name], without duplicates (RFC 2181 §5).
  static List<ResourceRecord> _rrset(List<ResourceRecord> section, DnsName name, int type) {
    final seen = _byteSet();
    return [
      for (final rr in _recordsAt(section, name, type))
        if (rr.cls == DnsClass.internet && seen.add(rr.canonicalRdata)) rr,
    ];
  }

  static List<Rrsig> _sigs(List<ResourceRecord> section, DnsName name, int type) {
    final out = <Rrsig>[];
    for (final rr in _recordsAt(section, name, RRType.rrsig)) {
      try {
        final sig = Rrsig.fromRecord(rr);
        if (sig.typeCovered == type) out.add(sig);
      } on FormatException {
        // Ignore malformed signatures; others may still validate.
      }
    }
    return out;
  }

  // ---------------------------------------------------------------------
  // One lookup step (no CNAME following)

  Future<_Step> _resolveStep(DnsName name, int type) async {
    final (msg, error) = await _query(name, type);
    if (msg == null) return _Step(SecurityStatus.indeterminate, why: error);

    final answers = _rrset(msg.answers, name, type);
    if (answers.isNotEmpty) {
      final (status, why) = await _validatePositive(
          name, type, answers, _sigs(msg.answers, name, type), msg);
      return _Step(status, records: answers, why: why);
    }

    if (type != RRType.cname) {
      final cnames = _rrset(msg.answers, name, RRType.cname);
      if (cnames.isNotEmpty) {
        if (cnames.length != 1) {
          return _Step(SecurityStatus.bogus,
              why: _why(ValidationError.invalidData, 'Multiple CNAMEs at $name'));
        }
        final target = readRdataName(cnames.first.rdata, 0).$1;
        final sigs = _sigs(msg.answers, name, RRType.cname);
        final (status, why) = sigs.isEmpty
            ? await _validateDnameSynthesis(name, target, msg)
            : await _validatePositive(name, RRType.cname, cnames, sigs, msg);
        return _Step(status, cnameTarget: target, why: why);
      }
    }

    return _validateNegative(name, type, msg);
  }

  /// A CNAME synthesised from a DNAME is unsigned; it is trusted when a
  /// validated DNAME produces exactly that target (RFC 6672 §5.3.1).
  Future<(SecurityStatus, _Why?)> _validateDnameSynthesis(
      DnsName name, DnsName target, DnsMessage msg) async {
    for (final rr in msg.answers) {
      if (rr.type != RRType.dname || !name.isStrictSubdomainOf(rr.name)) continue;
      final dnameTarget = readRdataName(rr.rdata, 0).$1;
      final prefix = name.labels.sublist(0, name.labelCount - rr.name.labelCount);
      final DnsName expected;
      try {
        expected = DnsName([...prefix, ...dnameTarget.labels]);
      } on FormatException {
        continue;
      }
      if (expected != target) continue;
      return _validatePositive(rr.name, RRType.dname,
          _rrset(msg.answers, rr.name, RRType.dname),
          _sigs(msg.answers, rr.name, RRType.dname), msg);
    }
    return _unsignedStatus(name, RRType.cname);
  }

  Future<(SecurityStatus, _Why?)> _validatePositive(DnsName owner, int type,
      List<ResourceRecord> rrset, List<Rrsig> sigs, DnsMessage msg) async {
    if (sigs.isEmpty) return _unsignedStatus(owner, type);

    final signers = <DnsName>{
      for (final s in sigs)
        // DS records are signed by the parent zone, never the child.
        if (type == RRType.ds ? owner.isStrictSubdomainOf(s.signer) : owner.isSubdomainOf(s.signer))
          s.signer,
    };
    if (signers.isEmpty) {
      return (SecurityStatus.bogus,
          _why(ValidationError.bogus, 'RRSIG signer for $owner is not an ancestor'));
    }

    _Why? failure;
    for (final signer in signers) {
      final keys = await _keysFor(signer);
      if (keys.status != SecurityStatus.secure) return (keys.status, keys.why);
      final sig = _verifyRRset(rrset, sigs, signer, keys.keys);
      if (sig == null) {
        failure = _unverified(sigs, signer, type, 'No valid signature for $owner ${RRType.name(type)}');
        continue;
      }
      if (sig.labels < owner.rrsigLabelCount) {
        final proof = await _denialProof(msg, signer, keys.keys, (nsecs, prover) {
          return nsecs.isNotEmpty
              ? nsecProveWildcardExpansion(owner, sig.labels, nsecs, signer)
              : prover.proveWildcardExpansion(owner, sig.labels);
        });
        switch (proof) {
          case Proof.failed:
            return (SecurityStatus.bogus, _why(ValidationError.nsecMissing,
                'Wildcard answer for $owner lacks a proof that the name does not exist'));
          case Proof.optOut:
            return (SecurityStatus.insecure, _why(null, 'Wildcard proof for $owner relies on NSEC3 opt-out'));
          case Proof.tooManyIterations:
            return (SecurityStatus.insecure, _why(ValidationError.unsupportedNsec3Iterations,
                'Wildcard proof for $owner uses more than $maxNsec3Iterations NSEC3 iterations'));
          case Proof.proven:
            break;
        }
      }
      return (SecurityStatus.secure, null);
    }
    return (SecurityStatus.bogus, failure);
  }

  Future<_Step> _validateNegative(DnsName name, int type, DnsMessage msg) async {
    final nx = msg.rcode == Rcode.nxDomain;
    // The SOA in the authority section names the zone that answered.
    ResourceRecord? soa;
    for (final rr in msg.authority) {
      if (rr.type != RRType.soa) continue;
      final ok = type == RRType.ds
          ? name.isStrictSubdomainOf(rr.name)
          : name.isSubdomainOf(rr.name);
      if (ok) soa = rr;
    }
    final soaSigs = soa == null ? <Rrsig>[] : _sigs(msg.authority, soa.name, RRType.soa);
    if (soa == null || soaSigs.isEmpty) {
      final (status, why) = await _unsignedStatus(name, type);
      return _Step(status, nxDomain: nx, why: why);
    }

    final zone = soa.name;
    final keys = await _keysFor(zone);
    if (keys.status != SecurityStatus.secure) {
      return _Step(keys.status, nxDomain: nx, why: keys.why);
    }
    if (_verifyRRset(_rrset(msg.authority, zone, RRType.soa), soaSigs, zone, keys.keys) == null) {
      return _Step(SecurityStatus.bogus, nxDomain: nx,
          why: _unverified(soaSigs, zone, RRType.soa, 'Invalid SOA signature for $zone'));
    }

    final proof = await _denialProof(msg, zone, keys.keys, (nsecs, prover) {
      if (nsecs.isNotEmpty) {
        return nx
            ? nsecProveNxDomain(name, nsecs, zone)
            : nsecProveNoData(name, type, nsecs, zone);
      }
      return nx ? prover.proveNxDomain(name) : prover.proveNoData(name, type);
    });
    return switch (proof) {
      Proof.proven => _Step(SecurityStatus.secure, nxDomain: nx),
      Proof.optOut => _Step(SecurityStatus.insecure, nxDomain: nx,
          why: _why(null, 'Denial for $name relies on NSEC3 opt-out')),
      Proof.tooManyIterations => _Step(SecurityStatus.insecure, nxDomain: nx,
          why: _why(ValidationError.unsupportedNsec3Iterations,
              'Denial for $name uses more than $maxNsec3Iterations NSEC3 iterations')),
      Proof.failed => _Step(SecurityStatus.bogus, nxDomain: nx,
          why: _why(ValidationError.nsecMissing,
              'No valid proof that $name ${RRType.name(type)} does not exist')),
    };
  }

  /// Validates the NSEC/NSEC3 records in the authority section with the
  /// zone's keys and runs [check] on the ones that verify.
  Future<Proof> _denialProof(DnsMessage msg, DnsName zone, List<Dnskey> keys,
      Proof Function(List<Nsec>, Nsec3Prover) check) async {
    final nsecs = <Nsec>[];
    final nsec3s = <Nsec3>[];
    final seen = <(DnsName, int)>{};
    for (final rr in msg.authority) {
      if (rr.type != RRType.nsec && rr.type != RRType.nsec3) continue;
      if (!rr.name.isSubdomainOf(zone) || !seen.add((rr.name, rr.type))) continue;
      final rrset = _rrset(msg.authority, rr.name, rr.type);
      if (_verifyRRset(rrset, _sigs(msg.authority, rr.name, rr.type), zone, keys) == null) {
        continue;
      }
      try {
        if (rr.type == RRType.nsec) {
          nsecs.add(Nsec.fromRecord(rr));
        } else {
          nsec3s.add(Nsec3.fromRecord(rr));
        }
      } on FormatException {
        continue;
      }
    }
    if (nsecs.isEmpty && nsec3s.isEmpty) return Proof.failed;
    return check(nsecs, Nsec3Prover(nsec3s, zone));
  }

  /// Status of data that arrived without signatures: insecure if its zone
  /// is provably unsigned, otherwise bogus.
  Future<(SecurityStatus, _Why?)> _unsignedStatus(DnsName name, int type) async {
    // A DS RRset lives in the parent zone.
    final (zone, error) = await _findZone(type == RRType.ds ? name.parent : name);
    if (zone == null) return (SecurityStatus.indeterminate, error);
    final keys = await _keysFor(zone);
    return switch (keys.status) {
      SecurityStatus.insecure => (SecurityStatus.insecure, keys.why),
      SecurityStatus.secure => (SecurityStatus.bogus, _why(ValidationError.rrsigsMissing,
          'Missing signatures for $name ${RRType.name(type)} in signed zone $zone')),
      _ => (keys.status, keys.why),
    };
  }

  /// Finds the apex of the zone holding [name] from the SOA a resolver
  /// returns. The answer is not trusted as such: [_keysFor] then has to
  /// prove that zone's status from the root down.
  ///
  /// A name whose SOA query gets an error rcode is skipped for its parent,
  /// as before. A query that got no answer at all (network failure, a
  /// malformed response, a spent budget) ends the search instead: going on
  /// up would blame a signed ancestor and call the data bogus when the
  /// lookup was really indeterminate.
  Future<(DnsName?, _Why?)> _findZone(DnsName name) async {
    var current = name;
    while (true) {
      if (current.isRoot) return (current, null);
      final (msg, error) = await _query(current, RRType.soa);
      if (msg != null) {
        if (_rrset(msg.answers, current, RRType.soa).isNotEmpty) return (current, null);
        for (final rr in msg.authority) {
          if (rr.type == RRType.soa && current.isSubdomainOf(rr.name)) return (rr.name, null);
        }
      } else if (error?.error != ValidationError.resolverError) {
        return (null, _why(error?.error, 'Could not find the zone of $current: ${error?.text}'));
      }
      current = current.parent;
    }
  }

  // ---------------------------------------------------------------------
  // Zone keys

  Future<_ZoneKeys> _keysFor(DnsName zone) {
    // Not cached, so the exception ends exactly when the anchor expires.
    final exempt = _negativeTrustAnchorFor(zone);
    if (exempt != null) {
      return Future.value(_ZoneKeys.insecure(
          _why(null, 'Validation of $exempt is off until ${negativeTrustAnchors[exempt]} '
              '(negative trust anchor)'),
          null));
    }
    final cached = _keyCache.remove(zone);
    if (cached != null && (cached.expires == null || cached.expires! > _now)) {
      _keyCache[zone] = cached; // now the most recently used
      return cached.keys;
    }
    final future = _fetchKeys(zone);
    final entry = _CachedKeys(future);
    _keyCache[zone] = entry;
    while (_keyCache.length > maxCachedZones) {
      // A dropped fetch still completes for whoever awaits it.
      _keyCache.remove(_keyCache.keys.first);
    }
    future.then((keys) {
      // Keep secure and insecure results for their TTL; retry anything else.
      if (keys.ttl == null) {
        if (identical(_keyCache[zone], entry)) _keyCache.remove(zone);
      } else {
        entry.expires = _now + keys.ttl!;
      }
    });
    return future;
  }

  Future<_ZoneKeys> _fetchKeys(DnsName zone) async {
    final keys = await _fetchKeysUnbounded(zone);
    // A failure caused by this lookup's budget says nothing about the zone,
    // and another lookup may be awaiting the same keys.
    final budget = Zone.current[_Budget] as _Budget?;
    if (budget != null && budget.checksExhausted && keys.status != SecurityStatus.secure) {
      return _ZoneKeys.fail(
          SecurityStatus.indeterminate, _why(ValidationError.limitExceeded, budget.checksReason));
    }
    return keys;
  }

  Future<_ZoneKeys> _fetchKeysUnbounded(DnsName zone) async {
    List<Ds> dsSet;
    var dsRecords = const <ResourceRecord>[];
    if (zone.isRoot) {
      dsSet = trustAnchors;
    } else {
      final ds = await _resolveStep(zone, RRType.ds);
      if (ds.cnameTarget != null) {
        return _ZoneKeys.fail(SecurityStatus.bogus, _why(ValidationError.invalidData, 'CNAME at zone cut $zone'));
      }
      if (ds.nxDomain && ds.status != SecurityStatus.insecure) {
        // A signer or SOA owner that does not exist is a forgery.
        return _ZoneKeys.fail(SecurityStatus.bogus, _why(ValidationError.bogus, 'Zone $zone does not exist'));
      }
      if (ds.status == SecurityStatus.insecure ||
          (ds.status == SecurityStatus.secure && ds.records.isEmpty)) {
        return _ZoneKeys.insecure(ds.why ?? _why(null, 'No DS for $zone: unsigned delegation'),
            _ttl(ds.records));
      }
      if (ds.status != SecurityStatus.secure) {
        return _ZoneKeys.fail(ds.status, ds.why);
      }
      dsRecords = ds.records;
      dsSet = [];
      for (final rr in ds.records) {
        try {
          dsSet.add(Ds.fromRecord(rr));
        } on FormatException {
          continue;
        }
      }
    }

    // RFC 4035 §5.2: if no DS uses a supported algorithm and digest, the
    // zone is treated as unsigned.
    final known = [
      for (final ds in dsSet)
        if (DnssecAlgorithm.supported.contains(ds.algorithm) &&
            DigestType.supported.contains(ds.digestType))
          ds,
    ];
    var usable = [
      for (final ds in known)
        if (_algorithms.contains(ds.algorithm) && _digests.contains(ds.digestType)) ds,
    ];
    if (usable.isEmpty) {
      if (known.isEmpty) {
        return _ZoneKeys.insecure(
            _why(ValidationError.unsupportedAlgorithm, 'No supported DS algorithm for $zone'), 3600);
      }
      final reason = _why(ValidationError.unsupportedAlgorithm, 'Zone $zone can only be validated with SHA-1');
      return sha1 == Sha1Policy.reject
          ? _ZoneKeys.fail(SecurityStatus.bogus, reason)
          : _ZoneKeys.insecure(reason, 3600);
    }
    // RFC 4509 §3: with a stronger digest present, SHA-1 DS records are
    // ignored, so a forged SHA-1 match cannot stand in for the key.
    if (usable.any((ds) => ds.digestType != DigestType.sha1)) {
      usable = [for (final ds in usable) if (ds.digestType != DigestType.sha1) ds];
    }

    final (msg, error) = await _query(zone, RRType.dnskey);
    if (msg == null) return _ZoneKeys.fail(SecurityStatus.indeterminate, error);
    final rrset = _rrset(msg.answers, zone, RRType.dnskey);
    final keys = <Dnskey>[];
    for (final rr in rrset) {
      try {
        final key = Dnskey.fromRecord(rr);
        if (key.isZoneKey && key.protocol == 3 && !key.isRevoked) keys.add(key);
      } on FormatException {
        continue;
      }
    }
    final anchored = [
      for (final key in keys)
        if (usable.any((ds) => dsMatchesKey(ds, key, zone))) key,
    ];
    if (anchored.isEmpty) {
      return _ZoneKeys.fail(SecurityStatus.bogus, _why(ValidationError.dnskeyMissing,
          zone.isRoot ? _rootMismatch(keys) : 'No DNSKEY of $zone matches its DS'));
    }
    final sigs = _sigs(msg.answers, zone, RRType.dnskey);
    final sig = _verifyRRset(rrset, sigs, zone, anchored);
    if (sig == null) {
      return _ZoneKeys.fail(SecurityStatus.bogus, _unverified(sigs, zone, RRType.dnskey,
          'DNSKEY set of $zone is not signed by a key its DS vouches for'));
    }
    return _ZoneKeys.secure(keys, _keyLifetime(rrset, dsRecords, sig));
  }

  /// Seconds the keys may be cached: no longer than the DNSKEY and DS
  /// records' TTLs, the signature's original TTL (RFC 4035 §5.3.3) or the
  /// time until the signature expires. Null (not cached) when the
  /// signature only counted because of [clockSkew].
  int? _keyLifetime(List<ResourceRecord> dnskeys, List<ResourceRecord> ds, Rrsig sig) {
    final left = (sig.expiration - _now) & 0xffffffff;
    if (left == 0 || left >= 0x80000000) return null;
    return [_ttl(dnskeys), _ttl(ds), sig.originalTtl, left].reduce(min);
  }

  /// The active negative trust anchor covering [zone], if any.
  DnsName? _negativeTrustAnchorFor(DnsName zone) {
    if (negativeTrustAnchors.isEmpty) return null;
    final now = _clock();
    for (final MapEntry(key: domain, value: until) in negativeTrustAnchors.entries) {
      if (zone.isSubdomainOf(domain) && now.isBefore(until)) return domain;
    }
    return null;
  }

  /// Explains a root key set that no trust anchor matches. After a root
  /// key rollover that is what stale built-in anchors look like; it is also
  /// what a resolver forging root keys looks like.
  String _rootMismatch(List<Dnskey> keys) {
    final anchorTags = {for (final ds in trustAnchors) ds.keyTag}.join(', ');
    final rootTags = {for (final key in keys) if (key.isSecureEntryPoint) key.keyTag}.join(', ');
    final source = identical(trustAnchors, rootTrustAnchors)
        ? 'the root trust anchors built into tlsa_resolver'
        : 'the configured trust anchors';
    return 'No root key matches $source (key tags $anchorTags; '
        'the root zone offers ${rootTags.isEmpty ? 'no key-signing keys' : 'key tags $rootTags'}). '
        'Either the anchors are out of date after a root key rollover, so update tlsa_resolver '
        'or pass current trustAnchors (https://data.iana.org/root-anchors/), or the resolver '
        'returned forged root keys.';
  }

  static int _ttl(List<ResourceRecord> records) {
    var ttl = 3600;
    for (final rr in records) {
      if (rr.ttl < ttl) ttl = rr.ttl;
    }
    return ttl < 30 ? 30 : ttl;
  }

  // ---------------------------------------------------------------------
  // Signatures

  /// Why no signature by [signer] verified an RRset of [type]: none were
  /// there, all were outside their validity period, or they did not verify.
  _Why _unverified(List<Rrsig> sigs, DnsName signer, int type, String text) {
    final relevant = [for (final s in sigs) if (s.signer == signer && s.typeCovered == type) s];
    if (relevant.isEmpty) return _why(ValidationError.rrsigsMissing, '$text: no signatures by $signer');
    final now = _now;
    final skew = clockSkew.inSeconds;
    if (relevant.every((s) => !s.isValidAt(now, skew: skew))) {
      return relevant.any((s) => s.isExpiredAt(now, skew: skew))
          ? _why(ValidationError.signatureExpired, '$text: signatures expired')
          : _why(ValidationError.signatureNotYetValid, '$text: signatures not valid yet (check the clock)');
    }
    return _why(ValidationError.bogus, text);
  }

  /// Returns the first of [sigs] that verifies [rrset] with one of [keys]
  /// of [zone], or null.
  Rrsig? _verifyRRset(List<ResourceRecord> rrset, List<Rrsig> sigs,
      DnsName zone, List<Dnskey> keys) {
    if (rrset.isEmpty) return null;
    final owner = rrset.first.name;
    final now = _now;
    final budget = Zone.current[_Budget] as _Budget?;
    var signaturesTried = 0;
    for (final sig in sigs) {
      if (sig.signer != zone ||
          sig.typeCovered != rrset.first.type ||
          sig.labels > owner.rrsigLabelCount ||
          !sig.isValidAt(now, skew: clockSkew.inSeconds) ||
          !_algorithms.contains(sig.algorithm)) {
        continue;
      }
      final candidates = [
        for (final key in keys)
          if (key.keyTag == sig.keyTag && key.algorithm == sig.algorithm) key,
      ].take(maxKeysPerSignature);
      if (candidates.isEmpty) continue;
      if (++signaturesTried > maxSignaturesPerRRset) return null;
      final data = _signedData(rrset, sig);
      for (final key in candidates) {
        if (budget != null && !budget.spendCheck()) return null;
        if (verifySignature(sig.algorithm, key.publicKey, data, sig.signature)) {
          return sig;
        }
      }
    }
    return null;
  }

  /// RFC 4034 §3.1.8.1: RRSIG RDATA (minus signature) followed by the RRset
  /// in canonical form and order.
  static Uint8List _signedData(List<ResourceRecord> rrset, Rrsig sig) {
    var owner = rrset.first.name;
    if (sig.labels < owner.rrsigLabelCount) {
      owner = owner.suffix(sig.labels).prependString('*');
    }
    final ownerWire = owner.toCanonicalWire();
    final rdatas = (_byteSet()..addAll([for (final rr in rrset) rr.canonicalRdata])).toList()
      ..sort(compareBytes);

    final out = BytesBuilder(copy: false)..add(sig.signedPrefix);
    for (final rdata in rdatas) {
      out.add(ownerWire);
      out.add((ByteData(10)
            ..setUint16(0, rrset.first.type)
            ..setUint16(2, rrset.first.cls)
            ..setUint32(4, sig.originalTtl)
            ..setUint16(8, rdata.length))
          .buffer
          .asUint8List());
      out.add(rdata);
    }
    return out.toBytes();
  }
}

/// What one [DnssecValidator.resolve] may still spend.
class _Budget {
  _Budget(this.maxQueries, this.maxChecks, this.timeout)
      : _queriesLeft = maxQueries,
        _watch = Stopwatch()..start();

  final int maxQueries;
  final int maxChecks;
  final Duration timeout;
  final Stopwatch _watch;
  int _queriesLeft;
  int checksUsed = 0;

  bool get checksExhausted => checksUsed > maxChecks;

  String get checksReason => 'Lookup needed more than $maxChecks signature checks';

  /// Spends one signature verification; false when none are left.
  bool spendCheck() => ++checksUsed <= maxChecks;

  Duration get remaining => timeout - _watch.elapsed;

  String get timeoutReason => 'Lookup took longer than ${timeout.inMilliseconds} ms';

  void expire() => _queriesLeft = -1;

  /// Spends one query, or says why there is none left.
  String? take() {
    if (_queriesLeft < 0 || remaining <= Duration.zero) return timeoutReason;
    if (checksExhausted) return checksReason;
    if (_queriesLeft == 0) return 'Lookup needed more than $maxQueries DNS queries';
    _queriesLeft--;
    return null;
  }
}

/// Thrown inside [DnssecValidator._query] when the lookup's time is up.
class _OutOfTime implements Exception {}

class _Step {
  _Step(this.status, {this.records = const [], this.nxDomain = false, this.cnameTarget, this.why});

  final SecurityStatus status;
  final List<ResourceRecord> records;
  final bool nxDomain;
  final DnsName? cnameTarget;
  final _Why? why;
}

class _ZoneKeys {
  _ZoneKeys.secure(this.keys, this.ttl)
      : status = SecurityStatus.secure,
        why = null;
  _ZoneKeys.insecure(this.why, this.ttl)
      : status = SecurityStatus.insecure,
        keys = const [];
  _ZoneKeys.fail(this.status, this.why)
      : keys = const [],
        ttl = null;

  final SecurityStatus status;
  final List<Dnskey> keys;
  final _Why? why;

  /// Seconds to cache this result, or null to not cache it.
  final int? ttl;
}

class _CachedKeys {
  _CachedKeys(this.keys);
  final Future<_ZoneKeys> keys;
  int? expires;
}
