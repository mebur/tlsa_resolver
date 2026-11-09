import 'dart:async';
import 'dart:typed_data';

import '../transport/transport.dart';
import '../wire/message.dart';
import '../wire/name.dart';
import '../wire/rdata.dart';
import 'crypto.dart';
import 'denial.dart';
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

/// The validated outcome of looking up one name and type.
class ValidatedAnswer {
  ValidatedAnswer({
    required this.name,
    required this.type,
    required this.status,
    this.records = const [],
    this.nxDomain = false,
    this.reason,
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

  /// Why the answer is not [SecurityStatus.secure].
  final String? reason;

  /// CNAME targets followed from [name], in order.
  final List<DnsName> aliases;

  /// The name the [records] belong to.
  DnsName get canonicalName => aliases.isEmpty ? name : aliases.last;

  bool get isSecure => status == SecurityStatus.secure;
}

/// A validating stub resolver: it asks a recursive resolver (through a
/// [DnsTransport]) for data plus signatures and checks the whole chain of
/// trust from the root trust anchors itself, following RFC 4033–4035,
/// RFC 5155 and RFC 6840.
///
/// Each [resolve] is bounded by [maxQueries] and [timeout], so a hostile
/// resolver cannot keep it busy with endless delegations or slow answers.
class DnssecValidator {
  DnssecValidator(
    this.transport, {
    List<Ds>? trustAnchors,
    DateTime Function()? clock,
    this.maxAliases = 8,
    this.sha1 = Sha1Policy.accept,
    this.maxQueries = 64,
    this.maxSignatureChecks = 64,
    this.timeout = const Duration(seconds: 20),
  })  : trustAnchors = trustAnchors ?? rootTrustAnchors,
        _clock = clock ?? DateTime.now {
    if (maxQueries < 1) throw ArgumentError.value(maxQueries, 'maxQueries');
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

  final _keyCache = <DnsName, _CachedKeys>{};

  int get _now => _clock().millisecondsSinceEpoch ~/ 1000;

  /// Clears cached zone keys.
  void clearCache() => _keyCache.clear();

  /// Looks up [type] at [name], following CNAMEs, and validates every step.
  /// The overall status is the weakest of the steps.
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
            reason: budget.checksReason, aliases: answer.aliases);
      }
      return answer;
    }).timeout(timeout, onTimeout: () {
      budget.expire();
      return ValidatedAnswer(
          name: name, type: type, status: SecurityStatus.indeterminate,
          reason: budget.timeoutReason);
    });
  }

  Future<ValidatedAnswer> _resolve(DnsName name, int type) async {
    final aliases = <DnsName>[];
    var current = name;
    var status = SecurityStatus.secure;
    String? reason;
    while (true) {
      final step = await _resolveStep(current, type);
      if (_rank(step.status) > _rank(status)) {
        status = step.status;
        reason = step.reason;
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
          reason: reason,
          aliases: aliases,
        );
      }
      current = step.cnameTarget!;
      if (aliases.contains(current) || current == name) {
        return ValidatedAnswer(
            name: name, type: type, status: SecurityStatus.bogus,
            reason: 'CNAME loop at $current', aliases: aliases);
      }
      aliases.add(current);
      if (aliases.length > maxAliases) {
        return ValidatedAnswer(
            name: name, type: type, status: SecurityStatus.indeterminate,
            reason: 'More than $maxAliases CNAMEs', aliases: aliases);
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

  Future<(DnsMessage?, String?)> _query(DnsName name, int type) async {
    final query = DnsMessage.buildQuery(name, type);
    final budget = Zone.current[_Budget] as _Budget?;
    if (budget != null) {
      final refusal = budget.take();
      if (refusal != null) return (null, refusal);
    }
    try {
      var response = transport.send(query);
      if (budget != null) {
        response = response.timeout(budget.remaining,
            onTimeout: () => throw DnsTransportException(budget.timeoutReason));
      }
      final bytes = await response;
      final msg = DnsMessage.parse(bytes);
      if (!msg.isResponse || msg.id != DnsMessage.queryId(query)) {
        return (null, 'Response does not match query for $name');
      }
      if (msg.questions.length != 1 ||
          msg.questions.first.name != name ||
          msg.questions.first.type != type) {
        return (null, 'Response question does not match $name');
      }
      if (msg.truncated) return (null, 'Truncated response for $name');
      if (msg.rcode != Rcode.noError && msg.rcode != Rcode.nxDomain) {
        return (null, 'Resolver returned rcode ${msg.rcode} for $name ${RRType.name(type)}');
      }
      return (msg, null);
    } on DnsTransportException catch (e) {
      return (null, e.message);
    } on FormatException catch (e) {
      return (null, 'Malformed response for $name: ${e.message}');
    }
  }

  /// The records of [type] at [name], without duplicates (RFC 2181 §5).
  static List<ResourceRecord> _rrset(List<ResourceRecord> section, DnsName name, int type) {
    final out = <ResourceRecord>[];
    for (final rr in section) {
      if (rr.type != type || rr.cls != DnsClass.internet || rr.name != name) continue;
      final rdata = rr.canonicalRdata;
      if (!out.any((r) => bytesEqual(r.canonicalRdata, rdata))) out.add(rr);
    }
    return out;
  }

  static List<Rrsig> _sigs(List<ResourceRecord> section, DnsName name, int type) {
    final out = <Rrsig>[];
    for (final rr in section) {
      if (rr.type != RRType.rrsig || rr.name != name) continue;
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
    if (msg == null) return _Step(SecurityStatus.indeterminate, reason: error);

    final answers = _rrset(msg.answers, name, type);
    if (answers.isNotEmpty) {
      final (status, reason) = await _validatePositive(
          name, type, answers, _sigs(msg.answers, name, type), msg);
      return _Step(status, records: answers, reason: reason);
    }

    if (type != RRType.cname) {
      final cnames = _rrset(msg.answers, name, RRType.cname);
      if (cnames.isNotEmpty) {
        if (cnames.length != 1) {
          return _Step(SecurityStatus.bogus, reason: 'Multiple CNAMEs at $name');
        }
        final target = readRdataName(cnames.first.rdata, 0).$1;
        final sigs = _sigs(msg.answers, name, RRType.cname);
        final (status, reason) = sigs.isEmpty
            ? await _validateDnameSynthesis(name, target, msg)
            : await _validatePositive(name, RRType.cname, cnames, sigs, msg);
        return _Step(status, cnameTarget: target, reason: reason);
      }
    }

    return _validateNegative(name, type, msg);
  }

  /// A CNAME synthesised from a DNAME is unsigned; it is trusted when a
  /// validated DNAME produces exactly that target (RFC 6672 §5.3.1).
  Future<(SecurityStatus, String?)> _validateDnameSynthesis(
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

  Future<(SecurityStatus, String?)> _validatePositive(DnsName owner, int type,
      List<ResourceRecord> rrset, List<Rrsig> sigs, DnsMessage msg) async {
    if (sigs.isEmpty) return _unsignedStatus(owner, type);

    final signers = <DnsName>{
      for (final s in sigs)
        // DS records are signed by the parent zone, never the child.
        if (type == RRType.ds ? owner.isStrictSubdomainOf(s.signer) : owner.isSubdomainOf(s.signer))
          s.signer,
    };
    if (signers.isEmpty) {
      return (SecurityStatus.bogus, 'RRSIG signer for $owner is not an ancestor');
    }

    String? failure;
    for (final signer in signers) {
      final keys = await _keysFor(signer);
      if (keys.status != SecurityStatus.secure) return (keys.status, keys.reason);
      final sig = _verifyRRset(rrset, sigs, signer, keys.keys);
      if (sig == null) {
        failure = 'No valid signature for $owner ${RRType.name(type)}';
        continue;
      }
      if (sig.labels < owner.rrsigLabelCount) {
        final proof = await _denialProof(msg, signer, keys.keys, (nsecs, prover) {
          return nsecs.isNotEmpty
              ? nsecProveWildcardExpansion(owner, nsecs)
              : prover.proveWildcardExpansion(owner, sig.labels);
        });
        if (proof == Proof.failed) {
          return (SecurityStatus.bogus, 'Wildcard answer for $owner lacks a proof that the name does not exist');
        }
        if (proof == Proof.insecure) {
          return (SecurityStatus.insecure, 'NSEC3 proof for $owner is insecure');
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
      final (status, reason) = await _unsignedStatus(name, type);
      return _Step(status, nxDomain: nx, reason: reason);
    }

    final zone = soa.name;
    final keys = await _keysFor(zone);
    if (keys.status != SecurityStatus.secure) {
      return _Step(keys.status, nxDomain: nx, reason: keys.reason);
    }
    if (_verifyRRset(_rrset(msg.authority, zone, RRType.soa), soaSigs, zone, keys.keys) == null) {
      return _Step(SecurityStatus.bogus, nxDomain: nx, reason: 'Invalid SOA signature for $zone');
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
      Proof.insecure => _Step(SecurityStatus.insecure, nxDomain: nx,
          reason: 'Denial for $name relies on NSEC3 opt-out or excessive iterations'),
      Proof.failed => _Step(SecurityStatus.bogus, nxDomain: nx,
          reason: 'No valid proof that $name ${RRType.name(type)} does not exist'),
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
  Future<(SecurityStatus, String?)> _unsignedStatus(DnsName name, int type) async {
    // A DS RRset lives in the parent zone.
    final zone = await _findZone(type == RRType.ds ? name.parent : name);
    if (zone == null) {
      return (SecurityStatus.indeterminate, 'Could not find the zone of $name');
    }
    final keys = await _keysFor(zone);
    return switch (keys.status) {
      SecurityStatus.insecure => (SecurityStatus.insecure, keys.reason),
      SecurityStatus.secure => (SecurityStatus.bogus,
          'Missing signatures for $name ${RRType.name(type)} in signed zone $zone'),
      _ => (keys.status, keys.reason),
    };
  }

  /// Finds the apex of the zone holding [name] from the SOA a resolver
  /// returns. The answer is not trusted as such: [_keysFor] then has to
  /// prove that zone's status from the root down.
  Future<DnsName?> _findZone(DnsName name) async {
    var current = name;
    while (true) {
      if (current.isRoot) return current;
      final (msg, _) = await _query(current, RRType.soa);
      if (msg != null) {
        if (_rrset(msg.answers, current, RRType.soa).isNotEmpty) return current;
        for (final rr in msg.authority) {
          if (rr.type == RRType.soa && current.isSubdomainOf(rr.name)) return rr.name;
        }
      }
      current = current.parent;
    }
  }

  // ---------------------------------------------------------------------
  // Zone keys

  Future<_ZoneKeys> _keysFor(DnsName zone) {
    final cached = _keyCache[zone];
    if (cached != null && (cached.expires == null || cached.expires! > _now)) {
      return cached.keys;
    }
    final future = _fetchKeys(zone);
    final entry = _CachedKeys(future);
    _keyCache[zone] = entry;
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
      return _ZoneKeys.fail(SecurityStatus.indeterminate, budget.checksReason);
    }
    return keys;
  }

  Future<_ZoneKeys> _fetchKeysUnbounded(DnsName zone) async {
    List<Ds> dsSet;
    if (zone.isRoot) {
      dsSet = trustAnchors;
    } else {
      final ds = await _resolveStep(zone, RRType.ds);
      if (ds.cnameTarget != null) {
        return _ZoneKeys.fail(SecurityStatus.bogus, 'CNAME at zone cut $zone');
      }
      if (ds.nxDomain && ds.status != SecurityStatus.insecure) {
        // A signer or SOA owner that does not exist is a forgery.
        return _ZoneKeys.fail(SecurityStatus.bogus, 'Zone $zone does not exist');
      }
      if (ds.status == SecurityStatus.insecure ||
          (ds.status == SecurityStatus.secure && ds.records.isEmpty)) {
        return _ZoneKeys.insecure(ds.reason ?? 'No DS for $zone: unsigned delegation',
            _ttl(ds.records));
      }
      if (ds.status != SecurityStatus.secure) {
        return _ZoneKeys.fail(ds.status, ds.reason);
      }
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
        return _ZoneKeys.insecure('No supported DS algorithm for $zone', 3600);
      }
      final reason = 'Zone $zone can only be validated with SHA-1';
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
      return _ZoneKeys.fail(SecurityStatus.bogus, 'No DNSKEY of $zone matches its DS');
    }
    final sigs = _sigs(msg.answers, zone, RRType.dnskey);
    if (_verifyRRset(rrset, sigs, zone, anchored) == null) {
      return _ZoneKeys.fail(SecurityStatus.bogus, 'DNSKEY set of $zone is not signed by a key its DS vouches for');
    }
    return _ZoneKeys.secure(keys, _ttl(rrset));
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
          !sig.isValidAt(now) ||
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
    final rdatas = <Uint8List>[];
    for (final rr in rrset) {
      final rdata = rr.canonicalRdata;
      if (!rdatas.any((r) => bytesEqual(r, rdata))) rdatas.add(rdata);
    }
    rdatas.sort(compareBytes);

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

class _Step {
  _Step(this.status, {this.records = const [], this.nxDomain = false, this.cnameTarget, this.reason});

  final SecurityStatus status;
  final List<ResourceRecord> records;
  final bool nxDomain;
  final DnsName? cnameTarget;
  final String? reason;
}

class _ZoneKeys {
  _ZoneKeys.secure(this.keys, this.ttl)
      : status = SecurityStatus.secure,
        reason = null;
  _ZoneKeys.insecure(this.reason, this.ttl)
      : status = SecurityStatus.insecure,
        keys = const [];
  _ZoneKeys.fail(this.status, this.reason)
      : keys = const [],
        ttl = null;

  final SecurityStatus status;
  final List<Dnskey> keys;
  final String? reason;

  /// Seconds to cache this result, or null to not cache it.
  final int? ttl;
}

class _CachedKeys {
  _CachedKeys(this.keys);
  final Future<_ZoneKeys> keys;
  int? expires;
}
