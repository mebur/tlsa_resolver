import 'dart:typed_data';

import '../wire/message.dart';
import '../wire/name.dart';
import '../wire/rdata.dart';
import 'crypto.dart';

/// Outcome of checking an authenticated denial of existence.
enum Proof {
  /// The records prove the claim.
  proven,

  /// The claim is covered only by an NSEC3 opt-out span, or the zone uses
  /// more NSEC3 iterations than [maxNsec3Iterations]; the answer is treated
  /// as insecure.
  insecure,

  /// The records do not prove the claim.
  failed,
}

/// RFC 9276 §3.2: validators may treat zones with more iterations than this
/// as insecure.
const maxNsec3Iterations = 150;

DnsName _wildcardAt(DnsName name) => name.prependString('*');

/// NSEC records an owner can not be used for names below a delegation point
/// or a DNAME (RFC 6840 §4.1).
bool _nsecUsableFor(Nsec nsec, DnsName name) {
  if (!name.isStrictSubdomainOf(nsec.owner)) return true;
  return !nsec.types.isDelegation && !nsec.types.contains(RRType.dname);
}

Nsec? _coveringNsec(List<Nsec> nsecs, DnsName name) {
  for (final nsec in nsecs) {
    if (nsec.covers(name) && _nsecUsableFor(nsec, name)) return nsec;
  }
  return null;
}

/// Closest encloser implied by an NSEC that covers [name] (RFC 4035 §5.4).
DnsName _nsecClosestEncloser(Nsec nsec, DnsName name, DnsName zone) {
  final a = name.commonSuffixLength(nsec.owner);
  final b = name.commonSuffixLength(nsec.next);
  final n = a > b ? a : b;
  return n < zone.labelCount ? zone : name.suffix(n);
}

bool _typeAbsent(TypeBitmap types, int type) =>
    !types.contains(type) && !types.contains(RRType.cname);

Proof nsecProveNxDomain(DnsName name, List<Nsec> nsecs, DnsName zone) {
  final cover = _coveringNsec(nsecs, name);
  if (cover == null) return Proof.failed;
  final wildcard = _wildcardAt(_nsecClosestEncloser(cover, name, zone));
  return _coveringNsec(nsecs, wildcard) != null ? Proof.proven : Proof.failed;
}

Proof nsecProveNoData(DnsName name, int type, List<Nsec> nsecs, DnsName zone) {
  for (final nsec in nsecs) {
    if (nsec.owner != name) continue;
    if (!_typeAbsent(nsec.types, type)) return Proof.failed;
    if (type == RRType.ds) {
      // Must come from the parent side of a real delegation.
      return nsec.types.isDelegation ? Proof.proven : Proof.failed;
    }
    // The parent side of a delegation is not authoritative for other types.
    return nsec.types.isDelegation ? Proof.failed : Proof.proven;
  }

  final cover = _coveringNsec(nsecs, name);
  if (cover == null) return Proof.failed;
  // Empty non-terminal: the name exists only because something below it does.
  if (type != RRType.ds && cover.next.isStrictSubdomainOf(name)) return Proof.proven;
  // Wildcard NODATA: the name is synthesised from *.CE, which lacks the type.
  final wildcard = _wildcardAt(_nsecClosestEncloser(cover, name, zone));
  for (final nsec in nsecs) {
    if (nsec.owner == wildcard && _typeAbsent(nsec.types, type)) return Proof.proven;
  }
  return Proof.failed;
}

/// A positive answer synthesised from a wildcard must come with proof that
/// [name] itself does not exist (RFC 4035 §5.3.4).
Proof nsecProveWildcardExpansion(DnsName name, List<Nsec> nsecs) =>
    _coveringNsec(nsecs, name) != null ? Proof.proven : Proof.failed;

/// NSEC3 proofs for one zone (RFC 5155 §8). Records with unknown hash
/// algorithms or from another zone are ignored.
class Nsec3Prover {
  Nsec3Prover(List<Nsec3> records, this.zone)
      : records = [
          for (final r in records)
            if (r.hashAlgorithm == 1 && r.zone == zone && r.ownerHash != null) r,
        ];

  final List<Nsec3> records;
  final DnsName zone;
  final _hashes = <(DnsName, String, int), Uint8List>{};

  bool get tooManyIterations =>
      records.any((r) => r.iterations > maxNsec3Iterations);

  Uint8List _hash(DnsName name, Nsec3 r) => _hashes.putIfAbsent(
      (name, String.fromCharCodes(r.salt), r.iterations),
      () => nsec3Hash(name, r.salt, r.iterations));

  Nsec3? _matching(DnsName name) {
    for (final r in records) {
      if (bytesEqual(r.ownerHash!, _hash(name, r))) return r;
    }
    return null;
  }

  Nsec3? _covering(DnsName name) {
    for (final r in records) {
      final h = _hash(name, r), owner = r.ownerHash!, next = r.nextHash;
      final covered = compareBytes(owner, next) < 0
          ? compareBytes(owner, h) < 0 && compareBytes(h, next) < 0
          : compareBytes(h, owner) > 0 || compareBytes(h, next) < 0;
      if (covered) return r;
    }
    return null;
  }

  /// Closest encloser proof (RFC 5155 §8.3). Returns the closest encloser
  /// and the NSEC3 covering the next closer name, or null.
  (DnsName, Nsec3)? _closestEncloser(DnsName name) {
    for (var n = name.labelCount - 1; n >= zone.labelCount; n--) {
      final candidate = name.suffix(n);
      final match = _matching(candidate);
      if (match == null) continue;
      if (match.types.isDelegation || match.types.contains(RRType.dname)) {
        return null;
      }
      final cover = _covering(name.suffix(n + 1));
      return cover == null ? null : (candidate, cover);
    }
    return null;
  }

  Proof proveNxDomain(DnsName name) {
    if (tooManyIterations) return Proof.insecure;
    if (_matching(name) != null) return Proof.failed; // The name exists.
    final ce = _closestEncloser(name);
    if (ce == null) return Proof.failed;
    if (_covering(_wildcardAt(ce.$1)) == null) return Proof.failed;
    return ce.$2.optOut ? Proof.insecure : Proof.proven;
  }

  Proof proveNoData(DnsName name, int type) {
    if (tooManyIterations) return Proof.insecure;
    final match = _matching(name);
    if (match != null) {
      if (!_typeAbsent(match.types, type)) return Proof.failed;
      if (type == RRType.ds) {
        return match.types.isDelegation ? Proof.proven : Proof.failed;
      }
      return match.types.isDelegation ? Proof.failed : Proof.proven;
    }
    final ce = _closestEncloser(name);
    if (ce == null) return Proof.failed;
    // §8.6: no DS at an unsigned delegation inside an opt-out span.
    if (type == RRType.ds) return ce.$2.optOut ? Proof.insecure : Proof.failed;
    // §8.7: wildcard NODATA.
    final wildcard = _matching(_wildcardAt(ce.$1));
    if (wildcard != null && _typeAbsent(wildcard.types, type)) return Proof.proven;
    return Proof.failed;
  }

  /// §8.8: an answer expanded from a wildcard at the ancestor with
  /// [rrsigLabels] labels needs the next closer name covered.
  Proof proveWildcardExpansion(DnsName name, int rrsigLabels) {
    if (tooManyIterations) return Proof.insecure;
    return _covering(name.suffix(rrsigLabels + 1)) != null
        ? Proof.proven
        : Proof.failed;
  }
}
