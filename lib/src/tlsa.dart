import 'dart:typed_data';

import 'dnssec/validator.dart';
import 'wire/message.dart';

/// TLSA certificate usage (RFC 6698 §2.1.1, names from RFC 7218).
abstract final class TlsaUsage {
  /// CA constraint: a CA in the PKIX-validated chain must match.
  static const pkixTa = 0;

  /// Service certificate constraint: the PKIX-validated leaf must match.
  static const pkixEe = 1;

  /// Trust anchor assertion: a certificate in the chain is the trust anchor.
  static const daneTa = 2;

  /// Domain-issued certificate: the leaf must match; no PKIX validation.
  static const daneEe = 3;
}

/// TLSA selector: what part of the certificate is matched.
abstract final class TlsaSelector {
  static const fullCertificate = 0;
  static const subjectPublicKeyInfo = 1;
}

/// TLSA matching type: how the selected data is compared.
abstract final class TlsaMatchingType {
  static const exact = 0;
  static const sha256 = 1;
  static const sha512 = 2;
}

/// One TLSA record (RFC 6698 §2.1).
class TlsaRecord {
  const TlsaRecord(this.usage, this.selector, this.matchingType, this.data);

  /// Parses TLSA RDATA. Throws [FormatException] if it is shorter than the
  /// three fixed fields.
  factory TlsaRecord.fromRdata(Uint8List rdata) {
    if (rdata.length < 4) throw const FormatException('TLSA RDATA too short');
    return TlsaRecord(rdata[0], rdata[1], rdata[2], Uint8List.fromList(rdata.sublist(3)));
  }

  final int usage;
  final int selector;
  final int matchingType;

  /// The certificate association data.
  final Uint8List data;

  /// Whether this record can be used: known parameters and a digest of the
  /// right length (RFC 7671 §4.1 says to ignore the rest).
  bool get isUsable {
    if (usage > TlsaUsage.daneEe || selector > TlsaSelector.subjectPublicKeyInfo) {
      return false;
    }
    return switch (matchingType) {
      TlsaMatchingType.exact => data.isNotEmpty,
      TlsaMatchingType.sha256 => data.length == 32,
      TlsaMatchingType.sha512 => data.length == 64,
      _ => false,
    };
  }

  /// Presentation format, e.g. `3 1 1 a1b2…`.
  @override
  String toString() =>
      '$usage $selector $matchingType ${data.map((b) => b.toRadixString(16).padLeft(2, '0')).join()}';

  @override
  bool operator ==(Object other) =>
      other is TlsaRecord &&
      other.usage == usage &&
      other.selector == selector &&
      other.matchingType == matchingType &&
      _eq(other.data, data);

  @override
  int get hashCode => Object.hash(usage, selector, matchingType, Object.hashAll(data));

  static bool _eq(List<int> a, List<int> b) {
    if (a.length != b.length) return false;
    for (var i = 0; i < a.length; i++) {
      if (a[i] != b[i]) return false;
    }
    return true;
  }
}

/// The result of a TLSA lookup.
class TlsaResult {
  TlsaResult(this.answer)
      : records = [
          for (final rr in answer.records)
            if (rr.type == RRType.tlsa && rr.rdata.length >= 4) TlsaRecord.fromRdata(rr.rdata),
        ];

  /// The underlying validated DNS answer.
  final ValidatedAnswer answer;

  /// All TLSA records found, usable or not. Only trustworthy if [isSecure].
  final List<TlsaRecord> records;

  SecurityStatus get status => answer.status;
  bool get isSecure => answer.status == SecurityStatus.secure;
  String? get reason => answer.reason;

  /// Records DANE should act on: present only when the answer is secure.
  List<TlsaRecord> get usableRecords =>
      isSecure ? [for (final r in records) if (r.isUsable) r] : const [];

  /// Whether DANE applies to the service: there are secure, usable records.
  bool get daneApplies => usableRecords.isNotEmpty;

  /// Whether the lookup failed in a way that must not be treated as
  /// "no TLSA records" (RFC 7672 §2.2): connections should be deferred or
  /// refused, not downgraded.
  bool get isFailure =>
      status == SecurityStatus.bogus || status == SecurityStatus.indeterminate;
}
