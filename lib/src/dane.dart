import 'dart:typed_data';

import 'package:crypto/crypto.dart';

import 'dnssec/crypto.dart';
import 'tlsa.dart';

/// A TLSA record that matched a certificate in the presented chain.
class DaneMatch {
  DaneMatch(this.record, this.certificateIndex);

  final TlsaRecord record;

  /// Index into the chain passed to [DaneVerifier.verify]; 0 is the leaf.
  final int certificateIndex;
}

enum DaneOutcome {
  /// A usable record matched and its usage's conditions hold.
  verified,

  /// DANE applies but no usable record matched: reject the connection.
  mismatch,

  /// No secure, usable TLSA records: DANE does not apply and ordinary
  /// certificate validation decides.
  notApplicable,

  /// The TLSA lookup was bogus or failed: do not downgrade to plain PKIX,
  /// defer or reject the connection.
  lookupFailed,
}

class DaneVerdict {
  DaneVerdict(this.outcome, {this.match, this.reason});

  final DaneOutcome outcome;
  final DaneMatch? match;
  final String? reason;

  bool get isVerified => outcome == DaneOutcome.verified;

  /// For a DANE-TA(2) match on a certificate other than the leaf, the caller
  /// still has to check that the leaf chains up to that certificate and that
  /// the leaf's name matches the service (RFC 7671 §5.2). This library does
  /// not build or verify X.509 paths.
  bool get requiresChainCheck =>
      match != null &&
      match!.record.usage == TlsaUsage.daneTa &&
      match!.certificateIndex > 0;

  @override
  String toString() => 'DaneVerdict(${outcome.name}'
      '${match == null ? '' : ', ${match!.record} on certificate ${match!.certificateIndex}'}'
      '${reason == null ? '' : ', $reason'})';
}

/// Matches a presented certificate chain against TLSA records.
abstract final class DaneVerifier {
  /// Checks [chain] (DER certificates, leaf first, as the server sent them)
  /// against [result].
  ///
  /// [pkixValidated] says whether the chain passed ordinary PKIX validation,
  /// including the host name check; PKIX-TA(0) and PKIX-EE(1) records only
  /// count when it did.
  static DaneVerdict verify(TlsaResult result, List<Uint8List> chain,
      {bool pkixValidated = false}) {
    if (result.isFailure) {
      return DaneVerdict(DaneOutcome.lookupFailed, reason: result.reason);
    }
    final records = result.usableRecords;
    if (records.isEmpty) {
      return DaneVerdict(DaneOutcome.notApplicable,
          reason: result.isSecure ? 'No usable TLSA records' : result.reason);
    }
    if (chain.isEmpty) {
      return DaneVerdict(DaneOutcome.mismatch, reason: 'Empty certificate chain');
    }

    // Prefer DANE-EE, then DANE-TA, then the PKIX usages.
    final ordered = [...records]..sort((a, b) => _preference(a.usage) - _preference(b.usage));
    for (final record in ordered) {
      final needsPkix = record.usage == TlsaUsage.pkixTa || record.usage == TlsaUsage.pkixEe;
      if (needsPkix && !pkixValidated) continue;
      final leafOnly = record.usage == TlsaUsage.daneEe || record.usage == TlsaUsage.pkixEe;
      final candidates = leafOnly ? 1 : chain.length;
      for (var i = 0; i < candidates; i++) {
        if (matches(record, chain[i])) {
          return DaneVerdict(DaneOutcome.verified, match: DaneMatch(record, i));
        }
      }
    }
    return DaneVerdict(DaneOutcome.mismatch,
        reason: 'No TLSA record matches the presented chain');
  }

  static int _preference(int usage) => switch (usage) {
        TlsaUsage.daneEe => 0,
        TlsaUsage.daneTa => 1,
        TlsaUsage.pkixEe => 2,
        _ => 3,
      };

  /// Whether [record] matches one DER-encoded certificate.
  static bool matches(TlsaRecord record, Uint8List certificateDer) {
    final Uint8List selected;
    try {
      selected = record.selector == TlsaSelector.subjectPublicKeyInfo
          ? subjectPublicKeyInfo(certificateDer)
          : certificateDer;
    } on FormatException {
      return false;
    }
    final List<int> value = switch (record.matchingType) {
      TlsaMatchingType.exact => selected,
      TlsaMatchingType.sha256 => sha256.convert(selected).bytes,
      TlsaMatchingType.sha512 => sha512.convert(selected).bytes,
      _ => const [],
    };
    return value.isNotEmpty && bytesEqual(value, record.data);
  }

  /// Computes the TLSA association data for a certificate, e.g. to publish
  /// a `3 1 1` record.
  static TlsaRecord recordFor(Uint8List certificateDer,
      {int usage = TlsaUsage.daneEe,
      int selector = TlsaSelector.subjectPublicKeyInfo,
      int matchingType = TlsaMatchingType.sha256}) {
    final selected = selector == TlsaSelector.subjectPublicKeyInfo
        ? subjectPublicKeyInfo(certificateDer)
        : certificateDer;
    final data = switch (matchingType) {
      TlsaMatchingType.exact => selected,
      TlsaMatchingType.sha256 => Uint8List.fromList(sha256.convert(selected).bytes),
      TlsaMatchingType.sha512 => Uint8List.fromList(sha512.convert(selected).bytes),
      _ => throw ArgumentError.value(matchingType, 'matchingType'),
    };
    return TlsaRecord(usage, selector, matchingType, data);
  }

  /// Extracts the DER SubjectPublicKeyInfo from an X.509 certificate:
  ///
  /// ```text
  /// Certificate ::= SEQUENCE { tbsCertificate SEQUENCE { [0] version
  ///   OPTIONAL, serialNumber, signature, issuer, validity, subject,
  ///   subjectPublicKeyInfo, ... }, ... }
  /// ```
  static Uint8List subjectPublicKeyInfo(Uint8List der) {
    final cert = _Der(der, 0);
    if (cert.tag != 0x30) throw const FormatException('Certificate is not a SEQUENCE');
    final tbs = _Der(der, cert.contentStart);
    if (tbs.tag != 0x30) throw const FormatException('tbsCertificate is not a SEQUENCE');
    var element = _Der(der, tbs.contentStart);
    if (element.tag == 0xa0) element = _Der(der, element.end); // version
    // serialNumber, signature, issuer, validity, subject
    for (var i = 0; i < 5; i++) {
      element = _Der(der, element.end);
    }
    if (element.tag != 0x30 || element.end > tbs.end) {
      throw const FormatException('No SubjectPublicKeyInfo');
    }
    return Uint8List.sublistView(der, element.start, element.end);
  }
}

/// One DER TLV header.
class _Der {
  factory _Der(Uint8List d, int start) {
    if (start + 2 > d.length) throw const FormatException('DER truncated');
    final tag = d[start];
    var pos = start + 1;
    var length = d[pos++];
    if (length & 0x80 != 0) {
      final n = length & 0x7f;
      if (n == 0 || n > 4 || pos + n > d.length) throw const FormatException('Bad DER length');
      length = 0;
      for (var i = 0; i < n; i++) {
        length = (length << 8) | d[pos++];
      }
    }
    if (pos + length > d.length) throw const FormatException('DER truncated');
    return _Der._(tag, start, pos, pos + length);
  }

  _Der._(this.tag, this.start, this.contentStart, this.end);

  final int tag;
  final int start;
  final int contentStart;
  final int end;
}
