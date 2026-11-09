import 'dart:typed_data';

import 'message.dart';
import 'name.dart';

ByteData _view(Uint8List b) => ByteData.sublistView(b);

void _require(bool ok, String what) {
  if (!ok) throw FormatException('Malformed $what RDATA');
}

/// RRSIG (RFC 4034 §3).
class Rrsig {
  Rrsig._(this.record, this.typeCovered, this.algorithm, this.labels,
      this.originalTtl, this.expiration, this.inception, this.keyTag,
      this.signer, this.signature);

  factory Rrsig.fromRecord(ResourceRecord rr) {
    final d = rr.rdata;
    _require(d.length > 18, 'RRSIG');
    final v = _view(d);
    final (signer, end) = readRdataName(d, 18);
    _require(end < d.length, 'RRSIG');
    return Rrsig._(rr, v.getUint16(0), d[2], d[3], v.getUint32(4),
        v.getUint32(8), v.getUint32(12), v.getUint16(16), signer,
        Uint8List.sublistView(d, end));
  }

  final ResourceRecord record;
  final int typeCovered;
  final int algorithm;
  final int labels;
  final int originalTtl;
  final int expiration;
  final int inception;
  final int keyTag;
  final DnsName signer;
  final Uint8List signature;

  /// The RDATA fields that are signed: everything but the signature, with
  /// the signer name in canonical form.
  Uint8List get signedPrefix {
    final out = BytesBuilder(copy: false)
      ..add(Uint8List.sublistView(record.rdata, 0, 18))
      ..add(signer.toCanonicalWire());
    return out.toBytes();
  }

  /// Whether [now] (seconds since epoch) is inside the validity window, using
  /// serial number arithmetic (RFC 1982) as RFC 4034 §3.1.5 requires.
  bool isValidAt(int now) {
    final t = now & 0xffffffff;
    return _serialLessOrEqual(inception, t) && _serialLessOrEqual(t, expiration);
  }

  /// Whether the validity period ended before [now].
  bool isExpiredAt(int now) => !_serialLessOrEqual(now & 0xffffffff, expiration);

  static bool _serialLessOrEqual(int a, int b) =>
      a == b || ((b - a) & 0xffffffff) < 0x80000000;
}

/// DNSKEY (RFC 4034 §2).
class Dnskey {
  Dnskey._(this.record, this.flags, this.protocol, this.algorithm, this.publicKey);

  factory Dnskey.fromRecord(ResourceRecord rr) {
    final d = rr.rdata;
    _require(d.length >= 4, 'DNSKEY');
    return Dnskey._(rr, _view(d).getUint16(0), d[2], d[3],
        Uint8List.sublistView(d, 4));
  }

  final ResourceRecord record;
  final int flags;
  final int protocol;
  final int algorithm;
  final Uint8List publicKey;

  bool get isZoneKey => flags & 0x0100 != 0;

  /// The SEP flag: conventionally set on key-signing keys (RFC 4034 §2.1.1).
  bool get isSecureEntryPoint => flags & 0x0001 != 0;
  bool get isRevoked => flags & 0x0080 != 0;
  bool get isSep => flags & 0x0001 != 0;

  /// Key tag (RFC 4034 Appendix B).
  int get keyTag {
    final d = record.rdata;
    var ac = 0;
    for (var i = 0; i < d.length; i++) {
      ac += i.isOdd ? d[i] : d[i] << 8;
    }
    ac += (ac >> 16) & 0xffff;
    return ac & 0xffff;
  }
}

/// DS (RFC 4034 §5).
class Ds {
  Ds(this.keyTag, this.algorithm, this.digestType, this.digest);

  factory Ds.fromRecord(ResourceRecord rr) {
    final d = rr.rdata;
    _require(d.length > 4, 'DS');
    return Ds(_view(d).getUint16(0), d[2], d[3], Uint8List.sublistView(d, 4));
  }

  final int keyTag;
  final int algorithm;
  final int digestType;
  final Uint8List digest;
}

/// A type bitmap as used in NSEC and NSEC3 (RFC 4034 §4.1.2).
class TypeBitmap {
  TypeBitmap(this.types);

  factory TypeBitmap.parse(Uint8List d, int pos, String owner) {
    final types = <int>{};
    var lastWindow = -1;
    while (pos < d.length) {
      _require(pos + 2 <= d.length, owner);
      final window = d[pos], length = d[pos + 1];
      _require(window > lastWindow && length >= 1 && length <= 32, owner);
      _require(pos + 2 + length <= d.length, owner);
      for (var i = 0; i < length; i++) {
        final byte = d[pos + 2 + i];
        for (var bit = 0; bit < 8; bit++) {
          if (byte & (0x80 >> bit) != 0) types.add(window * 256 + i * 8 + bit);
        }
      }
      lastWindow = window;
      pos += 2 + length;
    }
    return TypeBitmap(types);
  }

  final Set<int> types;

  bool contains(int type) => types.contains(type);

  /// NS present without SOA: the owner is a delegation point seen from the
  /// parent side.
  bool get isDelegation => contains(RRType.ns) && !contains(RRType.soa);
}

/// NSEC (RFC 4034 §4).
class Nsec {
  Nsec._(this.owner, this.next, this.types);

  factory Nsec.fromRecord(ResourceRecord rr) {
    final (next, end) = readRdataName(rr.rdata, 0);
    return Nsec._(rr.name, next, TypeBitmap.parse(rr.rdata, end, 'NSEC'));
  }

  final DnsName owner;
  final DnsName next;
  final TypeBitmap types;

  /// Whether [name] falls strictly between owner and next in canonical order.
  /// The last NSEC in a zone wraps around to the apex.
  bool covers(DnsName name) {
    if (!(owner < name)) return false;
    return next <= owner ? true : name < next;
  }
}

extension on DnsName {
  bool operator <=(DnsName other) => compareTo(other) <= 0;
}

/// NSEC3 (RFC 5155 §3).
class Nsec3 {
  Nsec3._(this.record, this.hashAlgorithm, this.flags, this.iterations,
      this.salt, this.nextHash, this.types);

  factory Nsec3.fromRecord(ResourceRecord rr) {
    final d = rr.rdata;
    _require(d.length >= 5, 'NSEC3');
    final saltLength = d[4];
    var pos = 5 + saltLength;
    _require(pos < d.length, 'NSEC3');
    final salt = Uint8List.sublistView(d, 5, pos);
    final hashLength = d[pos++];
    _require(hashLength > 0 && pos + hashLength <= d.length, 'NSEC3');
    final next = Uint8List.sublistView(d, pos, pos + hashLength);
    pos += hashLength;
    return Nsec3._(rr, d[0], d[1], _view(d).getUint16(2), salt, next,
        TypeBitmap.parse(d, pos, 'NSEC3'));
  }

  final ResourceRecord record;
  final int hashAlgorithm;
  final int flags;
  final int iterations;
  final Uint8List salt;
  final Uint8List nextHash;
  final TypeBitmap types;

  bool get optOut => flags & 0x01 != 0;

  /// The hash encoded in the first label of the owner name, or null if that
  /// label is not valid base32hex.
  Uint8List? get ownerHash =>
      record.name.isRoot ? null : base32HexDecode(record.name.labels.first);

  /// The zone this NSEC3 belongs to (the owner minus its hash label).
  DnsName get zone => record.name.parent;
}

const _b32hex = '0123456789abcdefghijklmnopqrstuv';

/// Decodes unpadded base32hex (RFC 4648 §7), case-insensitive.
Uint8List? base32HexDecode(Uint8List label) {
  final out = <int>[];
  var buffer = 0, bits = 0;
  for (var c in label) {
    if (c >= 0x41 && c <= 0x5a) c += 0x20;
    final v = _b32hex.codeUnits.indexOf(c);
    if (v < 0) return null;
    buffer = (buffer << 5) | v;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.add((buffer >> bits) & 0xff);
    }
  }
  return Uint8List.fromList(out);
}

String base32HexEncode(Uint8List data) {
  final sb = StringBuffer();
  var buffer = 0, bits = 0;
  for (final b in data) {
    buffer = (buffer << 8) | b;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      sb.write(_b32hex[(buffer >> bits) & 0x1f]);
    }
  }
  if (bits > 0) sb.write(_b32hex[(buffer << (5 - bits)) & 0x1f]);
  return sb.toString();
}
