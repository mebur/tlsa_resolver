import 'dart:math';
import 'dart:typed_data';

import 'name.dart';

/// Resource record type numbers used by this library.
abstract final class RRType {
  static const a = 1;
  static const ns = 2;
  static const md = 3;
  static const mf = 4;
  static const cname = 5;
  static const soa = 6;
  static const mb = 7;
  static const mg = 8;
  static const mr = 9;
  static const ptr = 12;
  static const minfo = 14;
  static const mx = 15;
  static const txt = 16;
  static const rp = 17;
  static const afsdb = 18;
  static const rt = 21;
  static const aaaa = 28;
  static const srv = 33;
  static const kx = 36;
  static const dname = 39;
  static const opt = 41;
  static const ds = 43;
  static const rrsig = 46;
  static const nsec = 47;
  static const dnskey = 48;
  static const nsec3 = 50;
  static const tlsa = 52;

  static String name(int type) => switch (type) {
        a => 'A',
        ns => 'NS',
        cname => 'CNAME',
        soa => 'SOA',
        aaaa => 'AAAA',
        dname => 'DNAME',
        ds => 'DS',
        rrsig => 'RRSIG',
        nsec => 'NSEC',
        dnskey => 'DNSKEY',
        nsec3 => 'NSEC3',
        tlsa => 'TLSA',
        _ => 'TYPE$type',
      };
}

abstract final class DnsClass {
  static const internet = 1;
}

abstract final class Rcode {
  static const noError = 0;
  static const formErr = 1;
  static const servFail = 2;
  static const nxDomain = 3;
  static const notImp = 4;
  static const refused = 5;
}

/// One resource record. [rdata] is self-contained: any compressed names in
/// it have been expanded while parsing.
class ResourceRecord {
  ResourceRecord(this.name, this.type, this.cls, this.ttl, this.rdata);

  final DnsName name;
  final int type;
  final int cls;
  final int ttl;
  final Uint8List rdata;

  /// RDATA in canonical form (RFC 4034 §6.2, as amended by RFC 6840 §5.1):
  /// embedded names lowercased for the listed types.
  Uint8List get canonicalRdata {
    final layout = _nameLayout(type);
    if (layout == null || !_lowercaseTypes.contains(type)) return rdata;
    final out = BytesBuilder(copy: false);
    var pos = 0;
    for (final step in layout) {
      if (step > 0) {
        out.add(Uint8List.sublistView(rdata, pos, pos + step));
        pos += step;
      } else {
        final (name, end) = _readUncompressedName(rdata, pos);
        out.add(name.toCanonicalWire());
        pos = end;
      }
    }
    out.add(Uint8List.sublistView(rdata, pos));
    return out.toBytes();
  }

  @override
  String toString() => '$name $ttl ${RRType.name(type)} (${rdata.length} bytes)';
}

class Question {
  Question(this.name, this.type, [this.cls = DnsClass.internet]);
  final DnsName name;
  final int type;
  final int cls;
}

class DnsMessage {
  DnsMessage({
    required this.id,
    required this.flags,
    required this.rcode,
    required this.questions,
    required this.answers,
    required this.authority,
    required this.additional,
  });

  final int id;

  /// The 16-bit header flags word.
  final int flags;

  /// Response code including EDNS extended bits.
  final int rcode;
  final List<Question> questions;
  final List<ResourceRecord> answers;
  final List<ResourceRecord> authority;
  final List<ResourceRecord> additional;

  bool get isResponse => flags & 0x8000 != 0;
  bool get truncated => flags & 0x0200 != 0;
  bool get authenticatedData => flags & 0x0020 != 0;

  /// Builds a recursive query with an EDNS0 OPT record that sets the DO bit,
  /// so the resolver includes RRSIG, NSEC and NSEC3 records, and the CD bit,
  /// so it hands back data it could not validate itself for us to judge.
  static Uint8List buildQuery(DnsName name, int type, {int? id, int udpSize = 4096}) {
    final out = BytesBuilder(copy: false);
    final header = ByteData(12)
      ..setUint16(0, id ?? Random.secure().nextInt(0x10000))
      ..setUint16(2, 0x0100 | 0x0010) // RD | CD
      ..setUint16(4, 1) // QDCOUNT
      ..setUint16(10, 1); // ARCOUNT (OPT)
    out.add(header.buffer.asUint8List());
    out.add(name.toWire());
    out.add((ByteData(4)
          ..setUint16(0, type)
          ..setUint16(2, DnsClass.internet))
        .buffer
        .asUint8List());
    // OPT: root owner, type 41, class = UDP size, TTL = ext-rcode/version/DO.
    out.addByte(0);
    out.add((ByteData(10)
          ..setUint16(0, RRType.opt)
          ..setUint16(2, udpSize)
          ..setUint32(4, 0x00008000)
          ..setUint16(8, 0))
        .buffer
        .asUint8List());
    return out.toBytes();
  }

  static int queryId(Uint8List query) => (query[0] << 8) | query[1];

  /// Parses a complete message. Throws [FormatException] on malformed input.
  factory DnsMessage.parse(Uint8List bytes) {
    final r = _Reader(bytes);
    final id = r.u16();
    final flags = r.u16();
    final qd = r.u16(), an = r.u16(), ns = r.u16(), ar = r.u16();
    final questions = [
      for (var i = 0; i < qd; i++) Question(r.name(), r.u16(), r.u16()),
    ];
    final answers = [for (var i = 0; i < an; i++) r.record()];
    final authority = [for (var i = 0; i < ns; i++) r.record()];
    final additional = [for (var i = 0; i < ar; i++) r.record()];
    var rcode = flags & 0xf;
    for (final rr in additional) {
      if (rr.type == RRType.opt) rcode |= ((rr.ttl >> 24) & 0xff) << 4;
    }
    return DnsMessage(
      id: id,
      flags: flags,
      rcode: rcode,
      questions: questions,
      answers: answers,
      authority: authority,
      additional: additional,
    );
  }
}

/// Where names sit inside RDATA, for types whose names may be compressed or
/// must be lowercased in canonical form. Positive entries are fixed-size
/// byte runs, 0 is a domain name. Trailing bytes are copied unchanged.
List<int>? _nameLayout(int type) => switch (type) {
      RRType.ns ||
      RRType.md ||
      RRType.mf ||
      RRType.cname ||
      RRType.mb ||
      RRType.mg ||
      RRType.mr ||
      RRType.ptr ||
      RRType.dname =>
        const [0],
      RRType.mx || RRType.afsdb || RRType.rt || RRType.kx => const [2, 0],
      RRType.soa || RRType.rp || RRType.minfo => const [0, 0],
      RRType.srv => const [6, 0],
      RRType.rrsig => const [18, 0],
      _ => null,
    };

const _lowercaseTypes = {
  RRType.ns, RRType.md, RRType.mf, RRType.cname, RRType.soa, RRType.mb,
  RRType.mg, RRType.mr, RRType.ptr, RRType.minfo, RRType.mx, RRType.rp,
  RRType.afsdb, RRType.rt, RRType.kx, RRType.srv, RRType.dname, RRType.rrsig,
};

/// Reads an uncompressed name from self-contained RDATA.
(DnsName, int) _readUncompressedName(Uint8List data, int pos) {
  final labels = <Uint8List>[];
  while (true) {
    if (pos >= data.length) throw const FormatException('Name past end of RDATA');
    final len = data[pos++];
    if (len == 0) break;
    if (len > 63) throw const FormatException('Compressed name in RDATA');
    if (pos + len > data.length) throw const FormatException('Label past end');
    labels.add(Uint8List.fromList(data.sublist(pos, pos + len)));
    pos += len;
  }
  return (DnsName(labels), pos);
}

/// Public helper for RDATA parsers.
(DnsName, int) readRdataName(Uint8List data, int pos) =>
    _readUncompressedName(data, pos);

class _Reader {
  _Reader(this.bytes) : data = ByteData.sublistView(bytes);

  final Uint8List bytes;
  final ByteData data;
  int pos = 0;

  void _need(int n) {
    if (pos + n > bytes.length) throw const FormatException('Message truncated');
  }

  int u8() {
    _need(1);
    return bytes[pos++];
  }

  int u16() {
    _need(2);
    final v = data.getUint16(pos);
    pos += 2;
    return v;
  }

  int u32() {
    _need(4);
    final v = data.getUint32(pos);
    pos += 4;
    return v;
  }

  DnsName name() {
    final (n, end) = _nameAt(pos);
    pos = end;
    return n;
  }

  /// Reads a possibly compressed name at [start]; returns it and the offset
  /// just past it in the original stream.
  (DnsName, int) _nameAt(int start) {
    final labels = <Uint8List>[];
    var p = start;
    int? end;
    var jumps = 0;
    while (true) {
      if (p >= bytes.length) throw const FormatException('Name past end');
      final len = bytes[p];
      if (len & 0xc0 == 0xc0) {
        if (p + 1 >= bytes.length) throw const FormatException('Bad pointer');
        end ??= p + 2;
        final target = ((len & 0x3f) << 8) | bytes[p + 1];
        if (target >= p || ++jumps > 64) {
          throw const FormatException('Compression loop');
        }
        p = target;
      } else if (len & 0xc0 != 0) {
        throw const FormatException('Unknown label type');
      } else if (len == 0) {
        end ??= p + 1;
        break;
      } else {
        if (p + 1 + len > bytes.length) throw const FormatException('Label past end');
        labels.add(Uint8List.fromList(bytes.sublist(p + 1, p + 1 + len)));
        p += 1 + len;
      }
    }
    return (DnsName(labels), end);
  }

  ResourceRecord record() {
    final owner = name();
    final type = u16();
    final cls = u16();
    final ttl = u32();
    final length = u16();
    _need(length);
    final start = pos;
    final end = start + length;
    pos = end;
    final layout = _nameLayout(type);
    Uint8List rdata;
    if (layout == null) {
      rdata = Uint8List.fromList(bytes.sublist(start, end));
    } else {
      // Expand compressed names so the RDATA stands on its own.
      final out = BytesBuilder(copy: false);
      var p = start;
      for (final step in layout) {
        if (step > 0) {
          if (p + step > end) throw const FormatException('RDATA too short');
          out.add(bytes.sublist(p, p + step));
          p += step;
        } else {
          final (n, after) = _nameAt(p);
          if (after > end) throw const FormatException('Name past RDATA');
          out.add(n.toWire());
          p = after;
        }
      }
      out.add(bytes.sublist(p, end));
      rdata = out.toBytes();
    }
    return ResourceRecord(owner, type, cls, ttl, rdata);
  }
}
