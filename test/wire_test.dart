import 'dart:convert';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:tlsa_resolver/src/dnssec/crypto.dart';
import 'package:tlsa_resolver/src/wire/message.dart';
import 'package:tlsa_resolver/src/wire/rdata.dart';
import 'package:tlsa_resolver/tlsa_resolver.dart';

Uint8List _hex(String s) => Uint8List.fromList([
      for (var i = 0; i < s.length; i += 2) int.parse(s.substring(i, i + 2), radix: 16),
    ]);

void main() {
  group('DnsName', () {
    test('parses and prints presentation format', () {
      expect(DnsName.parse('Example.COM').toString(), 'Example.COM.');
      expect(DnsName.parse('a\\.b.example.').labelCount, 2);
      expect(DnsName.parse('\\001.z.example').labels.first, [1]);
      expect(DnsName.parse('.').isRoot, isTrue);
    });

    test('compares case-insensitively', () {
      expect(DnsName.parse('WWW.Example.com'), DnsName.parse('www.example.COM.'));
      expect(DnsName.parse('WWW.Example.com').hashCode,
          DnsName.parse('www.example.com').hashCode);
    });

    test('sorts in canonical order (RFC 4034 §6.1)', () {
      final ordered = [
        'example', 'a.example', 'yljkjljk.a.example', 'Z.a.example',
        'zABC.a.EXAMPLE', 'z.example', '\\001.z.example', '*.z.example',
        '\\200.z.example',
      ].map(DnsName.parse).toList();
      final shuffled = [...ordered.reversed]..sort();
      expect(shuffled.map((e) => e.toString()), ordered.map((e) => e.toString()));
    });

    test('rejects oversize labels', () {
      expect(() => DnsName.parse('${'a' * 64}.example'), throwsFormatException);
    });
  });

  group('DnsMessage', () {
    test('query carries DO and CD', () {
      final q = DnsMessage.buildQuery(DnsName.parse('example.com'), RRType.tlsa, id: 0x1234);
      final m = DnsMessage.parse(q);
      expect(m.id, 0x1234);
      expect(m.flags & 0x0010, isNot(0)); // CD
      final opt = m.additional.single;
      expect(opt.type, RRType.opt);
      expect(opt.ttl & 0x8000, isNot(0)); // DO
      expect(opt.cls, 1232); // UDP payload size (RFC 9715)
    });

    test('expands compressed names inside RDATA', () {
      // Response to example.com CNAME with target www.<ptr to example.com>.
      final bytes = <int>[
        0, 1, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0,
        7, ...ascii.encode('example'), 3, ...ascii.encode('com'), 0, // @12
        0, 5, 0, 1,
        0xc0, 12, 0, 5, 0, 1, 0, 0, 0, 60, 0, 6,
        3, ...ascii.encode('www'), 0xc0, 12,
      ];
      final m = DnsMessage.parse(Uint8List.fromList(bytes));
      final cname = m.answers.single;
      expect(cname.name, DnsName.parse('example.com'));
      expect(readRdataName(cname.rdata, 0).$1, DnsName.parse('www.example.com'));
    });

    test('rejects compression loops', () {
      final bytes = <int>[0, 1, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0, 12, 0, 1, 0, 1];
      expect(() => DnsMessage.parse(Uint8List.fromList(bytes)), throwsFormatException);
    });

    test('rejects compression pointers that point forward', () {
      // The question name points past itself, to a name after the question.
      // Only pointers to earlier names are allowed, which also rules out loops.
      final bytes = <int>[
        0, 1, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0,
        0xc0, 18, 0, 1, 0, 1, // @12
        3, ...ascii.encode('com'), 0, // @18
      ];
      expect(() => DnsMessage.parse(Uint8List.fromList(bytes)), throwsFormatException);
    });
  });

  group('DNSSEC primitives', () {
    test('NSEC3 hash (RFC 5155 Appendix A)', () {
      final salt = _hex('aabbccdd');
      expect(base32HexEncode(nsec3Hash(DnsName.parse('example'), salt, 12)),
          '0p9mhaveqvm6t7vbl5lop2u3t2rp3tom');
      expect(base32HexEncode(nsec3Hash(DnsName.parse('a.example'), salt, 12)),
          '35mthgpgcu1qg68fab165klnsnk3dpvl');
    });

    test('base32hex round trip', () {
      final data = _hex('00ff10203040506070809a');
      expect(base32HexDecode(Uint8List.fromList(ascii.encode(base32HexEncode(data)))), data);
    });

    test('key tag and DS digest (RFC 4034 §5.4)', () {
      final key = Dnskey.fromRecord(ResourceRecord(
          DnsName.parse('dskey.example.com'), RRType.dnskey, 1, 86400,
          Uint8List.fromList([1, 0, 3, 5, ...base64.decode(
              'AQOeiiR0GOMYkDshWoSKz9XzfwJr1AYtsmx3TGkJaNXVbfi/2pHm822aJ5iI9BMz'
              'NXxeYCmZDRD99WYwYqUSdjMmmAphXdvxegXd/M5+X7OrzKBaMbCVdFLUUh6DhweJ'
              'BjEVv5f2wwjM9XzcnOf+EPbtG9DMBmADjFDc2w/rljwvFw==')])));
      expect(key.keyTag, 60485);
      final ds = Ds(60485, 5, 1, _hex('2bb183af5f22588179a53b0a98631fad1a292118'));
      expect(dsMatchesKey(ds, key, DnsName.parse('dskey.example.com')), isTrue);
    });

    test('RRSIG validity uses serial arithmetic', () {
      final sig = Rrsig.fromRecord(ResourceRecord(DnsName.root, RRType.rrsig, 1, 0,
          Uint8List.fromList([0, 1, 8, 0, 0, 0, 0, 0, 0x80, 0, 0, 10, 0x7f, 0xff, 0xff, 0xf0, 0, 0, 0, 1])));
      expect(sig.isValidAt(0x7ffffff5), isTrue);
      expect(sig.isValidAt(0x80000005), isTrue);
      expect(sig.isValidAt(0x80000010), isFalse);
    });
  });
}
