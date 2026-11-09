import 'dart:convert';
import 'dart:typed_data';

/// A domain name as a sequence of labels, leftmost first. The root is the
/// empty list.
///
/// Equality, hashing and ordering are case-insensitive, and ordering is the
/// DNSSEC canonical order (RFC 4034 §6.1).
class DnsName implements Comparable<DnsName> {
  DnsName(List<Uint8List> labels) : labels = List.unmodifiable(labels) {
    var length = 1;
    for (final label in this.labels) {
      if (label.isEmpty || label.length > 63) {
        throw FormatException('Invalid label length ${label.length}');
      }
      length += label.length + 1;
    }
    if (length > 255) throw const FormatException('Name longer than 255 bytes');
  }

  static final DnsName root = DnsName(const []);

  /// Parses presentation format: dot-separated labels, `\.`, `\\` and `\DDD`
  /// escapes, optional trailing dot.
  factory DnsName.parse(String text) {
    if (text == '.' || text.isEmpty) return root;
    final labels = <Uint8List>[];
    var current = <int>[];
    final bytes = utf8.encode(text);
    for (var i = 0; i < bytes.length; i++) {
      final c = bytes[i];
      if (c == 0x5c /* \ */) {
        if (i + 3 < bytes.length &&
            _isDigit(bytes[i + 1]) &&
            _isDigit(bytes[i + 2]) &&
            _isDigit(bytes[i + 3])) {
          final v = (bytes[i + 1] - 48) * 100 +
              (bytes[i + 2] - 48) * 10 +
              (bytes[i + 3] - 48);
          if (v > 255) throw FormatException('Bad escape in $text');
          current.add(v);
          i += 3;
        } else if (i + 1 < bytes.length) {
          current.add(bytes[++i]);
        } else {
          throw FormatException('Trailing backslash in $text');
        }
      } else if (c == 0x2e /* . */) {
        if (current.isEmpty) throw FormatException('Empty label in $text');
        labels.add(Uint8List.fromList(current));
        current = [];
      } else {
        current.add(c);
      }
    }
    if (current.isNotEmpty) labels.add(Uint8List.fromList(current));
    return DnsName(labels);
  }

  final List<Uint8List> labels;

  int get labelCount => labels.length;
  bool get isRoot => labels.isEmpty;

  /// Whether the leftmost label is `*`.
  bool get isWildcard =>
      labels.isNotEmpty && labels.first.length == 1 && labels.first[0] == 0x2a;

  /// Label count as used in the RRSIG labels field: excludes a leading `*`.
  int get rrsigLabelCount => isWildcard ? labelCount - 1 : labelCount;

  DnsName get parent => DnsName(labels.sublist(1));

  /// The rightmost [count] labels of this name.
  DnsName suffix(int count) => DnsName(labels.sublist(labelCount - count));

  /// `label.this`
  DnsName prepend(Uint8List label) => DnsName([label, ...labels]);

  DnsName prependString(String label) =>
      prepend(Uint8List.fromList(utf8.encode(label)));

  /// Whether this name equals [other] or lies below it.
  bool isSubdomainOf(DnsName other) {
    if (other.labelCount > labelCount) return false;
    final offset = labelCount - other.labelCount;
    for (var i = 0; i < other.labelCount; i++) {
      if (!_labelEquals(labels[offset + i], other.labels[i])) return false;
    }
    return true;
  }

  bool isStrictSubdomainOf(DnsName other) =>
      labelCount > other.labelCount && isSubdomainOf(other);

  /// Number of rightmost labels this name shares with [other].
  int commonSuffixLength(DnsName other) {
    var n = 0;
    while (n < labelCount &&
        n < other.labelCount &&
        _labelEquals(labels[labelCount - 1 - n],
            other.labels[other.labelCount - 1 - n])) {
      n++;
    }
    return n;
  }

  /// Uncompressed wire format, original case.
  Uint8List toWire() => _encode(lowercase: false);

  /// Uncompressed wire format, lowercased (RFC 4034 §6.2).
  Uint8List toCanonicalWire() => _encode(lowercase: true);

  Uint8List _encode({required bool lowercase}) {
    final out = BytesBuilder(copy: false);
    for (final label in labels) {
      out.addByte(label.length);
      out.add(lowercase ? _lower(label) : label);
    }
    out.addByte(0);
    return out.toBytes();
  }

  @override
  int compareTo(DnsName other) {
    // Compare labels right to left, each as lowercased byte strings.
    final n = labelCount < other.labelCount ? labelCount : other.labelCount;
    for (var i = 1; i <= n; i++) {
      final c = _compareLabels(labels[labelCount - i], other.labels[other.labelCount - i]);
      if (c != 0) return c;
    }
    return labelCount - other.labelCount;
  }

  bool operator <(DnsName other) => compareTo(other) < 0;

  @override
  bool operator ==(Object other) =>
      other is DnsName &&
      other.labelCount == labelCount &&
      isSubdomainOf(other);

  @override
  int get hashCode {
    var h = labelCount;
    for (final label in labels) {
      for (final b in label) {
        h = (h * 31 + _lowerByte(b)) & 0x3fffffff;
      }
    }
    return h;
  }

  @override
  String toString() {
    if (isRoot) return '.';
    final sb = StringBuffer();
    for (final label in labels) {
      for (final b in label) {
        if (b == 0x2e || b == 0x5c) {
          sb.write('\\${String.fromCharCode(b)}');
        } else if (b <= 0x20 || b >= 0x7f) {
          sb.write('\\${b.toString().padLeft(3, '0')}');
        } else {
          sb.writeCharCode(b);
        }
      }
      sb.write('.');
    }
    return sb.toString();
  }

  static bool _isDigit(int c) => c >= 48 && c <= 57;
  static int _lowerByte(int b) => b >= 0x41 && b <= 0x5a ? b + 0x20 : b;
  static Uint8List _lower(Uint8List label) =>
      Uint8List.fromList([for (final b in label) _lowerByte(b)]);

  static bool _labelEquals(Uint8List a, Uint8List b) =>
      _compareLabels(a, b) == 0;

  static int _compareLabels(Uint8List a, Uint8List b) {
    final n = a.length < b.length ? a.length : b.length;
    for (var i = 0; i < n; i++) {
      final d = _lowerByte(a[i]) - _lowerByte(b[i]);
      if (d != 0) return d;
    }
    return a.length - b.length;
  }
}
