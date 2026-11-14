// Summarises coverage/lcov.info (from `flutter test --coverage`) per file and
// fails when the code that decides what is secure is less covered than
// [_floor]. The transports are listed but not held to it: their tests need
// the network or a device.
//
//   flutter test --coverage -x network && dart run tool/coverage.dart

// ignore_for_file: avoid_print

import 'dart:io';

/// Line coverage the validation code must keep, in percent.
const _floor = 95.0;

/// The code held to [_floor]: validation, wire parsing and DANE matching.
bool _core(String file) =>
    file.startsWith('lib/src/dnssec/') ||
    file.startsWith('lib/src/wire/') ||
    file == 'lib/src/dane.dart' ||
    file == 'lib/src/tlsa.dart' ||
    file == 'lib/src/resolver.dart';

void main(List<String> args) {
  final path = args.isEmpty ? 'coverage/lcov.info' : args.first;
  final hits = <String, Map<int, int>>{};
  String? file;
  for (final line in File(path).readAsLinesSync()) {
    if (line.startsWith('SF:')) {
      file = line.substring(3);
    } else if (line.startsWith('DA:') && file != null) {
      final [number, count, ...] = line.substring(3).split(',');
      hits.putIfAbsent(file, () => {})[int.parse(number)] = int.parse(count);
    }
  }

  var coreLines = 0, coreHit = 0;
  for (final file in hits.keys.toList()..sort()) {
    final lines = hits[file]!;
    final missed = [for (final MapEntry(:key, :value) in lines.entries) if (value == 0) key]..sort();
    final hit = lines.length - missed.length;
    if (_core(file)) {
      coreLines += lines.length;
      coreHit += hit;
    }
    print('${(100 * hit / lines.length).toStringAsFixed(1).padLeft(5)}%  '
        '${_core(file) ? '*' : ' '} $file'
        '${missed.isEmpty ? '' : '  (not run: ${missed.join(', ')})'}');
  }

  final core = 100 * coreHit / coreLines;
  print('\nValidation code (*): ${core.toStringAsFixed(1)}% of $coreLines lines; floor $_floor%.');
  if (core < _floor) {
    print('Below the floor: add tests for the lines listed above.');
    exit(1);
  }
}
