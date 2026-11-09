@Tags(['network'])
library;

import 'package:flutter_test/flutter_test.dart';
import 'package:tlsa_device_test/suite.dart';
import 'package:tlsa_resolver/tlsa_resolver.dart';

/// Runs the device suite on the host, to check the expectations before
/// taking the app to a phone.
void main() {
  for (final option in transportOptions) {
    test('suite via ${option.label}', () async {
      final resolver = TlsaResolver(transport: option.create());
      final results = [for (final c in testCases) await runCase(resolver, c)];
      // ignore: avoid_print
      print(formatReport(option.label, results));
      expect(results.where((r) => !r.passed).map((r) => r.testCase.title), isEmpty);
    }, timeout: const Timeout(Duration(minutes: 3)));
  }

  // The app validates on a background isolate; check that each transport
  // can be sent there.
  for (final option in transportOptions) {
    test('suite via ${option.label} in the background', () async {
      final resolver = TlsaResolver.inBackground(transport: option.create());
      addTearDown(resolver.close);
      final results = [for (final c in testCases) await runCase(resolver, c)];
      expect(results.where((r) => !r.passed).map((r) => r.testCase.title), isEmpty);
    }, timeout: const Timeout(Duration(minutes: 3)));
  }
}
