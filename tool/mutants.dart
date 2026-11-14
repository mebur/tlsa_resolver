// Plants one bug at a time in the checks that keep forged data from being
// reported as secure, runs the tests, and fails if any bug survives: a
// check whose removal no test notices is a check nobody is testing.
//
//   dart run tool/mutants.dart [--only <substring>]
//
// Every file is restored after each run, also when the tool is stopped
// with an error. Takes a few minutes.

// ignore_for_file: avoid_print

import 'dart:io';

class _Mutant {
  const _Mutant(this.file, this.what, this.from, this.to, {this.expectedToSurvive});
  final String file;
  final String what;
  final String from;
  final String to;

  /// Why no test can catch this one, for a check that is defence in depth.
  final String? expectedToSurvive;
}

const _mutants = [
  // Chain of trust and signatures
  _Mutant('lib/src/dnssec/validator.dart', 'signer need not be an ancestor',
      ': owner.isSubdomainOf(s.signer))', ': true)'),
  _Mutant('lib/src/dnssec/validator.dart', 'signature validity period ignored',
      '!sig.isValidAt(now, skew: clockSkew.inSeconds) ||', ''),
  _Mutant('lib/src/dnssec/validator.dart', 'RRSIG label count not checked',
      'sig.labels > owner.rrsigLabelCount ||', ''),
  _Mutant('lib/src/dnssec/validator.dart', 'DNSKEY set may be signed by any of its keys',
      '_verifyRRset(rrset, sigs, zone, anchored)', '_verifyRRset(rrset, sigs, zone, keys)'),
  _Mutant('lib/src/dnssec/validator.dart', 'SHA-1 DS kept next to a stronger digest',
      'if (usable.any((ds) => ds.digestType != DigestType.sha1)) {', 'if (false) {'),
  _Mutant('lib/src/dnssec/validator.dart', 'revoked keys used',
      '&& !key.isRevoked', ''),
  _Mutant('lib/src/dnssec/validator.dart', 'no limit on keys tried per signature',
      '].take(maxKeysPerSignature);', '];'),
  _Mutant('lib/src/dnssec/validator.dart', 'response ID not checked',
      'msg.id != DnsMessage.queryId(query)', 'false'),
  _Mutant('lib/src/dnssec/validator.dart', 'response question not checked',
      'msg.questions.first.name != name ||', ''),
  _Mutant('lib/src/dnssec/validator.dart', 'keys cached past their signature',
      'if (left == 0 || left >= 0x80000000) return null;', ''),
  _Mutant('lib/src/dnssec/validator.dart', 'a non-existent zone counts as unsigned',
      'if (ds.nxDomain && ds.status != SecurityStatus.insecure) {', 'if (false) {'),
  _Mutant('lib/src/dnssec/validator.dart', 'DNAME target not compared',
      'if (expected != target) continue;', ''),
  // Denial of existence
  _Mutant('lib/src/dnssec/denial.dart', 'NSEC wildcard closest encloser not checked',
      '.labelCount == rrsigLabels', '.labelCount >= 0'),
  _Mutant('lib/src/dnssec/denial.dart', 'NSEC DS denial without a delegation',
      'return nsec.types.isDelegation ? Proof.proven : Proof.failed;', 'return Proof.proven;'),
  _Mutant('lib/src/dnssec/denial.dart', 'NSEC3 DS denial without a delegation',
      'return match.types.isDelegation ? Proof.proven : Proof.failed;', 'return Proof.proven;'),
  _Mutant('lib/src/dnssec/denial.dart', 'NSEC below a delegation used',
      'return !nsec.types.isDelegation && !nsec.types.contains(RRType.dname);', 'return true;'),
  _Mutant('lib/src/dnssec/denial.dart', 'NSEC3 hash length not checked',
      'r.nextHash.length == _nsec3HashLength', 'true'),
  _Mutant('lib/src/dnssec/denial.dart', 'NSEC3 wildcard opt-out counts as proven',
      'return cover.optOut ? Proof.optOut : Proof.proven;', 'return Proof.proven;'),
  _Mutant('lib/src/dnssec/denial.dart', 'NSEC3 name shown to exist still denied',
      'if (_matching(name) != null) return Proof.failed; // The name exists.', ''),
  _Mutant('lib/src/dnssec/denial.dart', 'NSEC3 iteration limit ignored',
      'records.any((r) => r.iterations > maxNsec3Iterations)', 'false'),
  // Crypto
  _Mutant('lib/src/dnssec/crypto.dart', 'small-order Ed25519 keys accepted',
      '!_ed25519SmallOrder(publicKey) &&', ''),
  _Mutant('lib/src/dnssec/crypto.dart', 'small-order Ed25519 R accepted',
      '!_ed25519SmallOrder(signature) &&', ''),
  _Mutant('lib/src/dnssec/crypto.dart', 'ECDSA point not checked to be on the curve',
      'if (!_onCurve(curve, x, y)) return false;', '',
      expectedToSurvive: 'pointycastle combines both multiplications in one pass, so an '
          'off-curve key fails verification even without the check (tried with an '
          'order-2 point on another curve)'),
  _Mutant('lib/src/dnssec/crypto.dart', 'RSA modulus size not limited',
      'modulus.bitLength > _maxRsaModulusBits ||', ''),
  _Mutant('lib/src/dnssec/crypto.dart', 'DS digest not compared',
      'return digest != null && bytesEqual(digest, ds.digest);', 'return digest != null;'),
  // Wire format
  _Mutant('lib/src/wire/message.dart', 'compression pointers may point forward',
      'if (target >= p || ++jumps > 64) {', 'if (++jumps > 64) {'),
  // DANE
  _Mutant('lib/src/dane.dart', 'DANE-TA reported as verified',
      'return DaneVerdict(DaneOutcome.needsChainCheck, match: anchor,',
      'return DaneVerdict(DaneOutcome.verified, match: anchor,'),
  _Mutant('lib/src/dane.dart', 'DANE-EE matched anywhere in the chain',
      'final candidates = leafOnly ? 1 : chain.length;', 'final candidates = chain.length;'),
  _Mutant('lib/src/dane.dart', 'PKIX usages count without PKIX validation',
      'if (needsPkix && !pkixValidated) continue;', ''),
  _Mutant('lib/src/tlsa.dart', 'records of an insecure answer used',
      'isSecure ? [for (final r in records) if (r.isUsable) r] : const [];',
      '[for (final r in records) if (r.isUsable) r];'),
  _Mutant('lib/src/resolver.dart', 'bogus address lookup falls back to the host',
      'if (address.status == SecurityStatus.bogus || address.status == SecurityStatus.indeterminate) {',
      'if (false) {'),
];

Future<void> main(List<String> args) async {
  final only = args.contains('--only') ? args[args.indexOf('--only') + 1] : null;
  final mutants = [for (final m in _mutants) if (only == null || m.what.contains(only)) m];
  final survivors = <_Mutant>[];

  for (final (i, m) in mutants.indexed) {
    final file = File(m.file);
    final original = file.readAsStringSync();
    final count = original.split(m.from).length - 1;
    if (count != 1) {
      print('Mutant "${m.what}": its text occurs $count times in ${m.file}; update tool/mutants.dart.');
      exit(2);
    }
    stdout.write('[${i + 1}/${mutants.length}] ${m.what} ... ');
    file.writeAsStringSync(original.replaceFirst(m.from, m.to));
    try {
      final result = await Process.run('flutter', ['test', '-x', 'network'],
          environment: {'FUZZ_ITERATIONS': '2000'});
      if (result.exitCode == 0 && m.expectedToSurvive != null) {
        print('survived, as expected: ${m.expectedToSurvive}');
      } else if (result.exitCode == 0) {
        survivors.add(m);
        print('SURVIVED');
      } else if (m.expectedToSurvive != null) {
        print('caught: a test now covers it, so drop expectedToSurvive');
      } else {
        print('caught');
      }
    } finally {
      file.writeAsStringSync(original);
    }
  }

  print('');
  if (survivors.isEmpty) {
    print('All ${mutants.length} planted bugs were caught by the tests.');
    return;
  }
  print('${survivors.length} of ${mutants.length} planted bugs went unnoticed:');
  for (final m in survivors) {
    print('  ${m.what} (${m.file})');
  }
  exit(1);
}
