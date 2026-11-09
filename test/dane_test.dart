import 'dart:convert';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:tlsa_resolver/tlsa_resolver.dart';

import 'support/fake_dns.dart';

/// Self-signed P-256 certificate for CN=dane.example.test, with digests
/// computed by openssl.
final _cert = base64.decode(
    'MIIBjDCCATOgAwIBAgIUKpovXbYQCX5YRkSzFXzFERnriJIwCgYIKoZIzj0EAwIwHDEaMBgGA1UE'
    'AwwRZGFuZS5leGFtcGxlLnRlc3QwHhcNMjYxMTA4MTY1OTA5WhcNMzYxMTA1MTY1OTA5WjAcMRow'
    'GAYDVQQDDBFkYW5lLmV4YW1wbGUudGVzdDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABMSsm8qH'
    'rfdyjL2JRif0iBzA8z7e82WfKoUMZr9LyPAACfy64AJLwrdB+255Zb+AIGeBNBDfvpxP0LWWa9JY'
    'kjCjUzBRMB0GA1UdDgQWBBS64ukgOArUBl2A51rW1B1ZMsyeTjAfBgNVHSMEGDAWgBS64ukgOArU'
    'Bl2A51rW1B1ZMsyeTjAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0cAMEQCIA+lfa0FWbdj'
    'RWkftPHOTOERIf+/PKuAVDLQF0MbMbKqAiAIcf1r58qygQkISUo8wO2nMmOlVSXdkZgAw/likOZ6'
    'Dg==');
const _spkiSha256 = 'b4bc2285bc8c21d099432ad0eabbf65fcd298c475e071f36165ce3b810e29be1';
const _certSha256 = '45b79568c92f67745f5489ccf38d0d7097e535bd1c37aa7c5fc2e0959506637e';
const _spkiSha512 =
    '7629c529689de1ab2baa2f78929f55292de8f44ecc659b58ed94b4ef07940321'
    'e29aa72724cdb48263ba0b5c74214eb131979539b27e82263afbacfca22cce15';

List<int> _hex(String s) =>
    [for (var i = 0; i < s.length; i += 2) int.parse(s.substring(i, i + 2), radix: 16)];

String _toHex(List<int> b) => b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();

TlsaResult _secureResult(List<TlsaRecord> records, {SecurityStatus status = SecurityStatus.secure}) =>
    TlsaResult(ValidatedAnswer(
      name: n('_443._tcp.dane.example.test'),
      type: RRType.tlsa,
      status: status,
      records: [
        for (final r in records)
          tlsaRecord('_443._tcp.dane.example.test', r.usage, r.selector, r.matchingType, r.data),
      ],
    ));

void main() {
  final cert = Uint8List.fromList(_cert);
  final other = Uint8List.fromList([..._cert]..[200] ^= 0xff); // different public key

  test('computes association data like openssl', () {
    expect(_toHex(DaneVerifier.recordFor(cert).data), _spkiSha256);
    expect(_toHex(DaneVerifier.recordFor(cert, selector: 0).data), _certSha256);
    expect(_toHex(DaneVerifier.recordFor(cert, matchingType: 2).data), _spkiSha512);
  });

  test('DANE-EE 3 1 1 matches the leaf', () {
    final result = _secureResult([TlsaRecord(3, 1, 1, Uint8List.fromList(_hex(_spkiSha256)))]);
    final verdict = DaneVerifier.verify(result, [cert]);
    expect(verdict.outcome, DaneOutcome.verified);
    expect(verdict.match!.certificateIndex, 0);
    expect(verdict.requiresChainCheck, isFalse);
  });

  test('DANE-EE does not match another key', () {
    final result = _secureResult([TlsaRecord(3, 1, 1, Uint8List.fromList(_hex(_spkiSha256)))]);
    expect(DaneVerifier.verify(result, [other]).outcome, DaneOutcome.mismatch);
  });

  test('DANE-EE is checked against the leaf only', () {
    final result = _secureResult([TlsaRecord(3, 0, 1, Uint8List.fromList(_hex(_certSha256)))]);
    expect(DaneVerifier.verify(result, [other, cert]).outcome, DaneOutcome.mismatch);
  });

  test('DANE-TA matches an issuer and asks for a chain check', () {
    final result = _secureResult([TlsaRecord(2, 0, 1, Uint8List.fromList(_hex(_certSha256)))]);
    final verdict = DaneVerifier.verify(result, [other, cert]);
    expect(verdict.outcome, DaneOutcome.verified);
    expect(verdict.match!.certificateIndex, 1);
    expect(verdict.requiresChainCheck, isTrue);
  });

  test('PKIX usages need PKIX validation', () {
    final result = _secureResult([TlsaRecord(1, 1, 2, Uint8List.fromList(_hex(_spkiSha512)))]);
    expect(DaneVerifier.verify(result, [cert]).outcome, DaneOutcome.mismatch);
    expect(DaneVerifier.verify(result, [cert], pkixValidated: true).outcome, DaneOutcome.verified);
  });

  test('unusable records are ignored', () {
    final result = _secureResult([
      TlsaRecord(3, 1, 1, Uint8List(20)), // wrong digest length
      TlsaRecord(4, 1, 1, Uint8List(32)), // unknown usage
    ]);
    expect(result.usableRecords, isEmpty);
    expect(DaneVerifier.verify(result, [cert]).outcome, DaneOutcome.notApplicable);
  });

  test('insecure answers do not apply, bogus ones fail', () {
    final record = TlsaRecord(3, 1, 1, Uint8List.fromList(_hex(_spkiSha256)));
    expect(DaneVerifier.verify(_secureResult([record], status: SecurityStatus.insecure), [cert]).outcome,
        DaneOutcome.notApplicable);
    expect(DaneVerifier.verify(_secureResult([record], status: SecurityStatus.bogus), [cert]).outcome,
        DaneOutcome.lookupFailed);
  });

  test('rejects malformed DER', () {
    expect(() => DaneVerifier.subjectPublicKeyInfo(Uint8List.fromList([0x30, 0x82, 0xff])),
        throwsFormatException);
    expect(DaneVerifier.matches(TlsaRecord(3, 1, 0, Uint8List(1)), Uint8List(3)), isFalse);
  });
}
