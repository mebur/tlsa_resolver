# tlsa_device_test

On-device test bench for `tlsa_resolver`. It runs a fixed set of live
lookups (secure, insecure, bogus, denials, CNAMEs, TLS handshakes with DANE
matching) through the transport you pick, and shows pass/fail per case.
**Copy report** puts a plain-text summary on the clipboard to share.

The expectations match how these public zones were set up in November 2026.
A failure can mean a zone changed rather than a bug; the report shows what
was observed.

## Run

```sh
flutter run --release -d <device>
```

* **iOS:** no signing team is committed. Copy
  `ios/Flutter/Signing.xcconfig.example` to `ios/Flutter/Signing.xcconfig`
  (gitignored) and set your own `DEVELOPMENT_TEAM`. Change the bundle
  identifier if it is already taken.
* **Android:** `flutter build apk --release` and install the APK; the system
  resolver transport needs Android 10+.

To check the expectations on the host first:

```sh
flutter test
```
