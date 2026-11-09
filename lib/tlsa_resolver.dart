/// Resolve TLSA records with local DNSSEC validation, and match certificates
/// against them (DANE, RFC 6698 / RFC 7671).
library;

export 'src/dane.dart';
export 'src/dnssec/trust_anchors.dart' show rootTrustAnchors;
export 'src/dnssec/isolate_validator.dart';
export 'src/dnssec/validator.dart'
    show DnssecLookup, DnssecValidator, SecurityStatus, Sha1Policy, ValidatedAnswer;
export 'src/resolver.dart';
export 'src/tlsa.dart';
export 'src/transport/direct_transport.dart';
export 'src/transport/native_transport.dart';
export 'src/transport/transport.dart';
export 'src/wire/message.dart' show RRType, ResourceRecord;
export 'src/wire/name.dart';
export 'src/wire/rdata.dart' show Ds;
