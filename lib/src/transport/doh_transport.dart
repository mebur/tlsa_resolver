import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'transport.dart';

/// Sends queries to a DNS-over-HTTPS resolver (RFC 8484), as POST requests
/// with an `application/dns-message` body.
///
/// Useful where the local network's resolver strips DNSSEC records (every
/// signed name then comes back bogus) or should not see the queries. The
/// answers are still validated locally; the DoH server is not trusted.
///
/// The server must accept HTTP/1.1, which is all `dart:io` speaks. Most do
/// (Cloudflare, Google); Quad9's DoH service requires HTTP/2 and resets the
/// connection.
///
/// One HTTP client, and with it one HTTPS connection, is reused for all
/// queries. It is created on first use in each isolate, so the transport
/// can be passed to a background validator.
class DohTransport implements DnsTransport {
  DohTransport(this.endpoint,
      {this.timeout = const Duration(seconds: 5), this.createClient = _defaultClient});

  /// Cloudflare (https://cloudflare-dns.com/dns-query).
  DohTransport.cloudflare({Duration timeout = const Duration(seconds: 5)})
      : this(Uri.https('cloudflare-dns.com', '/dns-query'), timeout: timeout);

  /// Google Public DNS (https://dns.google/dns-query).
  DohTransport.google({Duration timeout = const Duration(seconds: 5)})
      : this(Uri.https('dns.google', '/dns-query'), timeout: timeout);

  final Uri endpoint;

  /// Longest one query may take, including connecting.
  final Duration timeout;

  /// Builds the HTTP client, for instance to set a proxy. It runs in the
  /// isolate that sends the queries.
  final HttpClient Function() createClient;

  /// DNS messages over TCP are at most 64 KiB; anything longer is not one.
  static const _maxResponseBytes = 65535;
  static const _mediaType = 'application/dns-message';

  // Per isolate: an HttpClient cannot be sent between isolates.
  static final _clients = Expando<HttpClient>();

  static HttpClient _defaultClient() => HttpClient();

  HttpClient get _client => _clients[this] ??= createClient()..connectionTimeout = timeout;

  @override
  Future<Uint8List> send(Uint8List query) async {
    try {
      return await _send(query).timeout(timeout);
    } on TimeoutException {
      throw DnsTransportException('No DoH answer from ${endpoint.host} within ${timeout.inSeconds} s');
    } on SocketException catch (e) {
      throw DnsTransportException('DoH connection to ${endpoint.host} failed: ${e.message}');
    } on HttpException catch (e) {
      throw DnsTransportException('DoH request to ${endpoint.host} failed: ${e.message}');
    } on HandshakeException catch (e) {
      throw DnsTransportException('TLS handshake with ${endpoint.host} failed: ${e.message}');
    }
  }

  Future<Uint8List> _send(Uint8List query) async {
    final request = await _client.postUrl(endpoint);
    request.headers
      ..contentType = ContentType.parse(_mediaType)
      ..set(HttpHeaders.acceptHeader, _mediaType);
    request.contentLength = query.length;
    request.add(query);
    final response = await request.close();
    if (response.statusCode != HttpStatus.ok) {
      await response.drain<void>();
      throw DnsTransportException('DoH server ${endpoint.host} answered HTTP ${response.statusCode}');
    }
    if (response.headers.contentType?.mimeType != _mediaType) {
      await response.drain<void>();
      throw DnsTransportException(
          'DoH server ${endpoint.host} answered ${response.headers.contentType} instead of $_mediaType');
    }
    final body = BytesBuilder(copy: false);
    await for (final chunk in response) {
      body.add(chunk);
      if (body.length > _maxResponseBytes) {
        throw DnsTransportException('DoH answer from ${endpoint.host} is over $_maxResponseBytes bytes');
      }
    }
    return body.takeBytes();
  }

  /// Closes this isolate's HTTP client and its connection. The next query
  /// opens a new one.
  void close() {
    _clients[this]?.close(force: true);
    _clients[this] = null;
  }
}
