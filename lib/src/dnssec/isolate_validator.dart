import 'dart:async';
import 'dart:isolate';

import '../wire/name.dart';
import 'validator.dart';

/// Runs a [DnssecValidator] on a long-lived background isolate, so its
/// signature checks never block the calling isolate (in a Flutter app, the
/// UI isolate).
///
/// The function passed in runs on the background isolate and builds the
/// validator there, so its transport and zone key cache live there too.
/// Whatever it captures, such as a transport, is copied to that isolate and
/// must be sendable (`DirectDnsTransport`, `DohTransport` and
/// `NativeDnsTransport` are).
///
/// The isolate starts with the first lookup. While it runs it keeps the
/// program alive; call [close] when done.
class IsolateValidator implements DnssecLookup {
  IsolateValidator(this._create);

  final DnssecValidator Function() _create;
  Future<SendPort>? _worker;
  final _pending = <int, Completer<ValidatedAnswer>>{};
  Completer<void>? _clearing;
  var _nextId = 0;
  var _closed = false;

  @override
  Future<ValidatedAnswer> resolve(DnsName name, int type) async {
    final worker = await _start();
    final id = _nextId++;
    final reply = Completer<ValidatedAnswer>();
    _pending[id] = reply;
    worker.send(_Request(id, name, type));
    return reply.future;
  }

  @override
  Future<void> clearCache() async {
    if (_worker == null) return;
    final worker = await _start();
    final done = _clearing ??= Completer<void>();
    worker.send(_clearCache);
    return done.future;
  }

  /// Stops the background isolate once lookups in progress have finished.
  /// Later lookups throw a [StateError].
  Future<void> close() async {
    if (_closed) return;
    _closed = true;
    final worker = _worker;
    if (worker == null) return;
    (await worker).send(_close);
  }

  Future<SendPort> _start() {
    if (_closed) throw StateError('IsolateValidator is closed');
    return _worker ??= _spawn();
  }

  Future<SendPort> _spawn() async {
    final replies = ReceivePort();
    final ready = Completer<SendPort>();
    replies.listen((message) {
      switch (message) {
        case SendPort port:
          ready.complete(port);
        case _Reply(:final id, :final answer):
          _pending.remove(id)?.complete(answer);
        case _Failure(:final id, :final error, :final stack):
          _pending.remove(id)?.completeError(RemoteError(error, stack));
        case _cacheCleared:
          _clearing?.complete();
          _clearing = null;
        case [final error, final stack]:
          // An uncaught error took the isolate down; onExit follows.
          _fail(RemoteError('$error', '$stack'));
        case null:
          // The isolate exited. Start a new one on the next lookup unless
          // closed.
          _fail(RemoteError('Validation isolate exited', ''));
          replies.close();
          _worker = null;
      }
    });
    try {
      await Isolate.spawn(_run, (replies.sendPort, _create),
          onExit: replies.sendPort, onError: replies.sendPort, debugName: 'tlsa_resolver validator');
    } catch (_) {
      replies.close();
      _worker = null;
      rethrow;
    }
    return ready.future;
  }

  void _fail(RemoteError error) {
    final pending = [..._pending.values];
    _pending.clear();
    for (final reply in pending) {
      reply.completeError(error);
    }
    _clearing?.completeError(error);
    _clearing = null;
  }

  /// The background isolate: builds the validator and answers requests
  /// until told to close.
  static void _run((SendPort, DnssecValidator Function()) args) {
    final (replies, create) = args;
    final validator = create();
    final requests = ReceivePort();
    replies.send(requests.sendPort);
    requests.listen((message) async {
      switch (message) {
        case _Request(:final id, :final name, :final type):
          try {
            replies.send(_Reply(id, await validator.resolve(name, type)));
          } catch (e, st) {
            replies.send(_Failure(id, '$e', '$st'));
          }
        case _clearCache:
          await validator.clearCache();
          replies.send(_cacheCleared);
        case _close:
          // Lookups in progress still reply; the isolate exits after them.
          requests.close();
      }
    });
  }
}

const _close = 'close';
const _clearCache = 'clearCache';
const _cacheCleared = 'cacheCleared';

final class _Request {
  const _Request(this.id, this.name, this.type);
  final int id;
  final DnsName name;
  final int type;
}

final class _Reply {
  const _Reply(this.id, this.answer);
  final int id;
  final ValidatedAnswer answer;
}

final class _Failure {
  const _Failure(this.id, this.error, this.stack);
  final int id;
  final String error;
  final String stack;
}
