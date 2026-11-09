import 'package:flutter/material.dart';
import 'package:tlsa_resolver/tlsa_resolver.dart';

void main() => runApp(const MaterialApp(home: TlsaLookupPage()));

class TlsaLookupPage extends StatefulWidget {
  const TlsaLookupPage({super.key});

  @override
  State<TlsaLookupPage> createState() => _TlsaLookupPageState();
}

class _TlsaLookupPageState extends State<TlsaLookupPage> {
  // Validation runs on a background isolate, so it never stalls the UI.
  final _resolver = TlsaResolver.inBackground();
  final _host = TextEditingController(text: 'mail.ietf.org');
  final _port = TextEditingController(text: '25');
  TlsaResult? _result;
  Object? _error;
  bool _busy = false;

  @override
  void dispose() {
    _resolver.close();
    _host.dispose();
    _port.dispose();
    super.dispose();
  }

  Future<void> _lookup() async {
    setState(() => _busy = true);
    try {
      final result = await _resolver.lookup(_host.text.trim(), port: int.parse(_port.text));
      setState(() {
        _result = result;
        _error = null;
      });
    } catch (e) {
      setState(() {
        _result = null;
        _error = e;
      });
    } finally {
      setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final result = _result;
    return Scaffold(
      appBar: AppBar(title: const Text('TLSA lookup')),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          Row(children: [
            Expanded(child: TextField(controller: _host, decoration: const InputDecoration(labelText: 'Host'))),
            const SizedBox(width: 12),
            SizedBox(
              width: 80,
              child: TextField(
                controller: _port,
                keyboardType: TextInputType.number,
                decoration: const InputDecoration(labelText: 'Port'),
              ),
            ),
          ]),
          const SizedBox(height: 16),
          FilledButton(onPressed: _busy ? null : _lookup, child: Text(_busy ? 'Looking up…' : 'Look up')),
          const SizedBox(height: 24),
          if (_error != null) Text('$_error', style: TextStyle(color: Theme.of(context).colorScheme.error)),
          if (result != null) ...[
            Text('Status: ${result.status.name}', style: Theme.of(context).textTheme.titleMedium),
            if (result.reason != null) Text(result.reason!),
            if (result.answer.aliases.isNotEmpty) Text('Via: ${result.answer.aliases.join(' → ')}'),
            const SizedBox(height: 12),
            if (result.records.isEmpty) const Text('No TLSA records'),
            for (final record in result.records) SelectableText('$record', style: const TextStyle(fontFamily: 'monospace')),
          ],
        ],
      ),
    );
  }
}
