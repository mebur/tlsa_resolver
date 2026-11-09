import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:tlsa_resolver/tlsa_resolver.dart';

import 'suite.dart';

void main() => runApp(const DeviceTestApp());

class DeviceTestApp extends StatelessWidget {
  const DeviceTestApp({super.key});

  @override
  Widget build(BuildContext context) => MaterialApp(
        title: 'TLSA device test',
        theme: ThemeData(colorSchemeSeed: Colors.teal),
        darkTheme: ThemeData(colorSchemeSeed: Colors.teal, brightness: Brightness.dark),
        home: const SuitePage(),
      );
}

class SuitePage extends StatefulWidget {
  const SuitePage({super.key});

  @override
  State<SuitePage> createState() => _SuitePageState();
}

class _SuitePageState extends State<SuitePage> {
  var _transport = transportOptions.first;
  final _results = <TestCase, CaseResult>{};
  TestCase? _running;
  bool _busy = false;

  Future<void> _runAll() async {
    setState(() {
      _busy = true;
      _results.clear();
    });
    // A fresh resolver per run, so every run validates the chain from the
    // root with a cold cache.
    final resolver = TlsaResolver(transport: _transport.create());
    for (final c in testCases) {
      setState(() => _running = c);
      final result = await runCase(resolver, c);
      if (!mounted) return;
      setState(() => _results[c] = result);
    }
    setState(() {
      _running = null;
      _busy = false;
    });
  }

  Future<void> _copyReport() async {
    final report = formatReport(_transport.label, [
      for (final c in testCases)
        if (_results[c] != null) _results[c]!,
    ]);
    await Clipboard.setData(ClipboardData(text: report));
    if (!mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text('Report copied')));
  }

  @override
  Widget build(BuildContext context) {
    final passed = _results.values.where((r) => r.passed).length;
    final theme = Theme.of(context);
    return Scaffold(
      appBar: AppBar(
        title: const Text('TLSA device test'),
        actions: [
          IconButton(
            tooltip: 'Custom lookup',
            icon: const Icon(Icons.search),
            onPressed: () => Navigator.of(context).push(MaterialPageRoute<void>(
                builder: (_) => CustomLookupPage(transport: _transport))),
          ),
          IconButton(
            tooltip: 'Copy report',
            icon: const Icon(Icons.copy_all),
            onPressed: _results.isEmpty || _busy ? null : _copyReport,
          ),
        ],
      ),
      body: ListView(
        padding: const EdgeInsets.only(bottom: 24),
        children: [
          Padding(
            padding: const EdgeInsets.fromLTRB(16, 12, 16, 0),
            child: Text(environmentSummary(), style: theme.textTheme.bodySmall),
          ),
          Padding(
            padding: const EdgeInsets.all(16),
            child: Row(children: [
              Expanded(
                child: DropdownButtonFormField<TransportOption>(
                  initialValue: _transport,
                  decoration: const InputDecoration(labelText: 'Transport', border: OutlineInputBorder()),
                  items: [
                    for (final o in transportOptions) DropdownMenuItem(value: o, child: Text(o.label)),
                  ],
                  onChanged: _busy ? null : (o) => setState(() => _transport = o!),
                ),
              ),
              const SizedBox(width: 12),
              FilledButton.icon(
                onPressed: _busy ? null : _runAll,
                icon: const Icon(Icons.play_arrow),
                label: Text(_busy ? '${_results.length}/${testCases.length}' : 'Run all'),
              ),
            ]),
          ),
          if (_results.isNotEmpty)
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 16),
              child: Text(
                'Passed $passed of ${_results.length}',
                style: theme.textTheme.titleMedium?.copyWith(
                  color: passed == _results.length ? Colors.green : theme.colorScheme.error,
                ),
              ),
            ),
          for (final c in testCases) _CaseTile(testCase: c, result: _results[c], running: _running == c),
        ],
      ),
    );
  }
}

class _CaseTile extends StatelessWidget {
  const _CaseTile({required this.testCase, required this.result, required this.running});

  final TestCase testCase;
  final CaseResult? result;
  final bool running;

  @override
  Widget build(BuildContext context) {
    final r = result;
    final theme = Theme.of(context);
    final Widget leading = running
        ? const SizedBox.square(dimension: 20, child: CircularProgressIndicator(strokeWidth: 2))
        : r == null
            ? Icon(Icons.radio_button_unchecked, color: theme.disabledColor)
            : r.passed
                ? const Icon(Icons.check_circle, color: Colors.green)
                : Icon(Icons.cancel, color: theme.colorScheme.error);
    final expected = [
      testCase.status.name,
      if (testCase.dane != null) 'DANE ${testCase.dane!.name}',
    ].join(', ');
    return ExpansionTile(
      leading: SizedBox(width: 24, child: Center(child: leading)),
      title: Text(testCase.title),
      subtitle: Text(r == null
          ? 'expect $expected'
          : '${r.result?.status.name ?? 'error'} · ${r.elapsed.inMilliseconds} ms'),
      expandedCrossAxisAlignment: CrossAxisAlignment.start,
      childrenPadding: const EdgeInsets.fromLTRB(16, 0, 16, 12),
      children: [
        Text(testCase.note, style: theme.textTheme.bodySmall),
        const SizedBox(height: 4),
        SelectableText(describe(testCase), style: const TextStyle(fontFamily: 'monospace', fontSize: 12)),
        Text('expect $expected', style: theme.textTheme.bodySmall),
        if (r != null)
          for (final line in detailLines(r))
            SelectableText(line,
                style: TextStyle(
                  fontFamily: 'monospace',
                  fontSize: 12,
                  color: line.startsWith('!') ? theme.colorScheme.error : null,
                )),
      ],
    );
  }
}

class CustomLookupPage extends StatefulWidget {
  const CustomLookupPage({super.key, required this.transport});

  final TransportOption transport;

  @override
  State<CustomLookupPage> createState() => _CustomLookupPageState();
}

class _CustomLookupPageState extends State<CustomLookupPage> {
  late final _resolver = TlsaResolver(transport: widget.transport.create());
  final _host = TextEditingController(text: 'www.freebsd.org');
  final _port = TextEditingController(text: '443');
  CaseResult? _result;
  bool _busy = false;

  Future<void> _lookup() async {
    final port = int.tryParse(_port.text.trim());
    if (port == null) return;
    setState(() => _busy = true);
    // runCase compares against an expected status; "secure" is only a
    // placeholder here and that comparison is hidden below.
    final c = TestCase('Custom', _host.text.trim(), port,
        status: SecurityStatus.secure, note: 'Ad-hoc lookup');
    final result = await runCase(_resolver, c);
    if (!mounted) return;
    setState(() {
      _result = result;
      _busy = false;
    });
  }

  @override
  Widget build(BuildContext context) {
    final r = _result;
    return Scaffold(
      appBar: AppBar(title: Text('Lookup via ${widget.transport.label}')),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          Row(children: [
            Expanded(
              child: TextField(
                controller: _host,
                autocorrect: false,
                keyboardType: TextInputType.url,
                decoration: const InputDecoration(labelText: 'Host'),
              ),
            ),
            const SizedBox(width: 12),
            SizedBox(
              width: 72,
              child: TextField(
                controller: _port,
                keyboardType: TextInputType.number,
                decoration: const InputDecoration(labelText: 'Port'),
              ),
            ),
          ]),
          const SizedBox(height: 16),
          FilledButton(onPressed: _busy ? null : _lookup, child: Text(_busy ? 'Looking up…' : 'Look up')),
          const SizedBox(height: 16),
          if (r != null) ...[
            Text('${r.result?.status.name ?? 'error'} · ${r.elapsed.inMilliseconds} ms',
                style: Theme.of(context).textTheme.titleMedium),
            const SizedBox(height: 8),
            for (final line in detailLines(r))
              if (!line.startsWith('! status'))
                SelectableText(line, style: const TextStyle(fontFamily: 'monospace', fontSize: 12)),
          ],
        ],
      ),
    );
  }
}
