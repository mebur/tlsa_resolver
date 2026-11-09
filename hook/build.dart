// ignore_for_file: avoid_print

import 'package:code_assets/code_assets.dart';
import 'package:hooks/hooks.dart';
import 'package:logging/logging.dart';
import 'package:native_toolchain_c/native_toolchain_c.dart';

void main(List<String> args) async {
  await build(args, (input, output) async {
    final os = input.config.code.targetOS;
    final cbuilder = CBuilder.library(
      name: input.packageName,
      assetName: 'src/transport/native_transport.dart',
      sources: ['src/tlsa_resolver.c'],
      // res_nsend lives in libresolv on Apple platforms and (pre-2.34) glibc.
      // Android looks its API up with dlopen at run time.
      libraries: [
        if (os == OS.macOS || os == OS.iOS || os == OS.linux) 'resolv',
      ],
    );
    await cbuilder.run(
      input: input,
      output: output,
      logger: Logger('')
        ..level = Level.ALL
        ..onRecord.listen((record) => print(record.message)),
    );
  });
}
