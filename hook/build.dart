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
      // Warnings and the usual hardening for clang and gcc. Warnings are
      // not errors here, so a newer compiler cannot break an app's build;
      // CI builds the shim with -Werror and sanitizers instead.
      flags: [
        if (os != OS.windows) ...[
          '-Wall',
          '-Wextra',
          '-Wformat=2',
          '-fstack-protector-strong',
        ],
      ],
      defines: {
        if (os != OS.windows) '_FORTIFY_SOURCE': '2',
      },
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
