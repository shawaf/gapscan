import 'dart:io';

Future<String> kernelVersion() async {
  final result = await Process.run('uname', ['-r']);
  return (result.stdout as String).trim();
}
