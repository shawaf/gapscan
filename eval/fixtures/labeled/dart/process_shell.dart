import 'dart:io';

Future<String> resolve(String host) async {
  final result = await Process.run('sh', ['-c', 'dig +short ' + host]);
  return result.stdout as String;
}
