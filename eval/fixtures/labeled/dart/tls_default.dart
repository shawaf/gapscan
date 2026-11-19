import 'dart:convert';
import 'dart:io';

Future<String> fetch(Uri uri) async {
  final client = HttpClient();
  final req = await client.getUrl(uri);
  final res = await req.close();
  return res.transform(utf8.decoder).join();
}
