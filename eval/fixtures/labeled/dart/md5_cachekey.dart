import 'dart:convert';
import 'package:crypto/crypto.dart';

String cacheKey(Uri url) {
  return md5.convert(utf8.encode(url.toString())).toString();
}
