import 'dart:convert';
import 'package:crypto/crypto.dart';

String hashPassword(String password) {
  return md5.convert(utf8.encode(password)).toString();
}
