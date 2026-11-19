import 'package:encrypt/encrypt.dart';

String seal(String plain) {
  final key = Key.fromUtf8('7f3c9a1d5b8e2f406a9c1d3e5b7f8a2c');
  final iv = IV.fromLength(16);
  return Encrypter(AES(key, mode: AESMode.gcm)).encrypt(plain, iv: iv).base64;
}
