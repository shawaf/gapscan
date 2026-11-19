import 'package:encrypt/encrypt.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

Future<String> seal(String plain) async {
  const storage = FlutterSecureStorage();
  final raw = await storage.read(key: 'vault-key');
  final key = Key.fromBase64(raw!);
  final iv = IV.fromSecureRandom(12);
  return Encrypter(AES(key, mode: AESMode.gcm)).encrypt(plain, iv: iv).base64;
}
