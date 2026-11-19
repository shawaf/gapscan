import 'package:flutter_secure_storage/flutter_secure_storage.dart';

Future<void> remember(String user, String token) async {
  const storage = FlutterSecureStorage();
  await storage.write(key: 'user', value: user);
  await storage.write(key: 'token', value: token);
}
