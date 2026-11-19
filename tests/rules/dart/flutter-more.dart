import 'dart:math';
import 'package:crypto/crypto.dart';
import 'package:encrypt/encrypt.dart';

class Cases {
  void random() {
    // ruleid: gapscan.dart.random-seeded
    final seeded = Random(42);
    // ruleid: gapscan.dart.random-not-secure
    final plain = Random();
    // ok: gapscan.dart.random-seeded
    final strong = Random.secure();
  }

  void kdf(String password) {
    // ruleid: gapscan.dart.weak-key-derivation
    final params = Pbkdf2Parameters(salt, 1000, 32);
    // ruleid: gapscan.dart.weak-key-derivation
    final raw = sha256.convert(utf8.encode(password));
    // ok: gapscan.dart.weak-key-derivation
    final good = Pbkdf2Parameters(salt, 600000, 32);
  }

  void storage() {
    // ruleid: gapscan.dart.external-storage
    final dir = await getExternalStorageDirectory();
    // ruleid: gapscan.dart.external-storage
    final path = '/sdcard/Android/data/app/files';
    // ok: gapscan.dart.external-storage
    final safe = await getApplicationSupportDirectory();
  }

  void secure() {
    // ruleid: gapscan.dart.secure-storage-weak-accessibility
    final opts = IOSOptions(accessibility: KeychainAccessibility.unlocked);
    // ruleid: gapscan.dart.secure-storage-weak-accessibility
    const a = AndroidOptions(encryptedSharedPreferences: false);
    // ok: gapscan.dart.secure-storage-weak-accessibility
    final b = IOSOptions(accessibility: KeychainAccessibility.passcode);
  }

  // ruleid: gapscan.dart.hardcoded-secret-literal
  static const String apiKey = 'sk_live_abcdef123456';
  // ok: gapscan.dart.hardcoded-secret-literal
  static const String apiKeyHeader = '';

  void cipher(Key key, IV iv) {
    // ruleid: gapscan.dart.cipher-without-authentication
    final e = Encrypter(AES(key, mode: AESMode.cbc));
    // ok: gapscan.dart.cipher-without-authentication
    final g = Encrypter(AES(key, mode: AESMode.gcm));
  }

  bool verify(String hmacHex, String expected) {
    // ruleid: gapscan.dart.non-constant-time-compare
    return hmacHex == expected;
  }
}

class MoreCases {
  void ciphers() {
    // ruleid: gapscan.dart.pointycastle-unauthenticated-mode
    final cbc = CBCBlockCipher(AESEngine());
    // ruleid: gapscan.dart.rsa-without-oaep
    final rsa = PKCS1Encoding(RSAEngine());
    // ok: gapscan.dart.rsa-without-oaep
    final oaep = OAEPEncoding(RSAEngine());
  }

  void temp() async {
    // ruleid: gapscan.dart.temp-file-use
    final dir = await getTemporaryDirectory();
  }

  void logs(String authToken) {
    // ruleid: gapscan.dart.log-sensitive-interpolation
    debugPrint('login ok, token=$authToken');
    // ok: gapscan.dart.log-sensitive-interpolation
    debugPrint('login ok');
  }
}
