import 'dart:io';
import 'dart:math';
import 'package:crypto/crypto.dart';

class Cases {
  // --- sqli
  void sqlBad(db, String name) {
    // ruleid: gapscan.dart.sqli-string-built
    db.rawQuery("SELECT * FROM users WHERE name = '$name'");
    // ruleid: gapscan.dart.sqli-string-built
    db.rawQuery('SELECT * FROM users WHERE name = ' + name);
    // ruleid: gapscan.dart.sqli-string-built
    db.execute("DELETE FROM users WHERE id = ${name}");
  }

  void sqlOk(db, String name) {
    // ok: gapscan.dart.sqli-string-built
    db.rawQuery('SELECT * FROM users WHERE name = ?', [name]);
    // ok: gapscan.dart.sqli-string-built
    db.execute('DELETE FROM users');
  }

  // --- tls
  HttpClient clientBad() {
    final client = HttpClient();
    // ruleid: gapscan.dart.tls-bad-certificate-callback
    client.badCertificateCallback = (X509Certificate cert, String host, int port) => true;
    return client;
  }

  HttpClient clientOk() {
    // ok: gapscan.dart.tls-bad-certificate-callback
    return HttpClient();
  }

  // --- prefs
  Future<void> prefsBad(prefs, String pw) async {
    // ruleid: gapscan.dart.prefs-sensitive-value
    await prefs.setString('password', pw);
    // ruleid: gapscan.dart.prefs-sensitive-value
    await prefs.setString("authToken", pw);
  }

  Future<void> prefsOk(prefs, String v) async {
    // ok: gapscan.dart.prefs-sensitive-value
    await prefs.setString('theme', v);
  }

  // --- crypto
  String hashBad(String s) {
    // ruleid: gapscan.dart.weak-crypto
    return md5.convert(utf8.encode(s)).toString();
  }

  String hashBad2(String s) {
    // ruleid: gapscan.dart.weak-crypto
    return sha1.convert(utf8.encode(s)).toString();
  }

  String hashOk(String s) {
    // ok: gapscan.dart.weak-crypto
    return sha256.convert(utf8.encode(s)).toString();
  }

  // --- command
  Future<void> shellBad(String host) async {
    // ruleid: gapscan.dart.command-string-built
    await Process.run('sh', ['-c', 'dig +short ' + host]);
    // ruleid: gapscan.dart.command-string-built
    await Process.run('bash', ['-c', 'ping $host']);
  }

  Future<void> shellOk() async {
    // ok: gapscan.dart.command-string-built
    await Process.run('uname', ['-r']);
  }

  // --- keys
  String keyBad(String plain) {
    // ruleid: gapscan.dart.hardcoded-crypto-key
    final key = Key.fromUtf8('0123456789abcdef0123456789abcdef');
    return key.base64;
  }

  String keyOk(String stored) {
    // ok: gapscan.dart.hardcoded-crypto-key
    final key = Key.fromBase64(stored);
    return key.base64;
  }

  // --- randomness
  // ruleid: gapscan.dart.insecure-random-for-secret
  String newSessionToken() {
    final rnd = Random(DateTime.now().millisecondsSinceEpoch);
    return List.generate(32, (_) => rnd.nextInt(16).toRadixString(16)).join();
  }

  // ok: gapscan.dart.insecure-random-for-secret
  String newSecureToken() {
    final rnd = Random.secure();
    return List.generate(32, (_) => rnd.nextInt(16).toRadixString(16)).join();
  }

  // ok: gapscan.dart.insecure-random-for-secret
  int pickColor() {
    final rnd = Random();
    return rnd.nextInt(255);
  }

  // --- http
  Uri httpBad() {
    // ruleid: gapscan.dart.cleartext-http-url
    return Uri.parse('http://api.example.com/v1/users');
  }

  Uri httpOk() {
    // ok: gapscan.dart.cleartext-http-url
    Uri.parse('http://localhost:8080/dev');
    // ok: gapscan.dart.cleartext-http-url
    return Uri.parse('https://api.example.com/v1/users');
  }

  // --- logging
  void logBad(String token) {
    // ruleid: gapscan.dart.log-sensitive-value
    print('token is $token and password');
  }

  void logOk(int count) {
    // ok: gapscan.dart.log-sensitive-value
    print('synced $count items');
    // ok: gapscan.dart.log-sensitive-value
    print('No endpoint found for client secret');
    // ruleid: gapscan.dart.log-sensitive-value
    print(authToken);
  }

  // --- web view
  void webBad(controller, String name) {
    // ruleid: gapscan.dart.webview-unrestricted-javascript
    final mode = JavascriptMode.unrestricted;
    // ruleid: gapscan.dart.webview-unrestricted-javascript
    controller.runJavaScript("setUser('$name')");
  }

  void webOk(controller) {
    // ok: gapscan.dart.webview-unrestricted-javascript
    controller.runJavaScript('refresh()');
  }
}
