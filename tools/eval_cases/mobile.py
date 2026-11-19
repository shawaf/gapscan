"""Kotlin, Swift and Dart (Flutter) cases: each weakness appears as a vulnerable site and a
look-alike safe site. No comments hint at the answer."""

from __future__ import annotations

from collections.abc import Callable

A01, A02, A04, A05, A07 = "A01:2025", "A02:2025", "A04:2025", "A05:2025", "A07:2025"


def register(case: Callable[..., None]) -> None:
    # ----------------------------------------------------------------------------- Kotlin
    case(
        "kt-sqli-concat",
        "kotlin/SqliConcat.kt",
        "rawQuery(",
        "CWE-89",
        A05,
        True,
        """
package app.data

import android.database.sqlite.SQLiteDatabase

class UserDao(private val db: SQLiteDatabase) {
    fun findByName(name: String): List<String> {
        val out = mutableListOf<String>()
        val c = db.rawQuery("SELECT email FROM users WHERE name = '" + name + "'", null)
        while (c.moveToNext()) out.add(c.getString(0))
        c.close()
        return out
    }
}
""",
    )
    case(
        "kt-sqli-param",
        "kotlin/SqliParam.kt",
        "rawQuery(",
        "CWE-89",
        A05,
        False,
        """
package app.data

import android.database.sqlite.SQLiteDatabase

class UserDao(private val db: SQLiteDatabase) {
    fun findByName(name: String): List<String> {
        val out = mutableListOf<String>()
        val c = db.rawQuery("SELECT email FROM users WHERE name = ?", arrayOf(name))
        while (c.moveToNext()) out.add(c.getString(0))
        c.close()
        return out
    }
}
""",
    )
    case(
        "kt-tls-trustall",
        "kotlin/TrustAll.kt",
        "checkServerTrusted",
        "CWE-295",
        A04,
        True,
        """
package app.net

import java.security.cert.X509Certificate
import javax.net.ssl.SSLContext
import javax.net.ssl.X509TrustManager

object Http {
    fun context(): SSLContext {
        val tm = object : X509TrustManager {
            override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}
            override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {}
            override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
        }
        val ctx = SSLContext.getInstance("TLS")
        ctx.init(null, arrayOf(tm), null)
        return ctx
    }
}
""",
    )
    case(
        "kt-tls-pinned",
        "kotlin/Pinned.kt",
        "CertificatePinner",
        "CWE-295",
        A04,
        False,
        """
package app.net

import okhttp3.CertificatePinner
import okhttp3.OkHttpClient

object Http {
    fun client(): OkHttpClient {
        val pinner = CertificatePinner.Builder()
            .add("api.example.com", "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
            .build()
        return OkHttpClient.Builder().certificatePinner(pinner).build()
    }
}
""",
    )
    case(
        "kt-prefs-password",
        "kotlin/PrefsPassword.kt",
        'putString("password"',
        "CWE-312",
        A04,
        True,
        """
package app.auth

import android.content.Context

class Session(private val ctx: Context) {
    fun remember(user: String, password: String) {
        val prefs = ctx.getSharedPreferences("auth", Context.MODE_PRIVATE)
        prefs.edit().putString("user", user).putString("password", password).apply()
    }
}
""",
    )
    case(
        "kt-prefs-encrypted",
        "kotlin/PrefsEncrypted.kt",
        "EncryptedSharedPreferences",
        "CWE-312",
        A04,
        False,
        """
package app.auth

import android.content.Context
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

class Session(private val ctx: Context) {
    fun remember(user: String, token: String) {
        val key = MasterKey.Builder(ctx).setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build()
        val prefs = EncryptedSharedPreferences.create(
            ctx, "auth", key,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
        )
        prefs.edit().putString("user", user).putString("token", token).apply()
    }
}
""",
    )
    case(
        "kt-md5-password",
        "kotlin/Md5Password.kt",
        'getInstance("MD5")',
        "CWE-327",
        A04,
        True,
        """
package app.auth

import java.security.MessageDigest

object Passwords {
    fun hash(password: String): String {
        val md = MessageDigest.getInstance("MD5")
        return md.digest(password.toByteArray()).joinToString("") { "%02x".format(it) }
    }
}
""",
    )
    case(
        "kt-md5-cachekey",
        "kotlin/Md5CacheKey.kt",
        'getInstance("MD5")',
        "CWE-327",
        A04,
        False,
        """
package app.cache

import java.security.MessageDigest

object ImageCache {
    fun keyFor(url: String): String {
        val md = MessageDigest.getInstance("MD5")
        return md.digest(url.toByteArray()).joinToString("") { "%02x".format(it) }
    }
}
""",
    )
    case(
        "kt-exec-concat",
        "kotlin/ExecConcat.kt",
        "exec(",
        "CWE-78",
        A05,
        True,
        """
package app.tools

import io.ktor.server.application.call
import io.ktor.server.response.respondText
import io.ktor.server.routing.Route
import io.ktor.server.routing.get

fun Route.ping() {
    get("/ping") {
        val host = call.request.queryParameters["host"] ?: ""
        val p = Runtime.getRuntime().exec("ping -c 1 " + host)
        call.respondText(p.inputStream.bufferedReader().readText())
    }
}
""",
    )
    case(
        "kt-exec-fixed",
        "kotlin/ExecFixed.kt",
        "exec(",
        "CWE-78",
        A05,
        False,
        """
package app.tools

object Diagnostics {
    fun kernel(): String {
        val p = Runtime.getRuntime().exec(arrayOf("uname", "-r"))
        return p.inputStream.bufferedReader().readText().trim()
    }
}
""",
    )
    case(
        "kt-hardcoded-key",
        "kotlin/HardcodedKey.kt",
        "7f3c9a1d5b8e2f40",
        "CWE-798",
        A04,
        True,
        """
package app.crypto

import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

object Vault {
    private val KEY = "7f3c9a1d5b8e2f406a9c1d3e5b7f8a2c".toByteArray()

    fun encrypt(plain: ByteArray, iv: ByteArray): ByteArray {
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, SecretKeySpec(KEY, "AES"), GCMParameterSpec(128, iv))
        return c.doFinal(plain)
    }
}
""",
    )
    case(
        "kt-keystore-key",
        "kotlin/KeystoreKey.kt",
        "getKey(",
        "CWE-798",
        A04,
        False,
        """
package app.crypto

import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

object Vault {
    fun encrypt(plain: ByteArray, iv: ByteArray): ByteArray {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val key = ks.getKey("vault-key", null) as SecretKey
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, iv))
        return c.doFinal(plain)
    }
}
""",
    )

    # ------------------------------------------------------------------------------ Swift
    case(
        "sw-sqli-interp",
        "swift/SqliInterp.swift",
        "sqlite3_exec(",
        "CWE-89",
        A05,
        True,
        """
import Foundation
import SQLite3

final class UserStore {
    private var db: OpaquePointer?

    func delete(name: String) {
        let sql = "DELETE FROM users WHERE name = '\\(name)'"
        sqlite3_exec(db, sql, nil, nil, nil)
    }
}
""",
    )
    case(
        "sw-sqli-bound",
        "swift/SqliBound.swift",
        "sqlite3_prepare_v2(",
        "CWE-89",
        A05,
        False,
        """
import Foundation
import SQLite3

final class UserStore {
    private var db: OpaquePointer?

    func delete(name: String) {
        var stmt: OpaquePointer?
        sqlite3_prepare_v2(db, "DELETE FROM users WHERE name = ?", -1, &stmt, nil)
        sqlite3_bind_text(stmt, 1, name, -1, nil)
        sqlite3_step(stmt)
        sqlite3_finalize(stmt)
    }
}
""",
    )
    case(
        "sw-tls-trustall",
        "swift/TrustAll.swift",
        "useCredential",
        "CWE-295",
        A04,
        True,
        """
import Foundation

final class Loader: NSObject, URLSessionDelegate {
    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        guard let trust = challenge.protectionSpace.serverTrust else {
            completionHandler(.performDefaultHandling, nil)
            return
        }
        completionHandler(.useCredential, URLCredential(trust: trust))
    }
}
""",
    )
    case(
        "sw-tls-default",
        "swift/TlsDefault.swift",
        "URLSession.shared",
        "CWE-295",
        A04,
        False,
        """
import Foundation

struct Api {
    func fetch(path: String) async throws -> Data {
        let url = URL(string: "https://api.example.com")!.appendingPathComponent(path)
        let (data, _) = try await URLSession.shared.data(from: url)
        return data
    }
}
""",
    )
    case(
        "sw-defaults-password",
        "swift/DefaultsPassword.swift",
        "UserDefaults.standard.set(",
        "CWE-312",
        A04,
        True,
        """
import Foundation

final class Login {
    func remember(user: String, password: String) {
        UserDefaults.standard.set(user, forKey: "user")
        UserDefaults.standard.set(password, forKey: "password")
    }
}
""",
    )
    case(
        "sw-keychain",
        "swift/Keychain.swift",
        "SecItemAdd(",
        "CWE-312",
        A04,
        False,
        """
import Foundation
import Security

final class Login {
    func remember(user: String, password: String) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: user,
            kSecValueData as String: Data(password.utf8),
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        ]
        SecItemAdd(query as CFDictionary, nil)
    }
}
""",
    )
    case(
        "sw-md5-password",
        "swift/Md5Password.swift",
        "CC_MD5(",
        "CWE-327",
        A04,
        True,
        """
import CommonCrypto
import Foundation

enum Passwords {
    static func hash(_ password: String) -> String {
        var digest = [UInt8](repeating: 0, count: Int(CC_MD5_DIGEST_LENGTH))
        let data = Array(password.utf8)
        CC_MD5(data, CC_LONG(data.count), &digest)
        return digest.map { String(format: "%02x", $0) }.joined()
    }
}
""",
    )
    case(
        "sw-md5-cachekey",
        "swift/Md5CacheKey.swift",
        "CC_MD5(",
        "CWE-327",
        A04,
        False,
        """
import CommonCrypto
import Foundation

enum ImageCache {
    static func key(for url: URL) -> String {
        var digest = [UInt8](repeating: 0, count: Int(CC_MD5_DIGEST_LENGTH))
        let data = Array(url.absoluteString.utf8)
        CC_MD5(data, CC_LONG(data.count), &digest)
        return digest.map { String(format: "%02x", $0) }.joined()
    }
}
""",
    )
    case(
        "sw-process-shell",
        "swift/ProcessShell.swift",
        "Process()",
        "CWE-78",
        A05,
        True,
        """
import Foundation

func lookup(host: String) -> String {
    let task = Process()
    task.executableURL = URL(fileURLWithPath: "/bin/sh")
    task.arguments = ["-c", "dig +short " + host]
    let pipe = Pipe()
    task.standardOutput = pipe
    try? task.run()
    return String(data: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
}
""",
    )
    case(
        "sw-process-fixed",
        "swift/ProcessFixed.swift",
        "Process()",
        "CWE-78",
        A05,
        False,
        """
import Foundation

func osVersion() -> String {
    let task = Process()
    task.executableURL = URL(fileURLWithPath: "/usr/bin/sw_vers")
    task.arguments = ["-productVersion"]
    let pipe = Pipe()
    task.standardOutput = pipe
    try? task.run()
    return String(data: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
}
""",
    )
    case(
        "sw-hardcoded-token",
        "swift/HardcodedToken.swift",
        "let apiToken",
        "CWE-798",
        A07,
        True,
        """
import Foundation

enum Backend {
    static let apiToken = "sk_live_51NfQ2dHx7Yb3KpLm9TzVwR4uJ8aXcE0q"

    static func request(_ path: String) -> URLRequest {
        var req = URLRequest(url: URL(string: "https://api.example.com/" + path)!)
        req.setValue("Bearer " + apiToken, forHTTPHeaderField: "Authorization")
        return req
    }
}
""",
    )
    case(
        "sw-token-keychain-read",
        "swift/TokenFromKeychain.swift",
        "SecItemCopyMatching(",
        "CWE-798",
        A07,
        False,
        """
import Foundation
import Security

enum Backend {
    static func token() -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: "api-token",
            kSecReturnData as String: true,
        ]
        var item: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess,
              let data = item as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }
}
""",
    )

    # ------------------------------------------------------------------------------- Dart
    case(
        "dart-sqli-interp",
        "dart/sqli_interp.dart",
        "rawQuery(",
        "CWE-89",
        A05,
        True,
        """
import 'package:sqflite/sqflite.dart';

class UserRepo {
  UserRepo(this.db);
  final Database db;

  Future<List<Map<String, Object?>>> byName(String name) {
    return db.rawQuery("SELECT * FROM users WHERE name = '$name'");
  }
}
""",
    )
    case(
        "dart-sqli-args",
        "dart/sqli_args.dart",
        "rawQuery(",
        "CWE-89",
        A05,
        False,
        """
import 'package:sqflite/sqflite.dart';

class UserRepo {
  UserRepo(this.db);
  final Database db;

  Future<List<Map<String, Object?>>> byName(String name) {
    return db.rawQuery('SELECT * FROM users WHERE name = ?', [name]);
  }
}
""",
    )
    case(
        "dart-tls-badcert",
        "dart/bad_cert.dart",
        "badCertificateCallback",
        "CWE-295",
        A04,
        True,
        """
import 'dart:io';

HttpClient makeClient() {
  final client = HttpClient();
  client.badCertificateCallback = (X509Certificate cert, String host, int port) => true;
  return client;
}
""",
    )
    case(
        "dart-tls-default",
        "dart/tls_default.dart",
        "HttpClient()",
        "CWE-295",
        A04,
        False,
        """
import 'dart:convert';
import 'dart:io';

Future<String> fetch(Uri uri) async {
  final client = HttpClient();
  final req = await client.getUrl(uri);
  final res = await req.close();
  return res.transform(utf8.decoder).join();
}
""",
    )
    case(
        "dart-prefs-password",
        "dart/prefs_password.dart",
        "setString('password'",
        "CWE-312",
        A04,
        True,
        """
import 'package:shared_preferences/shared_preferences.dart';

Future<void> remember(String user, String password) async {
  final prefs = await SharedPreferences.getInstance();
  await prefs.setString('user', user);
  await prefs.setString('password', password);
}
""",
    )
    case(
        "dart-secure-storage",
        "dart/secure_storage.dart",
        "FlutterSecureStorage(",
        "CWE-312",
        A04,
        False,
        """
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

Future<void> remember(String user, String token) async {
  const storage = FlutterSecureStorage();
  await storage.write(key: 'user', value: user);
  await storage.write(key: 'token', value: token);
}
""",
    )
    case(
        "dart-md5-password",
        "dart/md5_password.dart",
        "md5.convert(",
        "CWE-327",
        A04,
        True,
        """
import 'dart:convert';
import 'package:crypto/crypto.dart';

String hashPassword(String password) {
  return md5.convert(utf8.encode(password)).toString();
}
""",
    )
    case(
        "dart-md5-cachekey",
        "dart/md5_cachekey.dart",
        "md5.convert(",
        "CWE-327",
        A04,
        False,
        """
import 'dart:convert';
import 'package:crypto/crypto.dart';

String cacheKey(Uri url) {
  return md5.convert(utf8.encode(url.toString())).toString();
}
""",
    )
    case(
        "dart-process-shell",
        "dart/process_shell.dart",
        "Process.run(",
        "CWE-78",
        A05,
        True,
        """
import 'dart:io';

Future<String> resolve(String host) async {
  final result = await Process.run('sh', ['-c', 'dig +short ' + host]);
  return result.stdout as String;
}
""",
    )
    case(
        "dart-process-fixed",
        "dart/process_fixed.dart",
        "Process.run(",
        "CWE-78",
        A05,
        False,
        """
import 'dart:io';

Future<String> kernelVersion() async {
  final result = await Process.run('uname', ['-r']);
  return (result.stdout as String).trim();
}
""",
    )
    case(
        "dart-hardcoded-key",
        "dart/hardcoded_key.dart",
        "Key.fromUtf8(",
        "CWE-798",
        A04,
        True,
        """
import 'package:encrypt/encrypt.dart';

String seal(String plain) {
  final key = Key.fromUtf8('7f3c9a1d5b8e2f406a9c1d3e5b7f8a2c');
  final iv = IV.fromLength(16);
  return Encrypter(AES(key, mode: AESMode.gcm)).encrypt(plain, iv: iv).base64;
}
""",
    )
    case(
        "dart-key-from-storage",
        "dart/key_from_storage.dart",
        "storage.read(",
        "CWE-798",
        A04,
        False,
        """
import 'package:encrypt/encrypt.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

Future<String> seal(String plain) async {
  const storage = FlutterSecureStorage();
  final raw = await storage.read(key: 'vault-key');
  final key = Key.fromBase64(raw!);
  final iv = IV.fromSecureRandom(12);
  return Encrypter(AES(key, mode: AESMode.gcm)).encrypt(plain, iv: iv).base64;
}
""",
    )
    case(
        "dart-random-token",
        "dart/random_token.dart",
        "Random(",
        "CWE-338",
        A04,
        True,
        """
import 'dart:math';

String newSessionToken() {
  final rnd = Random(DateTime.now().millisecondsSinceEpoch);
  return List.generate(32, (_) => rnd.nextInt(16).toRadixString(16)).join();
}
""",
    )
    case(
        "dart-secure-random",
        "dart/secure_random.dart",
        "Random.secure(",
        "CWE-338",
        A04,
        False,
        """
import 'dart:math';

String newSessionToken() {
  final rnd = Random.secure();
  return List.generate(32, (_) => rnd.nextInt(16).toRadixString(16)).join();
}
""",
    )
