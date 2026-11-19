package app.test

import android.database.sqlite.SQLiteDatabase
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec

class Cases(private val db: SQLiteDatabase) {
    // --- sqli
    fun sqlBad(name: String) {
        // ruleid: gapscan.kotlin.sqli-string-built
        db.rawQuery("SELECT * FROM users WHERE name = '" + name + "'", null)
        // ruleid: gapscan.kotlin.sqli-string-built
        db.rawQuery("SELECT * FROM users WHERE name = '$name'", null)
        // ruleid: gapscan.kotlin.sqli-string-built
        db.execSQL("DELETE FROM users WHERE name = '${name}'")
    }
    fun sqlOk(name: String) {
        // ok: gapscan.kotlin.sqli-string-built
        db.rawQuery("SELECT * FROM users WHERE name = ?", arrayOf(name))
        // ok: gapscan.kotlin.sqli-string-built
        db.execSQL("DELETE FROM users")
    }

    // --- tls
    val trustAll = object : X509TrustManager {
        override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}
        // ruleid: gapscan.kotlin.tls-trust-all
        override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {}
        override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
    }
    // ruleid: gapscan.kotlin.tls-trust-all
    val verifier = HostnameVerifier { _, _ -> true }

    // --- prefs
    fun prefsBad(p: android.content.SharedPreferences, pw: String) {
        // ruleid: gapscan.kotlin.prefs-sensitive-value
        p.edit().putString("password", pw).apply()
        // ruleid: gapscan.kotlin.prefs-sensitive-value
        p.edit().putString("auth_token", pw).apply()
        // ruleid: gapscan.kotlin.prefs-sensitive-value
        p.edit().putString(KEY_ACCESS_TOKEN, pw).apply()
        // ruleid: gapscan.kotlin.prefs-sensitive-value
        p.edit().putString(Keys.USER_PIN, pw).apply()
    }
    suspend fun dataStoreBad(store: DataStore<Preferences>, token: String) {
        store.edit { prefs ->
            // ruleid: gapscan.kotlin.prefs-sensitive-value
            prefs[stringPreferencesKey("refresh_token")] = token
        }
    }
    fun prefsOk(p: android.content.SharedPreferences, v: String) {
        // ok: gapscan.kotlin.prefs-sensitive-value
        p.edit().putString("theme", v).apply()
        // ok: gapscan.kotlin.prefs-sensitive-value
        p.edit().putString(KEY_SHIPPING_ADDRESS, v).apply()
        // ok: gapscan.kotlin.prefs-sensitive-value
        val k = stringPreferencesKey("ui_theme")
    }

    // --- crypto
    fun hashBad(s: String) {
        // ruleid: gapscan.kotlin.weak-hash
        MessageDigest.getInstance("MD5").digest(s.toByteArray())
        // ruleid: gapscan.kotlin.weak-hash
        MessageDigest.getInstance("SHA-1").digest(s.toByteArray())
    }
    fun hashOk(s: String) {
        // ok: gapscan.kotlin.weak-hash
        MessageDigest.getInstance("SHA-256").digest(s.toByteArray())
    }
    fun cipherBad() {
        // ruleid: gapscan.kotlin.weak-cipher
        Cipher.getInstance("DES/ECB/PKCS5Padding")
        // ruleid: gapscan.kotlin.weak-cipher
        Cipher.getInstance("AES")
        // ruleid: gapscan.kotlin.weak-cipher
        Cipher.getInstance("AES/ECB/PKCS5Padding")
    }
    fun cipherOk() {
        // ok: gapscan.kotlin.weak-cipher
        Cipher.getInstance("AES/GCM/NoPadding")
    }

    // --- command
    fun execBad(host: String) {
        // ruleid: gapscan.kotlin.command-string-built
        Runtime.getRuntime().exec("ping -c 1 " + host)
        // ruleid: gapscan.kotlin.command-string-built
        Runtime.getRuntime().exec("ping -c 1 $host")
        // ruleid: gapscan.kotlin.command-string-built
        ProcessBuilder("sh", "-c", "ping $host")
    }
    fun execOk() {
        // ok: gapscan.kotlin.command-string-built
        Runtime.getRuntime().exec(arrayOf("uname", "-r"))
    }

    // --- keys
    fun keyBad() {
        // ruleid: gapscan.kotlin.hardcoded-crypto-key
        SecretKeySpec("0123456789abcdef".toByteArray(), "AES")
        // ruleid: gapscan.kotlin.hardcoded-crypto-key
        SecretKeySpec(byteArrayOf(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16), "AES")
        // ruleid: gapscan.kotlin.hardcoded-crypto-key
        SecretKeySpec(Base64.decode("c2VjcmV0c2VjcmV0c2VjcmV0", Base64.DEFAULT), "AES")
    }
    fun keyOk(raw: ByteArray) {
        // ok: gapscan.kotlin.hardcoded-crypto-key
        SecretKeySpec(raw, "AES")
    }

    // --- webview
    fun webBad(w: android.webkit.WebView) {
        // ruleid: gapscan.kotlin.webview-unsafe-settings
        w.settings.allowUniversalAccessFromFileURLs = true
        // ruleid: gapscan.kotlin.webview-unsafe-settings
        w.addJavascriptInterface(Bridge(), "bridge")
        // ruleid: gapscan.kotlin.webview-load-untrusted-url
        w.loadUrl(intent.getStringExtra("url"))
    }
    fun webOk(w: android.webkit.WebView) {
        // ok: gapscan.kotlin.webview-unsafe-settings
        w.settings.allowFileAccessFromFileURLs = false
        // ok: gapscan.kotlin.webview-load-untrusted-url
        w.loadUrl("https://example.com/help")
    }

    // --- randomness
    fun newSessionToken(): Int {
        // ruleid: gapscan.kotlin.insecure-random-for-secret
        return java.util.Random().nextInt()
    }
    fun pickColor(): Int {
        // ok: gapscan.kotlin.insecure-random-for-secret
        return java.util.Random().nextInt(255)
    }

    // --- logging
    fun logBad(token: String) {
        // ruleid: gapscan.kotlin.log-sensitive-value
        Log.d("auth", "token = $token and password")
    }
    fun logOk(count: Int) {
        // ok: gapscan.kotlin.log-sensitive-value
        Log.d("sync", "synced $count items")
        // ok: gapscan.kotlin.log-sensitive-value
        Timber.w("No endpoint or gateway found for client secret")
        // ok: gapscan.kotlin.log-sensitive-value
        Log.d("auth", "Password login supported: $count")
    }

    // --- cleartext
    fun httpBad() {
        // ruleid: gapscan.kotlin.cleartext-http-url
        Request.Builder().url("http://api.example.com/v1/users")
    }
    fun httpOk() {
        // ok: gapscan.kotlin.cleartext-http-url
        Request.Builder().url("https://api.example.com/v1/users")
        // ok: gapscan.kotlin.cleartext-http-url
        Request.Builder().url("http://10.0.2.2:8080/dev")
    }
}

class WebFromIntent : android.app.Activity() {
    fun web(webView: android.webkit.WebView) {
        val target = intent.data?.getQueryParameter("url")
        // ruleid: gapscan.kotlin.webview-load-untrusted-url
        webView.loadUrl(target!!)
        val html = intent.getStringExtra("html")
        // ruleid: gapscan.kotlin.webview-load-untrusted-url
        webView.loadDataWithBaseURL(null, html!!, "text/html", "utf-8", null)
        // ok: gapscan.kotlin.webview-load-untrusted-url
        webView.loadUrl("https://example.com/help")
    }

}

class RoomQueries {
    fun rooms(db: androidx.sqlite.db.SupportSQLiteDatabase, name: String) {
        // ruleid: gapscan.kotlin.sqli-string-built
        val q = SimpleSQLiteQuery("SELECT * FROM notes WHERE title = '$name'")
        // ruleid: gapscan.kotlin.sqli-string-built
        db.query("SELECT * FROM notes WHERE owner = '" + name + "'")
        // ok: gapscan.kotlin.sqli-string-built
        val ok = SimpleSQLiteQuery("SELECT * FROM notes WHERE title = ?", arrayOf(name))
    }
}

