package com.example

import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.http.SslError
import android.webkit.SslErrorHandler
import android.webkit.WebView
import android.webkit.WebViewClient

class MoreCases(private val context: Context) {

    fun keyCases() {
        // ruleid: gapscan.kotlin.weak-key-length
        generator.initialize(1024, SecureRandom())
        // ruleid: gapscan.kotlin.weak-key-length
        keyGen.init(64)
        // ok: gapscan.kotlin.weak-key-length
        generator.initialize(2048, SecureRandom())
        // ok: gapscan.kotlin.weak-key-length
        keyGen.init(256)
    }

    fun webViewCases(webView: WebView) {
        webView.webViewClient = object : WebViewClient() {
            override fun onReceivedSslError(view: WebView, handler: SslErrorHandler, error: SslError) {
                // ruleid: gapscan.kotlin.webview-ssl-error-ignored
                handler.proceed()
            }
        }
        webView.webViewClient = object : WebViewClient() {
            override fun onReceivedSslError(view: WebView?, handler: SslErrorHandler?, error: SslError?) {
                // ruleid: gapscan.kotlin.webview-ssl-error-ignored
                handler?.proceed()
            }
        }
        webView.webViewClient = object : WebViewClient() {
            // ok: gapscan.kotlin.webview-ssl-error-ignored
            override fun onReceivedSslError(view: WebView, handler: SslErrorHandler, error: SslError) {
                handler.cancel()
            }
        }
        // ruleid: gapscan.kotlin.webview-file-access
        webView.settings.allowFileAccess = true
        // ok: gapscan.kotlin.webview-file-access
        webView.settings.allowFileAccess = false
    }

    fun storageCases() {
        // ruleid: gapscan.kotlin.external-storage-use
        val dir = context.getExternalFilesDir(null)
        // ok: gapscan.kotlin.external-storage-use
        val internal = context.filesDir
        // ruleid: gapscan.kotlin.world-accessible-file
        context.openFileOutput("a.txt", Context.MODE_WORLD_READABLE)
        // ok: gapscan.kotlin.world-accessible-file
        context.openFileOutput("b.txt", Context.MODE_PRIVATE)
        // ruleid: gapscan.kotlin.strictmode-penalty-log
        builder.penaltyLog()
        // ruleid: gapscan.kotlin.ui-cache-enabled
        view.isDrawingCacheEnabled = true
    }

    fun intentCases() {
        // ruleid: gapscan.kotlin.pendingintent-mutable
        PendingIntent.getActivity(context, 0, intent, PendingIntent.FLAG_UPDATE_CURRENT)
        // ok: gapscan.kotlin.pendingintent-mutable
        PendingIntent.getActivity(context, 0, intent, PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
        // ruleid: gapscan.kotlin.implicit-intent-sensitive-extra
        val leaky = Intent().apply {
            action = "com.example.SHOW"
            putExtra("session_token", "abc")
        }
        // ok: gapscan.kotlin.implicit-intent-sensitive-extra
        val safe = Intent().apply {
            setPackage("com.example")
            putExtra("session_token", "abc")
        }
    }

    fun deserialize(input: java.io.InputStream) {
        // ruleid: gapscan.kotlin.unsafe-deserialization
        val o = ObjectInputStream(input).readObject()
    }

    fun deepLink(intent: Intent) {
        // ruleid: gapscan.kotlin.deeplink-data-used
        val data = intent?.data
    }
}

class StudentProvider : ContentProvider() {
    override fun query(uri: Uri, projection: Array<String>?, selection: String?, selectionArgs: Array<String>?, sortOrder: String?): Cursor? {
        val qb = SQLiteQueryBuilder()
        // ruleid: gapscan.kotlin.provider-sql-injection
        return qb.query(db, projection, selection, selectionArgs, null, null, sortOrder)
    }
}

class InputCases(private val context: Context) {
    fun cases(db: SQLiteDatabase, usr: String, pwd: String, editor: SharedPreferences.Editor, input: EditText) {
        // ruleid: gapscan.kotlin.log-user-input
        Log.e("tag", "Error with card " + input.text.toString())
        // ok: gapscan.kotlin.log-user-input
        Log.e("tag", "Error")
        // ruleid: gapscan.kotlin.prefs-user-input
        editor.putString("k", input.text.toString())
        // ruleid: gapscan.kotlin.credentials-in-database
        db.execSQL("INSERT INTO myuser VALUES ('" + usr + "', '" + pwd + "');")
        // ok: gapscan.kotlin.credentials-in-database
        db.execSQL("INSERT INTO settings VALUES ('theme', 'dark');")
    }
}
