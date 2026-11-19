package com.example

import android.app.Activity
import android.content.ContentProvider
import android.content.Context
import android.content.Intent
import android.database.Cursor
import android.database.MatrixCursor
import android.net.Uri
import android.os.Parcelable
import android.provider.OpenableColumns
import android.text.InputType
import android.widget.EditText
import java.io.File

class ShareTarget : Activity() {
    fun importShared() {
        var uri = intent.getParcelableExtra<Parcelable>(Intent.EXTRA_STREAM) as Uri
        // ruleid: gapscan.kotlin.shared-uri-opened-as-file
        val f = File(uri.toString())
        val data = intent.data
        // ruleid: gapscan.kotlin.shared-uri-opened-as-file
        val g = File(data!!.path)
        // ok: gapscan.kotlin.shared-uri-opened-as-file
        val stream = contentResolver.openInputStream(uri)
        // ok: gapscan.kotlin.shared-uri-opened-as-file
        val own = File(filesDir, "notes.txt")
    }

    fun copyNamed(uri: Uri, cursor: Cursor) {
        val name = uri.lastPathSegment
        // ruleid: gapscan.kotlin.uri-name-path-traversal
        val target = File(cacheDir, name)
        val display = cursor.getString(cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME))
        // ruleid: gapscan.kotlin.uri-name-path-traversal
        val other = File(filesDir, display)
        val safeName = File(uri.lastPathSegment!!).name
        // ok: gapscan.kotlin.uri-name-path-traversal
        val safe = File(cacheDir, safeName)
        // ok: gapscan.kotlin.uri-name-path-traversal
        val fixed = File(cacheDir, "import.tmp")
    }
}

class AccountProvider : ContentProvider() {
    fun rows(user: String, pass: String): Cursor {
        // ruleid: gapscan.kotlin.provider-returns-secret
        val c = MatrixCursor(arrayOf("username", "password"))
        c.addRow(arrayOf(user, pass))
        // ok: gapscan.kotlin.provider-returns-secret
        val d = MatrixCursor(arrayOf("_id", "title"))
        return c
    }
}

class Archives {
    fun unzip(zis: java.util.zip.ZipInputStream, dest: File) {
        var entry = zis.nextEntry
        while (entry != null) {
            // ruleid: gapscan.kotlin.zip-slip
            val out = File(dest, entry.name)
            out.outputStream().use { zis.copyTo(it) }
            entry = zis.nextEntry
        }
    }

    fun unzipChecked(zis: java.util.zip.ZipInputStream, dest: File) {
        var entry = zis.nextEntry
        while (entry != null) {
            // ok: gapscan.kotlin.zip-slip
            val out = File(dest, entry.name)
            if (!out.canonicalPath.startsWith(dest.canonicalPath + File.separator)) throw SecurityException("bad entry")
            entry = zis.nextEntry
        }
    }

    fun unpack(zip: java.util.zip.ZipFile, dest: String) {
        zip.entries().asSequence().forEach { e ->
            // ruleid: gapscan.kotlin.zip-slip
            val out = File("$dest/${e.name}")
        }
    }

    fun profile(user: User, dest: File) {
        // ok: gapscan.kotlin.zip-slip
        val out = File(dest, user.name)
    }
}

class Screens(private val activity: Activity, private val webView: android.webkit.WebView) {
    fun copy(clipboard: android.content.ClipboardManager, otpCode: String, title: String, user: User) {
        // ruleid: gapscan.kotlin.clipboard-sensitive-value
        clipboard.setPrimaryClip(ClipData.newPlainText("code", otpCode))
        // ruleid: gapscan.kotlin.clipboard-sensitive-value
        clipboard.setPrimaryClip(ClipData.newPlainText("pw", user.password))
        // ok: gapscan.kotlin.clipboard-sensitive-value
        clipboard.setPrimaryClip(ClipData.newPlainText("title", title))
    }

    fun secure() {
        // ruleid: gapscan.kotlin.flag-secure-cleared
        activity.window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
        // ok: gapscan.kotlin.flag-secure-cleared
        activity.window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
    }

    fun debugging() {
        // ruleid: gapscan.kotlin.webview-debugging-enabled
        WebView.setWebContentsDebuggingEnabled(true)
        if (BuildConfig.DEBUG) {
            // ok: gapscan.kotlin.webview-debugging-enabled
            WebView.setWebContentsDebuggingEnabled(true)
        }
    }

    fun scripts(name: String) {
        // ruleid: gapscan.kotlin.webview-javascript-built
        webView.evaluateJavascript("showUser('$name')", null)
        // ruleid: gapscan.kotlin.webview-javascript-built
        webView.loadUrl("javascript:render('" + name + "')")
        // ok: gapscan.kotlin.webview-javascript-built
        webView.evaluateJavascript("refresh()", null)
    }
}

object Config {
    // ruleid: gapscan.kotlin.hardcoded-secret
    const val STRIPE_SECRET_KEY = "sk_live_51Hc2xYz8a9QwErTy"
    // ruleid: gapscan.kotlin.hardcoded-secret
    val mapsKey = "AIzaSyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q"
    // ok: gapscan.kotlin.hardcoded-secret
    val apiKeyHeader = "X-Api-Key"
    // ok: gapscan.kotlin.hardcoded-secret
    val passwordHint = "your-password-here-1"
}

class SignUpForm(private val context: Context) {
    fun fields() {
        val a = EditText(context).apply {
            // ruleid: gapscan.kotlin.password-field-keyboard-cache
            hint = "Enter password"
            inputType = InputType.TYPE_CLASS_TEXT
        }
        val b = EditText(context).apply {
            // ok: gapscan.kotlin.password-field-keyboard-cache
            hint = "Enter password"
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
        }
        val c = EditText(context).apply {
            // ok: gapscan.kotlin.password-field-keyboard-cache
            hint = "Your name"
            inputType = InputType.TYPE_CLASS_TEXT
        }
    }
}
