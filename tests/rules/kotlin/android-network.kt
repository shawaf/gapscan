package com.example

import android.util.Log
import android.webkit.WebSettings
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import javax.net.ssl.SSLContext
import javax.net.ssl.X509TrustManager
import javax.xml.parsers.DocumentBuilderFactory
import okhttp3.ConnectionSpec
import okhttp3.OkHttpClient
import okhttp3.TlsVersion

class LoggingTrustManager : X509TrustManager {
    // ruleid: gapscan.kotlin.trust-manager-never-rejects
    override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {
        Log.d("tls", "server presented ${chain.size} certificates")
    }
    override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}
    override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
}

class SwallowingTrustManager(private val default: X509TrustManager) : X509TrustManager {
    // ruleid: gapscan.kotlin.trust-manager-never-rejects
    override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {
        try {
            chain[0].subjectDN
        } catch (e: Exception) {
            Log.w("tls", "ignored", e)
        }
    }
    override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}
    override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
}

class DelegatingTrustManager(private val default: X509TrustManager) : X509TrustManager {
    // ok: gapscan.kotlin.trust-manager-never-rejects
    override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {
        default.checkServerTrusted(chain, authType)
    }
    override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}
    override fun getAcceptedIssuers(): Array<X509Certificate> = default.acceptedIssuers
}

class PinningTrustManager : X509TrustManager {
    // ok: gapscan.kotlin.trust-manager-never-rejects
    override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {
        if (chain.isEmpty()) throw CertificateException("empty chain")
    }
    override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}
    override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
}

class Transport(private val settings: WebSettings) {
    fun tls() {
        // ruleid: gapscan.kotlin.weak-tls-protocol
        val old = SSLContext.getInstance("TLSv1")
        // ok: gapscan.kotlin.weak-tls-protocol
        val ctx = SSLContext.getInstance("TLS")
        val spec = ConnectionSpec.Builder(ConnectionSpec.MODERN_TLS)
            // ruleid: gapscan.kotlin.weak-tls-protocol
            .tlsVersions(TlsVersion.TLS_1_0, TlsVersion.TLS_1_2)
            .build()
        val client = OkHttpClient.Builder()
            // ruleid: gapscan.kotlin.weak-tls-protocol
            .connectionSpecs(listOf(ConnectionSpec.MODERN_TLS, ConnectionSpec.CLEARTEXT))
            .build()
        val good = OkHttpClient.Builder()
            // ok: gapscan.kotlin.weak-tls-protocol
            .connectionSpecs(listOf(ConnectionSpec.RESTRICTED_TLS))
            .build()
    }

    fun web() {
        // ruleid: gapscan.kotlin.webview-mixed-content
        settings.mixedContentMode = WebSettings.MIXED_CONTENT_ALWAYS_ALLOW
        // ok: gapscan.kotlin.webview-mixed-content
        settings.mixedContentMode = WebSettings.MIXED_CONTENT_NEVER_ALLOW
    }

    fun broadcast(context: android.content.Context, intent: android.content.Intent) {
        // ruleid: gapscan.kotlin.sticky-broadcast
        context.sendStickyBroadcast(intent)
        // ok: gapscan.kotlin.sticky-broadcast
        context.sendBroadcast(intent, "com.example.permission.SYNC")
    }
}

class Feeds {
    fun parse(input: java.io.InputStream) {
        // ruleid: gapscan.kotlin.xxe-parser-not-hardened
        val factory = DocumentBuilderFactory.newInstance()
        val doc = factory.newDocumentBuilder().parse(input)
    }

    fun parseSafely(input: java.io.InputStream) {
        // ok: gapscan.kotlin.xxe-parser-not-hardened
        val factory = DocumentBuilderFactory.newInstance()
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
        val doc = factory.newDocumentBuilder().parse(input)
    }
}
