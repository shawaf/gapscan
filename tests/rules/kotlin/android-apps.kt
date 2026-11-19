package com.example

import android.content.Context
import android.content.Intent
import javax.net.ssl.HostnameVerifier
import javax.net.ssl.SSLSession

class AppCases {
    fun commands(input: String) {
        val runtime = Runtime.getRuntime()
        // ruleid: gapscan.kotlin.command-from-variable
        runtime.exec(input)
        // ruleid: gapscan.kotlin.command-from-variable
        ProcessBuilder(input)
        // ok: gapscan.kotlin.command-from-variable
        runtime.exec("uptime")
    }

    fun loading(clazz: String) {
        // ruleid: gapscan.kotlin.dynamic-code-loading
        Class.forName(clazz)
        // ruleid: gapscan.kotlin.dynamic-code-loading
        System.loadLibrary(clazz)
        // ok: gapscan.kotlin.dynamic-code-loading
        Class.forName("com.example.Known")
        // ok: gapscan.kotlin.dynamic-code-loading
        System.loadLibrary("native-lib")
    }

    fun client(builder: OkHttpClient.Builder) {
        // ruleid: gapscan.kotlin.hostname-verifier-accepts-all
        builder.hostnameVerifier { hostname, session -> true }
        // ruleid: gapscan.kotlin.hostname-verifier-accepts-all
        HttpsURLConnection.setDefaultHostnameVerifier { _, _ -> true }
        // ruleid: gapscan.kotlin.hostname-verifier-accepts-all
        val v = NoopHostnameVerifier.INSTANCE
        // ruleid: gapscan.kotlin.hostname-verifier-accepts-all
        connection.setHostnameVerifier(SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER)
        // ok: gapscan.kotlin.hostname-verifier-accepts-all
        HttpsURLConnection.setDefaultHostnameVerifier { host, session -> host == "api.example.com" }
        // ruleid: gapscan.kotlin.http-redirects-followed
        builder.followRedirects(true)
        // ok: gapscan.kotlin.http-redirects-followed
        builder.followRedirects(false)
    }

    fun logging(password: String, authToken: String, message: String) {
        // ruleid: gapscan.kotlin.log-secret-variable
        Log.d("tag", password)
        // ruleid: gapscan.kotlin.log-secret-variable
        logger.info(authToken)
        // ok: gapscan.kotlin.log-secret-variable
        Log.d("tag", message)
        // ruleid: gapscan.kotlin.log-secret-variable
        Timber.d("unlocking with $userPin")
        // ok: gapscan.kotlin.log-secret-variable
        Timber.d("Wakelock timeout reached, stopping service")
        // ok: gapscan.kotlin.log-secret-variable
        Timber.e(message, "Failed to unpin event ${message.length}")
        // ok: gapscan.kotlin.log-secret-variable
        Timber.w("Unable to get userId from client secret")
    }
}

class CustomVerifier : HostnameVerifier {
    // ruleid: gapscan.kotlin.hostname-verifier-accepts-all
    override fun verify(hostname: String?, session: SSLSession?): Boolean {
        return true
    }
}

class ChooserLike : android.app.Activity() {
    fun launch(context: Context, receiver: android.content.BroadcastReceiver, filter: android.content.IntentFilter) {
        // ruleid: gapscan.kotlin.embedded-intent-started
        startActivity(intent.getParcelableExtra<Intent>("extra_intent"))
        // ruleid: gapscan.kotlin.dynamic-receiver-exported
        registerReceiver(receiver, filter)
        // ok: gapscan.kotlin.dynamic-receiver-exported
        registerReceiver(receiver, filter, Context.RECEIVER_NOT_EXPORTED)
    }
}

class Redirects : android.app.Activity() {
    fun forward() {
        val next = intent.getParcelableExtra<Intent>("next")
        // ruleid: gapscan.kotlin.embedded-intent-started
        startService(next)
        // ruleid: gapscan.kotlin.embedded-intent-started
        setResult(RESULT_OK, intent.getParcelableExtra("result"))
        val parsed = Intent.parseUri(intent.getStringExtra("uri"), Intent.URI_INTENT_SCHEME)
        // ruleid: gapscan.kotlin.embedded-intent-started
        sendBroadcast(parsed)
        // ok: gapscan.kotlin.embedded-intent-started
        startActivity(Intent(this, ShareTarget::class.java))
    }

}
