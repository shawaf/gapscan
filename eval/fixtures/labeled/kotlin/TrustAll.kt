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
