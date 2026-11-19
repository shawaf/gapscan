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
