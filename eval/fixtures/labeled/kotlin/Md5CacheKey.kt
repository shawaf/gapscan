package app.cache

import java.security.MessageDigest

object ImageCache {
    fun keyFor(url: String): String {
        val md = MessageDigest.getInstance("MD5")
        return md.digest(url.toByteArray()).joinToString("") { "%02x".format(it) }
    }
}
