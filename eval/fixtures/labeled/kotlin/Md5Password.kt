package app.auth

import java.security.MessageDigest

object Passwords {
    fun hash(password: String): String {
        val md = MessageDigest.getInstance("MD5")
        return md.digest(password.toByteArray()).joinToString("") { "%02x".format(it) }
    }
}
