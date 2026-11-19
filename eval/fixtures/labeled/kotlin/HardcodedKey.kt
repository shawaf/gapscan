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
