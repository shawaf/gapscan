package app.crypto

import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

object Vault {
    fun encrypt(plain: ByteArray, iv: ByteArray): ByteArray {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val key = ks.getKey("vault-key", null) as SecretKey
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, iv))
        return c.doFinal(plain)
    }
}
