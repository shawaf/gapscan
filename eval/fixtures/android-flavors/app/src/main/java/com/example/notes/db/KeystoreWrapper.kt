package com.example.notes.db

import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

object KeystoreWrapper {
    private const val ALIAS = "notes-db-key"

    fun storedKey(): Pair<ByteArray, ByteArray> = Prefs.wrappedKey()

    fun unwrap(stored: Pair<ByteArray, ByteArray>): ByteArray {
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val key = keyStore.getKey(ALIAS, null) as SecretKey
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, stored.first))
        return cipher.doFinal(stored.second)
    }
}
