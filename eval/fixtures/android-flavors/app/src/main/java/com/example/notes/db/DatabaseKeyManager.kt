package com.example.notes.db

import com.example.notes.BuildConfig

object DatabaseKeyManager {
    // Legacy passphrase, kept so databases created before 2.0 still open.
    private const val LEGACY_DB_PASSWORD = "n0tes-legacy-passphrase-2019"

    fun passphrase(): ByteArray {
        if (!BuildConfig.ENCRYPT_DB) {
            return LEGACY_DB_PASSWORD.toByteArray()
        }
        return KeystoreWrapper.unwrap(KeystoreWrapper.storedKey())
    }
}
