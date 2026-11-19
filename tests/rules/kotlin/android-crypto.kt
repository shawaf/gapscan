package com.example

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.biometric.BiometricPrompt
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.PBEKeySpec

class AuthCases(private val biometricPrompt: BiometricPrompt, private val cipher: Cipher) {
    fun unlock(info: BiometricPrompt.PromptInfo) {
        // ruleid: gapscan.kotlin.biometric-without-crypto-object
        biometricPrompt.authenticate(info)
        // ok: gapscan.kotlin.biometric-without-crypto-object
        biometricPrompt.authenticate(info, BiometricPrompt.CryptoObject(cipher))
        // ok: gapscan.kotlin.biometric-without-crypto-object
        session.authenticate(info)
    }

    fun keySpec(alias: String): KeyGenParameterSpec {
        return KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT)
            // ruleid: gapscan.kotlin.keystore-key-auth-weakened
            .setUserAuthenticationRequired(false)
            // ruleid: gapscan.kotlin.keystore-key-auth-weakened
            .setInvalidatedByBiometricEnrollment(false)
            // ok: gapscan.kotlin.keystore-key-auth-weakened
            .setUserAuthenticationRequired(true)
            // ruleid: gapscan.kotlin.keystore-randomized-encryption-off
            .setRandomizedEncryptionRequired(false)
            // ok: gapscan.kotlin.keystore-randomized-encryption-off
            .setRandomizedEncryptionRequired(true)
            .build()
    }
}

class CryptoCases {
    fun ivs(key: javax.crypto.SecretKey) {
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        // ruleid: gapscan.kotlin.static-iv
        cipher.init(Cipher.ENCRYPT_MODE, key, IvParameterSpec(ByteArray(16)))
        // ruleid: gapscan.kotlin.static-iv
        cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, byteArrayOf(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12)))
        val fixed = byteArrayOf(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15)
        // ruleid: gapscan.kotlin.static-iv
        val spec = IvParameterSpec(fixed)
        val iv = ByteArray(12)
        SecureRandom().nextBytes(iv)
        // ok: gapscan.kotlin.static-iv
        val good = GCMParameterSpec(128, iv)
    }

    fun decrypt(blob: ByteArray) {
        val iv = ByteArray(16)
        System.arraycopy(blob, 0, iv, 0, 16)
        // ok: gapscan.kotlin.static-iv
        val spec = IvParameterSpec(iv)
    }

    fun seeds() {
        // ruleid: gapscan.kotlin.securerandom-fixed-seed
        val a = SecureRandom("seed".toByteArray())
        val b = SecureRandom()
        // ruleid: gapscan.kotlin.securerandom-fixed-seed
        b.setSeed(42L)
        // ruleid: gapscan.kotlin.securerandom-fixed-seed
        b.setSeed(System.currentTimeMillis())
        // ok: gapscan.kotlin.securerandom-fixed-seed
        b.setSeed(b.generateSeed(32))
        // ok: gapscan.kotlin.securerandom-fixed-seed
        val c = SecureRandom()
    }

    fun rsa() {
        // ruleid: gapscan.kotlin.rsa-without-oaep
        Cipher.getInstance("RSA")
        // ruleid: gapscan.kotlin.rsa-without-oaep
        Cipher.getInstance("RSA/ECB/PKCS1Padding")
        // ok: gapscan.kotlin.rsa-without-oaep
        Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")
    }

    fun derive(password: CharArray, salt: ByteArray) {
        // ruleid: gapscan.kotlin.pbkdf-low-iterations
        PBEKeySpec(password, salt, 1000, 256)
        // ruleid: gapscan.kotlin.pbkdf-low-iterations
        PBEKeySpec(password, salt, 10_000, 256)
        // ok: gapscan.kotlin.pbkdf-low-iterations
        PBEKeySpec(password, salt, 310_000, 256)
        // ok: gapscan.kotlin.pbkdf-low-iterations
        PBEKeySpec(password, salt, ITERATIONS, 256)
    }
}
