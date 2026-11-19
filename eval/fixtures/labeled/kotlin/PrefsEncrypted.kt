package app.auth

import android.content.Context
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

class Session(private val ctx: Context) {
    fun remember(user: String, token: String) {
        val key = MasterKey.Builder(ctx).setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build()
        val prefs = EncryptedSharedPreferences.create(
            ctx, "auth", key,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
        )
        prefs.edit().putString("user", user).putString("token", token).apply()
    }
}
