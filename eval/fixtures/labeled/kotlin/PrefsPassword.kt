package app.auth

import android.content.Context

class Session(private val ctx: Context) {
    fun remember(user: String, password: String) {
        val prefs = ctx.getSharedPreferences("auth", Context.MODE_PRIVATE)
        prefs.edit().putString("user", user).putString("password", password).apply()
    }
}
