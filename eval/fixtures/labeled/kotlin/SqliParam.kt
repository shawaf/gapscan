package app.data

import android.database.sqlite.SQLiteDatabase

class UserDao(private val db: SQLiteDatabase) {
    fun findByName(name: String): List<String> {
        val out = mutableListOf<String>()
        val c = db.rawQuery("SELECT email FROM users WHERE name = ?", arrayOf(name))
        while (c.moveToNext()) out.add(c.getString(0))
        c.close()
        return out
    }
}
