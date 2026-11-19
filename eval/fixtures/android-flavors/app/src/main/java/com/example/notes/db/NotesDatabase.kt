package com.example.notes.db

import android.content.Context
import net.zetetic.database.sqlcipher.SQLiteDatabase

object NotesDatabase {
    fun open(context: Context): SQLiteDatabase {
        val file = context.getDatabasePath("notes.db")
        return SQLiteDatabase.openOrCreateDatabase(file, DatabaseKeyManager.passphrase(), null, null)
    }
}
