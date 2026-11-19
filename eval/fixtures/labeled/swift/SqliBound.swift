import Foundation
import SQLite3

final class UserStore {
    private var db: OpaquePointer?

    func delete(name: String) {
        var stmt: OpaquePointer?
        sqlite3_prepare_v2(db, "DELETE FROM users WHERE name = ?", -1, &stmt, nil)
        sqlite3_bind_text(stmt, 1, name, -1, nil)
        sqlite3_step(stmt)
        sqlite3_finalize(stmt)
    }
}
