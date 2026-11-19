import Foundation
import SQLite3

final class UserStore {
    private var db: OpaquePointer?

    func delete(name: String) {
        let sql = "DELETE FROM users WHERE name = '\(name)'"
        sqlite3_exec(db, sql, nil, nil, nil)
    }
}
