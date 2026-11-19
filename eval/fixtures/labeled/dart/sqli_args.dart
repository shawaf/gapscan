import 'package:sqflite/sqflite.dart';

class UserRepo {
  UserRepo(this.db);
  final Database db;

  Future<List<Map<String, Object?>>> byName(String name) {
    return db.rawQuery('SELECT * FROM users WHERE name = ?', [name]);
  }
}
