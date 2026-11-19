import 'package:shared_preferences/shared_preferences.dart';

Future<void> remember(String user, String password) async {
  final prefs = await SharedPreferences.getInstance();
  await prefs.setString('user', user);
  await prefs.setString('password', password);
}
