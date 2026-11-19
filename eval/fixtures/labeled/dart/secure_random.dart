import 'dart:math';

String newSessionToken() {
  final rnd = Random.secure();
  return List.generate(32, (_) => rnd.nextInt(16).toRadixString(16)).join();
}
