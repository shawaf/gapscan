import 'dart:math';

String newSessionToken() {
  final rnd = Random(DateTime.now().millisecondsSinceEpoch);
  return List.generate(32, (_) => rnd.nextInt(16).toRadixString(16)).join();
}
