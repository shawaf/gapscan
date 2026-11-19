import 'dart:io';

HttpClient makeClient() {
  final client = HttpClient();
  client.badCertificateCallback = (X509Certificate cert, String host, int port) => true;
  return client;
}
