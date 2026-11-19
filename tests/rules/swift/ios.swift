import Foundation
import CommonCrypto
import CryptoKit
import SQLite3

final class Cases: NSObject, URLSessionDelegate {
    // --- sqli
    func sqlBad(db: OpaquePointer?, name: String) {
        // ruleid: gapscan.swift.sqli-interpolated
        sqlite3_exec(db, "DELETE FROM users WHERE name = '\(name)'", nil, nil, nil)
    }
    func sqlOk(db: OpaquePointer?, name: String) {
        var stmt: OpaquePointer?
        // ok: gapscan.swift.sqli-interpolated
        sqlite3_prepare_v2(db, "DELETE FROM users WHERE name = ?", -1, &stmt, nil)
        sqlite3_bind_text(stmt, 1, name, -1, nil)
    }

    // --- tls
    // ruleid: gapscan.swift.tls-trust-all
    func urlSession(_ s: URLSession, didReceive c: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        guard let trust = c.protectionSpace.serverTrust else { return }
        completionHandler(.useCredential, URLCredential(trust: trust))
    }
    func urlSessionOk(_ s: URLSession, didReceive c: URLAuthenticationChallenge,
                      completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        guard let trust = c.protectionSpace.serverTrust, SecTrustEvaluateWithError(trust, nil) else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        // ok: gapscan.swift.tls-trust-all
        completionHandler(.useCredential, URLCredential(trust: trust))
    }

    // --- defaults
    func defaultsBad(_ pw: String) {
        // ruleid: gapscan.swift.userdefaults-sensitive-value
        UserDefaults.standard.set(pw, forKey: "password")
        // ruleid: gapscan.swift.userdefaults-sensitive-value
        UserDefaults.standard.set(pw, forKey: "authToken")
    }
    func defaultsOk(_ v: String) {
        // ok: gapscan.swift.userdefaults-sensitive-value
        UserDefaults.standard.set(v, forKey: "theme")
    }

    // --- crypto
    func cryptoBad(_ d: [UInt8]) {
        var out = [UInt8](repeating: 0, count: 16)
        // ruleid: gapscan.swift.weak-crypto
        CC_MD5(d, CC_LONG(d.count), &out)
        // ruleid: gapscan.swift.weak-crypto
        _ = Insecure.SHA1.hash(data: Data(d))
    }
    func cryptoOk(_ d: Data) {
        // ok: gapscan.swift.weak-crypto
        _ = SHA256.hash(data: d)
    }

    // --- command
    func shellBad(host: String) {
        let task = Process()
        // ruleid: gapscan.swift.command-string-built
        task.arguments = ["-c", "dig +short " + host]
        // ruleid: gapscan.swift.command-string-built
        task.arguments = ["-c", "ping \(host)"]
    }
    func shellOk() {
        let task = Process()
        // ok: gapscan.swift.command-string-built
        task.arguments = ["-productVersion"]
    }

    // --- secrets
    // ruleid: gapscan.swift.hardcoded-secret
    static let apiToken = "AbCdEf0123456789XyZ"
    // ok: gapscan.swift.hardcoded-secret
    static let apiTokenHeader = "Authorization"

    // --- randomness
    // ruleid: gapscan.swift.insecure-random-for-secret
    func newSessionToken() -> Int {
        return Int(random())
    }
    // ok: gapscan.swift.insecure-random-for-secret
    func pickColor() -> Int {
        return Int(random())
    }

    // --- web view
    func jsBad(_ w: WKWebView, name: String) {
        // ruleid: gapscan.swift.webview-js-injection
        w.evaluateJavaScript("setUser('\(name)')")
    }
    func jsOk(_ w: WKWebView) {
        // ok: gapscan.swift.webview-js-injection
        w.evaluateJavaScript("refresh()")
    }

    // --- logging
    func logBad(token: String) {
        // ruleid: gapscan.swift.log-sensitive-value
        print("token is \(token) password")
    }
    func logOk(count: Int) {
        // ok: gapscan.swift.log-sensitive-value
        print("synced \(count) items")
        // ok: gapscan.swift.log-sensitive-value
        print("Password login supported: \(count)")
        // ruleid: gapscan.swift.log-sensitive-value
        print(authToken)
        // ruleid: gapscan.swift.log-sensitive-value
        NSLog("User logged in with %@", passwordField.text!)
        // ruleid: gapscan.swift.log-sensitive-value
        print("Credentials:", username, password)
        // ok: gapscan.swift.log-sensitive-value
        NSLog("Password reset requested for %@", username)
    }

    // --- http
    func httpBad() {
        // ruleid: gapscan.swift.cleartext-http-url
        _ = URL(string: "http://api.example.com/v1")
        // ruleid: gapscan.swift.cleartext-http-url
        _ = URL(string: "http://" + host + "/login")
    }
    // ruleid: gapscan.swift.cleartext-http-url
    static let baseURL = "http://api.example.com"
    // ok: gapscan.swift.cleartext-http-url
    static let secureBaseURL = "https://api.example.com"
    // ok: gapscan.swift.cleartext-http-url
    static let devServer = "http://192.168.1.10:8080"
    func httpOk() {
        // ok: gapscan.swift.cleartext-http-url
        _ = URL(string: "https://api.example.com/v1")
        // ok: gapscan.swift.cleartext-http-url
        _ = URL(string: "http://localhost:8080/dev")
    }

    // --- keychain
    func keychainBad() -> [String: Any] {
        // ruleid: gapscan.swift.keychain-accessible-always
        return [kSecAttrAccessible as String: kSecAttrAccessibleAlways]
    }
    func keychainOk() -> [String: Any] {
        // ok: gapscan.swift.keychain-accessible-always
        return [kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly]
    }
}

// --- trust-all handler in a WKNavigationDelegate, with a comment that mentions SecTrustEvaluateWithError ---
class Delegate: NSObject, WKNavigationDelegate {
    // ruleid: gapscan.swift.tls-trust-all
    func webView(_ webView: WKWebView, didReceive challenge: URLAuthenticationChallenge,
                 completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        // FAIL: no check, SecTrustEvaluateWithError is not called here
        guard let serverTrust = challenge.protectionSpace.serverTrust else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        completionHandler(.useCredential, URLCredential(trust: serverTrust))
    }
}

class SafeDelegate: NSObject, WKNavigationDelegate {
    // ok: gapscan.swift.tls-trust-all
    func webView(_ webView: WKWebView, didReceive challenge: URLAuthenticationChallenge,
                 completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        guard let serverTrust = challenge.protectionSpace.serverTrust,
              SecTrustEvaluateWithError(serverTrust, nil) else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        completionHandler(.useCredential, URLCredential(trust: serverTrust))
    }
}

