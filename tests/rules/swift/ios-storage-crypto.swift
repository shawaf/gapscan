import Foundation
import Security
import CryptoKit
import LocalAuthentication
import GameplayKit
import WebKit
import os

func keychainItems() -> [[String: Any]] {
    return [
        // ruleid: gapscan.swift.keychain-accessible-after-first-unlock
        [kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlock],
        // ok: gapscan.swift.keychain-accessible-after-first-unlock
        [kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly],
    ]
}

func cryptoCases(plain: Data) throws {
    // ruleid: gapscan.swift.hardcoded-symmetric-key
    let key = SymmetricKey(data: "0123456789abcdef0123456789abcdef".data(using: .utf8)!)
    // ruleid: gapscan.swift.hardcoded-symmetric-key
    let other = SymmetricKey(data: [0x01, 0x02, 0x03, 0x04])
    // ok: gapscan.swift.hardcoded-symmetric-key
    let fresh = SymmetricKey(size: .bits256)

    // ruleid: gapscan.swift.static-iv
    let iv = "abcdefghijklmnop"
    // ruleid: gapscan.swift.static-iv
    let aesIV = [UInt8](repeating: 0, count: 16)
    // ruleid: gapscan.swift.static-iv
    let nonce = try AES.GCM.Nonce(data: Data(repeating: 0, count: 12))
    // ok: gapscan.swift.static-iv
    let ivLength = 16
    // ok: gapscan.swift.static-iv
    let freshNonce = AES.GCM.Nonce()
    _ = try AES.GCM.seal(plain, using: fresh, nonce: freshNonce)
}

func keyMaterialCases() {
    // ruleid: gapscan.swift.predictable-key-material
    let encryptionKey = UIDevice.current.identifierForVendor!.uuidString
    // ruleid: gapscan.swift.predictable-key-material
    let salt = "\(Date().timeIntervalSince1970)"
    // ok: gapscan.swift.predictable-key-material
    let cacheKey = "\(path)-\(Date().timeIntervalSince1970)"
    // ok: gapscan.swift.predictable-key-material
    let freshKey = SymmetricKey(size: .bits256)
}

func randomCases() -> Int {
    // ruleid: gapscan.swift.seeded-random-source
    let seeded = GKMersenneTwisterRandomSource(seed: 42)
    // ok: gapscan.swift.seeded-random-source
    let system = Int.random(in: 0..<1_000_000)
    return seeded.nextInt() + system
}

func logCases(token: String, count: Int) {
    let logger = Logger(subsystem: "app", category: "auth")
    // ruleid: gapscan.swift.log-public-secret
    os_log("refreshed %{public}@", log: .default, type: .info, authToken)
    // ruleid: gapscan.swift.log-public-secret
    logger.info("got \(token, privacy: .public)")
    // ok: gapscan.swift.log-public-secret
    logger.info("synced \(count, privacy: .public) items")
    // ok: gapscan.swift.log-public-secret
    os_log("synced %{public}d items", log: .default, type: .info, count)
}

func trustCases() {
    // ruleid: gapscan.swift.tls-validation-disabled-config
    let manager = ServerTrustManager(evaluators: ["api.example.com": DisabledTrustEvaluator()])
    // ruleid: gapscan.swift.tls-validation-disabled-config
    let settings: [String: Any] = [kCFStreamSSLValidatesCertificateChain as String: false]
    // ok: gapscan.swift.tls-validation-disabled-config
    let pinned = ServerTrustManager(evaluators: ["api.example.com": PinnedCertificatesTrustEvaluator()])
}

func webCases(webView: WKWebView, html: String) {
    // ruleid: gapscan.swift.webview-html-file-base-url
    webView.loadHTMLString(html, baseURL: Bundle.main.bundleURL)
    // ok: gapscan.swift.webview-html-file-base-url
    webView.loadHTMLString(html, baseURL: nil)
}

func cookieCases(value: String) {
    // ruleid: gapscan.swift.persistent-session-cookie
    let persistent = HTTPCookie(properties: [
        .name: "sessionToken", .value: value, .domain: "example.com", .path: "/",
        .expires: Date().addingTimeInterval(86_400 * 30),
    ])
    // ok: gapscan.swift.persistent-session-cookie
    let sessionOnly = HTTPCookie(properties: [
        .name: "sessionToken", .value: value, .domain: "example.com", .path: "/",
    ])
}

// A biometric prompt that releases a Keychain item bound to the user's biometrics: not a boolean gate.
// (The rule looks below the call, so this safe case comes before the vulnerable one.)
final class BoundUnlock {
    func unlock() {
        let context = LAContext()
        // ok: gapscan.swift.biometric-boolean-gate
        context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: "Unlock") { success, _ in
            guard success else { return }
            let query: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecUseAuthenticationContext as String: context,
                kSecReturnData as String: true,
            ]
            var item: CFTypeRef?
            SecItemCopyMatching(query as CFDictionary, &item)
        }
    }
}

final class LoginController {
    func unlock() {
        let context = LAContext()
        // ruleid: gapscan.swift.biometric-boolean-gate
        context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: "Unlock") { success, _ in
            if success { self.showAccount() }
        }
    }
    func showAccount() {}
}
