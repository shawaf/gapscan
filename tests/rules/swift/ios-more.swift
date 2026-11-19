import Foundation
import WebKit
import Security

// Databases opened with an encryption key (these come first: the rule looks below the open call for the key).
func openEncrypted(path: String, key: String) throws {
    var handle: OpaquePointer?
    // ok: gapscan.swift.database-not-encrypted
    sqlite3_open(path, &handle)
    sqlite3_key(handle, key, Int32(key.utf8.count))
    var config = DatabaseConfiguration()
    config.encryptionKey = EncryptionKey.password(key)
    // ok: gapscan.swift.database-not-encrypted
    let db = try Database(name: "notes", config: config)
}

struct MoreCases {
    func keyCases() {
        // ruleid: gapscan.swift.weak-key-size
        let weak: [String: Any] = [kSecAttrKeySizeInBits as String: 1024]
        // ok: gapscan.swift.weak-key-size
        let strong: [String: Any] = [kSecAttrKeySizeInBits as String: 2048]
    }

    func tlsCases(config: URLSessionConfiguration) {
        // ruleid: gapscan.swift.tls-min-version-lowered
        config.tlsMinimumSupportedProtocolVersion = .TLSv10
        // ok: gapscan.swift.tls-min-version-lowered
        config.tlsMinimumSupportedProtocolVersion = .TLSv13
    }

    func socketCases() {
        // ruleid: gapscan.swift.raw-socket-bypasses-ats
        let sock = socket(AF_INET, SOCK_STREAM, 0)
        // ok: gapscan.swift.raw-socket-bypasses-ats
        let task = URLSession.shared.dataTask(with: URL(string: "https://example.com")!)
    }

    func webViewCases(webView: WKWebView, url: URL, dir: URL) {
        // ruleid: gapscan.swift.webview-file-access
        webView.loadFileURL(url, allowingReadAccessTo: dir)
        // ruleid: gapscan.swift.webview-file-access
        config.preferences.setValue(true, forKey: "allowFileAccessFromFileURLs")
        // ok: gapscan.swift.webview-file-access
        webView.load(URLRequest(url: URL(string: "https://example.com")!))
    }

    func deserialize(data: Data) throws {
        // ruleid: gapscan.swift.unsafe-deserialization
        let obj = NSKeyedUnarchiver.unarchiveObject(with: data)
        // ok: gapscan.swift.unsafe-deserialization
        let safe = try NSKeyedUnarchiver.unarchivedObject(ofClasses: [NSString.self], from: data)
    }
}

struct App {
    func handlers() {
        // ruleid: gapscan.swift.url-scheme-handler-unvalidated
        .onOpenURL { url in handle(url) }
    }
}

// =================== real-app idioms ==========================================================================
// ruleid: gapscan.swift.uiwebview-used
func realApp(searchStr: String, db: OpaquePointer?, user: User, passwordTextField: UITextField, webView: UIWebView, name: String) {
    // ruleid: gapscan.swift.sql-string-interpolated
    let query = "SELECT title FROM article WHERE title LIKE '\(searchStr)' AND premium=0"
    // ok: gapscan.swift.sql-string-interpolated
    let fixed = "SELECT title FROM article WHERE title LIKE ?"
    // ruleid: gapscan.swift.hardcoded-key-literal
    var encryptionKey = "myencrytionkey"
    // ruleid: gapscan.swift.hardcoded-key-literal
    let enc = try? RNEncryptor.encryptData(data, with: settings, password: "@daloq3as$qweasdlasasjd")
    // ok: gapscan.swift.hardcoded-key-literal
    let key = loadKeyFromKeychain()
    // ruleid: gapscan.swift.credential-field-persisted
    newUser?.password = passwordTextField.text
    // ruleid: gapscan.swift.credential-field-persisted
    data.setValue(password, forKey: "password")
    // ok: gapscan.swift.credential-field-persisted
    newUser?.name = nameTextField.text
    // ruleid: gapscan.swift.pasteboard-general
    UIPasteboard.general.string = secret
    // ruleid: gapscan.swift.webview-html-interpolated
    webView.loadHTMLString("Hello \(name), I am inside a WebView!", baseURL: nil)
    // ok: gapscan.swift.webview-html-interpolated
    webView.loadHTMLString("<b>fixed</b>", baseURL: nil)
    // ruleid: gapscan.swift.webview-html-interpolated
    let page = "<html><body>Results for \(name)</body></html>"
    webView.loadHTMLString(page, baseURL: nil)
    // ruleid: gapscan.swift.webview-html-interpolated
    webView.loadHTMLString("<p>" + name + "</p>", baseURL: nil)
    // ok: gapscan.swift.webview-html-interpolated
    let title = "Results for \(name)"
    label.text = title
    // ruleid: gapscan.swift.response-cache-sensitive
    urlRequest.cachePolicy = .returnCacheDataElseLoad
    // ruleid: gapscan.swift.credential-file-name
    let plistPath = NSHomeDirectory() + "/Documents/Credentials.plist"
}

// ruleid: gapscan.swift.uiwebview-used
var legacy: UIWebView!

func moreIdioms() {
    // ruleid: gapscan.swift.database-not-encrypted
    let realm = try! Realm()
    // ok: gapscan.swift.database-not-encrypted
    let config = Realm.Configuration(encryptionKey: key)
    var handle: OpaquePointer?
    // ruleid: gapscan.swift.database-not-encrypted
    sqlite3_open(dbPath, &handle)
    // ruleid: gapscan.swift.database-not-encrypted
    let cbl = try Database(name: "patients")
    // ruleid: gapscan.swift.file-protection-none
    try data.write(to: url, options: .noFileProtection)
    // ok: gapscan.swift.file-protection-none
    try data.write(to: url, options: .completeFileProtection)
    // ruleid: gapscan.swift.weak-random-api
    let k = rand()
    // ok: gapscan.swift.weak-random-api
    let strong = Int.random(in: 0..<10)
}
