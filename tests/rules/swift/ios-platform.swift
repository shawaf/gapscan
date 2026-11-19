import UIKit
import WebKit

final class FormController: UIViewController {
    @IBOutlet weak var passwordField: UITextField!
    @IBOutlet weak var nameField: UITextField!

    func configure(alert: UIAlertController) {
        alert.addTextField { tf in
            // ruleid: gapscan.swift.keyboard-cache-enabled
            tf.autocorrectionType = .default
        }
        alert.addTextField { tf in
            // ok: gapscan.swift.keyboard-cache-enabled
            tf.autocorrectionType = .no
        }
        // ruleid: gapscan.swift.secret-field-not-masked
        passwordField.isSecureTextEntry = false
        // ok: gapscan.swift.secret-field-not-masked
        passwordField.isSecureTextEntry = true
        // ok: gapscan.swift.secret-field-not-masked
        nameField.isSecureTextEntry = false
    }
}

final class Bridge: NSObject, WKScriptMessageHandler {
    // ruleid: gapscan.swift.webview-message-handler-no-origin-check
    func userContentController(_ userContentController: WKUserContentController,
                               didReceive message: WKScriptMessage) {
        guard let body = message.body as? [String: String] else { return }
        if body["action"] == "getProfile" {
            let profile = loadProfile()
            // ruleid: gapscan.swift.webview-js-injection-variable
            let js = "window.receiveProfile('\(profile)')"
            message.webView?.evaluateJavaScript(js, completionHandler: nil)
        }
    }

    func send(_ webView: WKWebView) {
        // ok: gapscan.swift.webview-js-injection-variable
        let js = "window.refresh()"
        webView.evaluateJavaScript(js, completionHandler: nil)
    }
}

final class CheckedBridge: NSObject, WKScriptMessageHandler {
    // ok: gapscan.swift.webview-message-handler-no-origin-check
    func userContentController(_ userContentController: WKUserContentController,
                               didReceive message: WKScriptMessage) {
        guard message.frameInfo.isMainFrame,
              message.frameInfo.securityOrigin.host == "app.example.com" else { return }
        handle(message.body)
    }
}

func loginPage(_ webView: WKWebView) {
    let html = """
    <form>
      <input type="text" id="user" />
      <!-- ruleid: gapscan.swift.webview-password-field -->
      <input type="password" id="password" />
      <!-- ok: gapscan.swift.webview-password-field -->
      <input type="email" id="mail" />
    </form>
    """
    webView.loadHTMLString(html, baseURL: nil)
}

func shareContact(number: String, message: String) {
    // ruleid: gapscan.swift.custom-scheme-url-with-data
    let link = "messenger://send?to=\(number)&text=\(message)"
    // ok: gapscan.swift.custom-scheme-url-with-data
    let web = "https://example.com/send?to=\(number)"
    // ok: gapscan.swift.custom-scheme-url-with-data
    let store = "itms-apps://itunes.apple.com/app/id\(appId)"
    // ok: gapscan.swift.custom-scheme-url-with-data
    let plain = "messenger://open"
    UIApplication.shared.open(URL(string: link)!)
}

final class LinkDelegate: UIResponder, UIApplicationDelegate {
    var webView: WKWebView!
    func application(_ app: UIApplication, open url: URL, options: [UIApplication.OpenURLOptionsKey: Any] = [:]) -> Bool {
        let comps = URLComponents(url: url, resolvingAgainstBaseURL: false)
        let name = comps?.queryItems?.first?.value ?? ""
        // ruleid: gapscan.swift.deeplink-to-sensitive-sink
        webView.evaluateJavaScript("greet('\(name)')")
        let id = Int(comps?.queryItems?.first?.value ?? "") ?? 0
        // ok: gapscan.swift.deeplink-to-sensitive-sink
        webView.evaluateJavaScript("show(\(id))")
        return true
    }
}

struct LinkView: View {
    var body: some View {
        Text("Inbox").onOpenURL { url in
            let page = url.query ?? ""
            // ruleid: gapscan.swift.deeplink-to-sensitive-sink
            web.loadHTMLString("<p>\(page)</p>", baseURL: nil)
            // ok: gapscan.swift.deeplink-to-sensitive-sink
            web.loadHTMLString("<p>Welcome</p>", baseURL: nil)
        }
    }
}

func savePatient(record: [String: String], theme: String) {
    // ruleid: gapscan.swift.userdefaults-personal-data
    UserDefaults.standard.set(record, forKey: "current_patient")
    // ruleid: gapscan.swift.userdefaults-personal-data
    defaults.set(card, forKey: "creditCardNumber")
    // ok: gapscan.swift.userdefaults-personal-data
    UserDefaults.standard.set(theme, forKey: "theme")
    // ok: gapscan.swift.userdefaults-personal-data
    KeychainWrapper.standard.set(record, forKey: "patient_record")
}
