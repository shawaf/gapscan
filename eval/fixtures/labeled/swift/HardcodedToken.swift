import Foundation

enum Backend {
    static let apiToken = "sk_live_51NfQ2dHx7Yb3KpLm9TzVwR4uJ8aXcE0q"

    static func request(_ path: String) -> URLRequest {
        var req = URLRequest(url: URL(string: "https://api.example.com/" + path)!)
        req.setValue("Bearer " + apiToken, forHTTPHeaderField: "Authorization")
        return req
    }
}
