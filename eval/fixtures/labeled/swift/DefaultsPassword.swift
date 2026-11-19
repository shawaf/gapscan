import Foundation

final class Login {
    func remember(user: String, password: String) {
        UserDefaults.standard.set(user, forKey: "user")
        UserDefaults.standard.set(password, forKey: "password")
    }
}
