import CommonCrypto
import Foundation

enum Passwords {
    static func hash(_ password: String) -> String {
        var digest = [UInt8](repeating: 0, count: Int(CC_MD5_DIGEST_LENGTH))
        let data = Array(password.utf8)
        CC_MD5(data, CC_LONG(data.count), &digest)
        return digest.map { String(format: "%02x", $0) }.joined()
    }
}
