import CommonCrypto
import Foundation

enum ImageCache {
    static func key(for url: URL) -> String {
        var digest = [UInt8](repeating: 0, count: Int(CC_MD5_DIGEST_LENGTH))
        let data = Array(url.absoluteString.utf8)
        CC_MD5(data, CC_LONG(data.count), &digest)
        return digest.map { String(format: "%02x", $0) }.joined()
    }
}
