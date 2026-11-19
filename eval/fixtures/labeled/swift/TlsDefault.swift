import Foundation

struct Api {
    func fetch(path: String) async throws -> Data {
        let url = URL(string: "https://api.example.com")!.appendingPathComponent(path)
        let (data, _) = try await URLSession.shared.data(from: url)
        return data
    }
}
