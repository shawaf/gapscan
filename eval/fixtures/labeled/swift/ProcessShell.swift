import Foundation

func lookup(host: String) -> String {
    let task = Process()
    task.executableURL = URL(fileURLWithPath: "/bin/sh")
    task.arguments = ["-c", "dig +short " + host]
    let pipe = Pipe()
    task.standardOutput = pipe
    try? task.run()
    return String(data: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
}
