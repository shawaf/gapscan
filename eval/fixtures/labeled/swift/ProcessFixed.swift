import Foundation

func osVersion() -> String {
    let task = Process()
    task.executableURL = URL(fileURLWithPath: "/usr/bin/sw_vers")
    task.arguments = ["-productVersion"]
    let pipe = Pipe()
    task.standardOutput = pipe
    try? task.run()
    return String(data: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
}
