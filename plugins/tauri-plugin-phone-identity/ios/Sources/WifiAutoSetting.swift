import Foundation

final class WifiAutoSetting {
    private let url: URL
    private let enabledBytes = Data([0x41, 0x50, 0x57, 0x01])

    init() {
        let support = try! FileManager.default.url(for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: true)
        let root = support.appendingPathComponent("phone-identity", isDirectory: true)
        try? FileManager.default.createDirectory(at: root, withIntermediateDirectories: true, attributes: [.protectionKey: FileProtectionType.complete])
        var values = URLResourceValues(); values.isExcludedFromBackup = true
        var mutableRoot = root; try? mutableRoot.setResourceValues(values)
        url = root.appendingPathComponent("wifi-auto-listen-v1")
    }

    func enabled() -> Bool { (try? Data(contentsOf: url)) == enabledBytes }

    func setEnabled(_ enabled: Bool) throws {
        if !enabled {
            if FileManager.default.fileExists(atPath: url.path) { try FileManager.default.removeItem(at: url) }
            return
        }
        try enabledBytes.write(to: url, options: [.atomic, .completeFileProtection])
        var values = URLResourceValues(); values.isExcludedFromBackup = true
        var mutableURL = url; try mutableURL.setResourceValues(values)
    }
}
