// Shared between the app and the extension: the App Group container (journal, log, sessions),
// the shared settings, and the Keychain access group for profiles.

import Foundation

enum Shared {
    static let group = "group.org.example.maski"
    /// "<team>.org.example.maski.shared" (Info.plist MaskiKeychainGroup = $(AppIdentifierPrefix)...).
    static let keychainGroup = Bundle.main.object(forInfoDictionaryKey: "MaskiKeychainGroup") as? String ?? ""

    /// Library/maski in the App Group container (devicectl can copy Library, not the root); the
    /// process's own Documents if the group is not provisioned.
    static let dir: URL = {
        guard let g = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: group) else {
            return FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        }
        let u = g.appendingPathComponent("Library/maski", isDirectory: true)
        try? FileManager.default.createDirectory(at: u, withIntermediateDirectories: true)
        return u
    }()

    static func url(_ name: String) -> URL { dir.appendingPathComponent(name) }

    static let defaults = UserDefaults(suiteName: group) ?? .standard

    // File names in the container.
    static let journal = "events.jsonl"
    static let log = "tunnel.log"
    static let session = "session.json"
    static let prevSession = "session-prev.json"
}

func nowMs() -> UInt64 { UInt64(Date().timeIntervalSince1970 * 1000) }

/// Settings the user changes in the app; the extension reads its copy from providerConfiguration
/// (and `verbose` live from here).
enum Pref {
    static let profile = "profile"
    static let routeRU = "route_ru"
    static let routeLocal = "route_local"
    static let bypass = "bypass"
    static let keepOn = "keep_on"
    static let offSSIDs = "off_ssids"
    static let verbose = "verbose"
    /// Shows the «Российские сайты напрямую» switch (debug flag, see README).
    static let showRU = "show_ru"
    /// «Сотовая при сбое Wi-Fi»: the extension may move the tunnel to cellular while iOS still
    /// reports a dead Wi-Fi as the path (default on).
    static let cellFallback = "cell_fallback"
}

/// Append-only file with one rotation (`name` -> `name.1`) at `cap` bytes. Each `write` is one
/// write(2) of a whole line, so a line is never torn by a crash.
final class RotatingFile {
    private let lock = NSLock()
    private var h: FileHandle?
    let url: URL
    private let cap: UInt64
    private var size: UInt64 = 0

    init(_ url: URL, cap: UInt64) {
        self.url = url
        self.cap = cap
        open()
    }

    var rotated: URL { url.appendingPathExtension("1") }

    private func open() {
        if !FileManager.default.fileExists(atPath: url.path) { FileManager.default.createFile(atPath: url.path, contents: nil) }
        h = try? FileHandle(forWritingTo: url)
        size = (try? h?.seekToEnd()) ?? 0
    }

    func write(_ s: String) {
        lock.lock(); defer { lock.unlock() }
        let d = Data(s.utf8)
        if size + UInt64(d.count) > cap {
            try? h?.close()
            try? FileManager.default.removeItem(at: rotated)
            try? FileManager.default.moveItem(at: url, to: rotated)
            open()
        }
        try? h?.write(contentsOf: d)
        size += UInt64(d.count)
    }

    func reset() {
        lock.lock(); defer { lock.unlock() }
        try? h?.close()
        try? FileManager.default.removeItem(at: rotated)
        try? FileManager.default.removeItem(at: url)
        open()
    }
}
