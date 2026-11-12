// Server profiles in the Keychain, shared with the extension through the keychain access group.
// Link format (also the QR payload), see ../README.md:
//   maski://add?name=<name>&server=<host>:<port>&user=<user>&pass=<pass>&pin=<sha256 hex>[&sni=<sni>]

import Foundation
import Security

struct Profile: Codable, Identifiable, Equatable {
    var id: String = UUID().uuidString
    var name: String
    var host: String
    var port: Int
    var user: String
    var pass: String
    var pin: String
    /// Empty: the library's default SNI.
    var sni: String = ""
    var created: Double = Date().timeIntervalSince1970

    /// "host:port" (IPv6 literals in brackets).
    var server: String { host.contains(":") ? "[\(host)]:\(port)" : "\(host):\(port)" }

    static func parseServer(_ s: String) -> (String, Int)? {
        var host = s, port = 0
        if s.hasPrefix("["), let close = s.firstIndex(of: "]") {
            host = String(s[s.index(after: s.startIndex)..<close])
            let rest = s[s.index(after: close)...]
            guard rest.hasPrefix(":"), let p = Int(rest.dropFirst()) else { return nil }
            port = p
        } else {
            guard let c = s.lastIndex(of: ":"), let p = Int(s[s.index(after: c)...]) else { return nil }
            host = String(s[..<c])
            port = p
        }
        guard !host.isEmpty, (1...65535).contains(port) else { return nil }
        return (host, port)
    }

    /// Parse a `maski://add?...` link (or the same string from a QR code).
    static func from(link: String) -> Profile? {
        guard let c = URLComponents(string: link.trimmingCharacters(in: .whitespacesAndNewlines)),
              c.scheme == "maski", c.host == "add" else { return nil }
        var q: [String: String] = [:]
        for i in c.queryItems ?? [] { q[i.name] = i.value ?? "" }
        guard let name = q["name"], !name.isEmpty, let srv = q["server"], let (h, p) = parseServer(srv),
              let user = q["user"], let pass = q["pass"], let pin = q["pin"]?.lowercased(),
              pin.count == 64, pin.allSatisfy(\.isHexDigit) else { return nil }
        return Profile(name: name, host: h, port: p, user: user, pass: pass, pin: pin, sni: q["sni"] ?? "")
    }

    var link: String {
        var c = URLComponents()
        c.scheme = "maski"
        c.host = "add"
        var items = [URLQueryItem(name: "name", value: name), URLQueryItem(name: "server", value: server),
                     URLQueryItem(name: "user", value: user), URLQueryItem(name: "pass", value: pass),
                     URLQueryItem(name: "pin", value: pin)]
        if !sni.isEmpty { items.append(URLQueryItem(name: "sni", value: sni)) }
        c.queryItems = items
        // URLComponents leaves "+" and "&"-safe characters alone; encode "+" so it survives form decoders.
        return (c.string ?? "").replacingOccurrences(of: "+", with: "%2B")
    }
}

enum ProfileStore {
    private static let service = "org.example.maski.profile"

    private static func base() -> [String: Any] {
        var q: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service]
        if !Shared.keychainGroup.isEmpty { q[kSecAttrAccessGroup as String] = Shared.keychainGroup }
        return q
    }

    static func all() -> [Profile] {
        var q = base()
        q[kSecMatchLimit as String] = kSecMatchLimitAll
        q[kSecReturnData as String] = true
        var out: CFTypeRef?
        guard SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess, let arr = out as? [Data] else { return [] }
        return arr.compactMap { try? JSONDecoder().decode(Profile.self, from: $0) }.sorted { $0.created < $1.created }
    }

    static func get(_ id: String) -> Profile? {
        var q = base()
        q[kSecAttrAccount as String] = id
        q[kSecReturnData as String] = true
        var out: CFTypeRef?
        guard SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess, let d = out as? Data else { return nil }
        return try? JSONDecoder().decode(Profile.self, from: d)
    }

    @discardableResult
    static func save(_ p: Profile) -> Bool {
        guard let d = try? JSONEncoder().encode(p) else { return false }
        var q = base()
        q[kSecAttrAccount as String] = p.id
        let upd: [String: Any] = [kSecValueData as String: d]
        var st = SecItemUpdate(q as CFDictionary, upd as CFDictionary)
        if st == errSecItemNotFound {
            q[kSecValueData as String] = d
            // The extension must read it while the phone is locked (On Demand).
            q[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
            st = SecItemAdd(q as CFDictionary, nil)
        }
        return st == errSecSuccess
    }

    static func delete(_ id: String) {
        var q = base()
        q[kSecAttrAccount as String] = id
        SecItemDelete(q as CFDictionary)
    }
}
