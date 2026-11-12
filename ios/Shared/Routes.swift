// Address / CIDR parsing for the "Мимо маски" list and the bundled Russian prefix list.

import Darwin
import Foundation

struct CIDR: Equatable {
    var addr: String
    var prefix: Int
    var v6: Bool

    /// "1.2.3.4", "1.2.3.0/24", "2001:db8::1", "2001:db8::/32". The address is normalised.
    static func parse(_ raw: String) -> CIDR? {
        let s = raw.trimmingCharacters(in: .whitespaces)
        let parts = s.split(separator: "/", omittingEmptySubsequences: false)
        guard parts.count == 1 || parts.count == 2 else { return nil }
        let a = String(parts[0])
        var v4 = in_addr(), v6 = in6_addr()
        if inet_pton(AF_INET, a, &v4) == 1 {
            let p = parts.count == 2 ? Int(parts[1]) : 32
            guard let p, (0...32).contains(p) else { return nil }
            return CIDR(addr: a, prefix: p, v6: false)
        }
        if inet_pton(AF_INET6, a, &v6) == 1 {
            let p = parts.count == 2 ? Int(parts[1]) : 128
            guard let p, (0...128).contains(p) else { return nil }
            var buf = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
            inet_ntop(AF_INET6, &v6, &buf, socklen_t(buf.count))
            return CIDR(addr: String(cString: buf), prefix: p, v6: true)
        }
        return nil
    }

    static func mask4(_ p: Int) -> String {
        let m: UInt32 = p == 0 ? 0 : ~UInt32(0) << UInt32(32 - p)
        return "\(m >> 24 & 255).\(m >> 16 & 255).\(m >> 8 & 255).\(m & 255)"
    }

    var text: String { (v6 && prefix == 128) || (!v6 && prefix == 32) ? addr : "\(addr)/\(prefix)" }
}

func isIPLiteral(_ s: String) -> Bool {
    var v4 = in_addr(), v6 = in6_addr()
    return inet_pton(AF_INET, s, &v4) == 1 || inet_pton(AF_INET6, s, &v6) == 1
}
