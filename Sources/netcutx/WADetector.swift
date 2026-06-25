import Foundation

enum WAType: String, CustomStringConvertible {
    case web = "WEB"
    case chat = "CHAT"
    case media = "MEDIA"
    case static_ = "STATIC"
    case unknown = "UNKNOWN"
    var description: String { rawValue }
}

struct WAEvent: CustomStringConvertible {
    let ts: Date
    let targetIP: String
    let serverIP: String
    let serverDomain: String
    let type: WAType
    let dataSize: Int
    var description: String {
        "[WA] \(targetIP) → \(serverDomain) (\(serverIP)) \(type) \(ByteCountFormatter.string(fromByteCount: Int64(dataSize), countStyle: .binary))"
    }
}

private let waIPRanges: [(UInt32, UInt32)] = [
    (0x1F0D0000, 0xFFFF0000), // 31.13.0.0/16
    (0x1F0D1800, 0xFFFFF800), // 31.13.24.0/21
    (0x1F0D4000, 0xFFFFC000), // 31.13.64.0/18
    (0x1F0D4400, 0xFFFFFF00), // 31.13.68.0/24
    (0x1F0D4600, 0xFFFFFE00), // 31.13.70.0/23
    (0x1F0D4800, 0xFFFFFC00), // 31.13.72.0/22
]

private let waServerPatterns: [(suffix: String, type: WAType)] = [
    ("web.whatsapp.com", .web),
    ("wa.whatsapp.com", .chat),
    ("mmg.whatsapp.net", .media),
    ("mmg-1.whatsapp.com", .media),
    ("static.whatsapp.net", .static_),
    ("pps.whatsapp.net", .chat),
]

private func ipToU32(_ ip: String) -> UInt32? {
    let parts = ip.split(separator: ".").compactMap { UInt32($0) }
    guard parts.count == 4 else { return nil }
    return (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]
}

private func isWAIP(_ ip: String) -> Bool {
    guard let addr = ipToU32(ip) else { return false }
    for (base, mask) in waIPRanges {
        if addr & mask == base { return true }
    }
    return false
}

func parseSNI(from data: Data) -> String? {
    guard data.count >= 54 else { return nil }
    let ipHL = Int(data[14] & 0x0F) * 4
    guard ipHL >= 20, data[23] == 6 else { return nil }
    let tcpOff = Int((data[14 + ipHL + 12] >> 4) * 4)
    guard tcpOff >= 20 else { return nil }
    let payloadStart = 14 + ipHL + tcpOff
    guard data.count >= payloadStart + 5 else { return nil }
    guard data[payloadStart] == 0x16 else { return nil } // TLS Handshake
    let tlsLen = Int(UInt16(data[payloadStart + 3]) << 8 | UInt16(data[payloadStart + 4]))
    guard data.count >= payloadStart + 5 + tlsLen else { return nil }
    let hsStart = payloadStart + 5
    guard data[hsStart] == 0x01 else { return nil } // ClientHello
    var pos = hsStart + 4
    pos += 2 + 32 // version + random
    guard pos < data.count else { return nil }
    let sidLen = Int(data[pos]); pos += 1 + sidLen
    guard pos + 1 < data.count else { return nil }
    let csLen = Int(UInt16(data[pos]) << 8 | UInt16(data[pos + 1])); pos += 2 + csLen
    guard pos < data.count else { return nil }
    let cmLen = Int(data[pos]); pos += 1 + cmLen
    guard pos + 1 < data.count else { return nil }
    let extLen = Int(UInt16(data[pos]) << 8 | UInt16(data[pos + 1])); pos += 2
    let extEnd = pos + extLen
    guard extEnd <= data.count else { return nil }
    while pos + 3 < extEnd {
        let extType = UInt16(data[pos]) << 8 | UInt16(data[pos + 1])
        let extDataLen = Int(UInt16(data[pos + 2]) << 8 | UInt16(data[pos + 3]))
        pos += 4
        guard pos + extDataLen <= extEnd else { return nil }
        if extType == 0x0000 { // SNI
            let sniListLen = Int(UInt16(data[pos]) << 8 | UInt16(data[pos + 1]))
            guard sniListLen >= 5, extDataLen >= 5 else { return nil }
            let nameType = data[pos + 2]
            guard nameType == 0 else { return nil } // host_name
            let nameLen = Int(UInt16(data[pos + 3]) << 8 | UInt16(data[pos + 4]))
            guard pos + 5 + nameLen <= extEnd else { return nil }
            return String(bytes: data[pos + 5..<pos + 5 + nameLen], encoding: .utf8)
        }
        pos += extDataLen
    }
    return nil
}

private func classifyWADomain(_ domain: String) -> WAType? {
    for (suffix, type) in waServerPatterns {
        if domain.hasSuffix(suffix) || domain == suffix { return type }
    }
    return nil
}

func checkWA(in packet: Data, info: PacketInfo? = nil) -> WAEvent? {
    guard isWAIP(info?.srcIP ?? "") || isWAIP(info?.dstIP ?? "") else { return nil }
    let waIP = isWAIP(info?.srcIP ?? "") ? info?.srcIP : info?.dstIP
    let targetIP = isWAIP(info?.srcIP ?? "") ? info?.dstIP : info?.srcIP
    guard let ip = waIP, let target = targetIP else { return nil }

    let sni = parseSNI(from: packet)
    if let domain = sni, let type = classifyWADomain(domain) {
        return WAEvent(ts: Date(), targetIP: target, serverIP: ip,
                       serverDomain: domain, type: type, dataSize: info?.size ?? 0)
    }

    // Fallback: classify by IP without SNI
    let type: WAType = (info?.size ?? 0) > 100_000 ? .media : .unknown
    return WAEvent(ts: Date(), targetIP: target, serverIP: ip,
                   serverDomain: ip, type: type, dataSize: info?.size ?? 0)
}
