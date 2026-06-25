import Foundation
import CryptoKit
import Compression

// MARK: - Image Signatures
struct ImageSig {
    let magic: [UInt8]
    let ext: String
    let mime: String

    static let all: [ImageSig] = [
        .init(magic: [0xFF, 0xD8, 0xFF], ext: "jpg", mime: "image/jpeg"),
        .init(magic: [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A], ext: "png", mime: "image/png"),
        .init(magic: [0x47, 0x49, 0x46, 0x38, 0x37, 0x61], ext: "gif", mime: "image/gif"),
        .init(magic: [0x47, 0x49, 0x46, 0x38, 0x39, 0x61], ext: "gif", mime: "image/gif"),
        .init(magic: [0x52, 0x49, 0x46, 0x46], ext: "webp", mime: "image/webp"),
        .init(magic: [0x42, 0x4D], ext: "bmp", mime: "image/bmp"),
    ]
}

private let imageMimes: Set<String> = [
    "image/jpeg", "image/jpg", "image/png", "image/gif",
    "image/webp", "image/bmp", "image/x-icon"
]

func validateMagicBytes(_ data: Data) -> Bool {
    guard data.count >= 16 else { return false }
    let bytes = [UInt8](data.prefix(16))
    for sig in ImageSig.all {
        if bytes.starts(with: sig.magic) { return true }
    }
    // WEBP: RIFF....WEBP
    if bytes.count >= 12, bytes[0..<4] == [0x52, 0x49, 0x46, 0x46],
       bytes[8..<12] == [0x57, 0x45, 0x42, 0x50] { return true }
    return false
}

func isImageContentType(_ ct: String) -> Bool {
    let lower = ct.lowercased()
    return imageMimes.contains { lower.contains($0) } || lower.contains("octet-stream")
}

func detectImageExt(_ data: Data) -> String {
    let bytes = [UInt8](data.prefix(16))
    for sig in ImageSig.all {
        if bytes.starts(with: sig.magic) { return sig.ext }
    }
    if bytes.count >= 12, bytes[0..<4] == [0x52, 0x49, 0x46, 0x46],
       bytes[8..<12] == [0x57, 0x45, 0x42, 0x50] { return "webp" }
    return "bin"
}

// MARK: - HTTP Parser
struct ParsedHTTPResponse {
    let headers: [String: String]
    let body: Data
    let isChunked: Bool
    let contentLength: Int
}

func parseHTTPResponse(_ data: Data) -> ParsedHTTPResponse? {
    guard let text = String(data: data.prefix(8192), encoding: .utf8)
            ?? String(data: data.prefix(8192), encoding: .ascii) else { return nil }
    guard text.hasPrefix("HTTP/") else { return nil }

    let parts = text.components(separatedBy: "\r\n\r\n")
    guard parts.count >= 2 else { return nil }

    let headerBlock = parts[0]
    var headers: [String: String] = [:]
    for line in headerBlock.split(separator: "\r\n").dropFirst() {
        if let ci = line.firstIndex(of: ":") {
            let k = line[..<ci].trimmingCharacters(in: .whitespaces).lowercased()
            let v = line[line.index(after: ci)...].trimmingCharacters(in: .whitespaces)
            headers[k] = v
        }
    }

    let headerBytes = headerBlock.data(using: .utf8)?.count ?? 0
    let headerEnd = headerBytes + 4
    let rawBody: Data
    if data.count > headerEnd {
        rawBody = data.subdata(in: headerEnd..<data.count)
    } else {
        rawBody = Data()
    }

    var body = rawBody

    // Content-Encoding
    if let enc = headers["content-encoding"]?.lowercased() {
        switch enc {
        case "gzip":
            if let decoded = decompressGzip(body) { body = decoded }
        case "deflate":
            if let decoded = decompressDeflate(body) { body = decoded }
        default: break
        }
    }

    let isChunked = headers["transfer-encoding"]?.lowercased() == "chunked"
    if isChunked { body = dechunk(body) }

    let cl = Int(headers["content-length"] ?? "0") ?? 0
    return ParsedHTTPResponse(headers: headers, body: body, isChunked: isChunked, contentLength: cl)
}

private func decompressGzip(_ data: Data) -> Data? {
    guard !data.isEmpty else { return nil }
    let dstSize = data.count * 8
    let dst = UnsafeMutablePointer<UInt8>.allocate(capacity: dstSize)
    defer { dst.deallocate() }
    let decoded = data.withUnsafeBytes { (src: UnsafeRawBufferPointer) -> Int in
        guard let base = src.baseAddress else { return 0 }
        return Int(compression_decode_buffer(dst, dstSize, base.assumingMemoryBound(to: UInt8.self), data.count, nil, COMPRESSION_ZLIB))
    }
    guard decoded > 0 else { return nil }
    return Data(bytes: dst, count: decoded)
}

private func decompressDeflate(_ data: Data) -> Data? {
    return decompressGzip(data) // Same algorithm for deflate in HTTP
}

private func dechunk(_ data: Data) -> Data {
    guard let text = String(data: data, encoding: .utf8) else { return data }
    var result = Data()
    var cursor = text.startIndex
    while cursor < text.endIndex {
        guard let le = text[cursor...].firstIndex(of: "\r\n") else { break }
        let sizeStr = String(text[cursor..<le])
        guard let size = Int(sizeStr, radix: 16), size > 0 else { break }
        let cs = text.index(le, offsetBy: 2)
        guard let ce = text.index(cs, offsetBy: size, limitedBy: text.endIndex) else { break }
        let utfOff = cs.utf16Offset(in: text)
        let utfEnd = ce.utf16Offset(in: text)
        result.append(data.subdata(in: utfOff..<utfEnd))
        cursor = text.index(ce, offsetBy: 2)
    }
    return result
}

// MARK: - Multipart Parser
func extractMultipartImages(body: Data, boundary: String) -> [Data] {
    let delimiter = "--\(boundary)".data(using: .utf8)!
    let endDelimiter = "--\(boundary)--".data(using: .utf8)!
    var images: [Data] = []
    var search = body.startIndex..<body.endIndex

    while let ds = body.range(of: delimiter, in: search) {
        defer { search = ds.upperBound..<body.endIndex }
        guard ds.upperBound < body.endIndex else { break }
        guard let hs = body.range(of: "\r\n\r\n".data(using: .utf8)!, in: ds.upperBound..<body.endIndex) else {
            continue
        }
        let partHeaders = body.subdata(in: ds.upperBound..<hs.lowerBound)
        let hdrStr = String(data: partHeaders, encoding: .utf8) ?? ""
        let isImage = hdrStr.lowercased().contains("content-type: image")
            || hdrStr.lowercased().contains("content-type: application/octet-stream")
        guard isImage else { continue }

        guard let nb = body.range(of: delimiter, in: hs.upperBound..<body.endIndex)
                ?? body.range(of: endDelimiter, in: hs.upperBound..<body.endIndex) else { break }
        var partBody = body.subdata(in: hs.upperBound..<nb.lowerBound)
        let crlf = "\r\n".data(using: .utf8)!
        if partBody.suffix(crlf.count) == crlf {
            partBody = partBody.dropLast(2)
        }
        if validateMagicBytes(partBody) {
            images.append(partBody)
        }
    }
    return images
}

// MARK: - ImageHarvester
class ImageHarvester {
    struct Config {
        var outputDir = "/tmp/netcutx_images"
        var minSize = 5 * 1024
        var maxSize = 100 * 1024 * 1024
        var dedup = true
    }

    private let config: Config
    private var count = 0
    private var seenHashes = Set<String>()
    private var partialBodies: [String: Data] = [:]
    private let queue = DispatchQueue(label: "netcutx.harvester")

    init(config: Config = Config()) {
        self.config = config
        try? FileManager.default.createDirectory(atPath: config.outputDir, withIntermediateDirectories: true)
    }

    func feed(payload: Data, srcIP: String, dstIP: String, srcPort: UInt16, dstPort: UInt16, targetIP: String) {
        queue.async {
            self._feed(payload: payload, srcIP: srcIP, dstIP: dstIP, srcPort: srcPort, dstPort: dstPort, targetIP: targetIP)
        }
    }

    private func _feed(payload: Data, srcIP: String, dstIP: String, srcPort: UInt16, dstPort: UInt16, targetIP: String) {
        // Only process responses (server → target)
        let isResponse = srcIP != targetIP && (srcPort == 80 || srcPort == 443)
        guard isResponse else { return }

        let key = "\(srcIP):\(srcPort)-\(dstIP):\(dstPort)"

        // Try HTTP parse
        if let parsed = parseHTTPResponse(payload) {
            trySave(body: parsed.body, headers: parsed.headers, key: key)

            // Multipart
            if let ct = parsed.headers["content-type"], ct.lowercased().contains("multipart/form-data"),
               let br = ct.range(of: "boundary=") {
                let boundary = String(ct[br.upperBound...]).trimmingCharacters(in: .whitespaces)
                for img in extractMultipartImages(body: parsed.body, boundary: boundary) {
                    saveImage(img)
                }
            }

            // Partial: if body < content-length, save for reassembly
            if parsed.contentLength > 0 && parsed.body.count < parsed.contentLength {
                partialBodies[key] = parsed.body
            }
        } else {
            // Partial body continuation
            if var existing = partialBodies[key] {
                existing.append(payload)
                if existing.count >= 16, validateMagicBytes(existing) {
                    saveImage(existing)
                    partialBodies.removeValue(forKey: key)
                } else {
                    partialBodies[key] = existing
                }
            }
        }
    }

    private func trySave(body: Data, headers: [String: String], key: String) {
        guard body.count >= config.minSize, body.count <= config.maxSize else { return }
        guard validateMagicBytes(body) else {
            // Maybe body is not complete — check content-type
            if let ct = headers["content-type"], isImageContentType(ct) {
                partialBodies[key] = body
            }
            return
        }
        saveImage(body)
    }

    private func saveImage(_ data: Data) {
        guard data.count >= config.minSize, data.count <= config.maxSize else { return }

        let hash = SHA256.hash(data: data).compactMap { String(format: "%02x", $0) }.joined()
        if config.dedup { guard !seenHashes.contains(hash) else { return } }
        seenHashes.insert(hash)

        let ext = detectImageExt(data)
        let ts = ISO8601DateFormatter().string(from: Date()).replacingOccurrences(of: ":", with: "-")
        let fname = "img_\(ts)_\(count).\(ext)"
        let path = (config.outputDir as NSString).appendingPathComponent(fname)

        do {
            try data.write(to: URL(fileURLWithPath: path))
            count += 1
            statusErr("[IMAGE] \(fname) (\(data.count) bytes)")
        } catch {
            statusErr("[IMAGE] write failed: \(error.localizedDescription)")
        }
    }

    var stats: String { "Images: \(count), unique: \(seenHashes.count)" }
}

// MARK: - Data Extensions
private extension Data {
    func range(of other: Data, in bounds: Range<Index>? = nil) -> Range<Index>? {
        let r = bounds ?? startIndex..<endIndex
        guard r.count >= other.count else { return nil }
        for i in r.lowerBound..<(r.upperBound - other.count + 1) {
            if self[i..<i + other.count] == other { return i..<i + other.count }
        }
        return nil
    }
}
