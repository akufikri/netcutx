import Foundation
import Darwin

private let socketPath = "/var/run/netcutx.sock"

struct DaemonStatus {
    var running: Bool
    var manualStop: Bool
    var targets: [String]
    var iface: String
    var ip: String
}

class IPCClient {
    func status() -> DaemonStatus? {
        guard let json = send(["cmd": "status"]) else { return nil }
        return DaemonStatus(
            running:    json["running"]    as? Bool     ?? false,
            manualStop: json["manualStop"] as? Bool     ?? false,
            targets:    json["targets"]    as? [String] ?? [],
            iface:      json["iface"]      as? String   ?? "",
            ip:         json["ip"]         as? String   ?? ""
        )
    }

    func stop() { _ = send(["cmd": "stop"]) }
    func scan() { _ = send(["cmd": "scan"]) }

    private func send(_ cmd: [String: Any]) -> [String: Any]? {
        guard let data = try? JSONSerialization.data(withJSONObject: cmd),
              let msg  = String(data: data, encoding: .utf8) else { return nil }

        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { return nil }
        defer { close(fd) }

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        socketPath.withCString { cstr in
            withUnsafeMutablePointer(to: &addr.sun_path) {
                $0.withMemoryRebound(to: CChar.self, capacity: 104) {
                    _ = strncpy($0, cstr, 103)
                }
            }
        }

        let ok = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard ok == 0 else { return nil }

        _ = msg.withCString { write(fd, $0, strlen($0)) }

        var buf = [UInt8](repeating: 0, count: 4096)
        let n = read(fd, &buf, 4095)
        guard n > 0,
              let json = try? JSONSerialization.jsonObject(with: Data(buf[0..<n])) as? [String: Any]
        else { return nil }

        return json
    }
}
