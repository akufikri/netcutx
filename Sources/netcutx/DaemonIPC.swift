import Foundation
import Darwin

let ipcSocketPath = "/var/run/netcutx.sock"

func startIPCServer() {
    let t = Thread { runIPCServer() }
    t.name = "netcutx-ipc"
    t.start()
}

private func runIPCServer() {
    unlink(ipcSocketPath)

    let fd = socket(AF_UNIX, SOCK_STREAM, 0)
    guard fd >= 0 else {
        daemonLog("IPC socket create failed: \(errno)")
        return
    }

    var addr = sockaddr_un()
    addr.sun_family = sa_family_t(AF_UNIX)
    setSunPath(&addr, ipcSocketPath)

    let bindResult = withUnsafePointer(to: &addr) {
        $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
            bind(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
        }
    }
    guard bindResult == 0 else {
        daemonLog("IPC bind failed: \(errno)")
        close(fd); return
    }

    chmod(ipcSocketPath, 0o666)  // allow non-root GUI to connect
    guard listen(fd, 5) == 0 else {
        daemonLog("IPC listen failed: \(errno)")
        close(fd); return
    }

    daemonLog("IPC socket ready: \(ipcSocketPath)")

    while _daemonExitFlag == 0 {
        let client = accept(fd, nil, nil)
        guard client >= 0 else { continue }
        let t = Thread { handleClient(fd: client) }
        t.start()
    }

    close(fd)
    unlink(ipcSocketPath)
}

private func handleClient(fd: Int32) {
    defer { close(fd) }

    var buf = [UInt8](repeating: 0, count: 2048)
    let n = read(fd, &buf, 2047)
    guard n > 0 else { return }

    let msg = String(bytes: buf[0..<n], encoding: .utf8)?
                  .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""

    guard let data = msg.data(using: .utf8),
          let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
          let cmd  = json["cmd"] as? String else { return }

    var response: [String: Any]

    switch cmd {
    case "status":
        let snap = sharedState.snapshot()
        response = [
            "running":     snap.active,
            "manualStop":  _manualStopFlag != 0,
            "targets":     snap.targets,
            "iface":       snap.iface,
            "ip":          snap.ip
        ]

    case "stop":
        OSAtomicIncrement32(&_manualStopFlag)   // prevent auto-restart
        requestSpooferStop()
        response = ["ok": true]

    case "scan":
        OSAtomicIncrement32(&_rescanFlag)
        response = ["ok": true]

    case "exit":
        _daemonExitFlag = 1
        _stopFlag = 1
        response = ["ok": true]

    default:
        response = ["error": "unknown command: \(cmd)"]
    }

    if let respData = try? JSONSerialization.data(withJSONObject: response),
       let respStr  = String(data: respData, encoding: .utf8) {
        let out = respStr + "\n"
        _ = out.withCString { write(fd, $0, strlen($0)) }
    }
}

private func setSunPath(_ addr: inout sockaddr_un, _ path: String) {
    _ = withUnsafeMutablePointer(to: &addr.sun_path) { ptr in
        path.withCString { cstr in
            ptr.withMemoryRebound(to: CChar.self, capacity: 104) {
                strncpy($0, cstr, 103)
            }
        }
    }
}
