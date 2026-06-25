import Foundation

private let anchorName = "netcutx"
private let anchorFile = "/tmp/netcutx_anchor.conf"

func pfctl(_ args: [String]) -> (Bool, String) {
    let t = Process()
    t.executableURL = URL(fileURLWithPath: "/sbin/pfctl")
    t.arguments = args
    let out = Pipe()
    let err = Pipe()
    t.standardOutput = out
    t.standardError = err
    guard (try? t.run()) != nil else { return (false, "") }
    t.waitUntilExit()
    let data = (try? out.fileHandleForReading.readToEnd()) ?? Data()
    let errData = (try? err.fileHandleForReading.readToEnd()) ?? Data()
    let output = String(data: data, encoding: .utf8) ?? ""
    let errOut = String(data: errData, encoding: .utf8) ?? ""
    return (t.terminationStatus == 0, output + errOut)
}

func redirectStart(targetIP: String, proxyPort: Int = 8080, interface: String? = nil, launchProxy: Bool = false) {
    guard getuid() == 0 else {
        fail("Redirect requires sudo")
        return
    }

    let ifname: String
    if let provided = interface {
        ifname = provided
    } else if let detected = getDefaultInterface() {
        ifname = detected
    } else {
        fail("No interface detected")
        return
    }

    // Write anchor rules — pf evaluates rdr rules in all anchors
    let rules = "rdr pass on \(ifname) inet proto tcp from \(targetIP) to any port 443 -> 127.0.0.1 port \(proxyPort)\nrdr pass on \(ifname) inet proto tcp from \(targetIP) to any port 80 -> 127.0.0.1 port \(proxyPort)\n"
    do {
        try rules.write(toFile: anchorFile, atomically: true, encoding: .utf8)
    } catch {
        fail("Write rules: \(error.localizedDescription)")
        return
    }

    // Enable pf + load anchor
    _ = pfctl(["-e"])
    let (rc, out) = pfctl(["-a", anchorName, "-f", anchorFile])
    guard rc else {
        fail("pfctl anchor failed: \(out)")
        try? FileManager.default.removeItem(atPath: anchorFile)
        return
    }

    ok("Redirect: \(targetIP) → 127.0.0.1:\(proxyPort) (\(ifname))")
    status("HTTP/HTTPS redirected to proxy")
    status("netcutx redirect stop — to restore")

    if launchProxy {
        status("Launching mitmproxy...")
        let proxy = Process()
        proxy.executableURL = URL(fileURLWithPath: "/usr/local/bin/mitmproxy")
        proxy.arguments = ["-p", "\(proxyPort)", "--set", "ssl_insecure=true"]
        proxy.standardOutput = FileHandle.nullDevice
        proxy.standardError = FileHandle.nullDevice
        do {
            try proxy.run()
            ok("mitmproxy PID \(proxy.processIdentifier)")
            proxy.waitUntilExit()
        } catch {
            warn("mitmproxy not found at /usr/local/bin/mitmproxy")
        }
    }
}

func redirectStop() {
    _ = pfctl(["-a", anchorName, "-F", "all"])
    try? FileManager.default.removeItem(atPath: anchorFile)
    ok("Redirect stopped — anchor flushed")
}

func redirectStatus() {
    let (_, out) = pfctl(["-a", anchorName, "-s", "rules"])
    let rules = out.components(separatedBy: "\n").filter { !$0.isEmpty }
    if rules.isEmpty {
        print("  No active redirect rules")
    } else {
        print("  Active redirect rules:")
        for r in rules { print("    \(r)") }
    }
}
