import Foundation

struct FingerprintResult {
    let deviceType: DeviceType
    let ttl: UInt8
    let openPorts: [Int]
    let confidence: Float
}

let probePorts: [(port: Int, name: String)] = [
    (22, "SSH"), (80, "HTTP"), (443, "HTTPS"),
    (5555, "ADB"), (62078, "AFC"),
    (8443, "HTTPS-ALT"), (8080, "HTTP-PROXY"),
    (7000, "AirPlay"), (5000, "DAAP"),
]

// Known OUI prefixes. First 3 bytes of MAC, lowercase.
let appleOUIs: Set<String> = [
    "00:03:93", "00:05:02", "00:06:5b", "00:0a:27", "00:0a:95", "00:0d:93",
    "00:0e:a6", "00:11:24", "00:14:51", "00:16:cb", "00:17:f2", "00:19:e3",
    "00:1b:63", "00:1c:42", "00:1d:4f", "00:1e:52", "00:1f:5b", "00:1f:f3",
    "00:21:e9", "00:22:41", "00:23:12", "00:23:32", "00:23:6c", "00:23:df",
    "00:24:36", "00:25:00", "00:25:4b", "00:26:08", "00:26:b0", "00:26:bb",
    "00:30:65", "00:3e:e1", "00:50:e4", "0c:74:c2", "10:93:e9", "10:dd:b1",
    "14:10:9f", "14:7d:da", "14:99:e2", "18:65:90", "1c:36:bb", "1c:ab:a7",
    "28:cf:da", "28:e0:2c", "2c:be:08", "2c:f0:5d", "34:15:9e", "34:a8:eb",
    "34:c9:f0", "38:c9:86", "3c:07:54", "3c:15:c2", "3c:d9:2b", "40:6c:8f",
    "44:00:10", "44:d8:84", "48:43:7c", "48:60:bc", "48:e1:5c", "4c:32:75",
    "4c:6e:6e", "50:76:af", "50:a7:2b", "54:9e:2a", "58:55:ca", "58:8d:09",
    "5c:ad:cf", "60:03:08", "60:33:4b", "60:92:12", "60:f6:77", "64:76:ba",
    "64:a2:f9", "68:5b:35", "68:9c:70", "68:a0:3e", "6c:70:9f", "6c:96:cf",
    "70:14:a6", "70:3e:ac", "70:73:cb", "70:cd:60", "74:9e:af", "78:4f:43",
    "78:7b:8a", "7c:04:d0", "7c:11:be", "7c:6a:65", "7c:c3:a1", "80:7a:bf",
    "80:be:05", "80:d0:9b", "84:38:35", "84:7b:3b", "84:89:ad", "88:1f:a1",
    "88:53:2e", "88:66:5a", "88:e9:fe", "8c:2d:aa", "8c:58:77", "94:ef:e4",
    "98:01:a7", "98:da:92", "a0:51:0b", "a0:99:9b", "a4:d1:d2", "a8:86:dd",
    "a8:be:27", "ac:29:3a", "b0:65:bd", "b4:0b:44", "b4:86:55", "b8:4c:75",
    "b8:86:87", "b8:e8:56", "bc:4c:c4", "bc:d0:74", "c0:8c:60", "c8:4c:75",
    "c8:5b:76", "c8:c2:8b", "cc:5c:75", "cc:79:cf", "cc:aa:5a", "d0:03:4b",
    "d0:a6:37", "d4:61:da", "d4:9a:20", "d8:30:62", "d8:9e:f3", "dc:2b:61",
    "dc:37:14", "dc:4f:22", "dc:9c:9f", "e0:ac:cb", "e0:b9:4d", "e4:8b:7f",
    "e4:c8:1c", "e8:50:8b", "ec:85:2f", "f0:18:98", "f0:79:59", "f0:d5:bf",
    "f4:0f:24", "f4:5c:89", "f8:1e:df", "f8:1f:3f", "fc:25:3f", "fc:db:b3",
]

let samsungOUIs: Set<String> = [
    "00:15:99", "00:1a:a1", "00:1e:e0", "00:23:d4", "00:24:1d", "00:26:37",
    "00:30:31", "00:3b:8b", "00:50:55", "08:00:28", "08:21:ef", "0c:5a:19",
    "0c:6e:0f", "0c:84:0a", "0c:93:fb", "10:0d:32", "10:68:8d", "10:d5:9b",
    "14:5a:fc", "14:b4:f6", "18:35:d1", "1c:5a:3b", "1c:b0:94", "20:35:64",
    "20:3a:07", "20:4c:9e", "20:5d:47", "24:0a:c4", "24:19:ab", "24:4b:03",
    "28:6a:b5", "28:98:7b", "2c:00:fe", "2c:10:c1", "2c:20:3b", "2c:44:fd",
    "2c:59:e5", "2c:5d:34", "2c:8a:72", "30:14:4a", "30:45:96", "34:29:8f",
    "34:5d:a8", "34:e2:fd", "38:08:e2", "38:5a:f4", "38:7a:ca", "38:bb:23",
    "3c:08:f6", "3c:10:e1", "3c:52:11", "3c:e5:a6", "3c:f7:20", "40:16:f9",
    "40:1a:05", "40:4e:36", "40:61:86", "44:03:2c", "44:2c:05", "44:5a:fc",
    "44:71:6d", "44:8a:5b", "48:4b:aa", "48:59:29", "48:d0:cf", "48:e6:6d",
    "4c:0f:6e", "4c:17:44", "4c:34:88", "4c:49:e3", "4c:ac:0a", "50:3d:e5",
    "50:47:b9", "50:5a:cf", "50:6f:9a", "50:7e:5d", "50:b6:40", "50:bd:5f",
    "54:04:0f", "54:1a:68", "54:2a:a2", "54:4a:16", "54:6d:0d", "54:6e:8b",
    "54:72:4f", "54:7c:69", "54:95:62", "54:a9:41", "54:e4:bd", "58:46:e3",
    "58:6b:14", "58:8a:5a", "58:a0:6f", "58:b0:35", "58:c3:8b", "5c:49:79",
    "5c:51:4f", "5c:5f:67", "5c:7d:5e", "5c:e2:0c", "5c:f2:09", "5c:f3:80",
    "60:1f:c5", "60:57:18", "60:64:0d", "60:66:11", "60:6b:4d", "60:ab:14",
    "60:d0:a9", "60:e7:01", "64:1c:67", "64:1c:b0", "64:66:b3", "64:6b:8b",
    "64:a3:03", "64:db:81", "68:17:29", "68:1e:8b", "68:27:37", "68:8f:12",
    "68:93:39", "68:9e:ef", "68:df:dd", "6c:0e:0d", "6c:29:0e", "6c:56:97",
    "6c:5a:b0", "6c:71:d9", "6c:72:e7", "6c:83:36", "6c:c6:ec", "70:3a:88",
    "70:54:d2", "70:5d:23", "70:85:c2", "70:8b:cd", "70:8d:09", "70:90:2c",
    "70:9e:29", "70:b3:d5", "70:d4:f2", "70:f0:87", "74:40:2b", "74:75:4a",
    "74:a5:8c", "74:b5:7e", "74:bd:be", "74:cd:0c", "74:e5:0b", "74:f6:18",
    "78:28:f3", "78:4b:7e", "78:52:1a", "78:7c:7d", "78:a3:22", "78:ab:60",
    "7c:03:4c", "7c:11:96", "7c:2c:cd", "7c:4a:8e", "7c:4d:8f", "7c:5c:f8",
    "7c:61:93", "7c:a1:ae", "7c:c7:09", "7c:dd:11", "7c:e0:8c", "80:1f:12",
    "80:3f:fa", "80:5e:c0", "80:7e:bf", "80:91:aa", "80:b5:5a", "84:0f:f2",
    "84:2b:2b", "84:34:97", "84:41:66", "84:61:1e", "84:78:ac", "84:90:73",
    "84:a9:38", "84:cf:37", "84:e3:42", "88:36:6c", "88:74:e7", "88:75:45",
    "88:93:10", "88:97:df", "88:a2:5e", "88:d7:f6", "88:dd:79", "8c:04:ff",
    "8c:44:e2", "8c:5a:f8", "8c:69:6a", "8c:71:f8", "8c:73:92", "8c:77:12",
    "8c:7a:15", "8c:8e:76", "8c:97:ea", "8c:b7:f7", "8c:b8:4a", "8c:de:52",
    "90:17:ac", "90:57:88", "90:5c:44", "90:5e:6b", "90:66:45", "90:b0:ed",
    "90:b6:86", "90:ca:da", "90:d6:8c", "90:f7:b2", "94:10:3e", "94:15:a7",
    "94:42:0a", "94:50:cc", "94:51:3b", "94:67:38", "94:9a:a9", "94:ae:d3",
    "94:d4:e9", "94:d9:bc", "98:0d:2e", "98:0f:29", "98:2c:be", "98:7b:3d",
    "98:c3:eb", "98:d6:bb", "9c:02:98", "9c:20:7b", "9c:28:bf", "9c:2e:a1",
    "9c:3a:af", "9c:4e:36", "9c:5c:8e", "9c:6a:bd", "9c:8d:7c", "9c:93:4e",
    "9c:b6:54", "9c:b7:0d", "9c:b7:93", "9c:d2:4b", "9c:d3:6d", "a0:10:80",
    "a0:14:3d", "a0:20:a6", "a0:2f:3f", "a0:3b:e3", "a0:43:9b", "a0:4e:a7",
    "a0:6c:ec", "a0:77:71", "a0:8c:15", "a0:a0:8f", "a0:b4:a5", "a0:b9:ed",
    "a0:ce:c8", "a0:d0:ef", "a0:e2:03",     "a0:f0:00",
]

func lookupVendor(_ mac: String) -> String? {
    let prefix = mac.split(separator: ":").prefix(3).joined(separator: ":")
    if appleOUIs.contains(prefix) { return "Apple" }
    if samsungOUIs.contains(prefix) { return "Samsung" }
    return nil
}

func computeChecksum(_ data: [UInt8]) -> UInt16 {
    var sum: UInt32 = 0
    var i = 0
    while i < data.count - 1 {
        sum += UInt32(UInt16(data[i]) << 8 | UInt16(data[i + 1]))
        i += 2
    }
    if i < data.count {
        sum += UInt32(UInt16(data[i]) << 8)
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16)
    }
    return ~UInt16(truncatingIfNeeded: sum)
}

private func buildTCPSYN(ourMAC: MACAddr, theirMAC: MACAddr, ourIP: String, theirIP: String,
                         srcPort: UInt16, dstPort: UInt16) -> [UInt8]? {
    guard let srcBytes = ipToBytes(ourIP), let dstBytes = ipToBytes(theirIP) else { return nil }
    let seq = UInt32.random(in: 0...UInt32.max)

    // IP header (20 bytes)
    var ip = [UInt8](repeating: 0, count: 20)
    ip[0] = 0x45
    ip[2] = 0; ip[3] = 40
    ip[4] = UInt8.random(in: 0...255); ip[5] = UInt8.random(in: 0...255)
    ip[6] = 0x40; ip[7] = 0
    ip[8] = 64; ip[9] = 6
    ip[12] = srcBytes[0]; ip[13] = srcBytes[1]; ip[14] = srcBytes[2]; ip[15] = srcBytes[3]
    ip[16] = dstBytes[0]; ip[17] = dstBytes[1]; ip[18] = dstBytes[2]; ip[19] = dstBytes[3]

    let ipCS = computeChecksum(ip)
    ip[10] = UInt8(ipCS >> 8); ip[11] = UInt8(ipCS & 0xFF)

    // TCP header (20 bytes)
    var tcp = [UInt8](repeating: 0, count: 20)
    tcp[0] = UInt8(srcPort >> 8); tcp[1] = UInt8(srcPort & 0xFF)
    tcp[2] = UInt8(dstPort >> 8); tcp[3] = UInt8(dstPort & 0xFF)
    tcp[4] = UInt8((seq >> 24) & 0xFF); tcp[5] = UInt8((seq >> 16) & 0xFF)
    tcp[6] = UInt8((seq >> 8) & 0xFF); tcp[7] = UInt8(seq & 0xFF)
    tcp[12] = 0x50; tcp[13] = 0x02
    tcp[14] = 0xFF; tcp[15] = 0xFF
    // checksum at 16,17
    // urgent ptr at 18,19

    // TCP checksum with pseudo-header
    var pseudo = [UInt8]()
    pseudo.append(contentsOf: srcBytes)
    pseudo.append(contentsOf: dstBytes)
    pseudo.append(0); pseudo.append(6)
    pseudo.append(0); pseudo.append(20)
    pseudo.append(contentsOf: tcp)
    let tcpCS = computeChecksum(pseudo)
    tcp[16] = UInt8(tcpCS >> 8); tcp[17] = UInt8(tcpCS & 0xFF)

    // Assemble Ethernet frame
    var frame = [UInt8]()
    frame.append(contentsOf: macToBytes(theirMAC))
    frame.append(contentsOf: macToBytes(ourMAC))
    frame.append(0x08); frame.append(0x00)
    frame.append(contentsOf: ip)
    frame.append(contentsOf: tcp)
    return frame
}

private func getICMPTTL(_ ip: String) -> UInt8? {
    let task = Process()
    task.executableURL = URL(fileURLWithPath: "/sbin/ping")
    task.arguments = ["-c", "1", "-t", "30", "-o", ip, "-q"]
    let out = Pipe()
    task.standardOutput = out
    task.standardError = Pipe()
    guard (try? task.run()) != nil else { return nil }
    task.waitUntilExit()

    guard let data = try? out.fileHandleForReading.readToEnd(),
          let output = String(data: data, encoding: .utf8) else { return nil }

    for line in output.components(separatedBy: "\n") {
        if let r = line.range(of: "ttl=") {
            let val = line[r.upperBound...].prefix(while: { $0.isNumber || $0.isWhitespace }).trimmingCharacters(in: .whitespaces)
            return UInt8(val)
        }
    }
    return nil
}

func classifyDevice(ttl: UInt8, openPorts: Set<Int>, mac: String = "") -> (type: DeviceType, confidence: Float) {
    let hasADB = openPorts.contains(5555)
    let hasAFC = openPorts.contains(62078)
    let hasSSH = openPorts.contains(22)
    let hasHTTP = openPorts.contains(80) || openPorts.contains(8080)
    let hasHTTPS = openPorts.contains(443) || openPorts.contains(8443)
    let hasWeb = hasHTTP || hasHTTPS
    let hasAirPlay = openPorts.contains(7000)
    let hasDAAP = openPorts.contains(5000)
    let vendor = lookupVendor(mac)

    // Definite matches
    if hasADB, ttl <= 64 { return (.android, 0.9) }
    if hasAFC, ttl <= 64 { return (.iphone, 0.9) }
    if hasAirPlay || hasDAAP { return (.macos, 0.8) }

    // TTL 128+ = Windows (common)
    if ttl >= 128, hasWeb, openPorts.count >= 2 { return (.windows, 0.7) }
    if ttl >= 128, hasWeb { return (.windows, 0.6) }
    if ttl >= 128 { return (.windows, 0.4) }

    // TTL 64 = Linux, macOS, Android, iOS
    if ttl <= 64 {
        if hasSSH, !hasWeb { return (.linux, 0.7) }
        if openPorts.count >= 2 { return (.linux, 0.5) }
        if vendor == "Apple" { return (.macos, 0.6) }
        if hasSSH { return (.linux, 0.6) }
        // No open ports + TTL 64 = mobile device (Android/iOS)
        if openPorts.isEmpty {
            if vendor == "Samsung" || vendor == nil { return (.android, 0.4) }
            return (.iphone, 0.4)
        }
        return (.unknown, 0.2)
    }

    if ttl == 255 { return (.router, 0.5) }
    return (.unknown, 0.1)
}

func fingerprintDevice(bpf: NetcutxBPF, ourMAC: MACAddr, ourIP: String,
                       targetMAC: MACAddr, targetIP: String) -> FingerprintResult {
    let srcPort = UInt16.random(in: 10000...60000)
    var openPorts = Set<Int>()
    var observedTTL: UInt8 = 0

    // Phase 1: send all SYN probes
    for p in probePorts {
        guard let frame = buildTCPSYN(ourMAC: ourMAC, theirMAC: targetMAC,
                                       ourIP: ourIP, theirIP: targetIP,
                                       srcPort: srcPort, dstPort: UInt16(p.port)) else { continue }
        try? bpf.send(frame: Data(frame))
    }

    // Phase 2: listen for SYN-ACK
    let deadline = Date().addingTimeInterval(2.5)
    while Date() < deadline {
        guard let pkt = try? bpf.receive(timeout: 0.1) else { continue }
        guard let info = parseIPPacket(pkt.data, targetFilter: targetIP) else { continue }
        guard info.srcIP == targetIP else { continue }

        let respPort = Int(info.srcPort)
        if info.flags?.contains("SYN") == true {
            openPorts.insert(respPort)
        }
        if observedTTL == 0 { observedTTL = info.ttl }
    }

    // Phase 3: TTL from ICMP fallback
    if observedTTL == 0, let ttl = getICMPTTL(targetIP) {
        observedTTL = ttl
    }

    let (type, conf) = classifyDevice(ttl: observedTTL, openPorts: openPorts)
    return FingerprintResult(deviceType: type, ttl: observedTTL,
                           openPorts: openPorts.sorted(), confidence: conf)
}

func fingerprintAllDevices(bpf: NetcutxBPF, ourMAC: MACAddr, ourIP: String, devices: inout [DeviceInfo]) {
    let targets = devices.filter { !$0.isSelf && !$0.isGateway }
    guard !targets.isEmpty else { return }

    status("Fingerprinting \(targets.count) devices...")
    let srcPort = UInt16.random(in: 10000...60000)
    var openPorts: [String: Set<Int>] = [:]
    var ttlObserved: [String: UInt8] = [:]

    for d in targets {
        guard let mac = stringToMAC(d.mac), !isAllZeroMAC(mac) else { continue }
        for p in probePorts {
            guard let frame = buildTCPSYN(ourMAC: ourMAC, theirMAC: mac,
                                           ourIP: ourIP, theirIP: d.ip,
                                           srcPort: srcPort, dstPort: UInt16(p.port)) else { continue }
            try? bpf.send(frame: Data(frame))
        }
    }

    let deadline = Date().addingTimeInterval(2.5)
    while Date() < deadline {
        guard let pkt = try? bpf.receive(timeout: 0.1) else { continue }
        guard let info = parseIPPacket(pkt.data) else { continue }
        guard targets.contains(where: { $0.ip == info.srcIP }) else { continue }

        let respPort = Int(info.srcPort)
        if info.flags?.contains("SYN") == true {
            openPorts[info.srcIP, default: []].insert(respPort)
        }
        if ttlObserved[info.srcIP] == nil { ttlObserved[info.srcIP] = info.ttl }
    }

    for i in devices.indices {
        if devices[i].isSelf || devices[i].isGateway { continue }
        let ip = devices[i].ip
        let ttl = ttlObserved[ip] ?? 0
        let ports = openPorts[ip] ?? []
        let (type, _) = classifyDevice(ttl: ttl, openPorts: ports, mac: devices[i].mac)
        devices[i].deviceType = type
    }
}

func standaloneFingerprint(targetIP: String, interface: String? = nil) {
    let ifname: String
    if let provided = interface {
        ifname = provided
    } else if let detected = getDefaultInterface() {
        ifname = detected
    } else {
        fail("No interface detected")
        return
    }

    guard let ourIP = getInterfaceIP(ifname) else {
        fail("Cannot detect IP for \(ifname)")
        return
    }
    guard let ourMAC = getInterfaceMAC(ifname) else {
        fail("Cannot detect MAC")
        return
    }

    ok("Interface \(ifname) — \(ourIP)")
    status("Resolving MAC for \(targetIP)...")

    let bpf: NetcutxBPF
    do {
        bpf = try NetcutxBPF(interface: ifname)
    } catch {
        fail("BPF: \(error.localizedDescription)")
        return
    }
    defer { bpf.close() }

    guard let targetMAC = try? resolveMAC(bpf: bpf, ourMAC: ourMAC, ourIP: ourIP, targetIP: targetIP) else {
        fail("Cannot resolve MAC for \(targetIP)")
        return
    }
    ok("\(targetIP) = \(macToString(targetMAC))")

    status("Probing \(probePorts.count) ports...")
    let result = fingerprintDevice(bpf: bpf, ourMAC: ourMAC, ourIP: ourIP,
                                   targetMAC: targetMAC, targetIP: targetIP)

    print("")
    print("  ── Fingerprint Result ──")
    print("  Device    : \(targetIP)")
    print("  MAC       : \(macToString(targetMAC))")
    print("  OS        : \(result.deviceType.rawValue) (\(Int(result.confidence * 100))% confidence)")
    print("  TTL       : \(result.ttl)")
    print("  Open ports: \(result.openPorts.isEmpty ? "none" : result.openPorts.map(String.init).joined(separator: ", "))")
    print("")
}
