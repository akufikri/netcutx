import Foundation

private let isoFmt: ISO8601DateFormatter = {
    let f = ISO8601DateFormatter()
    f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    return f
}()

struct PacketInfo {
    let ts: Date
    let srcIP: String
    let dstIP: String
    let srcPort: UInt16
    let dstPort: UInt16
    let proto: String
    let size: Int
    let ttl: UInt8
    let flags: String?
}

func parseIPPacket(_ data: Data, targetFilter: String? = nil, ourIP: String? = nil) -> PacketInfo? {
    guard data.count >= 34 else { return nil }

    let ethType = (UInt16(data[12]) << 8) | UInt16(data[13])
    guard ethType == 0x0800 else { return nil }

    let versionIHL = data[14]
    let ipHeaderLen = Int(versionIHL & 0x0F) * 4
    guard ipHeaderLen >= 20, data.count >= 14 + ipHeaderLen + 4 else { return nil }

    let protocolByte = data[23]
    guard protocolByte == 6 || protocolByte == 17 else { return nil }

    let src = "\(data[26]).\(data[27]).\(data[28]).\(data[29])"
    let dst = "\(data[30]).\(data[31]).\(data[32]).\(data[33])"
    let ttl = data[22]

    if let our = ourIP, src == our || dst == our { return nil }
    if let f = targetFilter { guard src == f || dst == f else { return nil } }

    let payloadStart = 14 + ipHeaderLen
    let totalLen = Int((UInt16(data[16]) << 8) | UInt16(data[17]))

    let sport: UInt16
    let dport: UInt16
    let pname: String
    var flags: String?

    if protocolByte == 6 {
        guard data.count >= payloadStart + 14 else { return nil }
        sport = (UInt16(data[payloadStart]) << 8) | UInt16(data[payloadStart + 1])
        dport = (UInt16(data[payloadStart + 2]) << 8) | UInt16(data[payloadStart + 3])
        pname = "TCP"
        let tcpFlags = data[payloadStart + 13]
        var fv: [String] = []
        if tcpFlags & 0x01 != 0 { fv.append("FIN") }
        if tcpFlags & 0x02 != 0 { fv.append("SYN") }
        if tcpFlags & 0x04 != 0 { fv.append("RST") }
        if tcpFlags & 0x08 != 0 { fv.append("PSH") }
        if tcpFlags & 0x10 != 0 { fv.append("ACK") }
        if tcpFlags & 0x20 != 0 { fv.append("URG") }
        if !fv.isEmpty { flags = fv.joined(separator: ",") }
    } else {
        guard data.count >= payloadStart + 8 else { return nil }
        sport = (UInt16(data[payloadStart]) << 8) | UInt16(data[payloadStart + 1])
        dport = (UInt16(data[payloadStart + 2]) << 8) | UInt16(data[payloadStart + 3])
        pname = "UDP"
    }

    return PacketInfo(
        ts: Date(), srcIP: src, dstIP: dst,
        srcPort: sport, dstPort: dport,
        proto: pname, size: totalLen,
        ttl: ttl, flags: flags
    )
}

func captureRun(interface: String, targetIP: String?, ourIP: String?, detectWA: Bool = false, harvestImages: Bool = false) {
    let bpf: NetcutxBPF
    do {
        bpf = try NetcutxBPF(interface: interface)
    } catch {
        statusErr("Capture: \(error.localizedDescription)")
        return
    }
    defer { bpf.close() }

    let harvester = harvestImages ? ImageHarvester() : nil
    if harvestImages { statusErr("Image harvest: \(ImageHarvester.Config().outputDir)") }

    statusErr("Capture running — \(interface)" + (targetIP.map { " filter: \($0)" } ?? "") + (detectWA ? " [WA detection ON]" : "") + (harvestImages ? " [Image harvest ON]" : ""))

    var count = 0
    let start = Date()

    while _stopFlag == 0 {
        guard let pkt = try? bpf.receive(timeout: 0.5) else { continue }
        guard let info = parseIPPacket(pkt.data, targetFilter: targetIP, ourIP: ourIP) else { continue }
        count += 1

        var obj: [String: Any] = [
            "ts": isoFmt.string(from: info.ts),
            "src": info.srcIP, "dst": info.dstIP,
            "sport": info.srcPort, "dport": info.dstPort,
            "proto": info.proto, "size": info.size,
            "ttl": info.ttl, "n": count
        ]
        if let f = info.flags { obj["flags"] = f }

        if let j = try? JSONSerialization.data(withJSONObject: obj),
           let s = String(data: j, encoding: .utf8) {
            print(s)
            fflush(stdout)
        }

        if detectWA, let wa = checkWA(in: pkt.data, info: info) {
            fputs("  \(wa)\n", stderr)
        }
        if let h = harvester, let target = targetIP {
            h.feed(payload: pkt.data, srcIP: info.srcIP, dstIP: info.dstIP,
                   srcPort: info.srcPort, dstPort: info.dstPort, targetIP: target)
        }
    }

    statusErr("Capture done — \(count) packets in \(Int(Date().timeIntervalSince(start)))s")
}

func standaloneCapture(targetIP: String? = nil, interface: String? = nil, detectWA: Bool = false, harvestImages: Bool = false) {
    let ifname: String
    if let provided = interface {
        ifname = provided
    } else if let detected = getDefaultInterface() {
        ifname = detected
    } else {
        fail("No interface detected. Use -i")
        return
    }

    guard let ourIP = getInterfaceIP(ifname) else {
        fail("Cannot detect IP for \(ifname)")
        return
    }

    statusErr("")
    statusErr("Interface \(ifname) — \(ourIP)")
    if let t = targetIP { statusErr("Filter target \(t)") }
    statusErr("Press Ctrl+C to stop")
    statusErr("JSON output on stdout — pipe to jq")
    statusErr("")

    setupSignal()
    captureRun(interface: ifname, targetIP: targetIP, ourIP: ourIP, detectWA: detectWA, harvestImages: harvestImages)
}

func statusErr(_ msg: String) {
    fputs("  \(msg)\n", stderr)
}
