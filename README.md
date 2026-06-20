# netcutx

LAN access control tool for macOS. Cuts or intercepts network connections on your local network via ARP spoofing.

> **For authorized use only.** Use on networks you own or have explicit permission to test.

## Features

- Auto-detect interface, gateway, and local devices
- Network scan via ARP (active + cache)
- **Multi-target mass deauth** — cut multiple devices simultaneously (`3,4,5` or `all`)
- Two attack modes: cut connection or full MITM
- **Background daemon** — auto-starts on every network connect, survives disconnect/reconnect
- **Menubar GUI** — native macOS status bar app with live target list and stop/scan controls
- Graceful ARP restore on exit

## Requirements

- macOS 13+
- Xcode Command Line Tools
- `sudo` (BPF requires root)

## Build

```bash
# Build CLI daemon only
make

# Build GUI app only
make ui

# Build everything
make && make ui
```

Outputs:
- `build/netcutx` — CLI + daemon binary
- `build/NetcutxUI` — GUI binary
- `build/NetcutxUI.app` — macOS app bundle (after `make app`)

## Quick Start (daemon + GUI)

```bash
# 1. Build
make && make app

# 2. Install daemon (runs as root on every boot)
sudo ./build/netcutx install

# 3. Install GUI to ~/Applications and open it
make install-app
```

From that point: connect to any WiFi → daemon auto-scans + cuts all devices.  
Control via menubar icon `🛡`.

---

## Daemon

### Install

```bash
sudo ./build/netcutx install
```

Installs a LaunchDaemon (`/Library/LaunchDaemons/com.netcutx.daemon.plist`).  
Starts automatically on boot and on every network connect.

### Daemon behavior

| Event | Action |
|-------|--------|
| Connect to network | Scan all devices, start cutting all targets |
| Disconnect | Stop spoof, restore ARP tables |
| Reconnect (same or different network) | Rescan, start cutting again |
| Spoof thread crashes | Auto-restart |
| User stops via GUI | Stay idle until next network connect |

### Commands

```bash
sudo ./build/netcutx install      # Install and start daemon
sudo ./build/netcutx uninstall    # Remove daemon
sudo ./build/netcutx upgrade      # Rebuild and hot-reload running daemon
sudo ./build/netcutx stop all     # Stop active spoofing
sudo ./build/netcutx status       # Show daemon PID and status
```

### Upgrade workflow

```bash
make && sudo ./build/netcutx upgrade
```

Stops the running daemon cleanly (restores ARP tables), launchd auto-restarts it with the new binary.

### Logs

```bash
tail -f /var/log/netcutx.log
```

---

## Menubar GUI

```bash
make install-app
```

Installs `NetcutxUI.app` to `~/Applications` and opens it.  
No Dock icon — lives in the menu bar only.

### Menu

```
🛡  ← click
─────────────────────────
netcutx v1.0.0
─────────────────────────
🟢 Active
Interface: en0  192.168.1.12
─────────────────────────
Cutting (3 targets):
   · 192.168.1.3
   · 192.168.1.7
   · 192.168.1.11
─────────────────────────
Stop All          ⌘S
Scan Network      ⌘R
─────────────────────────
Open Log…         ⌘L
─────────────────────────
Quit              ⌘Q
```

### Icon states

| Icon | Meaning |
|------|---------|
| `🛡` | Actively spoofing |
| `🟡` | Manually stopped (won't auto-restart until next network connect) |
| `⚫` | Idle (no network or no targets found) |
| `⚠️` | Daemon not running |

### Stop All behavior

Clicking **Stop All** sends a stop signal to the daemon. The daemon:
1. Stops the spoof loop
2. Restores ARP tables for all targets
3. Enters idle state — **does not auto-restart** even though network is still connected

Auto-spoof resumes on the next network disconnect → reconnect, or by clicking **Scan Network**.

### IPC

GUI communicates with daemon via Unix socket `/var/run/netcutx.sock` (JSON protocol).  
Socket is world-readable so GUI runs without root.

---

## Interactive mode (manual)

```bash
sudo ./build/netcutx
```

1. Select network interface
2. Tool scans network, lists devices
3. Select target(s) — single, comma-separated, or `all`
4. Select attack mode
5. Confirm — spoofing starts
6. `Ctrl+C` to stop and restore ARP tables

### Multi-target selection

```
Pilih target [1-5] / pisah koma (mis: 3,4,5) / "all"  3,4,5
Pilih target [1-5] / pisah koma (mis: 3,4,5) / "all"  all
```

---

## CLI mode

```bash
sudo ./build/netcutx <victim-ip> [options]
```

| Option | Description |
|--------|-------------|
| `-i, --interface <name>` | Network interface (default: auto-detect) |
| `-g, --gateway <ip>` | Gateway IP (default: auto-detect) |
| `-r, --repeat <secs>` | Spoof interval in seconds (default: 2) |
| `-b, --bidirectional` | Bidirectional spoof (full MITM) |
| `-f, --forward` | Enable IP forwarding (use with `-b`) |
| `-v, --verbose` | Verbose output |

```bash
sudo ./build/netcutx 192.168.1.100
sudo ./build/netcutx 192.168.1.100 -b -f
sudo ./build/netcutx 192.168.1.100 -i en0 -g 192.168.1.1
```

---

## Attack modes

### Mode 1 — Cut connection

Poisons both ARP caches, drops all traffic. Target loses internet access.

Packets sent per interval:
- Unicast ARP reply to victim: `gateway IP → our MAC`
- Broadcast ARP: `gateway IP → our MAC`
- Unicast to gateway: `victim IP → our MAC`
- Broadcast: `victim IP → our MAC` (bypasses gateway ARP unicast filtering)

### Mode 2 — Full MITM (bidirectional)

Same as Mode 1 but enables IP forwarding. Traffic flows through attacker — intercept, inspect, or modify.

### Daemon mode (combined)

Daemon uses `bidirectional=true` + `forwardTraffic=false`: sends all bidirectional poison packets but drops traffic. Strongest cut — poisons both directions without forwarding.

---

## How it works

netcutx uses macOS BPF (Berkeley Packet Filter) to send raw Ethernet frames directly. No `libpcap` dependency — BPF accessed via `/dev/bpf*`.

```
Victim ARP cache:  gateway IP → attacker MAC  (victim sends to attacker)
Gateway ARP cache: victim IP  → attacker MAC  (gateway sends to attacker)

Without IP forwarding: packets dropped → target loses internet
With IP forwarding:    packets relayed → MITM
```

---

## Clean

```bash
make clean
```

## Version

v1.0.0
