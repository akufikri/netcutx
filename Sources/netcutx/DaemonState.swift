import Foundation

// Shared state between daemon loop and IPC server (thread-safe)
final class DaemonState {
    private let lock = NSLock()
    private var _active  = false
    private var _targets: [String] = []
    private var _iface: String?
    private var _ip: String?

    func update(active: Bool, targets: [String], iface: String?, ip: String?) {
        lock.lock(); defer { lock.unlock() }
        _active  = active
        _targets = targets
        _iface   = iface
        _ip      = ip
    }

    func snapshot() -> (active: Bool, targets: [String], iface: String, ip: String) {
        lock.lock(); defer { lock.unlock() }
        return (_active, _targets, _iface ?? "", _ip ?? "")
    }
}

let sharedState = DaemonState()

// Separate exit flag for daemon loop (vs _stopFlag which is for spoof loop only)
var _daemonExitFlag: Int32 = 0

// Rescan request from GUI
var _rescanFlag: Int32 = 0

// Set to 1 when user manually stops — prevents auto-restart until next network connect
var _manualStopFlag: Int32 = 0
