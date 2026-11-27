import Crypto
import Foundation

public enum Machine {
    /// SHA-256 of the OS machine id salted with `salt`: 64 hex characters.
    /// On iOS there is no machine id: pass your own stable id as
    /// `Config.fingerprint` (for example `identifierForVendor`, hashed).
    public static func fingerprint(salt: String) throws -> String {
        hashComponent(salt: salt, name: "", value: try machineId())
    }

    /// Salted SHA-256 of one hardware value (the raw value never leaves the machine).
    public static func hashComponent(salt: String, name: String, value: String) -> String {
        let v = value.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        return hexString(SHA256.hash(data: Data((name.isEmpty ? "\(salt):\(v)" : "\(salt):\(name):\(v)").utf8)))
    }

    static let vmMarkers = ["vmware", "virtualbox", "kvm", "qemu", "xen", "hyper-v", "virtual machine",
                            "parallels", "bochs", "bhyve", "google compute engine", "amazon ec2", "openstack"]

    public static func looksVirtual(_ s: String) -> Bool {
        let l = s.lowercased()
        return vmMarkers.contains { l.contains($0) }
    }

    static func read(_ path: String) -> String {
        (try? String(contentsOfFile: path, encoding: .utf8)) ?? ""
    }

    #if os(macOS)
    static func sysctl(_ name: String) -> String {
        var size = 0
        guard sysctlbyname(name, nil, &size, nil, 0) == 0, size > 0 else { return "" }
        var buf = [CChar](repeating: 0, count: size)
        guard sysctlbyname(name, &buf, &size, nil, 0) == 0 else { return "" }
        return String(cString: buf)
    }
    #endif

    /// Whether this machine is a virtual machine or a container.
    public static var isVirtual: Bool {
        #if os(Linux)
        for f in ["/sys/class/dmi/id/product_name", "/sys/class/dmi/id/sys_vendor", "/sys/class/dmi/id/board_vendor"] where looksVirtual(read(f)) {
            return true
        }
        if FileManager.default.fileExists(atPath: "/.dockerenv") { return true }
        let cg = read("/proc/1/cgroup")
        return ["docker", "kubepods", "containerd", "lxc"].contains { cg.contains($0) }
        #elseif os(macOS)
        var v: Int32 = 0
        var size = MemoryLayout<Int32>.size
        return sysctlbyname("kern.hv_vmm_present", &v, &size, nil, 0) == 0 && v == 1
        #else
        return false
        #endif
    }

    static func cpuModel() -> String {
        #if os(Linux)
        for l in read("/proc/cpuinfo").split(separator: "\n") where (l.hasPrefix("model name") || l.hasPrefix("Hardware")) && l.contains(":") {
            return l.split(separator: ":", maxSplits: 1)[1].trimmingCharacters(in: .whitespaces)
        }
        return ""
        #elseif os(macOS)
        return sysctl("machdep.cpu.brand_string")
        #else
        return ""
        #endif
    }

    static func primaryMac() -> String {
        #if os(Linux)
        let names = ((try? FileManager.default.contentsOfDirectory(atPath: "/sys/class/net")) ?? []).sorted()
        for n in names where n != "lo" && !["docker", "veth", "br-", "virbr"].contains(where: { n.hasPrefix($0) }) {
            let mac = read("/sys/class/net/\(n)/address").trimmingCharacters(in: .whitespacesAndNewlines)
            if !mac.isEmpty && mac != "00:00:00:00:00:00" { return mac }
        }
        #endif
        return ""
    }

    /// What the app tells the shop: salted hashes of hardware components and the VM flag.
    public struct HardwareInfo {
        public let components: [String: String]
        public let isVirtual: Bool
    }

    /// Hashed components (machine_id, hostname, mac, cpu, os) and the VM flag.
    public static func collect(salt: String) -> HardwareInfo {
        var comps: [String: String] = [:]
        let values: [(String, String)] = [
            ("machine_id", (try? machineId()) ?? ""),
            ("hostname", ProcessInfo.processInfo.hostName),
            ("mac", primaryMac()),
            ("cpu", "\(cpuModel())|\(ProcessInfo.processInfo.processorCount)"),
            ("os", "\(platform)|\(arch)"),
        ]
        for (name, value) in values where !value.trimmingCharacters(in: .whitespaces).isEmpty {
            comps[name] = hashComponent(salt: salt, name: name, value: value)
        }
        return HardwareInfo(components: comps, isVirtual: isVirtual)
    }

    static func machineId() throws -> String {
        #if os(macOS)
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/sbin/ioreg")
        p.arguments = ["-rd1", "-c", "IOPlatformExpertDevice"]
        let pipe = Pipe()
        p.standardOutput = pipe
        try p.run()
        p.waitUntilExit()
        let out = String(decoding: pipe.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        if let line = out.split(separator: "\n").first(where: { $0.contains("IOPlatformUUID") }) {
            let parts = line.split(separator: "\"")
            if parts.count >= 4 { return String(parts[3]) }
        }
        #elseif os(Linux)
        for f in ["/etc/machine-id", "/var/lib/dbus/machine-id"] {
            if let v = try? String(contentsOfFile: f, encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines), !v.isEmpty {
                return v
            }
        }
        #endif
        throw LicenseError.config("machine id not found: set Config.fingerprint")
    }

    public static var platform: String {
        #if os(macOS)
        return "macos"
        #elseif os(iOS)
        return "ios"
        #elseif os(Linux)
        return "linux"
        #elseif os(Windows)
        return "windows"
        #else
        return "any"
        #endif
    }

    public static var arch: String {
        #if arch(x86_64)
        return "x64"
        #elseif arch(arm64)
        return "arm64"
        #else
        return "any"
        #endif
    }
}
