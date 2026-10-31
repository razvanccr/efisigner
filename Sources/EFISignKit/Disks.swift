import Foundation

public struct EFIPartition: Identifiable, Hashable {
    public let id: String            // e.g. disk1s2
    public let volumeName: String
    public let mountPoint: String?
    public let size: Int64
    public let diskID: String
    public let diskName: String
    public let isInternal: Bool
    public let isRemovable: Bool
    public let partitionUUID: String?
    public var isMounted: Bool { mountPoint != nil }
}

public enum Tool {
    public struct Result { public let status: Int32; public let stdout: Data; public let stderr: String }

    @discardableResult
    public static func run(_ path: String, _ args: [String], timeout: TimeInterval = 120) throws -> Result {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: path)
        p.arguments = args
        let out = Pipe(), err = Pipe()
        p.standardOutput = out
        p.standardError = err
        try p.run()
        let outData = out.fileHandleForReading.readDataToEndOfFile()
        let errData = err.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        return Result(status: p.terminationStatus, stdout: outData, stderr: String(decoding: errData, as: UTF8.self))
    }
}

public enum DiskTools {
    static let deviceIDPattern = try! NSRegularExpression(pattern: "^disk[0-9]+s[0-9]+$")

    static func isDeviceID(_ s: String) -> Bool {
        deviceIDPattern.firstMatch(in: s, range: NSRange(s.startIndex..., in: s)) != nil
    }

    static func plist(_ args: [String]) throws -> [String: Any] {
        let r = try Tool.run("/usr/sbin/diskutil", args)
        guard r.status == 0, let obj = try? PropertyListSerialization.propertyList(from: r.stdout, format: nil),
              let dict = obj as? [String: Any] else { throw SignError.tool("diskutil \(args.joined(separator: " ")) failed: \(r.stderr)") }
        return dict
    }

    public static func listEFIPartitions() throws -> [EFIPartition] {
        let list = try plist(["list", "-plist"])
        var out: [EFIPartition] = []
        for disk in list["AllDisksAndPartitions"] as? [[String: Any]] ?? [] {
            guard let diskID = disk["DeviceIdentifier"] as? String else { continue }
            let parts = disk["Partitions"] as? [[String: Any]] ?? []
            guard parts.contains(where: { ($0["Content"] as? String) == "EFI" }) else { continue }
            let diskInfo = (try? plist(["info", "-plist", diskID])) ?? [:]
            let diskName = (diskInfo["MediaName"] as? String) ?? diskID
            let isInternal = (diskInfo["Internal"] as? Bool) ?? true
            let isRemovable = (diskInfo["RemovableMedia"] as? Bool) ?? ((diskInfo["Removable"] as? Bool) ?? false)
            for p in parts where (p["Content"] as? String) == "EFI" {
                guard let id = p["DeviceIdentifier"] as? String else { continue }
                let info = (try? plist(["info", "-plist", id])) ?? [:]
                let mp = (info["MountPoint"] as? String).flatMap { $0.isEmpty ? nil : $0 }
                out.append(EFIPartition(
                    id: id,
                    volumeName: (p["VolumeName"] as? String).flatMap { $0.isEmpty ? nil : $0 } ?? "EFI",
                    mountPoint: mp,
                    size: (p["Size"] as? Int64) ?? Int64((p["Size"] as? Int) ?? 0),
                    diskID: diskID, diskName: diskName, isInternal: isInternal, isRemovable: isRemovable,
                    partitionUUID: (info["DiskUUID"] as? String) ?? (info["VolumeUUID"] as? String)))
            }
        }
        return out
    }

    /// Mounts an EFI partition, asking for administrator rights through the system dialog.
    public static func mount(_ id: String) throws {
        guard isDeviceID(id) else { throw SignError.tool("bad device id") }
        let script = "do shell script \"/usr/sbin/diskutil mount \(id)\" with administrator privileges"
        let r = try Tool.run("/usr/bin/osascript", ["-e", script])
        guard r.status == 0 else {
            if r.stderr.contains("-128") { throw SignError.tool("Mount cancelled") }
            throw SignError.tool("Mount failed: \(r.stderr.trimmingCharacters(in: .whitespacesAndNewlines))")
        }
    }

    public static func unmount(_ id: String) throws {
        guard isDeviceID(id) else { throw SignError.tool("bad device id") }
        let r = try Tool.run("/usr/sbin/diskutil", ["unmount", id])
        guard r.status == 0 else { throw SignError.tool("Unmount failed: \(r.stderr.trimmingCharacters(in: .whitespacesAndNewlines))") }
    }
}
