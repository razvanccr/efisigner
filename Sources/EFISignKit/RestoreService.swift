import Foundation

/// Puts files back the way they were before signing.
public enum RestoreService {
    public struct Outcome {
        public let entry: EFIFileEntry
        public let method: String?
        public let error: String?
    }

    /// Restores `entry` from the oldest backup that holds it (the true original); if none exists,
    /// removes the signature instead, which leaves a functionally identical unsigned image.
    public static func revert(_ entry: EFIFileEntry, backupFolders: [URL]) -> Outcome {
        for folder in backupFolders {
            let src = folder.appendingPathComponent(entry.relativePath)
            guard FileManager.default.fileExists(atPath: src.path) else { continue }
            do {
                let data = try Data(contentsOf: src)
                _ = try PEImage(data: data)   // refuse to restore garbage over a bootloader
                try data.write(to: entry.url, options: .atomic)
                return Outcome(entry: entry, method: "restored from backup \(folder.lastPathComponent)", error: nil)
            } catch {
                return Outcome(entry: entry, method: nil, error: error.localizedDescription)
            }
        }
        do {
            var pe = try PEImage(data: Data(contentsOf: entry.url))
            guard pe.stripSignature() else {
                return Outcome(entry: entry, method: nil, error: "no backup found and the file carries no signature")
            }
            pe.updateChecksum()
            try pe.data.write(to: entry.url, options: .atomic)
            return Outcome(entry: entry, method: "signature removed (no backup found)", error: nil)
        } catch {
            return Outcome(entry: entry, method: nil, error: error.localizedDescription)
        }
    }

    /// The config.plist copies saved by Fix…, oldest first.
    public static func configBackups(in backupFolders: [URL]) -> [URL] {
        var out: [URL] = []
        for folder in backupFolders {
            let dir = folder.appendingPathComponent("EFI/OC")
            let names = (try? FileManager.default.contentsOfDirectory(atPath: dir.path)) ?? []
            out += names.filter { $0.hasPrefix("config.plist.") && $0.hasSuffix(".bak") }.sorted().map { dir.appendingPathComponent($0) }
        }
        return out
    }

    /// Restores the oldest saved config.plist (the one from before the first Fix…). The current
    /// file is saved alongside first, so this is reversible too.
    public static func restoreConfig(espRoot: URL, backupFolders: [URL]) throws -> String {
        guard let oldest = configBackups(in: backupFolders).first else { throw SignError.io("no config.plist backup found") }
        let url = OpenCoreConfig.configURL(espRoot: espRoot)
        let current = try Data(contentsOf: url)
        let restored = try Data(contentsOf: oldest)
        guard (try? PropertyListSerialization.propertyList(from: restored, format: nil)) != nil else { throw SignError.malformed("backup config.plist is not a valid plist") }
        let f = DateFormatter(); f.dateFormat = "yyyyMMdd-HHmmss"
        try current.write(to: oldest.deletingLastPathComponent().appendingPathComponent("config.plist.\(f.string(from: Date())).bak"))
        try restored.write(to: url, options: .atomic)
        return oldest.lastPathComponent
    }
}
