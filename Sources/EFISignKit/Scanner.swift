import Foundation

public enum FileRole: String, CaseIterable {
    case openCore = "OpenCore"
    case bootstrap = "Fallback loader (BOOT)"
    case windows = "Windows Boot Manager"
    case linux = "Linux / shim"
    case appleUpdater = "Apple firmware updater"
    case appleBoot = "macOS boot file"
    case other = "Other"

    static func classify(_ relativePath: String) -> FileRole {
        let p = relativePath.lowercased()
        if p.hasPrefix("efi/oc/") { return .openCore }
        if p.hasPrefix("efi/boot/") { return .bootstrap }
        if p.hasPrefix("efi/microsoft/") { return .windows }
        if p.hasPrefix("efi/apple/") { return .appleUpdater }
        if p.hasSuffix("coreservices/boot.efi") || p.hasSuffix("/apfs.efi") || p.hasPrefix("system/library/") || p.hasPrefix("usr/standalone/") { return .appleBoot }
        if p.contains("shim") || p.contains("grub") || p.hasPrefix("efi/ubuntu/") || p.hasPrefix("efi/fedora/") || p.hasPrefix("efi/debian/") || p.hasPrefix("efi/systemd/") { return .linux }
        return .other
    }
}

public enum Verdict: String {
    case needsSignature = "Needs signing"
    case signedByUs = "Signed with your key"
    case signedOther = "Signed (other key)"
    case signedInvalid = "Signature broken"
    case disabledInConfig = "Not loaded (disabled in config)"
    case notLoaded = "Not loaded by firmware"
    case appleSigned = "Apple-signed, handled by OpenCore"
    case notPE = "Not a PE image"

    /// Would the firmware refuse this file under Secure Boot with only your key added?
    public var blocksSecureBoot: Bool { self == .needsSignature || self == .signedInvalid }
}

public struct EFIFileEntry: Identifiable {
    public let id: String
    public let url: URL
    public let relativePath: String
    public let size: Int64
    public let status: FileStatus
    public let role: FileRole
    public let loadedByConfig: Bool?
    public let verdict: Verdict

    public var signerDescription: String {
        switch status {
        case .notPE(let why): return why
        case .unsigned: return "—"
        case .appleFormat: return "Apple EFI signature (not PKCS#7)"
        case .signed(let info):
            var s = info.signerName
            if let na = info.notAfter {
                let f = DateFormatter(); f.dateStyle = .medium; f.timeStyle = .none
                s += " (until \(f.string(from: na)))"
            }
            if !info.problems.isEmpty { s += " · " + info.problems.joined(separator: "; ") }
            return s
        }
    }
}

public enum Scanner {
    public static func scan(mountPoint: String, trustedCertificateDER: Data?) -> (entries: [EFIFileEntry], config: OpenCoreConfig?) {
        let root = URL(fileURLWithPath: mountPoint)
        let config = OpenCoreConfig.load(espRoot: root)
        var entries: [EFIFileEntry] = []
        let fm = FileManager.default
        guard let en = fm.enumerator(at: root, includingPropertiesForKeys: [.fileSizeKey, .isRegularFileKey], options: [.skipsHiddenFiles]) else {
            return ([], config)
        }
        for case let url as URL in en {
            guard url.pathExtension.lowercased() == "efi", !url.lastPathComponent.hasPrefix("._"),
                  (try? url.resourceValues(forKeys: [.isRegularFileKey]).isRegularFile) == true else { continue }
            let rel = url.path.hasPrefix(root.path + "/") ? String(url.path.dropFirst(root.path.count + 1)) : url.lastPathComponent
            let size = Int64((try? url.resourceValues(forKeys: [.fileSizeKey]).fileSize) ?? 0)
            let status = Inspector.inspect(url)
            let role = FileRole.classify(rel)
            let loaded = config?.isLoaded(relativePath: rel)
            let verdict = verdict(for: status, role: role, loaded: loaded, trusted: trustedCertificateDER)
            entries.append(EFIFileEntry(id: url.path, url: url, relativePath: rel, size: size, status: status, role: role, loadedByConfig: loaded, verdict: verdict))
        }
        entries.sort { $0.relativePath.lowercased() < $1.relativePath.lowercased() }
        return (entries, config)
    }

    static func verdict(for status: FileStatus, role: FileRole, loaded: Bool?, trusted: Data?) -> Verdict {
        if case .notPE = status { return .notPE }
        if role == .appleUpdater { return .notLoaded }
        if role == .appleBoot { return .appleSigned }
        if case .appleFormat = status { return .appleSigned }
        if loaded == false { return .disabledInConfig }
        switch status {
        case .unsigned: return .needsSignature
        case .signed(let info):
            if !info.isValid { return .signedInvalid }
            if let t = trusted, info.signerCertificateDER == t { return .signedByUs }
            return .signedOther
        case .notPE: return .notPE
        case .appleFormat: return .appleSigned
        }
    }
}

public enum SignerService {
    public struct Outcome { public let entry: EFIFileEntry; public let hash: Data?; public let error: String? }

    /// Signs the file in place, keeping a copy of the original under backupRoot/<relativePath> (first time only).
    public static func sign(_ entry: EFIFileEntry, identity: SigningIdentity, backupRoot: URL?) -> Outcome {
        do {
            let original = try Data(contentsOf: entry.url)
            if let b = backupRoot {
                let dest = b.appendingPathComponent(entry.relativePath)
                try FileManager.default.createDirectory(at: dest.deletingLastPathComponent(), withIntermediateDirectories: true)
                if !FileManager.default.fileExists(atPath: dest.path) { try original.write(to: dest) }
            }
            let (signed, hash) = try Authenticode.sign(image: original, identity: identity)
            // Verify what we are about to write before touching the disk.
            guard case .signed(let info) = Inspector.inspect(data: signed), info.isValid, info.signerCertificateDER == identity.certificateDER else {
                throw SignError.crypto("self-check of the new signature failed; file left untouched")
            }
            try signed.write(to: entry.url, options: .atomic)
            return Outcome(entry: entry, hash: hash, error: nil)
        } catch {
            return Outcome(entry: entry, hash: nil, error: error.localizedDescription)
        }
    }
}
