import SwiftUI
import EFISignKit

@MainActor
final class AppModel: ObservableObject {
    @Published var partitions: [EFIPartition] = []
    @Published var selectedPartitionID: String?
    @Published var entries: [EFIFileEntry] = []
    @Published var config: OpenCoreConfig?
    @Published var firmware = FirmwareState.read()
    @Published var keyInfo: KeyStore.CertificateInfo?
    @Published var busy = false
    @Published var statusText = ""
    @Published var log: [String] = []
    @Published var errorMessage: String?
    @Published var selection = Set<String>()

    let keyStore = KeyStore()

    init() { keyInfo = keyStore.certificateInfo() }

    var selectedPartition: EFIPartition? { partitions.first { $0.id == selectedPartitionID } }
    var needsSigning: [EFIFileEntry] { entries.filter { $0.verdict.blocksSecureBoot } }
    var signedByUs: [EFIFileEntry] { entries.filter { $0.verdict == .signedByUs } }
    /// Everything that is a PE image the firmware could load (excludes Apple's updater files).
    var signable: [EFIFileEntry] {
        entries.filter { e in
            if case .notPE = e.status { return false }
            return e.role != .appleUpdater && e.role != .appleBoot && e.verdict != .disabledInConfig && e.verdict != .appleSigned
        }
    }
    var selectedEntries: [EFIFileEntry] { entries.filter { selection.contains($0.id) } }

    var readyForSecureBoot: Bool {
        guard selectedPartition?.isMounted == true else { return false }
        return needsSigning.isEmpty && (config?.warnings.isEmpty ?? true)
    }

    /// One sentence telling the user what to do now, derived from key, partition, config and firmware state.
    var nextStep: String? {
        guard let p = selectedPartition else { return "Select an EFI partition in the sidebar." }
        if !p.isMounted { return "Mount the partition to scan it (macOS will ask for your password)." }
        if busy { return nil }
        if !keyStore.exists { return "Generate or import a signing key from the Key menu, then come back here." }
        if let c = config, !c.warnings.isEmpty { return "Fix the config.plist warnings above with their Fix… buttons." }
        if !needsSigning.isEmpty { return "Press Sign needed to sign the \(needsSigning.count) file(s) the firmware would reject." }
        if p.isRemovable {
            return "All signed. Press Unmount, then test the stick: reboot, open the BIOS boot menu and pick it. OpenCore should start with Secure Boot on, using the certificate already enrolled."
        }
        switch firmware.secureBootEnabled {
        case .some(true):
            return "All signed and Secure Boot is enforced. Nothing to do until the next OpenCore update; then press Sign needed again."
        default:
            return "All signed. Key menu → Export certificate for BIOS onto a FAT32 stick, add db.cer to the BIOS db (Append, keep Microsoft's keys), enable Secure Boot and reboot."
        }
    }

    func appendLog(_ s: String) {
        let f = DateFormatter(); f.dateFormat = "HH:mm:ss"
        log.append("\(f.string(from: Date()))  \(s)")
        if log.count > 500 { log.removeFirst() }
    }

    func refreshDisks() {
        busy = true; statusText = "Looking for EFI partitions…"
        Task {
            do {
                let parts = try await Task.detached { try DiskTools.listEFIPartitions() }.value
                partitions = parts
                firmware = FirmwareState.read()
                if selectedPartitionID == nil || !parts.contains(where: { $0.id == selectedPartitionID }) {
                    selectedPartitionID = parts.first(where: { $0.isMounted && $0.isInternal })?.id ?? parts.first(where: { $0.isMounted })?.id ?? parts.first?.id
                }
                await rescan()
            } catch {
                errorMessage = error.localizedDescription
            }
            busy = false; statusText = ""
        }
    }

    func rescan() async {
        guard let p = selectedPartition, let mp = p.mountPoint else { entries = []; config = nil; selection = []; return }
        busy = true; statusText = "Scanning \(p.volumeName) (\(p.id))…"
        let trusted = keyStore.certificateDER
        let result = await Task.detached { Scanner.scan(mountPoint: mp, trustedCertificateDER: trusted) }.value
        entries = result.entries
        config = result.config
        selection = []
        busy = false; statusText = ""
        appendLog("Scanned \(p.id) \(p.volumeName): \(entries.count) EFI files, \(needsSigning.count) need signing")
    }

    func select(_ id: String?) {
        selectedPartitionID = id
        Task { await rescan() }
    }

    func mount(_ p: EFIPartition) {
        busy = true; statusText = "Mounting \(p.id)…"
        Task {
            do {
                try await Task.detached { try DiskTools.mount(p.id) }.value
                appendLog("Mounted \(p.id)")
                selectedPartitionID = p.id
                refreshDisks()
            } catch {
                errorMessage = error.localizedDescription
                busy = false; statusText = ""
            }
        }
    }

    func unmount(_ p: EFIPartition) {
        busy = true; statusText = "Unmounting \(p.id)…"
        Task {
            do {
                try await Task.detached { try DiskTools.unmount(p.id) }.value
                appendLog("Unmounted \(p.id)")
                refreshDisks()
            } catch {
                errorMessage = error.localizedDescription
                busy = false; statusText = ""
            }
        }
    }

    func sign(_ list: [EFIFileEntry]) {
        guard keyStore.exists else { errorMessage = "Generate or import a signing key first (Key menu)."; return }
        guard let p = selectedPartition, !list.isEmpty else { return }
        busy = true; statusText = "Signing \(list.count) file(s)…"
        Task {
            do {
                let identity = try keyStore.identity()
                let backup = keyStore.backupFolder(for: p)
                let outcomes = await Task.detached { list.map { SignerService.sign($0, identity: identity, backupRoot: backup) } }.value
                for o in outcomes {
                    if let e = o.error { appendLog("FAILED \(o.entry.relativePath): \(e)") }
                    else { appendLog("Signed \(o.entry.relativePath)") }
                }
                let failed = outcomes.filter { $0.error != nil }.count
                appendLog("Originals kept in \(backup.path)")
                if failed > 0 { errorMessage = "\(failed) file(s) could not be signed. See the log at the bottom." }
                await rescan()
            } catch {
                errorMessage = error.localizedDescription
                busy = false; statusText = ""
            }
        }
    }

    func applyFix(_ fix: ConfigFix) {
        guard let p = selectedPartition, let mp = p.mountPoint else { return }
        busy = true; statusText = "Updating config.plist…"
        let backup = keyStore.backupFolder(for: p)
        Task {
            do {
                try await Task.detached { try OpenCoreConfig.apply(fix, espRoot: URL(fileURLWithPath: mp), backupRoot: backup) }.value
                appendLog("config.plist: \(fix.title) (previous copy in \(backup.path))")
            } catch {
                errorMessage = error.localizedDescription
            }
            await rescan()
        }
    }

    var backupFoldersForSelection: [URL] { selectedPartition.map { keyStore.backupFolders(for: $0) } ?? [] }

    func hasBackup(_ e: EFIFileEntry) -> Bool {
        backupFoldersForSelection.contains { FileManager.default.fileExists(atPath: $0.appendingPathComponent(e.relativePath).path) }
    }
    /// Files Revert can act on: anything we kept a backup of, plus anything carrying our or a broken signature.
    func isRevertable(_ e: EFIFileEntry) -> Bool {
        e.verdict == .signedByUs || e.verdict == .signedInvalid || (e.verdict == .signedOther && hasBackup(e))
    }
    var revertable: [EFIFileEntry] { entries.filter(isRevertable) }
    var hasConfigBackup: Bool { !RestoreService.configBackups(in: backupFoldersForSelection).isEmpty }

    /// Restores files from their backups (or strips the signature when no backup exists).
    func revert(_ list: [EFIFileEntry]) {
        guard let p = selectedPartition, !list.isEmpty else { return }
        busy = true; statusText = "Reverting \(list.count) file(s)…"
        let folders = keyStore.backupFolders(for: p)
        Task {
            let outcomes = await Task.detached { list.map { RestoreService.revert($0, backupFolders: folders) } }.value
            for o in outcomes {
                if let e = o.error { appendLog("FAILED \(o.entry.relativePath): \(e)") }
                else { appendLog("Reverted \(o.entry.relativePath): \(o.method ?? "")") }
            }
            let failed = outcomes.filter { $0.error != nil }.count
            if failed > 0 { errorMessage = "\(failed) file(s) could not be reverted. See the log." }
            await rescan()
        }
    }

    func restoreConfig() {
        guard let p = selectedPartition, let mp = p.mountPoint else { return }
        busy = true; statusText = "Restoring config.plist…"
        let folders = keyStore.backupFolders(for: p)
        Task {
            do {
                let name = try await Task.detached { try RestoreService.restoreConfig(espRoot: URL(fileURLWithPath: mp), backupFolders: folders) }.value
                appendLog("config.plist restored from \(name)")
            } catch {
                errorMessage = error.localizedDescription
            }
            await rescan()
        }
    }

    func generateKey(commonName: String, years: Int) {
        busy = true; statusText = "Generating RSA key…"
        let store = keyStore
        Task {
            do {
                try await Task.detached { try store.generate(commonName: commonName, days: years * 365) }.value
                keyInfo = store.certificateInfo()
                appendLog("Generated signing key \"\(commonName)\" in \(store.directory.path)")
                await rescan()
            } catch {
                errorMessage = error.localizedDescription
            }
            busy = false; statusText = ""
        }
    }

    func importKey(key: URL, certificate: URL) {
        do {
            try keyStore.importKey(keyFile: key, certificateFile: certificate)
            keyInfo = keyStore.certificateInfo()
            appendLog("Imported key \(key.lastPathComponent) and certificate \(certificate.lastPathComponent)")
            Task { await rescan() }
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func exportCertificate(to folder: URL) {
        do {
            let files = try keyStore.exportCertificate(to: folder)
            appendLog("Exported \(files.map(\.lastPathComponent).joined(separator: ", ")) to \(folder.path)")
        } catch {
            errorMessage = error.localizedDescription
        }
    }
}
