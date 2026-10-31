import SwiftUI
import AppKit
import EFISignKit

struct ContentView: View {
    @EnvironmentObject var model: AppModel
    @Environment(\.openWindow) private var openWindow
    @State private var showGenerate = false
    @State private var pendingSign: [EFIFileEntry] = []
    @State private var confirmSign = false
    @State private var pendingRevert: [EFIFileEntry] = []
    @State private var confirmRevert = false
    @State private var confirmRestoreConfig = false

    var body: some View {
        NavigationSplitView {
            SidebarView()
                .navigationSplitViewColumnWidth(min: 260, ideal: 300)
        } detail: {
            DetailView(requestSign: { list in pendingSign = list; confirmSign = true })
        }
        .toolbar { toolbar }
        .sheet(isPresented: $showGenerate) { GenerateKeySheet() }
        .confirmationDialog("Sign \(pendingSign.count) file(s) in place?", isPresented: $confirmSign, titleVisibility: .visible) {
            Button("Sign") { model.sign(pendingSign) }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("A copy of each original is kept in \(model.keyStore.backupsURL.path). Files already signed with another key are re-signed with yours.")
        }
        .confirmationDialog("Revert \(pendingRevert.count) file(s)?", isPresented: $confirmRevert, titleVisibility: .visible) {
            Button("Revert") { model.revert(pendingRevert) }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("Each file is put back from the backup made when it was first signed. If no backup exists, its signature is removed instead. Files signed by another key are only reverted when a backup of them exists, so Microsoft's loaders are never touched.")
        }
        .confirmationDialog("Restore the original config.plist?", isPresented: $confirmRestoreConfig, titleVisibility: .visible) {
            Button("Restore") { model.restoreConfig() }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("Puts back the copy saved before the first Fix… was applied. The current config.plist is saved in the Backups folder first.")
        }
        .alert("EFI Signer", isPresented: Binding(get: { model.errorMessage != nil }, set: { if !$0 { model.errorMessage = nil } })) {
            Button("OK") {}
        } message: { Text(model.errorMessage ?? "") }
        .onAppear { model.refreshDisks() }
        .frame(minWidth: 1000, minHeight: 620)
    }

    @ToolbarContentBuilder
    var toolbar: some ToolbarContent {
        ToolbarItemGroup {
            Button { model.refreshDisks() } label: { Label("Refresh", systemImage: "arrow.clockwise") }
                .help("Re-read the disk list and rescan the selected partition")
            if let p = model.selectedPartition {
                if p.isMounted {
                    Button { model.unmount(p) } label: { Label("Unmount", systemImage: "eject") }
                } else {
                    Button { model.mount(p) } label: { Label("Mount", systemImage: "externaldrive.badge.plus") }
                }
            }
            Divider()
            Button {
                pendingSign = model.needsSigning; confirmSign = true
            } label: { Label("Sign needed (\(model.needsSigning.count))", systemImage: "signature") }
                .disabled(model.needsSigning.isEmpty || model.busy)
                .help("Sign every file the firmware would reject under Secure Boot")
            Button {
                pendingSign = model.selectedEntries; confirmSign = true
            } label: { Label("Sign selected", systemImage: "checkmark.seal") }
                .disabled(model.selectedEntries.isEmpty || model.busy)
            Button {
                pendingSign = model.signable; confirmSign = true
            } label: { Label("Re-sign all", systemImage: "arrow.triangle.2.circlepath") }
                .disabled(model.signable.isEmpty || model.busy)
                .help("Re-sign every loadable EFI file with your key, including Windows and other loaders")
            Menu {
                Button("Revert selected files") { pendingRevert = model.selectedEntries.filter(model.isRevertable); confirmRevert = true }
                    .disabled(!model.selectedEntries.contains(where: model.isRevertable))
                Button("Revert all signed files (\(model.revertable.count))") { pendingRevert = model.revertable; confirmRevert = true }
                    .disabled(model.revertable.isEmpty)
                Divider()
                Button("Restore original config.plist…") { confirmRestoreConfig = true }
                    .disabled(!model.hasConfigBackup)
            } label: { Label("Revert", systemImage: "arrow.uturn.backward") }
                .disabled(model.busy || model.selectedPartition?.isMounted != true)
                .help("Put files or config.plist back the way they were before signing")
            Divider()
            Menu {
                Button("Generate new key…") { showGenerate = true }
                Button("Import key and certificate…") { importKey() }
                Divider()
                Button("Export certificate for BIOS…") { exportCert() }.disabled(!model.keyStore.exists)
                Button("Show key folder in Finder") { NSWorkspace.shared.activateFileViewerSelecting([model.keyStore.directory]) }
                Button("Show backups in Finder") { NSWorkspace.shared.activateFileViewerSelecting([model.keyStore.backupsURL]) }
            } label: { Label("Key", systemImage: "key") }
            Button { openWindow(id: "guide") } label: { Label("Guide", systemImage: "book") }
                .help("Step-by-step guide: signing, enrolling the certificate, keeping Secure Boot on")
        }
    }

    func importKey() {
        let p1 = NSOpenPanel(); p1.title = "Choose the private key (PEM, e.g. db.key)"; p1.canChooseDirectories = false
        guard p1.runModal() == .OK, let key = p1.url else { return }
        let p2 = NSOpenPanel(); p2.title = "Choose the certificate (PEM or DER, e.g. db.crt)"; p2.canChooseDirectories = false
        guard p2.runModal() == .OK, let cert = p2.url else { return }
        model.importKey(key: key, certificate: cert)
    }

    func exportCert() {
        let p = NSOpenPanel(); p.title = "Choose a folder (for example a FAT32 USB stick) for db.cer and db.esl"
        p.canChooseDirectories = true; p.canChooseFiles = false; p.canCreateDirectories = true; p.prompt = "Export here"
        guard p.runModal() == .OK, let dir = p.url else { return }
        model.exportCertificate(to: dir)
    }
}

struct SidebarView: View {
    @EnvironmentObject var model: AppModel

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            FirmwareView().padding(12)
            Divider()
            List(selection: Binding(get: { model.selectedPartitionID }, set: { model.select($0) })) {
                Section("EFI partitions") {
                    ForEach(model.partitions) { p in
                        PartitionRow(partition: p).tag(p.id)
                    }
                    if model.partitions.isEmpty { Text("None found").foregroundStyle(.secondary) }
                }
            }
        }
    }
}

struct FirmwareView: View {
    @EnvironmentObject var model: AppModel
    var body: some View {
        let f = model.firmware
        VStack(alignment: .leading, spacing: 4) {
            Label(f.summary, systemImage: f.secureBootEnabled == true ? "lock.shield.fill" : "lock.open")
                .foregroundStyle(f.secureBootEnabled == true ? Color.green : Color.orange)
                .font(.headline)
            if let oc = f.openCoreVersion {
                Text("OpenCore \(oc)").font(.caption).foregroundStyle(.secondary)
                Text("Apple Secure Boot policy: \(f.appleSecureBootPolicy.map { $0 == 0 ? "off" : "on (\($0))" } ?? "unknown")")
                    .font(.caption).foregroundStyle(.secondary)
            } else {
                Text("No OpenCore detected on this boot").font(.caption).foregroundStyle(.secondary)
            }
        }
    }
}

struct PartitionRow: View {
    let partition: EFIPartition
    var body: some View {
        HStack {
            Image(systemName: partition.isRemovable ? "externaldrive" : "internaldrive")
            VStack(alignment: .leading) {
                Text("\(partition.volumeName)  ·  \(partition.id)")
                Text("\(partition.diskName) · \(ByteCountFormatter.string(fromByteCount: partition.size, countStyle: .file))")
                    .font(.caption).foregroundStyle(.secondary)
            }
            Spacer()
            Circle().fill(partition.isMounted ? Color.green : Color.gray.opacity(0.4)).frame(width: 8, height: 8)
                .help(partition.isMounted ? "Mounted at \(partition.mountPoint ?? "")" : "Not mounted")
        }
        .padding(.vertical, 2)
    }
}

struct DetailView: View {
    @EnvironmentObject var model: AppModel
    let requestSign: ([EFIFileEntry]) -> Void
    @State private var pendingFix: ConfigFix?
    @State private var confirmFix = false

    var body: some View {
        content
            .confirmationDialog(pendingFix?.title ?? "Apply fix", isPresented: $confirmFix, titleVisibility: .visible) {
                Button("Apply to config.plist") { if let f = pendingFix { model.applyFix(f) } }
                Button("Cancel", role: .cancel) {}
            } message: {
                Text((pendingFix?.explanation ?? "") + "\n\nA copy of the current config.plist is saved in the Backups folder first.")
            }
    }

    var content: some View {
        VStack(spacing: 0) {
            if let p = model.selectedPartition {
                header(p)
                Divider()
                if p.isMounted {
                    if let c = model.config, !c.warnings.isEmpty {
                        ConfigWarnings(config: c, requestFix: { fix in pendingFix = fix; confirmFix = true })
                    }
                    FileTable()
                } else {
                    VStack(spacing: 12) {
                        Image(systemName: "externaldrive.badge.questionmark").font(.system(size: 40)).foregroundStyle(.secondary)
                        Text("This EFI partition is not mounted.").font(.title3)
                        Text("Mounting needs administrator rights; macOS will ask for your password.").foregroundStyle(.secondary)
                        Button("Mount \(p.id)") { model.mount(p) }.keyboardShortcut(.defaultAction)
                    }.frame(maxWidth: .infinity, maxHeight: .infinity)
                }
            } else {
                Text("Select an EFI partition").foregroundStyle(.secondary).frame(maxWidth: .infinity, maxHeight: .infinity)
            }
            Divider()
            KeyBar()
            LogView()
        }
    }

    func header(_ p: EFIPartition) -> some View {
        HStack(alignment: .top) {
            VStack(alignment: .leading, spacing: 4) {
                Text("\(p.volumeName) on \(p.diskName)").font(.title2).bold()
                Text("\(p.id) · \(p.mountPoint ?? "not mounted") · \(ByteCountFormatter.string(fromByteCount: p.size, countStyle: .file))")
                    .font(.callout).foregroundStyle(.secondary)
                if p.isMounted {
                    Text("\(model.entries.count) EFI files · \(model.needsSigning.count) need signing · \(model.signedByUs.count) signed with your key")
                        .font(.callout)
                }
                if let step = model.nextStep {
                    Label(step, systemImage: "arrow.turn.down.right")
                        .font(.callout)
                        .foregroundStyle(Color.accentColor)
                        .padding(.top, 4)
                }
            }
            Spacer()
            if p.isMounted {
                if model.busy {
                    HStack { ProgressView().controlSize(.small); Text(model.statusText).foregroundStyle(.secondary) }
                } else if model.readyForSecureBoot {
                    Label("Ready for Secure Boot", systemImage: "checkmark.shield.fill").foregroundStyle(.green).font(.headline)
                } else {
                    Label("Would be rejected under Secure Boot", systemImage: "exclamationmark.shield.fill").foregroundStyle(.red).font(.headline)
                }
            }
        }
        .padding(14)
    }
}

struct ConfigWarnings: View {
    @EnvironmentObject var model: AppModel
    let config: OpenCoreConfig
    let requestFix: (ConfigFix) -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Label("OpenCore config.plist", systemImage: "exclamationmark.triangle.fill").font(.headline).foregroundStyle(.orange)
            ForEach(config.warnings) { w in
                HStack(alignment: .top, spacing: 12) {
                    Text("• \(w.message)").font(.callout)
                        .frame(maxWidth: .infinity, alignment: .leading)
                    if let fix = w.fix {
                        Button("Fix…") { requestFix(fix) }.controlSize(.small).disabled(model.busy)
                    }
                }
            }
        }
        .padding(10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.orange.opacity(0.12))
    }
}

struct FileTable: View {
    @EnvironmentObject var model: AppModel

    var body: some View {
        Table(model.entries, selection: $model.selection) {
            TableColumn("File") { (e: EFIFileEntry) in
                Text(e.relativePath).font(.system(.body, design: .monospaced))
            }.width(min: 220, ideal: 300)
            TableColumn("Status") { (e: EFIFileEntry) in
                Label(e.verdict.rawValue, systemImage: icon(e.verdict)).foregroundStyle(color(e.verdict))
            }.width(min: 170, ideal: 220)
            TableColumn("Role") { (e: EFIFileEntry) in Text(e.role.rawValue) }.width(min: 120, ideal: 160)
            TableColumn("Signer") { (e: EFIFileEntry) in
                Text(e.signerDescription).lineLimit(1).truncationMode(.tail).help(e.signerDescription)
            }
            TableColumn("Size") { (e: EFIFileEntry) in
                Text(ByteCountFormatter.string(fromByteCount: e.size, countStyle: .file)).foregroundStyle(.secondary)
            }.width(70)
        }
        .contextMenu(forSelectionType: String.self) { ids in
            Button("Show in Finder") {
                NSWorkspace.shared.activateFileViewerSelecting(model.entries.filter { ids.contains($0.id) }.map(\.url))
            }
        }
    }

    func icon(_ v: Verdict) -> String {
        switch v {
        case .needsSignature: return "xmark.shield"
        case .signedByUs: return "checkmark.shield.fill"
        case .signedOther: return "checkmark.shield"
        case .signedInvalid: return "exclamationmark.shield"
        case .disabledInConfig, .notLoaded: return "minus.circle"
        case .appleSigned: return "apple.logo"
        case .notPE: return "questionmark.circle"
        }
    }

    func color(_ v: Verdict) -> Color {
        switch v {
        case .needsSignature, .signedInvalid: return .red
        case .signedByUs: return .green
        case .signedOther: return .blue
        case .disabledInConfig, .notLoaded, .notPE, .appleSigned: return .secondary
        }
    }
}

struct KeyBar: View {
    @EnvironmentObject var model: AppModel
    @Environment(\.openWindow) private var openWindow
    var body: some View {
        HStack {
            Image(systemName: "key.fill").foregroundStyle(model.keyInfo == nil ? Color.orange : Color.accentColor)
            if let k = model.keyInfo {
                Text("Signing key: \(k.subject)")
                if let na = k.notAfter {
                    Text("· certificate valid until \(na.formatted(date: .abbreviated, time: .omitted))").foregroundStyle(.secondary)
                }
            } else {
                Text("No signing key yet. Use the Key menu to generate one or import db.key and db.crt.").foregroundStyle(.orange)
                Button("Open the guide") { openWindow(id: "guide") }.controlSize(.small)
            }
            Spacer()
            Text(model.keyStore.directory.path).font(.caption).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
        }
        .padding(.horizontal, 14).padding(.vertical, 8)
    }
}

struct LogView: View {
    @EnvironmentObject var model: AppModel
    var body: some View {
        ScrollViewReader { proxy in
            ScrollView {
                VStack(alignment: .leading, spacing: 1) {
                    ForEach(Array(model.log.enumerated()), id: \.offset) { i, line in
                        Text(line).font(.system(.caption, design: .monospaced)).id(i)
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                }
                .padding(8)
            }
            .frame(height: 110)
            .background(Color(nsColor: .textBackgroundColor))
            .onChange(of: model.log.count) { _ in
                if let last = model.log.indices.last { proxy.scrollTo(last, anchor: .bottom) }
            }
        }
    }
}

struct GenerateKeySheet: View {
    @EnvironmentObject var model: AppModel
    @Environment(\.dismiss) var dismiss
    @State private var commonName = "OpenCore Secure Boot Signing"
    @State private var years = 10

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Generate a signing key").font(.title2).bold()
            Text("Creates an RSA-2048 key and a self-signed certificate. The certificate (db.cer) is what you add to the BIOS Secure Boot database; the key never leaves this Mac.")
                .foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            TextField("Certificate name", text: $commonName)
            Stepper("Valid for \(years) years", value: $years, in: 1...20)
            if model.keyStore.exists {
                Label("This replaces your current key. Files signed with the old key will show as \"other key\" and the old certificate stays in the BIOS until you remove it.", systemImage: "exclamationmark.triangle")
                    .foregroundStyle(.orange).fixedSize(horizontal: false, vertical: true)
            }
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
                Button("Generate") { model.generateKey(commonName: commonName, years: years); dismiss() }
                    .keyboardShortcut(.defaultAction).disabled(commonName.trimmingCharacters(in: .whitespaces).isEmpty)
            }
        }
        .padding(20)
        .frame(width: 460)
    }
}
