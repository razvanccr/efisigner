import Foundation
import EFISignKit

func usage() -> Never {
    print("""
    usage:
      efisign hash <file.efi>
      efisign inspect <file.efi>...
      efisign sign --key db.key --cert db.crt [--out out.efi] <file.efi>...
      efisign esl --cert db.crt --out db.esl
      efisign scan [mountpoint] [--cert db.crt]
      efisign firmware
      efisign disks
      efisign strip <file.efi>...        (remove the signature in place)
      efisign revert --backups <folder> <mountpoint> [relative/path.efi ...]   (restore from backups, else strip)
      efisign fix-config <mountpoint> secure-boot-model|security-policy|disable-tool:<name>
    """)
    exit(2)
}

var args = Array(CommandLine.arguments.dropFirst())
guard let cmd = args.first else { usage() }
args.removeFirst()

func option(_ name: String) -> String? {
    guard let i = args.firstIndex(of: name), i + 1 < args.count else { return nil }
    let v = args[i + 1]; args.removeSubrange(i...(i + 1)); return v
}

func hex(_ d: Data) -> String { d.map { String(format: "%02x", $0) }.joined() }
func pad(_ s: String, _ n: Int) -> String { s.count >= n ? s + " " : s + String(repeating: " ", count: n - s.count) }

do {
    switch cmd {
    case "hash":
        for f in args { print(hex(try PEImage(data: Data(contentsOf: URL(fileURLWithPath: f))).sha256), f) }
    case "inspect":
        for f in args {
            switch Inspector.inspect(URL(fileURLWithPath: f)) {
            case .notPE(let why): print("\(f): not a PE image (\(why))")
            case .unsigned: print("\(f): UNSIGNED")
            case .appleFormat: print("\(f): Apple EFI signature format (not PKCS#7)")
            case .signed(let i):
                print("\(f): \(i.isValid ? "VALID" : "INVALID") signer=\(i.signerName) issuer=\(i.issuerName) alg=\(i.digestAlgorithm)")
                print("   digest in sig: \(hex(i.digestInSignature))\n   computed:      \(hex(i.computedDigest))")
                if !i.problems.isEmpty { print("   problems: \(i.problems.joined(separator: "; "))") }
            }
        }
    case "sign":
        guard let key = option("--key"), let cert = option("--cert") else { usage() }
        let out = option("--out")
        let id = try SigningIdentity.load(keyURL: URL(fileURLWithPath: key), certificateURL: URL(fileURLWithPath: cert))
        for f in args {
            let (signed, hash) = try Authenticode.sign(image: Data(contentsOf: URL(fileURLWithPath: f)), identity: id)
            let dest = out ?? f
            try signed.write(to: URL(fileURLWithPath: dest), options: .atomic)
            print("signed \(dest)  sha256=\(hex(hash))")
        }
    case "esl":
        guard let cert = option("--cert"), let out = option("--out") else { usage() }
        let der = try SigningIdentity.certificateDER(from: Data(contentsOf: URL(fileURLWithPath: cert)))
        try Authenticode.makeESL(certificateDER: der).write(to: URL(fileURLWithPath: out))
        print("wrote \(out)")
    case "scan":
        let certPath = option("--cert")
        let trusted = try certPath.map { try SigningIdentity.certificateDER(from: Data(contentsOf: URL(fileURLWithPath: $0))) }
        let mps = args.isEmpty ? try DiskTools.listEFIPartitions().compactMap { $0.mountPoint } : args
        for mp in mps {
            let (entries, config) = Scanner.scan(mountPoint: mp, trustedCertificateDER: trusted)
            print("== \(mp)")
            if let c = config {
                print("   OpenCore config: SecureBootModel=\(c.secureBootModel ?? "?") Vault=\(c.vault ?? "?")")
                for w in c.warnings { print("   ! \(w.message)" + (w.fix.map { "  [fix: \($0.title)]" } ?? "")) }
            }
            for e in entries {
                print("   " + pad(e.relativePath, 34) + pad(e.verdict.rawValue, 28) + pad(e.role.rawValue, 24) + e.signerDescription)
            }
        }
    case "strip":
        for f in args {
            var pe = try PEImage(data: Data(contentsOf: URL(fileURLWithPath: f)))
            if pe.stripSignature() { pe.updateChecksum(); try pe.data.write(to: URL(fileURLWithPath: f), options: .atomic); print("stripped \(f)") }
            else { print("\(f): no signature") }
        }
    case "revert":
        guard let backups = option("--backups"), let mp = args.first else { usage() }
        let (entries, _) = Scanner.scan(mountPoint: mp, trustedCertificateDER: nil)
        let wanted = Set(args.dropFirst().map { $0.lowercased() })
        for e in entries where wanted.isEmpty || wanted.contains(e.relativePath.lowercased()) {
            let o = RestoreService.revert(e, backupFolders: [URL(fileURLWithPath: backups)])
            print(o.error.map { "FAILED \(e.relativePath): \($0)" } ?? "reverted \(e.relativePath): \(o.method ?? "")")
        }
    case "disks":
        for p in try DiskTools.listEFIPartitions() {
            print(pad(p.id, 10) + pad(p.volumeName, 12) + pad(p.isMounted ? (p.mountPoint ?? "") : "not mounted", 24)
                  + pad(ByteCountFormatter.string(fromByteCount: p.size, countStyle: .file), 12) + p.diskName
                  + (p.isRemovable ? " (removable)" : "") + (p.isInternal ? " (internal)" : " (external)"))
        }
    case "fix-config":
        guard args.count == 2 else { usage() }
        let fix: ConfigFix
        switch args[1] {
        case "secure-boot-model": fix = .secureBootModelDefault
        case "security-policy": fix = .disableSecurityPolicyOff
        case let s where s.hasPrefix("disable-tool:"): fix = .disableTool(String(s.dropFirst("disable-tool:".count)))
        default: usage()
        }
        try OpenCoreConfig.apply(fix, espRoot: URL(fileURLWithPath: args[0]), backupRoot: nil)
        print("applied: \(fix.title)")
    case "firmware":
        let s = FirmwareState.read()
        print(s.summary)
        print("Setup mode: \(s.setupMode.map(String.init) ?? "unknown")")
        print("OpenCore: \(s.openCoreVersion ?? "not detected")")
        print("Apple Secure Boot policy: \(s.appleSecureBootPolicy.map(String.init) ?? "unknown")")
    default: usage()
    }
} catch {
    FileHandle.standardError.write("error: \(error.localizedDescription)\n".data(using: .utf8)!)
    exit(1)
}
