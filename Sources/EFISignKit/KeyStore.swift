import Foundation
import Security

/// Where the signing key, certificate and exported BIOS files live.
public final class KeyStore {
    public let directory: URL
    public var keyURL: URL { directory.appendingPathComponent("db.key") }
    public var certPEMURL: URL { directory.appendingPathComponent("db.crt") }
    public var certDERURL: URL { directory.appendingPathComponent("db.cer") }
    public var eslURL: URL { directory.appendingPathComponent("db.esl") }
    public var backupsURL: URL { directory.appendingPathComponent("Backups") }

    public init(directory: URL? = nil) {
        let appSupport = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
        self.directory = directory ?? appSupport.appendingPathComponent("EFI Signer")
        try? FileManager.default.createDirectory(at: self.directory, withIntermediateDirectories: true)
    }

    public var exists: Bool {
        FileManager.default.fileExists(atPath: keyURL.path) && FileManager.default.fileExists(atPath: certPEMURL.path)
    }

    public func identity() throws -> SigningIdentity {
        try SigningIdentity.load(keyURL: keyURL, certificateURL: certPEMURL)
    }

    public var certificateDER: Data? {
        guard let pem = try? Data(contentsOf: certPEMURL) else { return nil }
        return try? SigningIdentity.certificateDER(from: pem)
    }

    public struct CertificateInfo { public let subject: String; public let notAfter: Date? }

    public func certificateInfo() -> CertificateInfo? {
        guard let der = certificateDER else { return nil }
        let subject = (try? Inspector.subjectCommonName(der)).flatMap { $0.isEmpty ? nil : $0 } ?? "certificate"
        return CertificateInfo(subject: subject, notAfter: try? Inspector.notAfter(der))
    }

    /// Generates a new RSA-2048 key and self-signed certificate with /usr/bin/openssl.
    public func generate(commonName: String, days: Int) throws {
        let cn = commonName.replacingOccurrences(of: "\n", with: " ").replacingOccurrences(of: "/", with: "-")
        let cfg = """
        [req]
        distinguished_name = dn
        x509_extensions = ext
        prompt = no
        [dn]
        CN = \(cn)
        [ext]
        basicConstraints = critical,CA:FALSE
        keyUsage = critical,digitalSignature
        extendedKeyUsage = codeSigning
        subjectKeyIdentifier = hash
        """
        let cfgURL = directory.appendingPathComponent("openssl.cnf")
        try cfg.write(to: cfgURL, atomically: true, encoding: .utf8)
        let r = try Tool.run("/usr/bin/openssl", ["req", "-new", "-x509", "-newkey", "rsa:2048", "-config", cfgURL.path,
                                                  "-keyout", keyURL.path, "-out", certPEMURL.path, "-days", String(days), "-nodes", "-sha256"])
        guard r.status == 0 else { throw SignError.tool("openssl failed: \(r.stderr)") }
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: keyURL.path)
        try writeDerivedFiles()
        _ = try identity()   // make sure Security can load what openssl wrote
    }

    public func importKey(keyFile: URL, certificateFile: URL) throws {
        let id = try SigningIdentity.load(keyURL: keyFile, certificateURL: certificateFile)   // validate first
        let fm = FileManager.default
        if fm.fileExists(atPath: keyURL.path) { try fm.removeItem(at: keyURL) }
        if fm.fileExists(atPath: certPEMURL.path) { try fm.removeItem(at: certPEMURL) }
        try fm.copyItem(at: keyFile, to: keyURL)
        try fm.setAttributes([.posixPermissions: 0o600], ofItemAtPath: keyURL.path)
        let pem = "-----BEGIN CERTIFICATE-----\n" + id.certificateDER.base64EncodedString(options: [.lineLength64Characters]) + "\n-----END CERTIFICATE-----\n"
        try pem.write(to: certPEMURL, atomically: true, encoding: .utf8)
        try writeDerivedFiles()
    }

    func writeDerivedFiles() throws {
        guard let der = certificateDER else { throw SignError.malformed("certificate") }
        try der.write(to: certDERURL)
        try Authenticode.makeESL(certificateDER: der).write(to: eslURL)
    }

    /// Copies db.cer and db.esl into a folder (for example a FAT32 USB stick for the BIOS).
    public func exportCertificate(to folder: URL) throws -> [URL] {
        if !FileManager.default.fileExists(atPath: certDERURL.path) { try writeDerivedFiles() }
        var out: [URL] = []
        for src in [certDERURL, eslURL] {
            let dst = folder.appendingPathComponent(src.lastPathComponent)
            if FileManager.default.fileExists(atPath: dst.path) { try FileManager.default.removeItem(at: dst) }
            try FileManager.default.copyItem(at: src, to: dst)
            out.append(dst)
        }
        return out
    }

    static let markerName = "partition-uuid.txt"

    /// Existing backup folders for this partition, oldest first. Matched by partition UUID
    /// (survives a USB stick coming back as a different diskN) or, for older folders, by device id.
    public func backupFolders(for partition: EFIPartition) -> [URL] {
        let names = ((try? FileManager.default.contentsOfDirectory(atPath: backupsURL.path)) ?? []).sorted()
        return names.compactMap { name -> URL? in
            let url = backupsURL.appendingPathComponent(name)
            if let uuid = partition.partitionUUID,
               let marker = try? String(contentsOf: url.appendingPathComponent(KeyStore.markerName), encoding: .utf8),
               marker.trimmingCharacters(in: .whitespacesAndNewlines).caseInsensitiveCompare(uuid) == .orderedSame {
                return url
            }
            return name.contains(" \(partition.id) ") ? url : nil
        }
    }

    /// Folder to write new backups into for this partition (today's, created on demand with a UUID marker).
    public func backupFolder(for partition: EFIPartition) -> URL {
        let f = DateFormatter(); f.dateFormat = "yyyy-MM-dd"
        let name = "\(f.string(from: Date())) \(partition.id) \(partition.volumeName)".replacingOccurrences(of: "/", with: "-")
        let url = backupsURL.appendingPathComponent(name)
        try? FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        if let uuid = partition.partitionUUID {
            try? uuid.write(to: url.appendingPathComponent(KeyStore.markerName), atomically: true, encoding: .utf8)
        }
        return url
    }
}
