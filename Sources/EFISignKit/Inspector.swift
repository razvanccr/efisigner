import Foundation
import Security
import CryptoKit

public struct SignatureInfo {
    public var signerName = "unknown signer"
    public var issuerName = ""
    public var notAfter: Date?
    public var digestAlgorithm = "?"
    public var digestInSignature = Data()
    public var computedDigest = Data()
    public var digestMatches = false
    public var signatureValid = false
    public var signerCertificateDER: Data?
    public var problems: [String] = []
    public var isValid: Bool { digestMatches && signatureValid }
}

public enum FileStatus {
    case notPE(String)
    case unsigned
    case signed(SignatureInfo)
    /// Certificate table present but not PKCS#7: Apple's own EFI signature format (boot.efi, apfs.efi, updaters).
    case appleFormat
}

public enum Inspector {
    public static func inspect(_ url: URL) -> FileStatus {
        guard let data = try? Data(contentsOf: url) else { return .notPE("unreadable") }
        return inspect(data: data)
    }

    public static func inspect(data: Data) -> FileStatus {
        let pe: PEImage
        do { pe = try PEImage(data: data) } catch { return .notPE(error.localizedDescription) }
        guard pe.hasCertificateTable else { return .unsigned }
        guard let p7 = pe.signatureBlob else { return .appleFormat }
        return .signed(parse(pkcs7: p7, image: pe))
    }

    static func hash(_ alg: String, _ data: Data) -> Data? {
        switch alg {
        case "sha256": return Data(SHA256.hash(data: data))
        case "sha1": return Data(Insecure.SHA1.hash(data: data))
        case "sha384": return Data(SHA384.hash(data: data))
        case "sha512": return Data(SHA512.hash(data: data))
        default: return nil
        }
    }

    static func imageHash(_ alg: String, _ pe: PEImage) -> Data? {
        switch alg {
        case "sha256": return pe.authenticodeHash(SHA256.self)
        case "sha1": return pe.authenticodeHash(Insecure.SHA1.self)
        case "sha384": return pe.authenticodeHash(SHA384.self)
        case "sha512": return pe.authenticodeHash(SHA512.self)
        default: return nil
        }
    }

    static func algName(_ oid: String) -> String {
        switch oid {
        case OID.sha1: return "sha1"
        case OID.sha256: return "sha256"
        case OID.sha384: return "sha384"
        case OID.sha512: return "sha512"
        default: return oid
        }
    }

    static func keyAlgorithm(_ alg: String) -> SecKeyAlgorithm? {
        switch alg {
        case "sha1": return .rsaSignatureMessagePKCS1v15SHA1
        case "sha256": return .rsaSignatureMessagePKCS1v15SHA256
        case "sha384": return .rsaSignatureMessagePKCS1v15SHA384
        case "sha512": return .rsaSignatureMessagePKCS1v15SHA512
        default: return nil
        }
    }

    static func parse(pkcs7 p7: Data, image pe: PEImage) -> SignatureInfo {
        var info = SignatureInfo()
        do {
            // ContentInfo { signedData OID, [0] SignedData }
            let ci = try DER.read(p7, at: 0)
            let ciKids = try DER.children(p7, of: ci)
            guard ciKids.count >= 2, ciKids[0].tag == 0x06, DER.oidString(DER.content(p7, ciKids[0])) == OID.signedData
            else { throw SignError.malformed("not PKCS#7 SignedData") }
            guard let sd = try DER.children(p7, of: ciKids[1]).first else { throw SignError.malformed("SignedData") }
            let sdKids = try DER.children(p7, of: sd)
            guard sdKids.count >= 4 else { throw SignError.malformed("SignedData fields") }

            // encapContentInfo { spcIndirectData OID, [0] SpcIndirectDataContent }
            let eci = sdKids[2]
            let eciKids = try DER.children(p7, of: eci)
            guard eciKids.count >= 2, DER.oidString(DER.content(p7, eciKids[0])) == OID.spcIndirectData,
                  let spc = try DER.children(p7, of: eciKids[1]).first
            else { throw SignError.malformed("missing SpcIndirectDataContent") }
            let spcKids = try DER.children(p7, of: spc)
            guard let digestInfo = spcKids.last, let digestInfoKids = try? DER.children(p7, of: digestInfo), digestInfoKids.count == 2,
                  let algOID = try DER.children(p7, of: digestInfoKids[0]).first
            else { throw SignError.malformed("missing DigestInfo") }
            info.digestAlgorithm = algName(DER.oidString(DER.content(p7, algOID)))
            info.digestInSignature = DER.content(p7, digestInfoKids[1])
            if let computed = imageHash(info.digestAlgorithm, pe) {
                info.computedDigest = computed
                info.digestMatches = (computed == info.digestInSignature)
                if !info.digestMatches { info.problems.append("image hash does not match the signed digest (file modified?)") }
            } else {
                info.problems.append("unsupported digest algorithm \(info.digestAlgorithm)")
            }

            // certificates [0] IMPLICIT, signerInfos SET
            var certs: [Data] = []
            var signerInfos: DER.TLV?
            for k in sdKids.dropFirst(3) {
                if k.tag == 0xA0 { certs = try DER.children(p7, of: k).map { DER.full(p7, $0) } }
                if k.tag == 0x31 { signerInfos = k }
            }
            guard let sis = signerInfos, let si = try DER.children(p7, of: sis).first else { throw SignError.malformed("no SignerInfo") }
            let siKids = try DER.children(p7, of: si)
            guard siKids.count >= 6 else { throw SignError.malformed("SignerInfo fields") }
            var idx = 3
            guard siKids[idx].tag == 0xA0 else { throw SignError.malformed("no signed attributes") }
            let signedAttrs = siKids[idx]
            idx += 1
            let sigAlgKids = try DER.children(p7, of: siKids[idx])
            let sigAlgOID = sigAlgKids.first.map { DER.oidString(DER.content(p7, $0)) } ?? ""
            idx += 1
            let signature = DER.content(p7, siKids[idx])

            // messageDigest attribute must equal hash(SpcIndirectDataContent without its outer header)
            var messageDigestAttr: Data?
            for attr in try DER.children(p7, of: signedAttrs) {
                let ak = try DER.children(p7, of: attr)
                guard ak.count == 2, ak[0].tag == 0x06 else { continue }
                if DER.oidString(DER.content(p7, ak[0])) == OID.messageDigest, let v = try DER.children(p7, of: ak[1]).first {
                    messageDigestAttr = DER.content(p7, v)
                }
            }
            let expectedMD = hash(info.digestAlgorithm, DER.content(p7, spc))
            if messageDigestAttr == nil { info.problems.append("no messageDigest attribute") }
            else if expectedMD != messageDigestAttr { info.problems.append("messageDigest attribute does not cover the content") }

            // Verify the RSA signature over the SET OF signed attributes with each embedded certificate.
            let setData = DER.tlv(0x31, DER.content(p7, signedAttrs))
            let rsaOK = sigAlgOID == OID.rsa || sigAlgOID.hasPrefix("1.2.840.113549.1.1.")
            if !rsaOK { info.problems.append("unsupported signature algorithm \(sigAlgOID)") }
            if let alg = keyAlgorithm(info.digestAlgorithm), rsaOK, expectedMD == messageDigestAttr {
                for certDER in certs {
                    guard let cert = SecCertificateCreateWithData(nil, certDER as CFData), let pub = SecCertificateCopyKey(cert) else { continue }
                    var err: Unmanaged<CFError>?
                    if SecKeyVerifySignature(pub, alg, setData as CFData, signature as CFData, &err) {
                        info.signatureValid = true
                        info.signerCertificateDER = certDER
                        info.signerName = (SecCertificateCopySubjectSummary(cert) as String?) ?? "unknown signer"
                        info.issuerName = (try? issuerCommonName(certDER)) ?? ""
                        info.notAfter = try? notAfter(certDER)
                        break
                    }
                }
                if !info.signatureValid { info.problems.append("RSA signature does not verify with any embedded certificate") }
            }
            if !info.signatureValid, let first = certs.first, let cert = SecCertificateCreateWithData(nil, first as CFData) {
                info.signerName = (SecCertificateCopySubjectSummary(cert) as String?) ?? info.signerName
            }
        } catch {
            info.problems.append(error.localizedDescription)
        }
        return info
    }

    static func tbsFields(_ cert: Data) throws -> [DER.TLV] {
        let outer = try DER.read(cert, at: 0)
        guard let tbs = try DER.children(cert, of: outer).first else { throw SignError.malformed("certificate") }
        var kids = try DER.children(cert, of: tbs)
        if kids.first?.tag == 0xA0 { kids.removeFirst() }
        return kids
    }

    static func commonName(in name: DER.TLV, _ d: Data) throws -> String? {
        for rdn in try DER.children(d, of: name) {
            for atv in try DER.children(d, of: rdn) {
                let k = try DER.children(d, of: atv)
                guard k.count == 2, k[0].tag == 0x06, DER.oidString(DER.content(d, k[0])) == OID.commonName else { continue }
                let v = DER.content(d, k[1])
                return k[1].tag == 0x1E ? String(data: v, encoding: .utf16BigEndian) : String(data: v, encoding: .utf8)
            }
        }
        return nil
    }

    public static func issuerCommonName(_ cert: Data) throws -> String {
        let f = try tbsFields(cert)
        guard f.count >= 3 else { throw SignError.malformed("certificate") }
        return try commonName(in: f[2], cert) ?? ""
    }

    public static func subjectCommonName(_ cert: Data) throws -> String {
        let f = try tbsFields(cert)
        guard f.count >= 5 else { throw SignError.malformed("certificate") }
        return try commonName(in: f[4], cert) ?? ""
    }

    public static func notAfter(_ cert: Data) throws -> Date? {
        let f = try tbsFields(cert)
        guard f.count >= 4, let na = try DER.children(cert, of: f[3]).last else { return nil }
        let s = String(decoding: DER.content(cert, na), as: UTF8.self)
        let fmt = DateFormatter()
        fmt.locale = Locale(identifier: "en_US_POSIX")
        fmt.timeZone = TimeZone(identifier: "UTC")
        fmt.dateFormat = na.tag == 0x17 ? "yyMMddHHmmss'Z'" : "yyyyMMddHHmmss'Z'"
        return fmt.date(from: s)
    }
}
