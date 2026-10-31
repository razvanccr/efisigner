import Foundation
import Security
import CryptoKit

enum OID {
    static let sha1 = "1.3.14.3.2.26"
    static let sha256 = "2.16.840.1.101.3.4.2.1"
    static let sha384 = "2.16.840.1.101.3.4.2.2"
    static let sha512 = "2.16.840.1.101.3.4.2.3"
    static let rsa = "1.2.840.113549.1.1.1"
    static let signedData = "1.2.840.113549.1.7.2"
    static let contentType = "1.2.840.113549.1.9.3"
    static let messageDigest = "1.2.840.113549.1.9.4"
    static let spcIndirectData = "1.3.6.1.4.1.311.2.1.4"
    static let spcPEImageData = "1.3.6.1.4.1.311.2.1.15"
    static let commonName = "2.5.4.3"
}

/// A private key + certificate pair used to sign images.
public struct SigningIdentity {
    public let privateKey: SecKey
    public let certificateDER: Data

    public init(keyFile: Data, certificateFile: Data) throws {
        let keyText = String(decoding: keyFile, as: UTF8.self)
        let pkcs1: Data
        if let b = PEM.body(keyText, label: "RSA PRIVATE KEY") {
            pkcs1 = b
        } else if let b = PEM.body(keyText, label: "PRIVATE KEY") {
            // PKCS#8: SEQUENCE { INTEGER 0, AlgorithmIdentifier, OCTET STRING (PKCS#1 key) }
            let outer = try DER.read(b, at: 0)
            let kids = try DER.children(b, of: outer)
            guard kids.count >= 3, kids[2].tag == 0x04 else { throw SignError.malformed("PKCS#8 private key") }
            pkcs1 = DER.content(b, kids[2])
        } else if PEM.body(keyText, label: "EC PRIVATE KEY") != nil {
            throw SignError.crypto("EC keys are not supported for UEFI Secure Boot; use an RSA key")
        } else {
            throw SignError.malformed("unrecognised private key file (expected PEM)")
        }
        var err: Unmanaged<CFError>?
        let attrs: [CFString: Any] = [kSecAttrKeyType: kSecAttrKeyTypeRSA, kSecAttrKeyClass: kSecAttrKeyClassPrivate]
        guard let key = SecKeyCreateWithData(pkcs1 as CFData, attrs as CFDictionary, &err) else {
            throw SignError.crypto("cannot load RSA key: \(err?.takeRetainedValue().localizedDescription ?? "unknown")")
        }
        privateKey = key
        certificateDER = try SigningIdentity.certificateDER(from: certificateFile)
    }

    public static func certificateDER(from file: Data) throws -> Data {
        if file.first == 0x30 { return file }
        let text = String(decoding: file, as: UTF8.self)
        guard let der = PEM.body(text, label: "CERTIFICATE") else { throw SignError.malformed("unrecognised certificate file") }
        return der
    }

    public static func load(keyURL: URL, certificateURL: URL) throws -> SigningIdentity {
        try SigningIdentity(keyFile: Data(contentsOf: keyURL), certificateFile: Data(contentsOf: certificateURL))
    }

    public var certificate: SecCertificate? { SecCertificateCreateWithData(nil, certificateDER as CFData) }
    public var subjectSummary: String {
        certificate.flatMap { SecCertificateCopySubjectSummary($0) as String? } ?? "?"
    }

    func sign(_ data: Data) throws -> Data {
        var err: Unmanaged<CFError>?
        guard let sig = SecKeyCreateSignature(privateKey, .rsaSignatureMessagePKCS1v15SHA256, data as CFData, &err) else {
            throw SignError.crypto("signing failed: \(err?.takeRetainedValue().localizedDescription ?? "unknown")")
        }
        return sig as Data
    }
}

public enum Authenticode {
    /// Builds the PKCS#7 SignedData (wrapped in ContentInfo) that Authenticode expects.
    public static func buildPKCS7(imageHash: Data, identity: SigningIdentity) throws -> Data {
        let algSHA256 = DER.seq(DER.oid(OID.sha256), DER.null)

        // SpcIndirectDataContent { data { SPC_PE_IMAGE_DATA, SpcPeImageData }, messageDigest DigestInfo }
        let obsolete = "<<<Obsolete>>>".data(using: .utf16BigEndian)!
        let spcPeImageData = DER.seq(
            Data([0x03, 0x01, 0x00]),                                               // flags BIT STRING (empty)
            DER.explicit(0, DER.explicit(2, DER.implicitPrimitive(0, obsolete)))    // file -> SpcLink.file -> unicode
        )
        let spcIndirect = DER.seq(
            DER.seq(DER.oid(OID.spcPEImageData), spcPeImageData),
            DER.seq(algSHA256, DER.octets(imageHash))                               // DigestInfo (digest must be last)
        )
        // Authenticode quirk: messageDigest covers the content without the outer SEQUENCE header.
        let spcTLV = try DER.read(spcIndirect, at: 0)
        let messageDigest = Data(SHA256.hash(data: DER.content(spcIndirect, spcTLV)))

        let attrs = [
            DER.seq(DER.oid(OID.contentType), DER.set([DER.oid(OID.spcIndirectData)])),
            DER.seq(DER.oid(OID.messageDigest), DER.set([DER.octets(messageDigest)])),
        ].sorted { $0.lexicographicallyPrecedes($1) }.reduce(Data(), +)
        let signature = try identity.sign(DER.tlv(0x31, attrs))                     // signed over the SET OF encoding

        let (issuer, serial) = try issuerAndSerial(of: identity.certificateDER)
        let signerInfo = DER.seq(
            DER.integer(1),
            DER.seq(issuer, serial),
            algSHA256,
            DER.tlv(0xA0, attrs),
            DER.seq(DER.oid(OID.rsa), DER.null),
            DER.octets(signature)
        )
        let signedData = DER.seq(
            DER.integer(1),
            DER.set([algSHA256]),
            DER.seq(DER.oid(OID.spcIndirectData), DER.explicit(0, spcIndirect)),    // PKCS#7 v1.5: bare SEQUENCE
            DER.tlv(0xA0, identity.certificateDER),
            DER.set([signerInfo])
        )
        return DER.seq(DER.oid(OID.signedData), DER.explicit(0, signedData))
    }

    static func issuerAndSerial(of cert: Data) throws -> (issuer: Data, serial: Data) {
        let outer = try DER.read(cert, at: 0)
        guard let tbs = try DER.children(cert, of: outer).first else { throw SignError.malformed("certificate") }
        var kids = try DER.children(cert, of: tbs)
        if kids.first?.tag == 0xA0 { kids.removeFirst() }
        guard kids.count >= 4, kids[0].tag == 0x02, kids[2].tag == 0x30 else { throw SignError.malformed("certificate TBS") }
        return (DER.full(cert, kids[2]), DER.full(cert, kids[0]))
    }

    /// Signs an image in memory: strips any old signature, pads, hashes, appends the new signature.
    public static func sign(image input: Data, identity: SigningIdentity) throws -> (signed: Data, hash: Data) {
        var pe = try PEImage(data: input)
        pe.stripSignature()
        pe.padTo8()
        let hash = pe.sha256
        let p7 = try buildPKCS7(imageHash: hash, identity: identity)
        pe.appendCertificate(pkcs7: p7)
        pe.updateChecksum()
        return (pe.data, hash)
    }

    /// EFI_SIGNATURE_LIST holding one X.509 certificate, for BIOS key enrolment.
    public static func makeESL(certificateDER: Data) -> Data {
        // EFI_CERT_X509_GUID a5c059a1-94e4-4aa7-87b5-ab155c2bf072, mixed-endian on disk
        var esl = Data([0xa1, 0x59, 0xc0, 0xa5, 0xe4, 0x94, 0xa7, 0x4a, 0x87, 0xb5, 0xab, 0x15, 0x5c, 0x2b, 0xf0, 0x72])
        let sigSize = UInt32(16 + certificateDER.count)
        let listSize = UInt32(28) + sigSize
        func le(_ v: UInt32) -> [UInt8] { [UInt8(v & 0xff), UInt8((v >> 8) & 0xff), UInt8((v >> 16) & 0xff), UInt8((v >> 24) & 0xff)] }
        esl.append(contentsOf: le(listSize) + le(0) + le(sigSize))
        var owner = [UInt8](repeating: 0, count: 16)
        for i in 0..<16 { owner[i] = UInt8.random(in: 0...255) }
        owner[6] = (owner[6] & 0x0f) | 0x40; owner[8] = (owner[8] & 0x3f) | 0x80
        esl.append(contentsOf: owner)
        esl.append(certificateDER)
        return esl
    }
}
