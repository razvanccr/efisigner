import Foundation
import CryptoKit

/// A PE/COFF image held in memory, with the Authenticode hashing rules the UEFI firmware applies.
public struct PEImage {
    public private(set) var data: Data
    public let isPE32Plus: Bool
    public let machine: UInt16
    let checksumOffset: Int
    let certDirOffset: Int
    let sizeOfHeaders: Int
    let sectionsOffset: Int
    let numSections: Int

    public struct Section {
        public let name: String
        public let rawPointer: Int
        public let rawSize: Int
    }

    public init(data input: Data) throws {
        let d = Data(input)   // zero-based copy
        guard d.count >= 0x40, d[0] == 0x4D, d[1] == 0x5A else { throw SignError.malformed("not an MZ/PE file") }
        let peOff = Int(PEImage.u32(d, 0x3C))
        guard peOff >= 0x40, peOff + 24 <= d.count,
              d[peOff] == 0x50, d[peOff + 1] == 0x45, d[peOff + 2] == 0, d[peOff + 3] == 0
        else { throw SignError.malformed("bad PE signature") }
        let coff = peOff + 4
        machine = PEImage.u16(d, coff)
        numSections = Int(PEImage.u16(d, coff + 2))
        let optSize = Int(PEImage.u16(d, coff + 16))
        let opt = coff + 20
        guard optSize >= 96, opt + optSize <= d.count else { throw SignError.malformed("optional header too small") }
        switch PEImage.u16(d, opt) {
        case 0x20B: isPE32Plus = true
        case 0x10B: isPE32Plus = false
        default: throw SignError.malformed("unknown optional header magic")
        }
        checksumOffset = opt + 64
        sizeOfHeaders = Int(PEImage.u32(d, opt + 60))
        let dirsOff = opt + (isPE32Plus ? 112 : 96)
        let nDirs = Int(PEImage.u32(d, dirsOff - 4))
        guard nDirs >= 5, dirsOff + nDirs * 8 <= opt + optSize else { throw SignError.malformed("no certificate table data directory") }
        certDirOffset = dirsOff + 4 * 8
        sectionsOffset = opt + optSize
        guard sectionsOffset + numSections * 40 <= d.count, sizeOfHeaders <= d.count, sizeOfHeaders >= sectionsOffset + numSections * 40
        else { throw SignError.malformed("section table past end of file") }
        data = d
    }

    static func u16(_ d: Data, _ o: Int) -> UInt16 { UInt16(d[o]) | UInt16(d[o + 1]) << 8 }
    static func u32(_ d: Data, _ o: Int) -> UInt32 {
        UInt32(d[o]) | UInt32(d[o + 1]) << 8 | UInt32(d[o + 2]) << 16 | UInt32(d[o + 3]) << 24
    }
    private mutating func put32(_ v: UInt32, at o: Int) {
        data[o] = UInt8(v & 0xff); data[o + 1] = UInt8((v >> 8) & 0xff)
        data[o + 2] = UInt8((v >> 16) & 0xff); data[o + 3] = UInt8((v >> 24) & 0xff)
    }

    public var certTable: (offset: Int, size: Int) {
        (Int(PEImage.u32(data, certDirOffset)), Int(PEImage.u32(data, certDirOffset + 4)))
    }

    public var sections: [Section] {
        (0..<numSections).map { i in
            let o = sectionsOffset + i * 40
            let name = String(decoding: data[o..<(o + 8)].prefix { $0 != 0 }, as: UTF8.self)
            return Section(name: name, rawPointer: Int(PEImage.u32(data, o + 20)), rawSize: Int(PEImage.u32(data, o + 16)))
        }
    }

    /// Authenticode hash per the PE spec: headers minus CheckSum and the certificate-table entry,
    /// then sections in file order, then trailing data minus the certificate table.
    public func authenticodeHash<H: HashFunction>(_: H.Type) -> Data {
        var h = H()
        let d = data
        h.update(data: d[0..<checksumOffset])
        h.update(data: d[(checksumOffset + 4)..<certDirOffset])
        h.update(data: d[(certDirOffset + 8)..<sizeOfHeaders])
        var hashed = sizeOfHeaders
        for s in sections.sorted(by: { $0.rawPointer < $1.rawPointer }) where s.rawSize > 0 {
            let start = min(s.rawPointer, d.count)
            let end = min(s.rawPointer + s.rawSize, d.count)
            if start < end { h.update(data: d[start..<end]) }
            hashed += (end - start)
        }
        let (certOff, certSize) = certTable
        if hashed < d.count {
            if certSize > 0, certOff >= hashed, certOff + certSize <= d.count {
                h.update(data: d[hashed..<certOff])
                if certOff + certSize < d.count { h.update(data: d[(certOff + certSize)..<d.count]) }
            } else {
                h.update(data: d[hashed..<d.count])
            }
        }
        return Data(h.finalize())
    }

    public var sha256: Data { authenticodeHash(SHA256.self) }

    /// PKCS#7 blob of the first WIN_CERTIFICATE (type 0x0002 = PKCS_SIGNED_DATA), if any.
    public var signatureBlob: Data? {
        let (off, size) = certTable
        guard size >= 8, off >= sizeOfHeaders, off + size <= data.count else { return nil }
        let dwLength = Int(PEImage.u32(data, off))
        let type = PEImage.u16(data, off + 6)
        guard type == 0x0002, dwLength >= 8, off + dwLength <= data.count else { return nil }
        return Data(data[(off + 8)..<(off + dwLength)])
    }

    public var hasCertificateTable: Bool { certTable.size > 0 }

    @discardableResult
    public mutating func stripSignature() -> Bool {
        let (off, size) = certTable
        guard size > 0 else { return false }
        if off >= sizeOfHeaders, off + size == data.count { data.removeSubrange(off..<data.count) }
        put32(0, at: certDirOffset)
        put32(0, at: certDirOffset + 4)
        return true
    }

    public mutating func padTo8() { while data.count % 8 != 0 { data.append(0) } }

    /// Appends WIN_CERTIFICATE { dwLength, wRevision 0x0200, wCertificateType 0x0002 } + PKCS#7, 8-byte padded.
    public mutating func appendCertificate(pkcs7: Data) {
        padTo8()
        let off = data.count
        var body = Data([0, 0, 0, 0, 0x00, 0x02, 0x02, 0x00])
        body.append(pkcs7)
        while body.count % 8 != 0 { body.append(0) }
        let len = UInt32(body.count)
        body[0] = UInt8(len & 0xff); body[1] = UInt8((len >> 8) & 0xff)
        body[2] = UInt8((len >> 16) & 0xff); body[3] = UInt8((len >> 24) & 0xff)
        data.append(body)
        put32(UInt32(off), at: certDirOffset)
        put32(len, at: certDirOffset + 4)
    }

    /// Recomputes the optional-header CheckSum (cosmetic; UEFI does not verify it).
    public mutating func updateChecksum() {
        put32(0, at: checksumOffset)
        let n = data.count
        var sum: UInt32 = 0
        data.withUnsafeBytes { (buf: UnsafeRawBufferPointer) in
            var i = 0
            while i + 1 < n {
                sum &+= UInt32(buf[i]) | UInt32(buf[i + 1]) << 8
                sum = (sum & 0xffff) + (sum >> 16)
                i += 2
            }
            if i < n { sum &+= UInt32(buf[i]); sum = (sum & 0xffff) + (sum >> 16) }
        }
        sum = (sum & 0xffff) + (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16)
        put32((sum & 0xffff) &+ UInt32(truncatingIfNeeded: n), at: checksumOffset)
    }
}
