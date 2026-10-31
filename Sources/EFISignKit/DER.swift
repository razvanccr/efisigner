import Foundation

/// Minimal DER encoder/decoder, enough for PKCS#7 Authenticode and X.509 field extraction.
enum DER {
    struct TLV {
        let tag: UInt8
        let headerLength: Int
        let length: Int
        let offset: Int
        var contentRange: Range<Int> { (offset + headerLength)..<(offset + headerLength + length) }
        var fullRange: Range<Int> { offset..<(offset + headerLength + length) }
        var end: Int { offset + headerLength + length }
    }

    // MARK: encoding

    static func length(_ n: Int) -> Data {
        if n < 0x80 { return Data([UInt8(n)]) }
        var bytes: [UInt8] = []
        var v = n
        while v > 0 { bytes.insert(UInt8(v & 0xff), at: 0); v >>= 8 }
        return Data([0x80 | UInt8(bytes.count)]) + bytes
    }

    static func tlv(_ tag: UInt8, _ content: Data) -> Data {
        Data([tag]) + length(content.count) + content
    }

    static func seq(_ items: [Data]) -> Data { tlv(0x30, items.reduce(Data(), +)) }
    static func seq(_ items: Data...) -> Data { seq(items) }
    static func set(_ items: [Data]) -> Data {
        tlv(0x31, items.sorted { $0.lexicographicallyPrecedes($1) }.reduce(Data(), +))
    }
    static func octets(_ d: Data) -> Data { tlv(0x04, d) }
    static let null = Data([0x05, 0x00])

    static func integer(_ n: Int) -> Data {
        var bytes: [UInt8] = []
        var v = n
        repeat { bytes.insert(UInt8(v & 0xff), at: 0); v >>= 8 } while v > 0
        if bytes[0] & 0x80 != 0 { bytes.insert(0, at: 0) }
        return tlv(0x02, Data(bytes))
    }

    static func explicit(_ n: UInt8, _ content: Data) -> Data { tlv(0xA0 | n, content) }
    static func implicitPrimitive(_ n: UInt8, _ content: Data) -> Data { tlv(0x80 | n, content) }

    static func oid(_ s: String) -> Data {
        let parts = s.split(separator: ".").map { Int($0)! }
        var body: [UInt8] = [UInt8(40 * parts[0] + parts[1])]
        for p in parts.dropFirst(2) {
            var enc: [UInt8] = [UInt8(p & 0x7f)]
            var v = p >> 7
            while v > 0 { enc.insert(0x80 | UInt8(v & 0x7f), at: 0); v >>= 7 }
            body += enc
        }
        return tlv(0x06, Data(body))
    }

    static func oidString(_ content: Data) -> String {
        let b = [UInt8](content)
        guard !b.isEmpty else { return "" }
        var parts = [String(b[0] / 40), String(b[0] % 40)]
        var v = 0
        for x in b.dropFirst() {
            v = (v << 7) | Int(x & 0x7f)
            if x & 0x80 == 0 { parts.append(String(v)); v = 0 }
        }
        return parts.joined(separator: ".")
    }

    // MARK: decoding (buffer must be zero-based Data)

    static func read(_ d: Data, at pos: Int) throws -> TLV {
        guard pos >= 0, pos + 2 <= d.count else { throw SignError.malformed("DER truncated") }
        let tag = d[pos]
        let l = Int(d[pos + 1])
        if l < 0x80 {
            guard pos + 2 + l <= d.count else { throw SignError.malformed("DER length past end") }
            return TLV(tag: tag, headerLength: 2, length: l, offset: pos)
        }
        let n = l & 0x7f
        guard n >= 1, n <= 4, pos + 2 + n <= d.count else { throw SignError.malformed("DER bad length") }
        var len = 0
        for i in 0..<n { len = (len << 8) | Int(d[pos + 2 + i]) }
        guard pos + 2 + n + len <= d.count else { throw SignError.malformed("DER length past end") }
        return TLV(tag: tag, headerLength: 2 + n, length: len, offset: pos)
    }

    static func children(_ d: Data, of t: TLV) throws -> [TLV] {
        var out: [TLV] = []
        var p = t.offset + t.headerLength
        let end = t.end
        while p < end {
            let c = try read(d, at: p)
            out.append(c)
            p = c.end
        }
        return out
    }

    static func content(_ d: Data, _ t: TLV) -> Data { d.subdata(in: t.contentRange) }
    static func full(_ d: Data, _ t: TLV) -> Data { d.subdata(in: t.fullRange) }
}

enum PEM {
    /// Returns the base64-decoded body of the first "-----BEGIN <label>-----" block, or nil.
    static func body(_ text: String, label: String) -> Data? {
        let begin = "-----BEGIN \(label)-----"
        let end = "-----END \(label)-----"
        guard let b = text.range(of: begin), let e = text.range(of: end, range: b.upperBound..<text.endIndex) else { return nil }
        let inner = text[b.upperBound..<e.lowerBound].split(whereSeparator: \.isNewline).joined()
        return Data(base64Encoded: inner)
    }
}
