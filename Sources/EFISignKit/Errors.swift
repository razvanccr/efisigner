import Foundation

public enum SignError: LocalizedError {
    case malformed(String)
    case io(String)
    case crypto(String)
    case tool(String)

    public var errorDescription: String? {
        switch self {
        case .malformed(let s): return "Malformed data: \(s)"
        case .io(let s): return s
        case .crypto(let s): return "Crypto error: \(s)"
        case .tool(let s): return s
        }
    }
}
