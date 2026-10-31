import Foundation
import IOKit

/// Secure Boot related state read from the firmware's NVRAM through the IORegistry.
public struct FirmwareState {
    public var secureBootEnabled: Bool?
    public var setupMode: Bool?
    public var openCoreVersion: String?
    public var appleSecureBootPolicy: Int?
    public var isHackintosh: Bool { openCoreVersion != nil }

    static let efiGlobal = "8BE4DF61-93CA-11D2-AA0D-00E098032B8C"

    public static func nvram(_ name: String) -> Data? {
        let entry = IORegistryEntryFromPath(kIOMainPortDefault, "IODeviceTree:/options")
        guard entry != 0 else { return nil }
        defer { IOObjectRelease(entry) }
        guard let v = IORegistryEntryCreateCFProperty(entry, name as CFString, kCFAllocatorDefault, 0) else { return nil }
        let obj = v.takeRetainedValue()
        if let d = obj as? Data { return d }
        if let s = obj as? String { return s.data(using: .utf8) }
        return nil
    }

    public static func read() -> FirmwareState {
        var s = FirmwareState()
        if let d = nvram("\(efiGlobal):SecureBoot"), let b = d.first { s.secureBootEnabled = (b == 1) }
        if let d = nvram("\(efiGlobal):SetupMode"), let b = d.first { s.setupMode = (b == 1) }
        if let d = nvram("4D1FDA02-38C7-4A6A-9CC6-4BCCA8B30102:opencore-version") {
            s.openCoreVersion = String(decoding: d.prefix { $0 != 0 }, as: UTF8.self)
        }
        if let d = nvram("94B73556-2197-4702-82A8-3E1337DAFBFB:AppleSecureBootPolicy"), let b = d.first { s.appleSecureBootPolicy = Int(b) }
        return s
    }

    public var summary: String {
        switch secureBootEnabled {
        case .some(true): return setupMode == true ? "UEFI Secure Boot: on, but firmware is in Setup Mode" : "UEFI Secure Boot: enforced"
        case .some(false): return "UEFI Secure Boot: off"
        case .none: return "UEFI Secure Boot: unknown (variable not exposed)"
        }
    }
}
