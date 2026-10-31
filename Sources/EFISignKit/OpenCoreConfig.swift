import Foundation

public enum ConfigFix: Hashable {
    case secureBootModelDefault
    case disableSecurityPolicyOff
    case disableTool(String)

    public var title: String {
        switch self {
        case .secureBootModelDefault: return "Set SecureBootModel to Default"
        case .disableSecurityPolicyOff: return "Set DisableSecurityPolicy to false"
        case .disableTool(let t): return "Disable \(t)"
        }
    }

    public var explanation: String {
        switch self {
        case .secureBootModelDefault:
            return "Sets Misc > Security > SecureBootModel to Default, so OpenCore runs Apple Secure Boot at Medium security and loads macOS boot.efi through its own verified loader. Reboot once with UEFI Secure Boot still off to confirm macOS and all your kexts still load before enabling it in the BIOS."
        case .disableSecurityPolicyOff:
            return "Sets UEFI > Quirks > DisableSecurityPolicy to false. That quirk switches off the firmware's own security features and defeats Secure Boot."
        case .disableTool(let t):
            return "Sets Enabled to false on the \(t) entry under Misc > Tools. A UEFI shell started from the boot picker could load anything, which bypasses the Secure Boot chain."
        }
    }
}

public struct ConfigWarning: Identifiable, Hashable {
    public let message: String
    public let fix: ConfigFix?
    public var id: String { message }
}

/// The parts of an OpenCore config.plist that matter for UEFI Secure Boot.
public struct OpenCoreConfig {
    public var secureBootModel: String?
    public var dmgLoading: String?
    public var vault: String?
    public var disableSecurityPolicy = false
    public var enabledDrivers: Set<String> = []
    public var disabledDrivers: Set<String> = []
    public var enabledTools: Set<String> = []
    public var disabledTools: Set<String> = []
    public var warnings: [ConfigWarning] = []

    public static func load(espRoot: URL) -> OpenCoreConfig? {
        let url = espRoot.appendingPathComponent("EFI/OC/config.plist")
        guard let data = try? Data(contentsOf: url),
              let obj = try? PropertyListSerialization.propertyList(from: data, format: nil),
              let root = obj as? [String: Any] else { return nil }
        var c = OpenCoreConfig()
        let misc = root["Misc"] as? [String: Any] ?? [:]
        let security = misc["Security"] as? [String: Any] ?? [:]
        c.secureBootModel = security["SecureBootModel"] as? String
        c.dmgLoading = security["DmgLoading"] as? String
        c.vault = security["Vault"] as? String
        let uefi = root["UEFI"] as? [String: Any] ?? [:]
        c.disableSecurityPolicy = ((uefi["Quirks"] as? [String: Any])?["DisableSecurityPolicy"] as? Bool) ?? false
        for d in uefi["Drivers"] as? [[String: Any]] ?? [] {
            guard let p = d["Path"] as? String else { continue }
            if (d["Enabled"] as? Bool) ?? false { c.enabledDrivers.insert(p.lowercased()) } else { c.disabledDrivers.insert(p.lowercased()) }
        }
        for t in misc["Tools"] as? [[String: Any]] ?? [] {
            guard let p = t["Path"] as? String else { continue }
            if (t["Enabled"] as? Bool) ?? false { c.enabledTools.insert(p.lowercased()) } else { c.disabledTools.insert(p.lowercased()) }
        }
        if c.secureBootModel == "Disabled" {
            c.warnings.append(ConfigWarning(message: "SecureBootModel is Disabled: with UEFI Secure Boot on, OpenCore hands macOS boot.efi to the firmware, which will reject it. Set it to Default.", fix: .secureBootModelDefault))
        }
        if c.disableSecurityPolicy {
            c.warnings.append(ConfigWarning(message: "UEFI > Quirks > DisableSecurityPolicy is true, which defeats Secure Boot. Set it to false.", fix: .disableSecurityPolicyOff))
        }
        for shell in ["openshell.efi", "shell.efi"] where c.enabledTools.contains(shell) {
            c.warnings.append(ConfigWarning(message: "\(shell) is enabled as a tool. OpenCore's docs say not to ship a UEFI shell under Secure Boot, since it bypasses the boot chain.", fix: .disableTool(shell)))
        }
        return c
    }

    /// nil = not an OpenCore driver/tool; true/false = enabled/disabled in config.plist
    public func isLoaded(relativePath: String) -> Bool? {
        let lower = relativePath.lowercased()
        if lower.hasPrefix("efi/oc/drivers/") {
            let name = String(lower.dropFirst("efi/oc/drivers/".count))
            return enabledDrivers.contains(name) ? true : (disabledDrivers.contains(name) ? false : false)
        }
        if lower.hasPrefix("efi/oc/tools/") {
            let name = String(lower.dropFirst("efi/oc/tools/".count))
            return enabledTools.contains(name) ? true : false
        }
        return nil
    }

    public static func configURL(espRoot: URL) -> URL { espRoot.appendingPathComponent("EFI/OC/config.plist") }

    /// Applies a fix to config.plist in place. A copy of the original is written next to it in backupRoot first.
    public static func apply(_ fix: ConfigFix, espRoot: URL, backupRoot: URL?) throws {
        let url = configURL(espRoot: espRoot)
        let data = try Data(contentsOf: url)
        var format = PropertyListSerialization.PropertyListFormat.xml
        guard var root = try PropertyListSerialization.propertyList(from: data, options: [], format: &format) as? [String: Any] else {
            throw SignError.malformed("config.plist is not a dictionary")
        }
        if let b = backupRoot {
            let f = DateFormatter(); f.dateFormat = "yyyyMMdd-HHmmss"
            let dest = b.appendingPathComponent("EFI/OC/config.plist.\(f.string(from: Date())).bak")
            try FileManager.default.createDirectory(at: dest.deletingLastPathComponent(), withIntermediateDirectories: true)
            try data.write(to: dest)
        }
        switch fix {
        case .secureBootModelDefault:
            var misc = root["Misc"] as? [String: Any] ?? [:]
            var security = misc["Security"] as? [String: Any] ?? [:]
            security["SecureBootModel"] = "Default"
            misc["Security"] = security
            root["Misc"] = misc
        case .disableSecurityPolicyOff:
            var uefi = root["UEFI"] as? [String: Any] ?? [:]
            var quirks = uefi["Quirks"] as? [String: Any] ?? [:]
            quirks["DisableSecurityPolicy"] = false
            uefi["Quirks"] = quirks
            root["UEFI"] = uefi
        case .disableTool(let name):
            var misc = root["Misc"] as? [String: Any] ?? [:]
            var tools = misc["Tools"] as? [[String: Any]] ?? []
            for i in tools.indices where (tools[i]["Path"] as? String)?.lowercased() == name.lowercased() {
                tools[i]["Enabled"] = false
            }
            misc["Tools"] = tools
            root["Misc"] = misc
        }
        let out = try PropertyListSerialization.data(fromPropertyList: root, format: format, options: 0)
        try out.write(to: url, options: .atomic)
    }
}
