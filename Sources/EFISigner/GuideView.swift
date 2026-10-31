import SwiftUI

struct GuideLink: Identifiable {
    let id = UUID()
    let label: String
    let detail: String
    let url: String
}

struct GuideSection: Identifiable {
    let id = UUID()
    let title: String
    let icon: String
    let intro: String?
    let steps: [String]
    var links: [GuideLink] = []
}

enum Guide {
    static let sections: [GuideSection] = [
        GuideSection(title: "What this app does", icon: "info.circle", intro:
            "A PC firmware with UEFI Secure Boot on will only run EFI files signed by a certificate in its database. OpenCore and its drivers are shipped unsigned, so you normally have to switch Secure Boot off to boot a Hackintosh. EFI Signer signs those files with your own certificate; once that certificate is added to the firmware, Secure Boot can stay on.",
            steps: []),
        GuideSection(title: "One-time setup", icon: "1.circle", intro: nil, steps: [
            "Key menu → Generate new key. This creates a private key and a self-signed certificate on this Mac. If you already have db.key and db.crt from elsewhere, use Import instead.",
            "Select the EFI partition of the disk you boot from in the sidebar. If it is grey, press Mount and enter your password.",
            "Read the header. Green \"Ready for Secure Boot\" means every file the firmware loads is signed with your key and OpenCore's config.plist has no blockers. Red means some rows say \"Needs signing\" or a config warning is shown above the table.",
            "Fix any config warning first; each one has a Fix… button that edits config.plist for you after keeping a copy. In particular SecureBootModel must not be Disabled: Apple's boot.efi carries an Apple-format signature the PC firmware cannot check, and only with Apple Secure Boot active does OpenCore verify and load it itself.",
            "Press Sign needed and confirm. A copy of every original is kept in the Backups folder (Key menu → Show backups).",
            "Key menu → Export certificate for BIOS and choose a FAT32 USB stick (the EFI partition of any USB disk works). This writes db.cer and db.esl.",
            "Reboot into the BIOS. On the Secure Boot page switch to Custom mode or open Key Management, choose db, then Append / Add from file, and pick db.cer from the stick (db.esl if .cer is refused). Do not touch PK or KEK and keep Microsoft's entries: they sign your graphics card's option ROM and Windows.",
            "Set Secure Boot to Enabled, save, and boot. Back in macOS the sidebar should read \"UEFI Secure Boot: enforced\".",
            "Optional but recommended: set a BIOS password, so nobody can switch Secure Boot off again without you noticing.",
        ]),
        GuideSection(title: "Enrolling the certificate, by motherboard brand", icon: "link", intro:
            "The menu is always under Secure Boot and only unlocks in Custom mode (ASUS, ASRock, Gigabyte, MSI) or with a custom policy switch (Dell, Lenovo, HP). Pick db, then Append / Add from file, and choose db.cer. Official references:",
            steps: [], links: [
            GuideLink(label: "ASUS", detail: "Secure Boot FAQ: Secure Boot Mode → Custom → Key Management", url: "https://www.asus.com/support/faq/1049829/"),
            GuideLink(label: "ASRock", detail: "FAQ 531: Security → Secure Boot → Custom → Key Management", url: "https://www.asrock.com/support/faq.asp?id=531"),
            GuideLink(label: "Gigabyte", detail: "FAQ 4395: Boot → Secure Boot Mode → Custom → Key Management", url: "https://www.gigabyte.com/Support/Consumer/Faq/4395"),
            GuideLink(label: "MSI", detail: "BIOS user guide (PDF): Secure Boot Mode → Custom shows the Key Management submenu", url: "https://download-2.msi.com/archive/mnu_exe/mb/AMDAM5BIOS.pdf"),
            GuideLink(label: "Dell", detail: "Expert Key Management: enable Custom Mode, then db → Append", url: "https://www.dell.com/support/kbdoc/en-us/000368610/how-to-update-secure-boot-active-database-from-bios"),
            GuideLink(label: "Lenovo", detail: "Secure Boot Policy → Custom Policy → enroll DB from a certificate file", url: "https://pubs.lenovo.com/uefi_edge_v2/secure_boot_custom_policy"),
            GuideLink(label: "HP (business PCs)", detail: "BIOS Setup guide (PDF): Key Ownership → Custom Keys, then import", url: "https://ftp.hp.com/pub/caps-softpaq/cmit/whitepapers/HPBIOSSetup.pdf"),
        ]),
        GuideSection(title: "After every OpenCore update", icon: "arrow.triangle.2.circlepath", intro:
            "New OpenCore builds replace the binaries, which invalidates the signatures.", steps: [
            "Copy the new OpenCore files onto the EFI partition as you normally do.",
            "Open EFI Signer, select the partition, press Sign needed.",
            "Reboot. Nothing changes in the BIOS; the certificate stays enrolled.",
        ]),
        GuideSection(title: "Other disks and USB sticks", icon: "externaldrive", intro:
            "Installer sticks and rescue disks carry their own OpenCore and need the same treatment.", steps: [
            "Mount the stick's EFI partition from the sidebar.",
            "Fix any config warning it shows with its Fix… button (installer configs often have SecureBootModel Disabled).",
            "Press Sign needed. It will then boot with Secure Boot on as well.",
        ]),
        GuideSection(title: "Reading the table", icon: "list.bullet.rectangle", intro: nil, steps: [
            "Needs signing: the firmware will refuse this file under Secure Boot.",
            "Signed with your key: fine.",
            "Signed (other key): Microsoft's loaders and similar. Fine as long as that vendor's certificate is still in the firmware's db.",
            "Signature broken: the file changed after it was signed. Re-sign it.",
            "Not loaded (disabled in config): an OpenCore driver or tool with Enabled set to false; the firmware never sees it.",
            "Apple-signed, handled by OpenCore / Not loaded by firmware: Apple's boot files and firmware-updater files. Ignore them.",
        ]),
        GuideSection(title: "If a boot fails under Secure Boot", icon: "exclamationmark.triangle", intro: nil, steps: [
            "Switch Secure Boot off in the BIOS and boot macOS. Windows keeps booting either way, since it has its own Microsoft-signed loader.",
            "Open EFI Signer and look for red rows or config warnings on the boot disk's EFI partition.",
            "Toolbar → Revert puts files back from the backup made when they were signed (or strips the signature if there is no backup), and can restore config.plist to the copy saved before the first Fix…. The Backups folder in Application Support holds the same files if you prefer to copy them by hand.",
            "The firmware usually names the file it refused on screen; that is the one to check first.",
        ]),
        GuideSection(title: "Where things are stored", icon: "folder", intro:
            "Key, certificate and backups live in ~/Library/Application Support/EFI Signer. Keep db.key private: anyone with it can sign files your firmware will trust. Losing it means generating a new key and enrolling the new certificate in the BIOS.",
            steps: []),
    ]
}

struct GuideView: View {
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 22) {
                Text("EFI Signer Guide").font(.largeTitle).bold()
                ForEach(Guide.sections) { s in
                    VStack(alignment: .leading, spacing: 8) {
                        Label(s.title, systemImage: s.icon).font(.title3).bold()
                        if let intro = s.intro {
                            Text(intro).fixedSize(horizontal: false, vertical: true)
                        }
                        ForEach(Array(s.steps.enumerated()), id: \.offset) { i, step in
                            HStack(alignment: .top, spacing: 8) {
                                Text("\(i + 1).").monospacedDigit().foregroundStyle(.secondary).frame(width: 22, alignment: .trailing)
                                Text(step).fixedSize(horizontal: false, vertical: true)
                            }
                        }
                        ForEach(s.links) { l in
                            HStack(alignment: .top, spacing: 8) {
                                if let u = URL(string: l.url) {
                                    Link(l.label, destination: u).frame(width: 130, alignment: .leading)
                                }
                                Text(l.detail).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                            }
                        }
                    }
                }
            }
            .padding(24)
            .frame(maxWidth: 720, alignment: .leading)
        }
        .frame(minWidth: 560, minHeight: 500)
    }
}
