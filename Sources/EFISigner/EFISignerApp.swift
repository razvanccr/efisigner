import SwiftUI
import AppKit

@main
struct EFISignerApp: App {
    @StateObject private var model = AppModel()

    init() {
        NSApplication.shared.setActivationPolicy(.regular)
    }

    var body: some Scene {
        WindowGroup("EFI Signer") {
            ContentView()
                .environmentObject(model)
                .onAppear { NSApp.activate(ignoringOtherApps: true) }
        }
        .commands {
            CommandGroup(replacing: .newItem) {}
            CommandGroup(replacing: .help) {
                Button("EFI Signer Guide") { openWindow(id: "guide") }.keyboardShortcut("?", modifiers: .command)
            }
        }
        Window("EFI Signer Guide", id: "guide") {
            GuideView()
        }
        .defaultSize(width: 720, height: 760)
    }

    @Environment(\.openWindow) private var openWindow
}
