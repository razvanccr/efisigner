// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "EFISigner",
    platforms: [.macOS(.v13)],
    products: [
        .library(name: "EFISignKit", targets: ["EFISignKit"]),
        .executable(name: "efisign", targets: ["efisign"]),
        .executable(name: "EFISigner", targets: ["EFISigner"]),
    ],
    targets: [
        .target(name: "EFISignKit", path: "Sources/EFISignKit"),
        .executableTarget(name: "efisign", dependencies: ["EFISignKit"], path: "Sources/efisign"),
        .executableTarget(name: "EFISigner", dependencies: ["EFISignKit"], path: "Sources/EFISigner"),
    ]
)
