// swift-tools-version: 6.0
import PackageDescription

// Tegata: a checkpoint for your AI coding agents. The detector (secrets your agents copied), the watcher
// (what your agents load, and what changes), the fixes, and the `tegata` command line. Apache-2.0.
let package = Package(
    name: "Tegata",
    platforms: [.macOS(.v15)],
    products: [
        // Portable: inventory, risk rules, diff, remedies, Exposure, sealed coding, key-provider abstraction.
        .library(name: "TegataCore", targets: ["TegataCore"]),
        // macOS: Secure Enclave key provider, keychain secrets, code-signature check, folder watcher.
        .library(name: "TegataDarwin", targets: ["TegataDarwin"]),
        // The `tegata` command line: scan, inventory, clean, fix, watch.
        .executable(name: "tegata", targets: ["tegata"]),
        // The same command as a library, for the signed bundle built by Packaging/macos.
        .library(name: "TegataCommand", targets: ["TegataCommand"]),
    ],
    targets: [
        .target(name: "TegataCore"),
        .target(name: "TegataDarwin", dependencies: ["TegataCore"]),
        .target(name: "TegataCommand", dependencies: ["TegataCore", .target(name: "TegataDarwin", condition: .when(platforms: [.macOS]))]),
        .executableTarget(name: "tegata", dependencies: ["TegataCommand"]),
        .testTarget(name: "TegataCoreTests", dependencies: ["TegataCore", "TegataCommand"]),
    ]
)
