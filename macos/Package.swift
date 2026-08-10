// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "PhoneAuth",
    platforms: [.macOS(.v13)],
    products: [
        .library(name: "PhoneAuthCore", targets: ["PhoneAuthCore"]),
        .executable(name: "phoneauthd",   targets: ["phoneauthd"]),
        .executable(name: "phoneauthctl", targets: ["phoneauthctl"]),
    ],
    targets: [
        .target(name: "PhoneAuthCore"),
        .executableTarget(name: "phoneauthd",   dependencies: ["PhoneAuthCore"]),
        .executableTarget(name: "phoneauthctl", dependencies: ["PhoneAuthCore"]),
        .testTarget(name: "PhoneAuthCoreTests",  dependencies: ["PhoneAuthCore"]),
    ]
)
