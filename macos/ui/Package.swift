// swift-tools-version: 6.0
import PackageDescription

// Pacote separado do daemon, de propósito.
//
// O `phoneauthd` tem alvo macOS 13: ele é infraestrutura e não há razão para
// exigir Tahoe de quem só quer autenticar. Liquid Glass é macOS 26, e a
// plataforma mínima no SwiftPM é do pacote inteiro, não por alvo — então
// misturar os dois obrigaria o daemon a subir junto.
//
// A UI depende do pacote de cima por caminho, o que funciona porque a mínima da
// dependência (13) é menor que a nossa (26).
let package = Package(
    name: "PhoneAuthUI",
    platforms: [.macOS("26.0")],
    products: [
        .executable(name: "PhoneAuthUI", targets: ["PhoneAuthUI"]),
    ],
    dependencies: [
        .package(path: ".."),
    ],
    targets: [
        .executableTarget(
            name: "PhoneAuthUI",
            dependencies: [.product(name: "PhoneAuthCore", package: "macos")],
            swiftSettings: [.swiftLanguageMode(.v6)]
        ),
    ]
)
