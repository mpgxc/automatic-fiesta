// swift-tools-version: 6.0
import PackageDescription

// Existe para o app iOS poder ser **compilado**.
//
// Não há .xcodeproj no repositório — um pbxproj é praticamente irrevisável em
// diff, e num projeto de autenticação isso importa: ninguém percebe uma flag de
// entitlement ou um framework a mais entrando por ali.
//
// A consequência era que o código iOS nunca passava por compilador nenhum. Este
// pacote resolve isso: `xcodebuild -destination 'generic/platform=iOS'` faz o
// type-check completo, incluindo as views SwiftUI, sem precisar de projeto.
//
// Para *rodar* no aparelho ainda é preciso um alvo de app — com assinatura,
// entitlements de Secure Enclave e permissão de rede local. Este pacote não
// substitui isso; garante que o código compila antes de chegar lá.
let package = Package(
    name: "PhoneAuthKit",
    platforms: [.iOS(.v17)],
    products: [
        .library(name: "PhoneAuthKit", targets: ["PhoneAuthKit"]),
    ],
    targets: [
        .target(
            name: "PhoneAuthKit",
            path: "PhoneAuth",
            // O Info.plist pertence ao alvo de app, não à biblioteca; sem
            // excluir, o SwiftPM reclama de recurso não tratado.
            exclude: ["Info.plist"],
            swiftSettings: [.swiftLanguageMode(.v5)]
        ),
    ]
)
