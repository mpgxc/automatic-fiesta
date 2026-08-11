import SwiftUI

/// Ponto de entrada do app iOS.
///
/// Mora fora de `PhoneAuth/` de propósito: aquele diretório é o alvo de
/// biblioteca do Package.swift, que existe para o CI conseguir compilar o código
/// sem um .xcodeproj. Um `@main` dentro de uma biblioteca não faz sentido e o
/// compilador reclama.
///
/// Quando houver um alvo de app de verdade — com assinatura, entitlements de
/// Secure Enclave e permissão de rede local — este arquivo entra nele junto com
/// o diretório PhoneAuth/.
@main
struct PhoneAuthApp: App {
    @StateObject private var client = PhoneAuthClient()
    @StateObject private var store = PeerStore()

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(client)
                .environmentObject(store)
        }
    }
}
