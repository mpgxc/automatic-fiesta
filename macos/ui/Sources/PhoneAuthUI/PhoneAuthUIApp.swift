import SwiftUI
import PhoneAuthCore

@main
struct PhoneAuthUIApp: App {

    @State private var client = DaemonClient()
    @State private var notifier = Notifier()

    var body: some Scene {
        // `.window` e não `.menu`: o estilo de menu só aceita itens de menu, e o
        // que precisa aparecer aqui — o pedido em voo, com o comando que o
        // celular está exibindo — é um painel, não uma lista de comandos.
        MenuBarExtra {
            StatusPanel(client: client)
        } label: {
            MenuBarIcon(status: client.status, rotationPending: client.rotationPending)
        }
        .menuBarExtraStyle(.window)
        .task {
            await notifier.requestPermission()
            client.onEvent = { [notifier] event in
                notifier.post(event)
            }
        }
    }
}

/// O ícone na barra.
///
/// É a única parte da interface que o usuário vê o tempo todo, então carrega
/// exatamente uma informação: dá para autenticar pelo celular agora ou não.
/// Detalhe fica no painel.
struct MenuBarIcon: View {
    let status: DaemonClient.Status
    let rotationPending: Bool

    var body: some View {
        Image(systemName: symbol)
            .symbolRenderingMode(.hierarchical)
            // Pulsa só enquanto o celular está com o pedido na mão. É o
            // equivalente visual de "olhe para o telefone".
            .symbolEffect(.pulse, options: .repeating, isActive: status == .awaiting)
            // Um "bounce" quando o estado muda evita que uma desconexão passe
            // despercebida sem precisar de notificação para isso.
            .symbolEffect(.bounce, value: status)
            .accessibilityLabel(accessibilityText)
    }

    private var symbol: String {
        switch status {
        case .daemonDown:   "iphone.slash"
        case .noDevices:    "iphone.badge.exclamationmark"
        case .disconnected: "iphone.badge.exclamationmark"
        case .ready:        rotationPending ? "lock.iphone.badge.clock" : "lock.iphone"
        case .awaiting:     "lock.open.iphone"
        }
    }

    private var accessibilityText: String {
        switch status {
        case .daemonDown:   "PhoneAuth desligado; o sudo vai pedir senha"
        case .noDevices:    "PhoneAuth sem celular pareado"
        case .disconnected: "PhoneAuth sem celular conectado"
        case .ready:        "PhoneAuth pronto"
        case .awaiting:     "PhoneAuth aguardando sua digital no celular"
        }
    }
}
