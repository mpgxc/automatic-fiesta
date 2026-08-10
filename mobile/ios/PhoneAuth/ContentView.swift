import SwiftUI

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

/// Guarda o Mac pareado. Só material público — o hash de SPKI e o endereço.
/// As chaves privadas vivem no Secure Enclave e nunca passam por aqui.
@MainActor
final class PeerStore: ObservableObject {
    @Published var peer: PhoneAuthClient.Peer? {
        didSet {
            guard let peer, let data = try? JSONEncoder().encode(peer) else {
                UserDefaults.standard.removeObject(forKey: key)
                return
            }
            UserDefaults.standard.set(data, forKey: key)
        }
    }

    private let key = "dev.phoneauth.peer"

    init() {
        guard let data = UserDefaults.standard.data(forKey: key),
              let decoded = try? JSONDecoder().decode(PhoneAuthClient.Peer.self, from: data) else {
            return
        }
        peer = decoded
    }

    func forget() {
        peer = nil
        DeviceKeys.deleteAll()
    }
}

struct ContentView: View {
    @EnvironmentObject var client: PhoneAuthClient
    @EnvironmentObject var store: PeerStore
    @State private var showingPairing = false

    var body: some View {
        NavigationStack {
            Group {
                if let request = client.pendingRequest {
                    ApprovalView(request: request)
                } else if let peer = store.peer {
                    IdleView(peer: peer)
                } else {
                    UnpairedView(showingPairing: $showingPairing)
                }
            }
            .navigationTitle("PhoneAuth")
        }
        .sheet(isPresented: $showingPairing) {
            PairingView()
        }
        .onAppear {
            if let peer = store.peer { client.connect(to: peer) }
        }
    }
}

/// A tela que carrega o peso da segurança do sistema.
///
/// A defesa contra um processo malicioso disparando `sudo` e torcendo pela
/// aprovação por reflexo é o usuário **ler** isto. Por isso o motivo vem
/// grande e primeiro, e o botão de aprovar não é o mais proeminente da tela.
struct ApprovalView: View {
    let request: PhoneAuthClient.AuthChallenge
    @EnvironmentObject var client: PhoneAuthClient
    @State private var error: String?
    @State private var now = Date()

    private let tick = Timer.publish(every: 1, on: .main, in: .common).autoconnect()

    var body: some View {
        VStack(spacing: 24) {
            Spacer()

            VStack(spacing: 8) {
                Image(systemName: "lock.shield")
                    .font(.system(size: 44))
                    .foregroundStyle(.tint)
                Text(request.context.host)
                    .font(.headline)
                Text("pede autenticação")
                    .foregroundStyle(.secondary)
            }

            VStack(alignment: .leading, spacing: 12) {
                Text(request.context.reason)
                    .font(.system(.body, design: .monospaced))
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)

                Divider()

                LabeledContent("usuário", value: request.context.user)
                LabeledContent("serviço", value: request.context.service)
                if !request.context.tty.isEmpty {
                    LabeledContent("terminal", value: request.context.tty)
                }
            }
            .font(.callout)
            .padding()
            .background(.quaternary.opacity(0.5), in: RoundedRectangle(cornerRadius: 12))

            Text("expira em \(request.secondsRemaining)s")
                .font(.caption)
                .foregroundStyle(request.secondsRemaining < 10 ? .red : .secondary)

            if let error {
                Text(error)
                    .font(.caption)
                    .foregroundStyle(.red)
                    .multilineTextAlignment(.center)
            }

            Spacer()

            VStack(spacing: 12) {
                Button {
                    Task {
                        do {
                            try await client.approve(request)
                        } catch {
                            // Cancelar a biometria cai aqui. Não é erro: é o
                            // usuário decidindo não aprovar.
                            self.error = error.localizedDescription
                        }
                    }
                } label: {
                    Label("Aprovar com biometria", systemImage: "faceid")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.large)

                Button("Negar", role: .destructive) {
                    client.deny(request)
                }
                .controlSize(.large)
            }
        }
        .padding()
        .onReceive(tick) { now = $0 }
    }
}

struct IdleView: View {
    let peer: PhoneAuthClient.Peer
    @EnvironmentObject var client: PhoneAuthClient
    @EnvironmentObject var store: PeerStore

    var body: some View {
        VStack(spacing: 16) {
            Spacer()
            Image(systemName: statusIcon)
                .font(.system(size: 48))
                .foregroundStyle(statusColor)
            Text(peer.name).font(.headline)
            Text(statusText).foregroundStyle(.secondary)
            Spacer()

            if case .failed = client.state {
                Button("Reconectar") { client.connect(to: peer) }
                    .buttonStyle(.bordered)
            }
            Button("Esquecer este Mac", role: .destructive) {
                client.disconnect()
                store.forget()
            }
            .font(.footnote)
        }
        .padding()
    }

    private var statusIcon: String {
        switch client.state {
        case .connected:  "checkmark.circle.fill"
        case .connecting: "arrow.triangle.2.circlepath"
        case .failed:     "exclamationmark.triangle.fill"
        case .idle:       "moon.zzz"
        }
    }

    private var statusColor: Color {
        switch client.state {
        case .connected: .green
        case .failed:    .orange
        default:         .secondary
        }
    }

    private var statusText: String {
        switch client.state {
        case .connected:          "pronto para aprovar"
        case .connecting:         "conectando..."
        case .failed(let reason): reason
        case .idle:               "desconectado"
        }
    }
}

struct UnpairedView: View {
    @Binding var showingPairing: Bool

    var body: some View {
        VStack(spacing: 20) {
            Spacer()
            Image(systemName: "qrcode.viewfinder").font(.system(size: 56))
            Text("Nenhum Mac pareado").font(.headline)
            Text("No Mac, rode `sudo phoneauthctl pair` e escaneie o código.")
                .font(.callout)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
            Spacer()
            Button("Escanear QR code") { showingPairing = true }
                .buttonStyle(.borderedProminent)
                .controlSize(.large)
        }
        .padding()
    }
}
