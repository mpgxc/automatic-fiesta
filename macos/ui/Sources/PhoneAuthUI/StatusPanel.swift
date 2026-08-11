import SwiftUI
import PhoneAuthCore

/// O painel do menu bar.
///
/// **Disciplina de Liquid Glass:** o painel do `MenuBarExtra` já é uma
/// superfície de vidro do sistema. Empilhar vidro sobre vidro deixa tudo
/// leitoso e mata a hierarquia — a orientação da Apple é explícita nisso. Então
/// o conteúdo informativo fica em material comum, e `glassEffect` aparece
/// só onde há **afordância**: a pílula de estado e os botões, agrupados num
/// único `GlassEffectContainer` para que o sistema os funda em vez de renderizar
/// cada um por conta.
struct StatusPanel: View {

    let client: DaemonClient
    @Namespace private var glass
    @Environment(\.openURL) private var openURL

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header
            Divider().padding(.vertical, 12)

            if let request = client.inFlight {
                inFlightCard(request)
                    .transition(.asymmetric(insertion: .scale(scale: 0.94).combined(with: .opacity),
                                            removal: .opacity))
            } else {
                deviceSection
            }

            if !client.events.isEmpty {
                Divider().padding(.vertical, 12)
                activitySection
            }

            Divider().padding(.vertical, 12)
            footer
        }
        .padding(16)
        .frame(width: 340)
        .animation(.smooth(duration: 0.28), value: client.inFlight?.id)
        .animation(.smooth(duration: 0.28), value: client.status)
    }

    // MARK: - Cabeçalho

    private var header: some View {
        HStack(alignment: .firstTextBaseline) {
            VStack(alignment: .leading, spacing: 2) {
                Text(client.hostName)
                    .font(.headline)
                Text(subtitle)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            statusPill
        }
    }

    private var statusPill: some View {
        HStack(spacing: 5) {
            Circle()
                .fill(tint)
                .frame(width: 6, height: 6)
            Text(pillLabel)
                .font(.caption2.weight(.medium))
        }
        .padding(.horizontal, 9)
        .padding(.vertical, 5)
        // `.clear` e não `.regular`: a pílula é pequena e fica sobre o vidro do
        // painel. A variante regular criaria uma segunda camada visível; a clear
        // deixa o tint conduzir a leitura.
        .glassEffect(.clear.tint(tint.opacity(0.55)), in: .capsule)
        .glassEffectID("pill", in: glass)
    }

    private var subtitle: String {
        switch client.status {
        case .daemonDown:
            "phoneauthd não está respondendo"
        case .noDevices:
            "nenhum celular pareado"
        case .disconnected:
            "\(client.devicesActive) pareado(s), nenhum ao alcance"
        case .ready, .awaiting:
            client.connected.first.map { "\($0.name)" } ?? "conectado"
        }
    }

    private var pillLabel: String {
        switch client.status {
        case .daemonDown:   "desligado"
        case .noDevices:    "sem par"
        case .disconnected: "offline"
        case .ready:        "pronto"
        case .awaiting:     "aguardando"
        }
    }

    private var tint: Color {
        switch client.status {
        case .daemonDown:   .secondary
        case .noDevices:    .orange
        case .disconnected: .orange
        case .ready:        .green
        case .awaiting:     .blue
        }
    }

    // MARK: - Pedido em voo

    /// A parte que mais importa da interface inteira.
    ///
    /// Mostra o **mesmo** motivo que está na tela do celular. Se os dois
    /// divergirem, algo está muito errado — e é justamente o ataque que o
    /// contexto assinado impede. Ter os dois lado a lado dá ao usuário como
    /// perceber isso sem entender de criptografia.
    private func inFlightCard(_ event: UIEvent.Event) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            Label("Confirme no celular", systemImage: "touchid")
                .font(.subheadline.weight(.semibold))
                .foregroundStyle(.blue)

            if let detail = event.detail {
                Text(detail)
                    .font(.system(.callout, design: .monospaced))
                    .textSelection(.enabled)
                    .lineLimit(3)
                    .truncationMode(.middle)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(10)
                    .background(.quaternary.opacity(0.5), in: .rect(cornerRadius: 8))
            }

            Text("O Mac não pode aprovar isto. A assinatura só existe se a sua digital for apresentada ao celular.")
                .font(.caption2)
                .foregroundStyle(.tertiary)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    // MARK: - Dispositivos

    @ViewBuilder
    private var deviceSection: some View {
        if client.connected.isEmpty {
            VStack(alignment: .leading, spacing: 6) {
                Text(emptyTitle).font(.subheadline.weight(.medium))
                Text(emptyHint)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        } else {
            VStack(alignment: .leading, spacing: 8) {
                ForEach(client.connected) { device in
                    HStack(spacing: 9) {
                        Image(systemName: device.platform == "android" ? "candybarphone" : "iphone")
                            .foregroundStyle(.secondary)
                        VStack(alignment: .leading, spacing: 1) {
                            Text(device.name).font(.callout)
                            Text("conectado desde \(device.since, format: .dateTime.hour().minute())")
                                .font(.caption2)
                                .foregroundStyle(.tertiary)
                        }
                        Spacer()
                    }
                }
            }
        }
    }

    private var emptyTitle: String {
        client.status == .daemonDown ? "Daemon fora do ar" : "Nenhum celular ao alcance"
    }

    /// Sempre dizer o que acontece na prática. O usuário não precisa saber o que
    /// é `sufficient`, precisa saber que a máquina não travou.
    private var emptyHint: String {
        switch client.status {
        case .daemonDown:
            "O sudo continua funcionando com a senha, como sempre. Verifique com: phoneauthctl status"
        case .noDevices:
            "Pareie um celular para começar. Até lá, o sudo pede senha normalmente."
        default:
            "O sudo vai pedir a senha até o celular voltar à mesma rede."
        }
    }

    // MARK: - Atividade

    private var activitySection: some View {
        VStack(alignment: .leading, spacing: 7) {
            Text("Atividade")
                .font(.caption.weight(.medium))
                .foregroundStyle(.secondary)

            ForEach(client.events.suffix(4).reversed()) { event in
                HStack(alignment: .top, spacing: 7) {
                    Image(systemName: icon(for: event.kind))
                        .font(.caption)
                        .foregroundStyle(color(for: event.kind))
                        .frame(width: 13)
                    VStack(alignment: .leading, spacing: 1) {
                        Text(event.title).font(.caption)
                        if let detail = event.detail {
                            Text(detail)
                                .font(.caption2)
                                .foregroundStyle(.tertiary)
                                .lineLimit(1)
                                .truncationMode(.middle)
                        }
                    }
                    Spacer()
                    Text(event.at, format: .dateTime.hour().minute())
                        .font(.caption2)
                        .foregroundStyle(.quaternary)
                }
            }
        }
    }

    private func icon(for kind: UIEvent.Kind) -> String {
        switch kind {
        case .requestApproved:  "checkmark.circle.fill"
        case .requestDenied:    "hand.raised.fill"
        case .requestExpired:   "clock.badge.xmark"
        case .requestNoDevice:  "iphone.slash"
        case .requestRejected:  "exclamationmark.triangle.fill"
        case .requestSent:      "paperplane"
        case .deviceConnected:  "link"
        case .deviceDisconnected: "link.badge.plus"
        case .devicePaired:     "checkmark.seal.fill"
        case .deviceRevoked:    "xmark.seal.fill"
        case .rotationAnnounced, .rotationCommitted: "key.horizontal"
        }
    }

    private func color(for kind: UIEvent.Kind) -> Color {
        if kind.isAlarming { return .red }
        switch kind {
        case .requestApproved, .devicePaired: return .green
        case .requestDenied, .requestExpired, .requestNoDevice: return .orange
        default: return .secondary
        }
    }

    // MARK: - Rodapé

    /// Um único container para o sistema fundir os botões entre si em vez de
    /// desenhar três lâminas de vidro separadas encostadas.
    private var footer: some View {
        GlassEffectContainer(spacing: 8) {
            HStack(spacing: 8) {
                Button {
                    pairInTerminal()
                } label: {
                    Label("Parear", systemImage: "qrcode")
                        .font(.caption)
                }
                .buttonStyle(.glass)
                .glassEffectID("pair", in: glass)
                .help("Abre o Terminal com o comando de pareamento")

                Button {
                    NSWorkspace.shared.open(URL(fileURLWithPath: "/var/log/phoneauthd.log"))
                } label: {
                    Label("Logs", systemImage: "doc.text")
                        .font(.caption)
                }
                .buttonStyle(.glass)
                .glassEffectID("logs", in: glass)

                Spacer()

                Button("Sair") { NSApplication.shared.terminate(nil) }
                    .buttonStyle(.glass)
                    .glassEffectID("quit", in: glass)
                    .font(.caption)
            }
        }
    }

    /// Parear exige root, e a UI roda como você.
    ///
    /// Poderia pedir uma autorização do sistema e falar com o daemon por um
    /// helper privilegiado — é o caminho correto e está anotado como fase 2. Até
    /// lá, abrir o Terminal com o comando é honesto: você vê exatamente o que
    /// vai rodar e digita a própria senha. Nenhum atalho de privilégio
    /// escondido dentro de um app de barra de menu.
    private func pairInTerminal() {
        let script = """
        tell application "Terminal"
            activate
            do script "sudo phoneauthctl pair"
        end tell
        """
        guard let apple = NSAppleScript(source: script) else { return }
        var error: NSDictionary?
        apple.executeAndReturnError(&error)
    }
}
