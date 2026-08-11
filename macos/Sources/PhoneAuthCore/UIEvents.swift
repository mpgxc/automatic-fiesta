import Foundation

/// Eventos que o daemon publica para a interface gráfica.
///
/// Este canal é **estritamente de leitura**. Ele carrega o que aconteceu, nunca
/// o que deve acontecer — a UI do Mac não decide nada.
///
/// A razão é o projeto inteiro: se fosse possível liberar um `sudo` clicando no
/// Mac, a biometria do celular viraria decoração. Quem já comprometeu a sessão
/// do usuário para disparar o `sudo` malicioso também consegue clicar no botão.
/// A única aprovação que vale é a assinatura que só o enclave do celular
/// produz, e ela nunca passa por aqui.
public enum UIEvent {

    public enum Kind: String, Codable, Sendable {
        /// Um pedido saiu para o celular. A UI anima o ícone; não notifica.
        case requestSent      = "request.sent"
        /// Aprovado e assinatura verificada. Não notifica: o terminal seguiu.
        case requestApproved  = "request.approved"
        /// Negado no celular.
        case requestDenied    = "request.denied"
        /// Ninguém respondeu a tempo.
        case requestExpired   = "request.expired"
        /// Pedido chegou sem celular conectado.
        case requestNoDevice  = "request.no_device"
        /// Assinatura inválida — isto nunca deveria acontecer.
        case requestRejected  = "request.rejected"

        case deviceConnected    = "device.connected"
        case deviceDisconnected = "device.disconnected"
        case devicePaired       = "device.paired"
        case deviceRevoked      = "device.revoked"

        case rotationAnnounced = "rotation.announced"
        case rotationCommitted = "rotation.committed"

        /// Se **este** evento merece uma notificação do sistema.
        ///
        /// A regra é: notifique o que o usuário não perceberia sozinho.
        ///
        /// Aprovar não notifica porque o terminal simplesmente seguiu — a
        /// evidência já está na tela dele. Pedido enviado também não, porque
        /// ele acabou de digitar `sudo` e está olhando para o cursor.
        ///
        /// Notificar tudo produziria uma enxurrada em cada `sudo`, e um usuário
        /// treinado a ignorar notificações é exatamente o que o atacante quer.
        public var deservesNotification: Bool {
            switch self {
            case .requestSent, .requestApproved, .deviceConnected:
                return false
            case .requestDenied, .requestExpired, .requestNoDevice, .requestRejected,
                 .deviceDisconnected, .devicePaired, .deviceRevoked,
                 .rotationAnnounced, .rotationCommitted:
                return true
            }
        }

        /// Eventos que pedem atenção real, não só informação.
        public var isAlarming: Bool {
            self == .requestRejected || self == .deviceRevoked
        }
    }

    public struct Event: Codable, Sendable, Identifiable {
        public let id: String
        public let type: String          // sempre "ui.event", para o roteamento do frame
        public let kind: Kind
        public let at: Date
        /// Uma linha, já pronta para exibição. Formatar no daemon evita que a UI
        /// precise conhecer o modelo de domínio inteiro.
        public let title: String
        /// O motivo do pedido, quando houver. É o argv de quem chamou o `sudo`.
        public let detail: String?
        public let deviceName: String?

        public init(kind: Kind, title: String, detail: String? = nil, deviceName: String? = nil) {
            self.id = UUID().uuidString
            self.type = "ui.event"
            self.kind = kind
            self.at = Date()
            self.title = title
            self.detail = detail
            self.deviceName = deviceName
        }
    }

    /// Retrato do estado atual, enviado assim que a UI se inscreve. Sem ele a
    /// interface abriria vazia e só ganharia conteúdo no próximo evento.
    public struct Snapshot: Codable, Sendable {
        public let type: String
        public let hostName: String
        public let devicesActive: Int
        public let devicesTotal: Int
        public let connected: [ConnectedDevice]
        public let rotationPending: Bool
        public let recent: [Event]

        public init(hostName: String, devicesActive: Int, devicesTotal: Int,
                    connected: [ConnectedDevice], rotationPending: Bool, recent: [Event]) {
            self.type = "ui.snapshot"
            self.hostName = hostName
            self.devicesActive = devicesActive
            self.devicesTotal = devicesTotal
            self.connected = connected
            self.rotationPending = rotationPending
            self.recent = recent
        }
    }

    public struct ConnectedDevice: Codable, Sendable, Identifiable {
        public let id: String
        public let name: String
        public let platform: String
        public let since: Date

        public init(id: String, name: String, platform: String, since: Date) {
            self.id = id
            self.name = name
            self.platform = platform
            self.since = since
        }
    }
}
