import Foundation
import UserNotifications
import PhoneAuthCore

/// Notificações do sistema.
///
/// **Nenhuma notificação daqui tem botão de ação.** Isso é decisão de
/// segurança, não simplificação.
///
/// Uma notificação com "Aprovar" no Mac destruiria o projeto: quem já
/// comprometeu a sessão para disparar um `sudo` malicioso também consegue
/// clicar naquele botão. A única aprovação que vale é a assinatura que o enclave
/// do celular produz mediante biometria, e ela não tem como nascer aqui.
///
/// Um patch que acrescente `UNNotificationAction` de aprovação é um bug de
/// severidade máxima, não uma melhoria de usabilidade.
@Observable
@MainActor
final class Notifier {

    private(set) var authorized = false

    /// Eventos idênticos em sequência viram um só.
    ///
    /// A janela existe porque a enxurrada de notificações é o ataque, não um
    /// incômodo: um usuário treinado a dispensar avisos no reflexo já perdeu a
    /// defesa que o contexto na tela deveria dar.
    private var lastSignature: String?
    private var lastPostedAt: Date?
    private static let coalesceWindow: TimeInterval = 5

    func requestPermission() async {
        do {
            authorized = try await UNUserNotificationCenter.current()
                .requestAuthorization(options: [.alert, .sound])
        } catch {
            authorized = false
        }
    }

    func post(_ event: UIEvent.Event) {
        guard authorized, event.kind.deservesNotification else { return }

        let signature = "\(event.kind.rawValue)|\(event.detail ?? "")"
        if signature == lastSignature,
           let last = lastPostedAt,
           Date().timeIntervalSince(last) < Self.coalesceWindow {
            return
        }
        lastSignature = signature
        lastPostedAt = Date()

        let content = UNMutableNotificationContent()
        content.title = event.title
        if let detail = event.detail {
            content.body = detail
        }
        content.sound = event.kind.isAlarming ? .defaultCritical : nil

        // `.timeSensitive` fura o Foco. Só para o que é de fato anômalo: uma
        // assinatura inválida ou uma revogação. Um `sudo` negado é rotina e não
        // merece atravessar o Não Perturbe de ninguém.
        content.interruptionLevel = event.kind.isAlarming ? .timeSensitive : .active

        // Agrupa por tipo para o Centro de Notificações empilhar em vez de
        // enfileirar dezenas de linhas iguais.
        content.threadIdentifier = event.kind.rawValue

        UNUserNotificationCenter.current().add(
            UNNotificationRequest(identifier: event.id, content: content, trigger: nil)
        )
    }
}
