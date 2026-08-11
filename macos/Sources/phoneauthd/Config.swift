import Foundation

struct Config: Codable {
    var port: UInt16 = 58731
    var serviceName: String = Host.current().localizedName ?? "Mac"
    /// Quanto tempo o pedido fica válido no celular.
    var requestTTLSeconds: Double = 60
    /// Quanto tempo o daemon espera pelo celular antes de desistir. Sempre
    /// menor que o timeout do módulo PAM, para que quem desista primeiro seja
    /// o daemon e o terminal caia limpo no próximo módulo.
    var responseTimeoutSeconds: Double = 25
    /// Serviços PAM que este daemon atende. `sudo` e `su` por padrão;
    /// `screensaver` exige mexer no authorization database (docs/instalacao.md).
    var allowedServices: [String] = ["sudo", "sudo_local", "su"]

    /// Quanto tempo, no mínimo, uma rotação de identidade fica apenas
    /// anunciada antes de poder ser comitada. É o prazo que um celular tem para
    /// aparecer e aprender o pin novo; durante ele nada quebra, porque a
    /// identidade viva ainda é a antiga. Uma semana cobre uma viagem.
    var rotationWindowSeconds: Double = 7 * 24 * 3600

    /// Quanto tempo, depois do commit, o daemon ainda aceita assinaturas
    /// calculadas com o binding da identidade anterior.
    ///
    /// **Isto tem custo de segurança** e é uma muleta de compatibilidade com
    /// prazo: enquanto ela vale, quem tivesse a chave TLS antiga conseguiria
    /// relaiar uma aprovação assinada sob o certificado antigo. Ver
    /// docs/rotacao-de-identidade.md §4.6. Deve virar zero assim que os apps
    /// derivarem o binding da conexão viva; numa rotação por comprometimento já
    /// é forçada a zero.
    var previousBindingGraceSeconds: Double = 24 * 3600

    static let stateDirectory = URL(fileURLWithPath: "/Library/Application Support/PhoneAuth", isDirectory: true)
    static let socketPath     = "/var/run/phoneauthd.sock"
    /// Socket separado para a interface gráfica: o de controle é 0600
    /// root:wheel e um app de barra de menu roda como o usuário. Abrir aquele
    /// para não-root entregaria pareamento e revogação junto.
    static let uiSocketPath   = "/var/run/phoneauthd-ui.sock"

    static func load() -> Config {
        let url = stateDirectory.appendingPathComponent("config.json")
        guard let data = try? Data(contentsOf: url),
              let cfg = try? JSONDecoder().decode(Config.self, from: data) else {
            return Config()
        }
        return cfg
    }
}

/// Log em stderr, capturado pelo launchd em /var/log/phoneauthd.log.
///
/// Nunca registramos desafios, assinaturas ou material de chave. O contexto do
/// pedido é registrado porque é o que torna um incidente investigável — e ele
/// já é exibido na tela do celular de qualquer forma.
enum Log {
    private static let formatter: ISO8601DateFormatter = {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime]
        return f
    }()

    static func write(_ level: String, _ message: String) {
        FileHandle.standardError.write(Data("\(formatter.string(from: Date())) [\(level)] \(message)\n".utf8))
    }

    static func info(_ m: String)  { write("info", m) }
    static func warn(_ m: String)  { write("warn", m) }
    static func error(_ m: String) { write("error", m) }
}
