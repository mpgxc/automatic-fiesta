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

    static let stateDirectory = URL(fileURLWithPath: "/Library/Application Support/PhoneAuth", isDirectory: true)
    static let socketPath     = "/var/run/phoneauthd.sock"

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
