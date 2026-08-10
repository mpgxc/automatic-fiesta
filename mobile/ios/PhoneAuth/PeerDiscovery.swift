import Foundation
import Network

/// Encontra o Mac pareado na LAN por Bonjour (`_phoneauth._tcp`, o mesmo tipo
/// que o daemon anuncia em `PhoneListener.start()`).
///
/// **Descoberta resolve endereço, nunca identidade.** O que sai daqui é um
/// palpite de *onde* o Mac está — e nada além disso. Quem decide se é o Mac
/// certo é o handshake TLS contra o hash de SPKI pinado no pareamento, em
/// `PhoneAuthClient`. Um serviço que se anuncie com o mesmo nome e apresente
/// outro certificado falha o handshake e cai como qualquer candidato ruim.
///
/// É por isso que nada aqui olha para registro TXT nem tira conclusão do nome
/// do serviço: o nome só serve para *ordenar* candidatos e poupar handshakes.
/// Se ele fosse usado como decisão de confiança, a descoberta viraria uma
/// segunda raiz de confiança — e uma raiz que qualquer um na rede consegue
/// forjar com um `dns-sd -R`.
///
/// Requer, no `Info.plist`:
///
/// - `NSLocalNetworkUsageDescription` — texto do prompt de permissão;
/// - `NSBonjourServices` contendo `_phoneauth._tcp`.
///
/// Sem as duas, o iOS 14+ não deixa navegar nem resolver: o browser fica em
/// `.waiting` para sempre e a descoberta silenciosamente nunca acha nada.
@MainActor
final class PeerDiscovery {

    /// O mesmo tipo anunciado pelo daemon. Se mudar de um lado, muda dos dois.
    static let serviceType = "_phoneauth._tcp"

    /// Chamado quando o conjunto de endpoints muda de verdade — aparecer um
    /// serviço novo é sinal forte de que o Mac voltou.
    var onResultsChanged: (() -> Void)?

    private var browser: NWBrowser?
    private var endpoints: [NWEndpoint] = []

    var isBrowsing: Bool { browser != nil }

    // MARK: - Ciclo de vida

    func start() {
        guard browser == nil else { return }

        let parameters = NWParameters()
        // O daemon escuta e anuncia só na LAN (`includePeerToPeer = false` no
        // listener). Ligar AWDL aqui acenderia rádio para achar serviços que
        // nunca vão existir.
        parameters.includePeerToPeer = false

        let browser = NWBrowser(
            for: .bonjour(type: Self.serviceType, domain: nil),
            using: parameters
        )

        browser.browseResultsChangedHandler = { [weak self] results, _ in
            // O handler chega na fila do browser; o estado é do MainActor.
            Task { @MainActor in self?.apply(results) }
        }

        browser.stateUpdateHandler = { [weak self] state in
            Task { @MainActor in
                guard let self else { return }
                switch state {
                case .failed:
                    // Browser que falhou não se recupera sozinho. Solta tudo e
                    // deixa o ciclo de reconexão do cliente mandar recomeçar —
                    // ele já tem backoff; reiniciar aqui viraria loop apertado.
                    self.stop()
                case .cancelled:
                    self.browser = nil
                default:
                    break
                }
            }
        }

        browser.start(queue: .main)
        self.browser = browser
    }

    func stop() {
        browser?.cancel()
        browser = nil
        // Endpoints de outra rede são pior que nenhum: gastariam tentativas
        // resolvendo nomes que não existem mais aqui.
        endpoints = []
    }

    // MARK: - Resultados

    private func apply(_ results: Set<NWBrowser.Result>) {
        let found = results.compactMap { result -> NWEndpoint? in
            // Só endpoints de serviço interessam. O `NWConnection` resolve um
            // deles sozinho na hora de conectar, sempre no endereço atual — é
            // exatamente o que o endereço fixo do QR não faz.
            guard case .service = result.endpoint else { return nil }
            return result.endpoint
        }

        // Ordem estável para que uma varredura que devolve o mesmo conjunto em
        // outra ordem não conte como mudança.
        let sorted = found.sorted { (Self.serviceName(of: $0) ?? "") < (Self.serviceName(of: $1) ?? "") }
        guard sorted != endpoints else { return }

        endpoints = sorted
        onResultsChanged?()
    }

    /// Candidatos com os de nome igual ao do Mac pareado na frente.
    ///
    /// O nome do serviço normalmente coincide com o que veio no QR — os dois
    /// saem de `Host.current().localizedName` no Mac — mas não dá para exigir:
    /// `serviceName` é configurável no daemon e o próprio Bonjour renomeia para
    /// "Mac (2)" quando há conflito na rede. Então o nome ordena; nunca filtra.
    /// Filtrar por nome deixaria o usuário sem conexão por um motivo cosmético.
    func candidates(preferringName name: String) -> [NWEndpoint] {
        let matching = endpoints.filter { Self.serviceName(of: $0) == name }
        let rest = endpoints.filter { Self.serviceName(of: $0) != name }
        return matching + rest
    }

    static func serviceName(of endpoint: NWEndpoint) -> String? {
        if case let .service(name, _, _, _) = endpoint { return name }
        return nil
    }
}
