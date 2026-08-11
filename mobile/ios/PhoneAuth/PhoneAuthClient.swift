import Foundation
import Network
import CryptoKit
import Combine
import UIKit

/// Conexão com o Mac: descoberta por Bonjour, TLS 1.3 com pinning de SPKI.
///
/// O certificado do daemon é auto-assinado, então não há CA nem cadeia para
/// validar. A confiança vem inteiramente do hash de SPKI capturado no QR
/// durante o pareamento — o que é mais forte que a PKI pública, porque não
/// depende de nenhuma autoridade terceira em quem você não escolheu confiar.
///
/// A descoberta por Bonjour existe só para responder "onde o Mac está agora",
/// porque o endereço do QR envelhece: DHCP novo, troca de rede, e o host
/// gravado no pareamento deixa de valer. Ela **não** afrouxa nada — todo
/// endereço, venha do QR ou da rede, passa pelo mesmo verify block e pelo mesmo
/// hash pinado. Um serviço que se anuncie como o Mac e apresente outro
/// certificado morre no handshake, antes de qualquer byte de aplicação.
@MainActor
final class PhoneAuthClient: ObservableObject {

    struct Peer: Codable, Equatable {
        var host: String
        var port: UInt16
        var spki: String        // hex do SHA-256 do SPKI; o valor pinado
        var name: String
        var deviceId: String?   // atribuído pelo Mac no pareamento
    }

    enum State: Equatable {
        case idle
        case connecting
        case connected
        case failed(String)
    }

    @Published private(set) var state: State = .idle
    @Published var pendingRequest: AuthChallenge?

    private var connection: NWConnection?
    private var decoder = FrameDecoder()
    private var peer: Peer?

    private let discovery = PeerDiscovery()

    /// Tempos da reconexão automática, todos em segundos.
    private enum Retry {
        /// Primeira espera; dobra a cada falha até `ceiling`.
        static let base: TimeInterval = 1
        static let ceiling: TimeInterval = 30
        /// Quanto uma tentativa pode demorar para chegar a `.ready` antes de
        /// ser abandonada.
        static let attemptTimeout: TimeInterval = 8
        /// Espera curta quando a descoberta acaba de achar um serviço novo.
        static let expedited: TimeInterval = 1
        /// Tempo que uma sessão precisa ficar de pé para contar como sucesso e
        /// zerar o backoff.
        static let healthySession: TimeInterval = 20
        /// Keepalive do protocolo (docs/protocolo.md §4).
        static let keepAlive: TimeInterval = 30
        static let silenceTolerated: TimeInterval = 90
        /// Prazo do ping de verificação disparado ao voltar do background.
        static let resumeProbe: TimeInterval = 6
    }

    /// O usuário quer estar conectado — pareou agora, ou o app abriu com um Mac
    /// já pareado. É o que distingue uma queda, que deve se reparar sozinha, de
    /// um `disconnect()` pedido de propósito.
    private var wantsConnection = false
    private var isForeground = true

    /// Cada tentativa leva um número. Callbacks do Network.framework chegam
    /// depois de já termos desistido da tentativa que os originou — sem essa
    /// etiqueta, um `.failed` atrasado derrubaria a conexão seguinte, que está
    /// perfeitamente boa.
    private var attemptGeneration = 0
    /// Rodízio entre os candidatos a endereço.
    private var candidateIndex = 0
    private var backoff: TimeInterval = Retry.base

    private var retryTask: Task<Void, Never>?
    private var watchdogTask: Task<Void, Never>?
    private var keepAliveTask: Task<Void, Never>?

    private var connectedSince: Date?
    /// Último byte recebido do Mac, de qualquer tipo. É a única prova de que a
    /// conexão continua viva.
    private var lastInboundAt: Date?

    init() {
        discovery.onResultsChanged = { [weak self] in self?.discoveryChanged() }
        observeAppLifecycle()
    }

    // MARK: - Mensagens

    struct AuthChallenge: Codable, Identifiable, Equatable {
        let type: String
        let requestId: String
        let challenge: String
        let issuedAt: Int64
        let expiresAt: Int64
        let channelBinding: String
        let context: SignedPayload.Context

        var id: String { requestId }
        var isExpired: Bool { Int64(Date().timeIntervalSince1970) > expiresAt }
        var secondsRemaining: Int { max(0, Int(expiresAt - Int64(Date().timeIntervalSince1970))) }
    }

    private struct HelloChallenge: Codable { let type: String; let nonce: String }
    private struct HelloResponse: Codable { let type: String; let deviceId: String; let signature: String }
    private struct AuthResponse: Codable {
        let type: String; let requestId: String
        let decision: SignedPayload.Decision; let signature: String
    }
    private struct TypeOnly: Codable { let type: String }

    // MARK: - Conexão

    /// Passa a querer estar conectado a este Mac, e começa a tentar. Daqui para
    /// frente a conexão se refaz sozinha enquanto o app estiver em primeiro
    /// plano; não há mais botão a apertar depois de uma queda.
    func connect(to peer: Peer) {
        // Chamado no `onAppear` e no botão "Reconectar". Se já estamos de pé
        // com o mesmo Mac, refazer o handshake seria jogar fora uma sessão boa.
        if wantsConnection, self.peer == peer, state == .connected || state == .connecting { return }

        self.peer = peer
        wantsConnection = true
        backoff = Retry.base
        candidateIndex = 0
        discovery.start()
        attemptNow()
    }

    /// Para de tentar, de propósito. Uma queda de rede **não** passa por aqui —
    /// ela vai para `drop(reason:generation:)`, que reagenda.
    func disconnect() {
        wantsConnection = false
        retryTask?.cancel()
        retryTask = nil
        teardown()
        discovery.stop()
        pendingRequest = nil
        state = .idle
    }

    private func attemptNow() {
        retryTask?.cancel()
        retryTask = nil
        attempt()
    }

    private func attempt() {
        guard wantsConnection, isForeground, let peer else { return }

        teardown()
        let generation = attemptGeneration
        let endpoint = nextEndpoint(for: peer)
        state = .connecting

        let connection = NWConnection(to: endpoint, using: Self.parameters(for: peer))
        self.connection = connection

        connection.stateUpdateHandler = { [weak self] newState in
            Task { @MainActor in
                guard let self, generation == self.attemptGeneration else { return }
                switch newState {
                case .ready:
                    self.watchdogTask?.cancel()
                    self.watchdogTask = nil
                    self.lastInboundAt = Date()
                    self.receive(generation: generation)
                    self.startKeepAlive(generation: generation)

                case .waiting(let error):
                    // `.waiting` não é fatal para o Network.framework: ele
                    // ficaria tentando sozinho, no mesmo endereço, para sempre.
                    // É justamente o que não serve aqui — o endereço pode estar
                    // velho, e quem conserta isso é a descoberta na tentativa
                    // seguinte. Então tratamos como falha nossa e reagendamos.
                    self.drop(reason: error.localizedDescription, generation: generation)

                case .failed(let error):
                    self.drop(reason: error.localizedDescription, generation: generation)

                case .cancelled:
                    // Cancelamento é sempre nosso, e quem cancelou já decidiu o
                    // que vem depois.
                    break

                default:
                    break
                }
            }
        }

        connection.start(queue: .global(qos: .userInitiated))
        armWatchdog(generation: generation)
    }

    /// Próximo endereço a tentar: descobertos primeiro, o do QR por último —
    /// mas em rodízio, e não por preferência fixa.
    ///
    /// O rodízio importa: um serviço fantasma que o cache do mDNS ainda não
    /// expirou ficaria eternamente na frente e prenderia o app numa tentativa
    /// que nunca completa. Alternando, todo candidato tem vez, e o handshake
    /// pinado é que separa o Mac certo dos outros.
    private func nextEndpoint(for peer: Peer) -> NWEndpoint {
        let saved = NWEndpoint.hostPort(
            host: NWEndpoint.Host(peer.host),
            port: NWEndpoint.Port(rawValue: peer.port) ?? 58731
        )

        var list = discovery.candidates(preferringName: peer.name)
        // O endereço do pareamento é o fallback: quando a descoberta não achou
        // nada — rede que bloqueia mDNS, permissão de rede local negada — ele é
        // tudo o que temos, e continua funcionando enquanto o IP não mudar.
        list.append(saved)

        let endpoint = list[candidateIndex % list.count]
        candidateIndex += 1
        return endpoint
    }

    /// Parâmetros TLS com o pinning. **Não existe caminho alternativo:** todo
    /// endereço passa por aqui, tenha vindo do QR ou da descoberta.
    private static func parameters(for peer: Peer) -> NWParameters {
        let expectedSPKI = peer.spki

        let tls = NWProtocolTLS.Options()
        sec_protocol_options_set_min_tls_protocol_version(tls.securityProtocolOptions, .TLSv13)

        // O pinning. Substitui inteiramente a validação de cadeia: aceitamos
        // exatamente uma chave pública, a que foi vista no QR.
        sec_protocol_options_set_verify_block(
            tls.securityProtocolOptions,
            { _, trustRef, complete in
                let trust = sec_trust_copy_ref(trustRef).takeRetainedValue()
                guard let chain = SecTrustCopyCertificateChain(trust) as? [SecCertificate],
                      let leaf = chain.first,
                      let hash = Self.spkiHash(of: leaf) else {
                    complete(false)
                    return
                }
                // Comparação de hashes hex de tamanho fixo; não há segredo aqui
                // que um ataque de tempo pudesse extrair.
                complete(hash == expectedSPKI)
            },
            DispatchQueue.global(qos: .userInitiated)
        )

        let parameters = NWParameters(tls: tls)
        // Mesma decisão do listener do daemon: só LAN, sem AWDL.
        parameters.includePeerToPeer = false
        return parameters
    }

    /// Encerra a tentativa/conexão atual e invalida tudo que ela agendou.
    ///
    /// Não mexe em `retryTask` de propósito: `attempt()` roda de dentro dele, e
    /// cancelar a própria task em execução é a receita para bugs sutis.
    private func teardown() {
        attemptGeneration &+= 1
        watchdogTask?.cancel()
        watchdogTask = nil
        keepAliveTask?.cancel()
        keepAliveTask = nil
        connection?.cancel()
        connection = nil
        decoder = FrameDecoder()
        connectedSince = nil
        lastInboundAt = nil
    }

    // MARK: - Backoff

    /// Derruba a conexão atual e agenda a próxima tentativa.
    private func drop(reason: String, generation: Int) {
        guard generation == attemptGeneration else { return }

        // Uma sessão que ficou de pé um tempo razoável conta como sucesso: a
        // queda foi da rede. Uma que caiu logo depois de conectar, não — é o
        // caso do dispositivo revogado, em que o Mac aceita o TLS e encerra
        // em seguida. Zerar o backoff aí viraria um loop apertado contra o
        // daemon, que é exatamente o que o backoff existe para evitar.
        let wasHealthy = connectedSince.map { Date().timeIntervalSince($0) >= Retry.healthySession } ?? false

        teardown()

        // O Mac cancela o pedido pendente assim que a sessão cai
        // (`Broker.onClosed` → `pending.cancelAll`) e o handler da resposta
        // morre com a sessão antiga. Manter a tela de aprovação no ar seria
        // oferecer ao usuário um botão que não faz mais nada.
        pendingRequest = nil

        guard wantsConnection, isForeground else {
            state = .idle
            return
        }

        if wasHealthy { backoff = Retry.base }
        scheduleRetry(reason: reason)
    }

    private func scheduleRetry(reason: String) {
        // Jitter pequeno. Não é para evitar tempestade de clientes — só existe
        // um celular — mas para não entrar em sincronia com eventos periódicos
        // da rede (renovação de DHCP, o Mac acordando em intervalo fixo) e
        // errar sempre no mesmo instante.
        let delay = backoff * Double.random(in: 0.85 ... 1.15)
        backoff = min(backoff * 2, Retry.ceiling)

        // A UI só tem quatro estados e `.failed` é o único que mostra motivo;
        // dizer quando vem a próxima tentativa evita que pareça travado.
        state = .failed("\(reason) — nova tentativa em \(Int(delay.rounded())) s")
        armRetry(after: delay)
    }

    private func armRetry(after delay: TimeInterval) {
        retryTask?.cancel()
        retryTask = Task { @MainActor [weak self] in
            try? await Task.sleep(for: .seconds(delay))
            guard !Task.isCancelled, let self else { return }
            self.retryTask = nil
            self.attempt()
        }
    }

    /// Falha local que insistir não resolve — a chave de identidade não assina,
    /// então o pareamento precisa ser refeito. Para de tentar e deixa o motivo
    /// na tela; o botão "Reconectar" continua ali para quando o usuário agir.
    private func stopTrying(reason: String) {
        retryTask?.cancel()
        retryTask = nil
        teardown()
        state = .failed(reason)
    }

    /// Um endereço velho não devolve recusa: o SYN some no vazio e a conexão
    /// fica em `.preparing` por dezenas de segundos antes de o sistema
    /// desistir. Esse é justamente o caso que a descoberta resolve — mas só se
    /// a tentativa morrer rápido o bastante para dar vez ao próximo candidato.
    private func armWatchdog(generation: Int) {
        watchdogTask = Task { @MainActor [weak self] in
            try? await Task.sleep(for: .seconds(Retry.attemptTimeout))
            guard !Task.isCancelled, let self, generation == self.attemptGeneration else { return }
            self.drop(reason: "sem resposta em \(Int(Retry.attemptTimeout)) s", generation: generation)
        }
    }

    private func startKeepAlive(generation: Int) {
        keepAliveTask = Task { @MainActor [weak self] in
            while true {
                try? await Task.sleep(for: .seconds(Retry.keepAlive))
                guard !Task.isCancelled, let self, generation == self.attemptGeneration else { return }

                // Silêncio longo demais é conexão morta sem aviso: o TCP não
                // avisa quando o outro lado some (Mac dormiu, celular trocou de
                // rede). Sem checar o pong, o app ficaria "conectado" para
                // sempre a um socket que não existe mais — e nenhum pedido
                // chegaria.
                if let last = self.lastInboundAt, Date().timeIntervalSince(last) > Retry.silenceTolerated {
                    self.drop(reason: "o Mac parou de responder", generation: generation)
                    return
                }
                self.send(TypeOnly(type: "ping"))
            }
        }
    }

    /// A descoberta achou ou perdeu serviços.
    ///
    /// Se estamos numa espera longa e um serviço acabou de aparecer, é sinal
    /// forte de que o Mac voltou — esperar mais 20 s seria bobagem. Encurta a
    /// espera **sem** zerar o backoff: um serviço que fica piscando (anuncia,
    /// some, anuncia) não pode virar um loop de tentativas.
    private func discoveryChanged() {
        guard wantsConnection, isForeground, retryTask != nil else { return }
        armRetry(after: Retry.expedited)
    }

    // MARK: - Ciclo de vida do app

    /// Em background o processo é congelado: não há como manter varredura de
    /// Bonjour nem terminar handshake. Insistir só gastaria bateria e encheria
    /// o backoff de falhas que não são falhas de rede. Paramos de tentar e
    /// retomamos ao voltar.
    ///
    /// Os observadores não são removidos: este objeto é o `@StateObject` do
    /// `App` e vive tanto quanto o processo.
    private func observeAppLifecycle() {
        let center = NotificationCenter.default
        _ = center.addObserver(forName: UIApplication.didEnterBackgroundNotification,
                               object: nil, queue: .main) { [weak self] _ in
            Task { @MainActor in self?.enterBackground() }
        }
        _ = center.addObserver(forName: UIApplication.willEnterForegroundNotification,
                               object: nil, queue: .main) { [weak self] _ in
            Task { @MainActor in self?.enterForeground() }
        }
    }

    private func enterBackground() {
        isForeground = false
        discovery.stop()
        retryTask?.cancel()
        retryTask = nil

        // Uma conexão já estabelecida fica: o app ainda pode ganhar alguns
        // segundos de execução em background e receber um pedido neles.
        // Tentativa em andamento, não — ela não tem como terminar congelada.
        if state == .connected { return }
        teardown()
        if wantsConnection { state = .idle }
    }

    private func enterForeground() {
        isForeground = true
        guard wantsConnection else { return }
        discovery.start()

        if state == .connected {
            probeAfterResume()
            return
        }

        // Voltar ao app é o usuário dizendo que quer isto funcionando agora.
        // Zerar o backoff aqui não abre espaço para loop apertado, porque quem
        // dispara é uma ação humana.
        backoff = Retry.base
        attemptNow()
    }

    /// Depois de o processo ser congelado, "conectado" é só uma crença: o
    /// socket pode ter morrido sem que o TCP tivesse chance de avisar. Um ping
    /// tira a dúvida em segundos, em vez dos 90 s do keepalive normal — e é
    /// justo quando o usuário está olhando para a tela.
    private func probeAfterResume() {
        let generation = attemptGeneration
        let sentAt = Date()
        send(TypeOnly(type: "ping"))

        Task { @MainActor [weak self] in
            try? await Task.sleep(for: .seconds(Retry.resumeProbe))
            // A etiqueta de geração torna esta task inerte se a conexão já
            // tiver sido trocada; não precisa ser cancelada.
            guard let self, generation == self.attemptGeneration else { return }
            guard (self.lastInboundAt ?? .distantPast) < sentAt else { return }
            self.drop(reason: "o Mac não respondeu depois que o app voltou", generation: generation)
        }
    }

    // MARK: - E/S

    private func send<T: Encodable>(_ message: T) {
        guard let connection, let body = try? JSONEncoder().encode(message) else { return }
        var framed = Data()
        let n = UInt32(body.count)
        framed.append(UInt8((n >> 24) & 0xFF)); framed.append(UInt8((n >> 16) & 0xFF))
        framed.append(UInt8((n >> 8) & 0xFF));  framed.append(UInt8(n & 0xFF))
        framed.append(body)

        // `.idempotent` descartaria o erro em silêncio. Um envio que falha é
        // dos sinais mais rápidos de que a conexão morreu — e num `deny()` é a
        // diferença entre a recusa chegar e o usuário achar que chegou.
        let generation = attemptGeneration
        connection.send(content: framed, completion: .contentProcessed { [weak self] error in
            guard let error else { return }
            Task { @MainActor in
                self?.drop(reason: "falha ao enviar: \(error.localizedDescription)",
                           generation: generation)
            }
        })
    }

    private func receive(generation: Int) {
        connection?.receive(minimumIncompleteLength: 1, maximumLength: 16 * 1024) { [weak self] data, _, isComplete, error in
            Task { @MainActor in
                guard let self, generation == self.attemptGeneration else { return }
                if let error {
                    self.drop(reason: error.localizedDescription, generation: generation)
                    return
                }
                if let data, !data.isEmpty {
                    // Qualquer byte vindo do Mac é prova de vida — inclusive o
                    // pong, que não precisa de tratamento além disto.
                    self.lastInboundAt = Date()
                    self.decoder.append(data)
                    while let frame = self.decoder.next() {
                        self.handle(frame)
                    }
                }
                if isComplete {
                    self.drop(reason: "o Mac encerrou a conexão", generation: generation)
                    return
                }
                self.receive(generation: generation)
            }
        }
    }

    private func handle(_ frame: Data) {
        guard let envelope = try? JSONDecoder().decode(TypeOnly.self, from: frame) else { return }

        switch envelope.type {
        case "hello.challenge":
            guard let challenge = try? JSONDecoder().decode(HelloChallenge.self, from: frame),
                  let peer, let deviceId = peer.deviceId else { return }
            do {
                let message = try SignedPayload.helloBytes(
                    deviceId: deviceId,
                    nonceBase64: challenge.nonce,
                    channelBinding: peer.spki
                )
                // Chave de identidade: sem biometria, de propósito. Reconectar
                // não pode custar um toque do dedo — e com reconexão automática
                // isso passou a valer literalmente: a cada troca de rede.
                let signature = try DeviceKeys.signWithIdentityKey(message)
                send(HelloResponse(type: "hello.response", deviceId: deviceId, signature: signature))
                state = .connected
                connectedSince = Date()
            } catch {
                stopTrying(reason: "falha ao autenticar a sessão: \(error.localizedDescription)")
            }

        case "auth.challenge":
            guard let challenge = try? JSONDecoder().decode(AuthChallenge.self, from: frame),
                  !challenge.isExpired else { return }
            pendingRequest = challenge

        case "ping":
            // O daemon hoje só responde ping, não manda. Responder mesmo assim
            // custa uma linha e evita que uma versão futura do Mac nos derrube
            // por silêncio.
            send(TypeOnly(type: "pong"))

        case "pong":
            break

        case "error":
            break

        default:
            break
        }
    }

    // MARK: - Decisão do usuário

    /// Aprova o pedido. A biometria é disparada dentro de
    /// `signWithApprovalKey` — imposta pelo Secure Enclave, não por este
    /// código. Se o usuário cancelar ou falhar, não existe assinatura para
    /// enviar.
    func approve(_ challenge: AuthChallenge) async throws {
        guard let peer else { return }
        let contextHash = try SignedPayload.contextHash(challenge.context)
        let message = try SignedPayload.authBytes(
            requestId: challenge.requestId,
            challengeBase64: challenge.challenge,
            contextHash: contextHash,
            channelBinding: peer.spki,
            issuedAt: challenge.issuedAt,
            decision: .allow
        )
        let signature = try DeviceKeys.signWithApprovalKey(
            message,
            prompt: "Liberar \(challenge.context.reason) em \(challenge.context.host)"
        )
        send(AuthResponse(type: "auth.response", requestId: challenge.requestId,
                          decision: .allow, signature: signature))
        pendingRequest = nil
    }

    /// Negar não exige biometria: recusar não é uma ação privilegiada, e pedir
    /// o dedo para dizer "não" treinaria justamente o reflexo que queremos
    /// evitar.
    func deny(_ challenge: AuthChallenge) {
        send(AuthResponse(type: "auth.response", requestId: challenge.requestId,
                          decision: .deny, signature: ""))
        pendingRequest = nil
    }

    // MARK: - Utilidades

    static func spkiHash(of certificate: SecCertificate) -> String? {
        guard let key = SecCertificateCopyKey(certificate),
              let raw = SecKeyCopyExternalRepresentation(key, nil) as Data? else { return nil }
        return Data(SHA256.hash(data: DeviceKeys.wrapP256InSPKI(raw))).hexLowercase
    }
}

/// Reconstitui frames a partir de um stream TCP, que não respeita fronteiras
/// de mensagem.
struct FrameDecoder {
    private var buffer = Data()

    mutating func append(_ data: Data) { buffer.append(data) }

    mutating func next() -> Data? {
        guard buffer.count >= 4 else { return nil }
        // Ver o gêmeo em PhoneAuthCore/Framing.swift: o subscript de Data é
        // ambíguo entre UnsafePointer e UnsafeRawBufferPointer.
        let length = buffer.prefix(4).reduce(0) { ($0 << 8) | Int($1) }
        guard length > 0, length <= 65_536 else {
            buffer.removeAll()   // peer com defeito ou hostil; descarta tudo
            return nil
        }
        guard buffer.count >= 4 + length else { return nil }
        let body = buffer.subdata(in: 4 ..< (4 + length))
        buffer.removeSubrange(0 ..< (4 + length))
        return body
    }
}
