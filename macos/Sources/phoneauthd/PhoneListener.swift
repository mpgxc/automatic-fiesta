import Foundation
import Network
import Security
import CryptoKit
import PhoneAuthCore

/// Uma conexão TLS com um celular.
///
/// Nasce não autenticada. O daemon manda um desafio de sessão; até o celular
/// devolver uma assinatura válida da `idKey`, a sessão não serve para nada e é
/// derrubada em 10 segundos.
final class PhoneSession {
    let connection: NWConnection
    private var decoder = Framing.Decoder()
    private let queue: DispatchQueue

    private(set) var deviceId: String?
    private var helloNonce: Data?
    private var pendingReplies: [String: (Message.AuthResponse) -> Void] = [:]
    private let lock = NSLock()

    var isAuthenticated: Bool { deviceId != nil }

    var onAuthenticated: ((String) -> Void)?
    var onClosed: ((String?) -> Void)?
    var verifyHello: ((Message.HelloResponse, Data, String) -> Bool)?
    /// Pareamento chega numa sessão ainda **não** autenticada — é justamente
    /// quando o dispositivo ainda não tem chave registrada. A prova de posse
    /// vem do HMAC do segredo do QR, verificado no Broker.
    var onPairRequest: ((Message.PairRequest, PhoneSession) -> Void)?
    var onRotateAck: ((Message.RotateAck, PhoneSession) -> Void)?

    let channelBinding: String

    init(connection: NWConnection, channelBinding: String, queue: DispatchQueue) {
        self.connection = connection
        self.channelBinding = channelBinding
        self.queue = queue
    }

    func start() {
        connection.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            switch state {
            case .ready:
                self.sendHelloChallenge()
                self.receive()
            case .failed, .cancelled:
                self.close()
            default:
                break
            }
        }
        connection.start(queue: queue)

        // Uma conexão que não se autentica é peso morto. Corta rápido.
        queue.asyncAfter(deadline: .now() + 10) { [weak self] in
            guard let self, !self.isAuthenticated else { return }
            Log.warn("sessão não se autenticou em 10s; encerrando")
            self.close()
        }
    }

    private func sendHelloChallenge() {
        var nonce = Data(count: 32)
        nonce.withUnsafeMutableBytes { raw in
            guard let base = raw.baseAddress else { return }
            _ = SecRandomCopyBytes(kSecRandomDefault, 32, base)
        }
        helloNonce = nonce
        send(Message.HelloChallenge(nonce: nonce.base64EncodedString()))
    }

    // MARK: - Envio

    func send<T: Encodable>(_ message: T) {
        guard let framed = try? Wire.encode(message) else { return }
        connection.send(content: framed, completion: .contentProcessed { error in
            if let error { Log.warn("falha ao enviar: \(error)") }
        })
    }

    /// Envia o desafio e chama o handler quando a resposta correspondente
    /// chegar. Timeout é responsabilidade do chamador.
    func sendChallenge(_ challenge: Message.AuthChallenge,
                       onReply: @escaping (Message.AuthResponse) -> Void) {
        lock.lock()
        pendingReplies[challenge.requestId] = onReply
        lock.unlock()
        send(challenge)
    }

    func forgetReply(requestId: String) {
        lock.lock(); defer { lock.unlock() }
        pendingReplies.removeValue(forKey: requestId)
    }

    // MARK: - Recepção

    private func receive() {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 16 * 1024) { [weak self] data, _, isComplete, error in
            guard let self else { return }
            if let error {
                Log.warn("erro de recepção: \(error)")
                self.close()
                return
            }
            if let data, !data.isEmpty {
                self.decoder.append(data)
                do {
                    while let frame = try self.decoder.next() {
                        self.handle(frame: frame)
                    }
                } catch {
                    Log.warn("enquadramento inválido: \(error)")
                    self.close()
                    return
                }
            }
            if isComplete { self.close(); return }
            self.receive()
        }
    }

    private func handle(frame: Data) {
        guard let kind = Wire.kind(of: frame) else {
            send(Message.ErrorMessage(.badFrame))
            return
        }

        switch kind {
        case .helloResponse:
            guard !isAuthenticated,
                  let nonce = helloNonce,
                  let response = try? Wire.decoder.decode(Message.HelloResponse.self, from: frame) else {
                close()
                return
            }
            guard verifyHello?(response, nonce, channelBinding) == true else {
                // Sem detalhes: um atacante sondando o daemon não ganha pistas.
                Log.warn("hello inválido do dispositivo \(response.deviceId); encerrando")
                close()
                return
            }
            deviceId = response.deviceId
            helloNonce = nil
            Log.info("dispositivo \(response.deviceId) autenticado")
            onAuthenticated?(response.deviceId)

        case .authResponse:
            guard isAuthenticated,
                  let response = try? Wire.decoder.decode(Message.AuthResponse.self, from: frame) else { return }
            lock.lock()
            let handler = pendingReplies.removeValue(forKey: response.requestId)
            lock.unlock()
            handler?(response)

        case .pairRequest:
            guard let request = try? Wire.decoder.decode(Message.PairRequest.self, from: frame) else {
                send(Message.ErrorMessage(.pairingInvalid))
                return
            }
            onPairRequest?(request, self)

        case .rotateAck:
            // Só de sessão autenticada: o ack é assinado pela `idKey`, e a
            // sessão já provou possuir essa chave no hello. Um ack de sessão
            // anônima não teria como ser atribuído a dispositivo nenhum.
            guard isAuthenticated,
                  let ack = try? Wire.decoder.decode(Message.RotateAck.self, from: frame) else { return }
            onRotateAck?(ack, self)

        case .ping:
            send(Message.Pong())

        case .pong:
            break

        default:
            send(Message.ErrorMessage(.unknownType))
        }
    }

    func close() {
        connection.cancel()
        let id = deviceId
        deviceId = nil
        onClosed?(id)
    }
}

/// Escuta conexões TLS e anuncia o serviço via Bonjour.
final class PhoneListener {
    private let queue = DispatchQueue(label: "phoneauth.listener")
    private var listener: NWListener?
    private let config: Config
    private let lock = NSLock()

    /// Mutáveis por causa da rotação. Só o `swapIdentity` os troca, e ele
    /// derruba a escuta antiga antes — nunca existem duas identidades TLS
    /// vivas ao mesmo tempo. É decisão de desenho, não limitação: servir dois
    /// certificados manteria a chave velha em uso por mais tempo, que é o
    /// oposto do objetivo da rotação.
    private var identity: SecIdentity
    private var binding: String

    /// O binding que as sessões novas recebem. Uma sessão carrega o binding da
    /// identidade que estava viva quando ela foi aceita.
    var channelBinding: String {
        lock.lock(); defer { lock.unlock() }
        return binding
    }

    var onSession: ((PhoneSession) -> Void)?

    init(identity: SecIdentity, channelBinding: String, config: Config) {
        self.identity = identity
        self.binding = channelBinding
        self.config = config
    }

    func start() throws {
        try openListener()
    }

    /// Reabre a escuta com a identidade nova. Chamado pelo commit da rotação.
    ///
    /// O chamador é responsável por derrubar as sessões existentes: elas
    /// carregam o binding da identidade antiga e precisam reconectar para
    /// re-derivar o novo.
    func swapIdentity(_ identity: SecIdentity, channelBinding: String) throws {
        lock.lock()
        self.identity = identity
        self.binding = channelBinding
        lock.unlock()

        listener?.cancel()
        listener = nil

        // A porta não fica livre no instante do `cancel`. Insistir um pouco é
        // mais honesto do que dormir um valor mágico e torcer.
        var lastError: Swift.Error?
        for attempt in 0 ..< 25 {
            do {
                try openListener()
                return
            } catch {
                lastError = error
                usleep(useconds_t(200_000 * min(attempt + 1, 5)))
            }
        }
        throw lastError ?? ListenerError.badPort
    }

    private func openListener() throws {
        lock.lock()
        let identity = self.identity
        let binding = self.binding
        lock.unlock()

        let tls = NWProtocolTLS.Options()
        guard let secIdentity = sec_identity_create(identity) else {
            throw ListenerError.identityUnusable
        }
        sec_protocol_options_set_local_identity(tls.securityProtocolOptions, secIdentity)

        // TLS 1.3 e nada menos. Não há legado a suportar: os dois lados são
        // nossos e ambos falam 1.3.
        //
        // Desde a rotação isto tem uma segunda razão de existir: o anúncio de
        // rotação é assinado pela mesma chave que faz o handshake, e a
        // separação de domínio que torna isso seguro depende do formato do
        // `CertificateVerify` do TLS 1.3. Ver `SignedPayload.rotateBytes`.
        sec_protocol_options_set_min_tls_protocol_version(tls.securityProtocolOptions, .TLSv13)

        let parameters = NWParameters(tls: tls)
        parameters.includePeerToPeer = false

        guard let port = NWEndpoint.Port(rawValue: config.port) else {
            throw ListenerError.badPort
        }
        let listener = try NWListener(using: parameters, on: port)
        listener.service = NWListener.Service(
            name: config.serviceName,
            type: "_phoneauth._tcp"
        )

        listener.newConnectionHandler = { [weak self] connection in
            guard let self else { return }
            let session = PhoneSession(
                connection: connection,
                channelBinding: binding,
                queue: self.queue
            )
            self.onSession?(session)
            session.start()
        }

        listener.stateUpdateHandler = { state in
            switch state {
            case .ready:          Log.info("escutando TLS na porta \(config.port), anunciado como _phoneauth._tcp")
            case .failed(let e):  Log.error("listener falhou: \(e)")
            default:              break
            }
        }

        listener.start(queue: queue)
        self.listener = listener
    }

    func stop() {
        listener?.cancel()
        listener = nil
    }

    enum ListenerError: Error, CustomStringConvertible {
        case identityUnusable
        case badPort

        var description: String {
            switch self {
            case .identityUnusable: return "identity.p12 não pôde ser usada como identidade TLS"
            case .badPort:          return "porta inválida na configuração"
            }
        }
    }
}
