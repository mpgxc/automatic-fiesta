import Foundation
import Security
import CryptoKit
import PhoneAuthCore

/// Orquestra o caminho completo: PAM pede, celular assina, daemon verifica.
final class Broker {

    private let config: Config
    private let registry: DeviceRegistry
    private let pending: PendingRequests
    private let channelBinding: String
    private let hostName: String

    private let lock = NSLock()
    private var sessions: [String: PhoneSession] = [:]   // deviceId -> sessão
    private var pairings: [String: PairingSession] = [:] // sid -> pareamento

    init(config: Config, registry: DeviceRegistry, channelBinding: String) {
        self.config = config
        self.registry = registry
        self.channelBinding = channelBinding
        self.pending = PendingRequests(ttl: config.requestTTLSeconds)
        self.hostName = Host.current().localizedName ?? "Mac"
    }

    // MARK: - Sessões

    func attach(_ session: PhoneSession) {
        session.verifyHello = { [weak self] response, nonce, binding in
            self?.verifyHello(response, nonce: nonce, channelBinding: binding) ?? false
        }
        session.onAuthenticated = { [weak self] deviceId in
            guard let self else { return }
            self.lock.lock()
            // Uma reconexão substitui a sessão anterior daquele dispositivo.
            self.sessions[deviceId]?.connection.cancel()
            self.sessions[deviceId] = session
            self.lock.unlock()
            self.registry.touch(id: deviceId)
        }
        session.onClosed = { [weak self] deviceId in
            guard let self, let deviceId else { return }
            self.lock.lock()
            if self.sessions[deviceId] === session { self.sessions.removeValue(forKey: deviceId) }
            self.lock.unlock()
            // Sem isto o dispositivo ficaria marcado como "ocupado" para sempre
            // e nenhum pedido novo passaria.
            self.pending.cancelAll(deviceId: deviceId)
        }
        session.onPairRequest = { [weak self] request, session in
            self?.handlePairRequest(request, on: session)
        }
    }

    private func verifyHello(_ response: Message.HelloResponse,
                             nonce: Data,
                             channelBinding: String) -> Bool {
        guard let device = registry.device(id: response.deviceId), device.isActive else { return false }
        guard let message = try? SignedPayload.helloBytes(
            deviceId: response.deviceId,
            nonceBase64: nonce.base64EncodedString(),
            channelBinding: channelBinding
        ) else { return false }

        do {
            try Verifier.verify(signatureBase64: response.signature,
                                over: message,
                                publicKeyBase64: device.idPublicKey)
            return true
        } catch {
            return false
        }
    }

    private func activeSession() -> PhoneSession? {
        lock.lock(); defer { lock.unlock() }
        // Com mais de um dispositivo pareado, o primeiro conectado atende.
        // Perguntar a todos multiplicaria notificações sem ganho real.
        return sessions.values.first { $0.isAuthenticated }
    }

    // MARK: - Autenticação

    /// Chamado de forma síncrona pela thread do socket de controle. Bloqueia
    /// até o celular responder ou o timeout estourar — o `sudo` do outro lado
    /// está esperando.
    func handleAuthRequest(_ request: Message.AuthBegin) -> Bool {
        guard config.allowedServices.contains(request.service) else {
            Log.warn("serviço '\(request.service)' não está na lista permitida; recusado")
            return false
        }

        guard let session = activeSession(), let deviceId = session.deviceId else {
            // Nenhum celular conectado. Falha imediata, sem espera: você não
            // fica olhando um terminal travado enquanto o celular está na
            // outra sala.
            Log.info("pedido de \(request.user) via \(request.service), mas nenhum dispositivo conectado")
            return false
        }

        let process = ProcessDescription.lookup(pid: request.pid)
        let context = SignedPayload.Context(
            host: hostName,
            user: request.user,
            service: request.service,
            reason: process?.summary ?? request.service,
            processPath: process?.executablePath ?? "",
            tty: request.tty
        )

        let item: PendingRequests.Pending
        do {
            item = try pending.create(context: context,
                                      channelBinding: channelBinding,
                                      deviceId: deviceId)
        } catch {
            Log.warn("pedido recusado: \(error)")
            return false
        }

        let challenge = Message.AuthChallenge(
            requestId: item.requestId,
            challenge: item.challenge.base64EncodedString(),
            issuedAt: item.issuedAt,
            expiresAt: item.expiresAt,
            channelBinding: item.channelBinding,
            context: context
        )

        Log.info("pedido \(item.requestId) enviado a \(deviceId): \(context.reason)")

        let semaphore = DispatchSemaphore(value: 0)
        var approved = false

        session.sendChallenge(challenge) { response in
            defer { semaphore.signal() }

            // Consome ANTES de verificar. Duas respostas simultâneas só
            // encontram o pedido uma vez — consumir depois abriria uma corrida.
            guard let consumed = self.pending.consume(requestId: response.requestId) else {
                Log.warn("resposta para pedido desconhecido ou já consumido")
                return
            }
            guard consumed.deviceId == deviceId else {
                Log.warn("resposta veio de dispositivo diferente do que recebeu o pedido")
                return
            }
            guard response.decision == .allow else {
                Log.info("pedido \(response.requestId) negado no celular")
                return
            }
            guard Int64(Date().timeIntervalSince1970) <= consumed.expiresAt else {
                Log.warn("pedido \(response.requestId) expirou")
                return
            }
            guard let device = self.registry.device(id: deviceId), device.isActive else {
                Log.warn("dispositivo revogado durante o pedido")
                return
            }

            do {
                let message = try SignedPayload.authBytes(
                    requestId: consumed.requestId,
                    challengeBase64: consumed.challenge.base64EncodedString(),
                    contextHash: consumed.contextHash,
                    channelBinding: consumed.channelBinding,
                    issuedAt: consumed.issuedAt,
                    decision: .allow
                )
                try Verifier.verify(signatureBase64: response.signature,
                                    over: message,
                                    publicKeyBase64: device.authPublicKey)
                approved = true
                Log.info("pedido \(response.requestId) aprovado e assinatura verificada")
            } catch {
                Log.warn("assinatura rejeitada para \(response.requestId): \(error)")
            }
        }

        if semaphore.wait(timeout: .now() + config.responseTimeoutSeconds) == .timedOut {
            Log.info("pedido \(item.requestId) expirou sem resposta")
            session.forgetReply(requestId: item.requestId)
            pending.cancel(requestId: item.requestId)
            return false
        }
        return approved
    }

    // MARK: - Pareamento

    final class PairingSession {
        let sid: String
        let secret: Data
        let createdAt: Date
        var request: Message.PairRequest?
        var session: PhoneSession?
        var sas: String?
        let arrived = DispatchSemaphore(value: 0)

        init(sid: String, secret: Data) {
            self.sid = sid
            self.secret = secret
            self.createdAt = Date()
        }

        var isExpired: Bool { Date().timeIntervalSince(createdAt) > 120 }
    }

    func beginPairing() -> (sid: String, qrPayload: String) {
        var secret = Data(count: 32)
        secret.withUnsafeMutableBytes { raw in
            guard let base = raw.baseAddress else { return }
            _ = SecRandomCopyBytes(kSecRandomDefault, 32, base)
        }

        let sid = UUID().uuidString
        let pairing = PairingSession(sid: sid, secret: secret)

        lock.lock()
        pairings = pairings.filter { !$0.value.isExpired }
        pairings[sid] = pairing
        lock.unlock()

        let payload: [String: Any] = [
            "v": 1,
            "host": "\(Host.current().localizedName ?? "mac").local",
            "port": Int(config.port),
            "spki": channelBinding,
            "sid": sid,
            "psk": secret.base64EncodedString(),
            "name": hostName,
        ]
        let json = (try? JSONSerialization.data(withJSONObject: payload)) ?? Data()
        let encoded = json.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")

        return (sid, encoded)
    }

    private func handlePairRequest(_ request: Message.PairRequest, on session: PhoneSession) {
        lock.lock()
        let pairing = pairings[request.sid]
        lock.unlock()

        guard let pairing, !pairing.isExpired else {
            session.send(Message.ErrorMessage(.pairingExpired))
            return
        }

        guard let transcript = try? SignedPayload.pairBytes(
            sid: request.sid,
            spki: channelBinding,
            idPublicKeyBase64: request.idPublicKey,
            authPublicKeyBase64: request.authPublicKey,
            deviceName: request.deviceName,
            platform: request.platform
        ) else {
            session.send(Message.ErrorMessage(.pairingInvalid))
            return
        }

        // O HMAC prova que quem pareia viu o QR na tela do Mac.
        guard Verifier.verifyPairingProof(proofBase64: request.proof,
                                          transcript: transcript,
                                          pairingSecret: pairing.secret) else {
            Log.warn("prova de pareamento inválida para sid \(request.sid)")
            session.send(Message.ErrorMessage(.pairingInvalid))
            return
        }

        // A assinatura pela authKey recém-criada prova duas coisas de uma vez:
        // que o celular tem mesmo a chave privada correspondente, e — porque
        // essa chave é travada por biometria — que o portão biométrico está
        // funcionando. A assinatura não teria como existir sem o dedo.
        do {
            try Verifier.verify(signatureBase64: request.authSignature,
                                over: transcript,
                                publicKeyBase64: request.authPublicKey)
        } catch {
            Log.warn("assinatura de pareamento rejeitada: \(error)")
            session.send(Message.ErrorMessage(.pairingInvalid))
            return
        }

        pairing.request = request
        pairing.session = session
        pairing.sas = Verifier.shortAuthString(transcript: transcript, pairingSecret: pairing.secret)
        pairing.arrived.signal()
    }

    /// Bloqueia até o celular enviar um pareamento válido para este sid.
    func awaitPairing(sid: String, timeout: TimeInterval = 120) -> PairingSession? {
        lock.lock()
        let pairing = pairings[sid]
        lock.unlock()
        guard let pairing else { return nil }
        guard pairing.arrived.wait(timeout: .now() + timeout) == .success else { return nil }
        return pairing
    }

    /// Só grava o dispositivo depois da confirmação humana de que os códigos
    /// de 6 dígitos batem nos dois lados.
    func confirmPairing(sid: String, accept: Bool) throws -> String? {
        lock.lock()
        let pairing = pairings.removeValue(forKey: sid)
        lock.unlock()

        guard let pairing, let request = pairing.request else { return nil }

        guard accept else {
            pairing.session?.send(Message.ErrorMessage(.pairingInvalid))
            return nil
        }

        let device = PairedDevice(
            id: UUID().uuidString,
            name: request.deviceName,
            platform: request.platform,
            idPublicKey: request.idPublicKey,
            authPublicKey: request.authPublicKey
        )
        try registry.add(device)
        pairing.session?.send(Message.PairOk(deviceId: device.id))
        Log.info("dispositivo pareado: \(device.name) (\(device.id))")
        return device.id
    }

    // MARK: - Status

    var connectedDeviceCount: Int {
        lock.lock(); defer { lock.unlock() }
        return sessions.values.filter(\.isAuthenticated).count
    }
}
