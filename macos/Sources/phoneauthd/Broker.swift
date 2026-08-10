import Foundation
import Security
import CryptoKit
import PhoneAuthCore

/// Orquestra o caminho completo: PAM pede, celular assina, daemon verifica.
final class Broker {

    private let config: Config
    private let registry: DeviceRegistry
    private let pending: PendingRequests
    private let rotation: RotationManager
    private let hostName: String

    private let lock = NSLock()
    private var sessions: [String: PhoneSession] = [:]   // deviceId -> sessão
    private var pairings: [String: PairingSession] = [:] // sid -> pareamento

    /// O binding da identidade TLS **viva agora**. Deixou de ser constante
    /// quando a rotação passou a existir: ele muda no commit.
    private var channelBinding: String { rotation.channelBinding }

    init(config: Config, registry: DeviceRegistry, rotation: RotationManager) {
        self.config = config
        self.registry = registry
        self.rotation = rotation
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

            // O anúncio vai em TODA autenticação enquanto a rotação estiver
            // pendente, e não num broadcast único no momento em que ela começa.
            // É isso que faz a janela valer alguma coisa: cobre reconexão,
            // celular que estava fora do ar e aparelho pareado no meio dela.
            if let announcement = self.rotation.pendingAnnouncement() {
                session.send(announcement)
            }
        }
        session.onRotateAck = { [weak self] ack, session in
            self?.handleRotateAck(ack, on: session)
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

    /// Os bindings que uma assinatura pode legitimamente carregar.
    ///
    /// Primeiro o da conexão — é o que um cliente correto usa, porque ele
    /// deriva o valor do certificado que está vendo. Depois, se e enquanto
    /// houver graça pós-rotação, o da identidade anterior.
    ///
    /// A graça é uma muleta com prazo e **tem custo**: aceitar o binding antigo
    /// devolve, para quem tiver a chave TLS antiga, a possibilidade de relaiar
    /// uma aprovação assinada sob o certificado antigo. Por isso ela é curta,
    /// desligável, forçada a zero numa rotação por comprometimento, e cada
    /// aceitação por essa via vira um `warn` no log. Ver
    /// docs/rotacao-de-identidade.md §4.6.
    private func bindingCandidates(connection binding: String) -> [String] {
        var candidates = [binding]
        for extra in rotation.acceptableBindings() where !candidates.contains(extra) {
            candidates.append(extra)
        }
        return candidates
    }

    private func verifyHello(_ response: Message.HelloResponse,
                             nonce: Data,
                             channelBinding: String) -> Bool {
        guard let device = registry.device(id: response.deviceId), device.isActive else { return false }

        let candidates = bindingCandidates(connection: channelBinding)
        for (index, candidate) in candidates.enumerated() {
            guard let message = try? SignedPayload.helloBytes(
                deviceId: response.deviceId,
                nonceBase64: nonce.base64EncodedString(),
                channelBinding: candidate
            ) else { continue }

            if (try? Verifier.verify(signatureBase64: response.signature,
                                     over: message,
                                     publicKeyBase64: device.idPublicKey)) != nil {
                if index > 0 {
                    Log.warn("hello de \(response.deviceId) aceito pelo binding ANTERIOR (graça de rotação ativa)")
                }
                return true
            }
        }
        return false
    }

    private func handleRotateAck(_ ack: Message.RotateAck, on session: PhoneSession) {
        guard let deviceId = session.deviceId, deviceId == ack.deviceId else { return }
        guard let device = registry.device(id: deviceId), device.isActive else { return }

        // O ack não autoriza nada — ele responde "quem já sabe do pin novo?",
        // que é o que decide se comitar tranca alguém para fora. É assinado
        // porque um ack forjado convenceria o operador a comitar cedo demais.
        guard let message = try? SignedPayload.rotateAckBytes(
            rotationId: ack.rotationId,
            deviceId: ack.deviceId,
            adoptedSpki: ack.adoptedSpki,
            channelBinding: session.channelBinding
        ) else { return }

        do {
            try Verifier.verify(signatureBase64: ack.signature,
                                over: message,
                                publicKeyBase64: device.idPublicKey)
        } catch {
            Log.warn("ack de rotação com assinatura inválida de \(deviceId); ignorado")
            return
        }

        if rotation.recordAck(deviceId: deviceId, rotationId: ack.rotationId, spki: ack.adoptedSpki) {
            Log.info("dispositivo \(device.name) confirmou o pin novo")
        }
    }

    /// Derruba todas as sessões. Chamado no commit da rotação: uma sessão
    /// estabelecida sob o certificado antigo carrega o binding antigo, e é mais
    /// limpo forçar todo mundo a reconectar e re-derivar do que manter estado
    /// misto vivo.
    func dropAllSessions() {
        lock.lock()
        let open = Array(sessions.values)
        sessions.removeAll()
        lock.unlock()
        for session in open { session.connection.cancel() }
    }

    /// deviceId -> nome, dos dispositivos ativos. É o conjunto que o commit da
    /// rotação usa para decidir quem ficaria trancado para fora.
    func activeDeviceNames() -> [String: String] {
        Dictionary(uniqueKeysWithValues: registry.active().map { ($0.id, $0.name) })
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
            // O binding da sessão, não o global: é o certificado que este
            // celular está de fato enxergando.
            item = try pending.create(context: context,
                                      channelBinding: session.channelBinding,
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

            let candidates = self.bindingCandidates(connection: consumed.channelBinding)
            for (index, candidate) in candidates.enumerated() {
                guard let message = try? SignedPayload.authBytes(
                    requestId: consumed.requestId,
                    challengeBase64: consumed.challenge.base64EncodedString(),
                    contextHash: consumed.contextHash,
                    channelBinding: candidate,
                    issuedAt: consumed.issuedAt,
                    decision: .allow
                ) else { continue }

                guard (try? Verifier.verify(signatureBase64: response.signature,
                                            over: message,
                                            publicKeyBase64: device.authPublicKey)) != nil else { continue }

                approved = true
                if index > 0 {
                    Log.warn("pedido \(response.requestId) aceito pelo binding ANTERIOR (graça de rotação ativa)")
                }
                Log.info("pedido \(response.requestId) aprovado e assinatura verificada")
                break
            }
            if !approved {
                Log.warn("assinatura rejeitada para \(response.requestId)")
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

        // O celular montou o transcript com o `spki` do QR, e o pin do TLS já
        // obrigou esse valor a ser o certificado desta conexão. Usar o binding
        // da sessão é dizer a mesma coisa de forma que continue verdadeira
        // depois de uma rotação.
        guard let transcript = try? SignedPayload.pairBytes(
            sid: request.sid,
            spki: session.channelBinding,
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
