import Foundation
import Network
import CryptoKit
import Combine

/// Conexão com o Mac: descoberta por Bonjour, TLS 1.3 com pinning de SPKI.
///
/// O certificado do daemon é auto-assinado, então não há CA nem cadeia para
/// validar. A confiança vem inteiramente do hash de SPKI capturado no QR
/// durante o pareamento — o que é mais forte que a PKI pública, porque não
/// depende de nenhuma autoridade terceira em quem você não escolheu confiar.
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
    private var keepAlive: Timer?

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

    func connect(to peer: Peer) {
        disconnect()
        self.peer = peer
        state = .connecting

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
                complete(hash == peer.spki)
            },
            DispatchQueue.global(qos: .userInitiated)
        )

        let parameters = NWParameters(tls: tls)
        let endpoint = NWEndpoint.hostPort(
            host: NWEndpoint.Host(peer.host),
            port: NWEndpoint.Port(rawValue: peer.port) ?? 58731
        )

        let connection = NWConnection(to: endpoint, using: parameters)
        self.connection = connection

        connection.stateUpdateHandler = { [weak self] newState in
            Task { @MainActor in
                guard let self else { return }
                switch newState {
                case .ready:
                    self.receive()
                    self.startKeepAlive()
                case .failed(let error):
                    self.state = .failed(error.localizedDescription)
                case .cancelled:
                    self.state = .idle
                default:
                    break
                }
            }
        }
        connection.start(queue: .global(qos: .userInitiated))
    }

    func disconnect() {
        keepAlive?.invalidate()
        keepAlive = nil
        connection?.cancel()
        connection = nil
        decoder = FrameDecoder()
        state = .idle
    }

    private func startKeepAlive() {
        keepAlive?.invalidate()
        keepAlive = Timer.scheduledTimer(withTimeInterval: 30, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.send(TypeOnly(type: "ping")) }
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
        connection.send(content: framed, completion: .idempotent)
    }

    private func receive() {
        connection?.receive(minimumIncompleteLength: 1, maximumLength: 16 * 1024) { [weak self] data, _, isComplete, error in
            Task { @MainActor in
                guard let self else { return }
                if error != nil || isComplete {
                    self.disconnect()
                    return
                }
                if let data {
                    self.decoder.append(data)
                    while let frame = self.decoder.next() {
                        self.handle(frame)
                    }
                }
                self.receive()
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
                // não pode custar um toque do dedo.
                let signature = try DeviceKeys.signWithIdentityKey(message)
                send(HelloResponse(type: "hello.response", deviceId: deviceId, signature: signature))
                state = .connected
            } catch {
                state = .failed("falha ao autenticar a sessão: \(error.localizedDescription)")
            }

        case "auth.challenge":
            guard let challenge = try? JSONDecoder().decode(AuthChallenge.self, from: frame),
                  !challenge.isExpired else { return }
            pendingRequest = challenge

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
        let length = buffer.withUnsafeBytes { raw -> Int in
            Int(raw[0]) << 24 | Int(raw[1]) << 16 | Int(raw[2]) << 8 | Int(raw[3])
        }
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
