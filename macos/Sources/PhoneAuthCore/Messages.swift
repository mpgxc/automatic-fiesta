import Foundation

/// Mensagens do protocolo. Ver docs/protocolo.md.
public enum Message {

    public enum Kind: String, Codable, Sendable {
        case authBegin      = "auth.begin"
        case authResult     = "auth.result"
        case authChallenge  = "auth.challenge"
        case authResponse   = "auth.response"
        case helloChallenge = "hello.challenge"
        case helloResponse  = "hello.response"
        case pairRequest    = "pair.request"
        case pairOk         = "pair.ok"
        case ping
        case pong
        case error
    }

    /// Só para descobrir o tipo antes de decodificar o corpo certo.
    public struct Envelope: Codable, Sendable {
        public let type: Kind
    }

    // MARK: - Socket Unix (PAM ↔ daemon)

    public struct AuthBegin: Codable, Sendable {
        public let type: Kind
        public let user: String
        public let service: String
        public let tty: String
        public let ruser: String
        public let rhost: String
        public let pid: Int32

        public init(user: String, service: String, tty: String,
                    ruser: String, rhost: String, pid: Int32) {
            self.type = .authBegin
            self.user = user; self.service = service; self.tty = tty
            self.ruser = ruser; self.rhost = rhost; self.pid = pid
        }
    }

    /// A resposta ao módulo PAM.
    ///
    /// **Invariante:** este frame carrega exclusivamente `type` e `ok`. Nada de
    /// eco de contexto, motivo, nome de dispositivo ou mensagem de erro.
    ///
    /// O módulo PAM não usa um parser de JSON completo — usa um scanner
    /// deliberadamente ingênuo, porque um parser dentro de um processo setuid
    /// seria superfície de ataque desproporcional. Esse scanner é seguro
    /// enquanto o frame não contiver dado influenciável por terceiros. Manter
    /// esta struct mínima é o que sustenta essa suposição.
    public struct AuthResult: Codable, Sendable {
        public let type: Kind
        public let ok: Bool

        public init(ok: Bool) {
            self.type = .authResult
            self.ok = ok
        }
    }

    // MARK: - TLS (daemon ↔ celular)

    public struct HelloChallenge: Codable, Sendable {
        public let type: Kind
        public let nonce: String

        public init(nonce: String) {
            self.type = .helloChallenge
            self.nonce = nonce
        }
    }

    public struct HelloResponse: Codable, Sendable {
        public let type: Kind
        public let deviceId: String
        public let signature: String
    }

    public struct AuthChallenge: Codable, Sendable {
        public let type: Kind
        public let requestId: String
        public let challenge: String
        public let issuedAt: Int64
        public let expiresAt: Int64
        public let channelBinding: String
        public let context: SignedPayload.Context

        public init(requestId: String, challenge: String,
                    issuedAt: Int64, expiresAt: Int64,
                    channelBinding: String, context: SignedPayload.Context) {
            self.type = .authChallenge
            self.requestId = requestId
            self.challenge = challenge
            self.issuedAt = issuedAt
            self.expiresAt = expiresAt
            self.channelBinding = channelBinding
            self.context = context
        }
    }

    public struct AuthResponse: Codable, Sendable {
        public let type: Kind
        public let requestId: String
        public let decision: SignedPayload.Decision
        public let signature: String
    }

    public struct PairRequest: Codable, Sendable {
        public let type: Kind
        public let sid: String
        public let deviceName: String
        public let platform: String
        public let idPublicKey: String
        public let authPublicKey: String
        public let proof: String
        public let authSignature: String
    }

    public struct PairOk: Codable, Sendable {
        public let type: Kind
        public let deviceId: String

        public init(deviceId: String) {
            self.type = .pairOk
            self.deviceId = deviceId
        }
    }

    public struct Ping: Codable, Sendable {
        public let type: Kind
        public init() { self.type = .ping }
    }

    public struct Pong: Codable, Sendable {
        public let type: Kind
        public init() { self.type = .pong }
    }

    // MARK: - Erros

    public enum ErrorCode: String, Codable, Sendable {
        case badFrame        = "bad_frame"
        case unknownType     = "unknown_type"
        case pairingExpired  = "pairing_expired"
        case pairingInvalid  = "pairing_invalid"
        case notPaired       = "not_paired"
        case deviceRevoked   = "device_revoked"
        case unauthenticated
        case rateLimited     = "rate_limited"
        case internalError   = "internal"
    }

    /// Erros são vagos de propósito. O celular do usuário legítimo não precisa
    /// saber o motivo — tenta de novo — e um atacante sondando o daemon
    /// também não.
    public struct ErrorMessage: Codable, Sendable {
        public let type: Kind
        public let code: ErrorCode
        public let message: String

        public init(_ code: ErrorCode, _ message: String = "") {
            self.type = .error
            self.code = code
            self.message = message
        }
    }
}

// MARK: - Codificação

public enum Wire {
    public static let encoder: JSONEncoder = {
        let e = JSONEncoder()
        e.outputFormatting = [.withoutEscapingSlashes]
        return e
    }()

    public static let decoder = JSONDecoder()

    public static func encode<T: Encodable>(_ value: T) throws -> Data {
        try Framing.encode(try encoder.encode(value))
    }

    public static func kind(of body: Data) -> Message.Kind? {
        try? decoder.decode(Message.Envelope.self, from: body).type
    }
}
