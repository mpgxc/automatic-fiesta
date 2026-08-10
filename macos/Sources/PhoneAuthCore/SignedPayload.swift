import Foundation
import CryptoKit

/// Serialização exata dos bytes que são assinados criptograficamente.
///
/// Este arquivo tem gêmeos em `mobile/ios/PhoneAuth/SignedPayload.swift` e
/// `mobile/android/.../SignedPayload.kt`. As três implementações precisam
/// produzir bytes idênticos ou nenhuma assinatura verifica. Alterar o formato
/// aqui sem alterar lá dá o sintoma clássico: "aprovei no celular e o Mac
/// recusou".
///
/// Regras (ver docs/protocolo.md §5.2):
///   - campos unidos por "\n", com "\n" final
///   - UTF-8
///   - campo ausente vira string vazia, mas a linha continua existindo
///   - nenhum campo pode conter "\n" ou "\r"
///
/// A última regra é de segurança, não de estilo. Sem ela um `reason` malicioso
/// injetaria linhas e um pedido conseguiria se apresentar como algo inofensivo
/// enquanto o hash cobre outra coisa.
public enum SignedPayload {

    public enum Error: Swift.Error, CustomStringConvertible {
        case newlineInField(String)

        public var description: String {
            switch self {
            case .newlineInField(let name):
                return "campo '\(name)' contém quebra de linha, o que tornaria o payload ambíguo"
            }
        }
    }

    public static let authDomain    = "PHONEAUTH-AUTH-V1"
    public static let contextDomain = "PHONEAUTH-CTX-V1"
    public static let pairDomain    = "PHONEAUTH-PAIR-V1"
    public static let helloDomain   = "PHONEAUTH-HELLO-V1"

    /// Domínios da rotação de identidade (docs/rotacao-de-identidade.md).
    ///
    /// Acrescentados, nunca substituindo: os quatro acima têm vetores fixados
    /// em docs/test-vectors.json e implementações gêmeas já escritas. Mudar um
    /// byte deles invalidaria pareamentos existentes — que é exatamente o
    /// problema que a rotação veio resolver.
    public static let rotateDomain    = "PHONEAUTH-ROTATE-V1"
    public static let rotateAckDomain = "PHONEAUTH-ROTATE-ACK-V1"

    // MARK: - Montagem

    private static func serialize(_ fields: [(name: String, value: String)]) throws -> Data {
        for field in fields where field.value.contains("\n") || field.value.contains("\r") {
            throw Error.newlineInField(field.name)
        }
        let joined = fields.map(\.value).joined(separator: "\n") + "\n"
        return Data(joined.utf8)
    }

    // MARK: - Contexto

    /// O que o usuário lê no celular antes de encostar o dedo. Entra nos bytes
    /// assinados para que o Mac não possa exibir um pedido e validar outro.
    public struct Context: Codable, Equatable, Sendable {
        public var host: String
        public var user: String
        public var service: String
        public var reason: String
        public var processPath: String
        public var tty: String

        public init(host: String, user: String, service: String,
                    reason: String, processPath: String = "", tty: String = "") {
            self.host = host
            self.user = user
            self.service = service
            self.reason = reason
            self.processPath = processPath
            self.tty = tty
        }
    }

    public static func contextBytes(_ ctx: Context) throws -> Data {
        try serialize([
            ("domain",      contextDomain),
            ("host",        ctx.host),
            ("user",        ctx.user),
            ("service",     ctx.service),
            ("reason",      ctx.reason),
            ("processPath", ctx.processPath),
            ("tty",         ctx.tty),
        ])
    }

    /// Hex minúsculo do SHA-256 do contexto.
    public static func contextHash(_ ctx: Context) throws -> String {
        Data(SHA256.hash(data: try contextBytes(ctx))).hexLowercase
    }

    // MARK: - Aprovação

    public enum Decision: String, Codable, Sendable {
        case allow
        case deny
    }

    public static func authBytes(requestId: String,
                                 challengeBase64: String,
                                 contextHash: String,
                                 channelBinding: String,
                                 issuedAt: Int64,
                                 decision: Decision) throws -> Data {
        try serialize([
            ("domain",         authDomain),
            ("requestId",      requestId),
            ("challenge",      challengeBase64),
            ("contextHash",    contextHash),
            ("channelBinding", channelBinding),
            ("issuedAt",       String(issuedAt)),
            ("decision",       decision.rawValue),
        ])
    }

    // MARK: - Pareamento

    public static func pairBytes(sid: String,
                                 spki: String,
                                 idPublicKeyBase64: String,
                                 authPublicKeyBase64: String,
                                 deviceName: String,
                                 platform: String) throws -> Data {
        try serialize([
            ("domain",        pairDomain),
            ("sid",           sid),
            ("spki",          spki),
            ("idPublicKey",   idPublicKeyBase64),
            ("authPublicKey", authPublicKeyBase64),
            ("deviceName",    deviceName),
            ("platform",      platform),
        ])
    }

    // MARK: - Sessão

    public static func helloBytes(deviceId: String,
                                  nonceBase64: String,
                                  channelBinding: String) throws -> Data {
        try serialize([
            ("domain",         helloDomain),
            ("deviceId",       deviceId),
            ("nonce",          nonceBase64),
            ("channelBinding", channelBinding),
        ])
    }

    // MARK: - Rotação de identidade

    /// Anúncio de rotação, assinado pela chave privada **TLS atual** do daemon.
    ///
    /// A chave que sai assina a chave que entra — é o único mecanismo
    /// disponível, porque a chave TLS é a única coisa do daemon em que o
    /// celular já confia.
    ///
    /// Reusar a chave TLS para assinar dados de aplicação é seguro aqui por
    /// separação de domínio: o `CertificateVerify` do TLS 1.3 (RFC 8446
    /// §4.4.3) cobre bytes que começam obrigatoriamente com 64 bytes 0x20,
    /// enquanto isto começa com "PHONEAUTH-ROTATE-V1\n". Nenhuma entrada é
    /// aceita pelos dois. Depende de o listener só falar TLS 1.3, que é o caso.
    public static func rotateBytes(rotationId: String,
                                   currentSpki: String,
                                   nextSpki: String,
                                   announcedAt: Int64,
                                   commitNotBefore: Int64,
                                   expiresAt: Int64,
                                   retirePrevious: Bool) throws -> Data {
        try serialize([
            ("domain",          rotateDomain),
            ("rotationId",      rotationId),
            ("currentSpki",     currentSpki),
            ("nextSpki",        nextSpki),
            ("announcedAt",     String(announcedAt)),
            ("commitNotBefore", String(commitNotBefore)),
            ("expiresAt",       String(expiresAt)),
            ("retirePrevious",  retirePrevious ? "true" : "false"),
        ])
    }

    /// Reconhecimento do anúncio, assinado pela `idKey` — sem biometria.
    ///
    /// Não autoriza nada; responde à pergunta operacional "quem já sabe do pin
    /// novo?", que é o que decide se comitar tranca alguém para fora. É
    /// assinado porque um ack forjado convenceria o operador a comitar cedo
    /// demais, e o `channelBinding` na última linha impede que um ack gravado
    /// seja reapresentado numa rotação futura.
    public static func rotateAckBytes(rotationId: String,
                                      deviceId: String,
                                      adoptedSpki: String,
                                      channelBinding: String) throws -> Data {
        try serialize([
            ("domain",         rotateAckDomain),
            ("rotationId",     rotationId),
            ("deviceId",       deviceId),
            ("adoptedSpki",    adoptedSpki),
            ("channelBinding", channelBinding),
        ])
    }
}

// MARK: - Utilidades

extension Data {
    public var hexLowercase: String {
        map { String(format: "%02x", $0) }.joined()
    }
}
