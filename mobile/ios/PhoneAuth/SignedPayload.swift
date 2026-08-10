import Foundation
import CryptoKit

/// Gêmeo de `macos/Sources/PhoneAuthCore/SignedPayload.swift` e de
/// `mobile/android/.../SignedPayload.kt`.
///
/// Os três precisam produzir bytes idênticos. Os testes das três
/// implementações rodam os mesmos vetores de `docs/test-vectors.json`, então
/// uma divergência aparece como teste vermelho e não como um misterioso
/// "aprovei e o Mac recusou".
///
/// Se você mudar este arquivo, mude os outros dois na mesma mudança.
enum SignedPayload {

    enum Error: Swift.Error {
        case newlineInField(String)
    }

    static let authDomain    = "PHONEAUTH-AUTH-V1"
    static let contextDomain = "PHONEAUTH-CTX-V1"
    static let pairDomain    = "PHONEAUTH-PAIR-V1"
    static let helloDomain   = "PHONEAUTH-HELLO-V1"

    private static func serialize(_ fields: [(name: String, value: String)]) throws -> Data {
        for field in fields where field.value.contains("\n") || field.value.contains("\r") {
            throw Error.newlineInField(field.name)
        }
        return Data((fields.map(\.value).joined(separator: "\n") + "\n").utf8)
    }

    struct Context: Codable, Equatable {
        var host: String
        var user: String
        var service: String
        var reason: String
        var processPath: String
        var tty: String
    }

    static func contextBytes(_ ctx: Context) throws -> Data {
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

    static func contextHash(_ ctx: Context) throws -> String {
        Data(SHA256.hash(data: try contextBytes(ctx))).hexLowercase
    }

    enum Decision: String, Codable {
        case allow, deny
    }

    static func authBytes(requestId: String,
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

    static func pairBytes(sid: String,
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

    static func helloBytes(deviceId: String,
                           nonceBase64: String,
                           channelBinding: String) throws -> Data {
        try serialize([
            ("domain",         helloDomain),
            ("deviceId",       deviceId),
            ("nonce",          nonceBase64),
            ("channelBinding", channelBinding),
        ])
    }
}

extension Data {
    var hexLowercase: String {
        map { String(format: "%02x", $0) }.joined()
    }
}
