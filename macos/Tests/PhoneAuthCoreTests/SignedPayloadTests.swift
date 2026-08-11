import XCTest
import CryptoKit
@testable import PhoneAuthCore

/// Vetores de resposta conhecida para a serialização assinada.
///
/// Estes hashes foram calculados de forma independente por
/// `docs/generate-test-vectors.py` e estão fixados em `docs/test-vectors.json`.
/// As três implementações — este daemon, o app iOS e o app Android — rodam os
/// mesmos vetores. Se as três baterem contra os mesmos valores, as assinaturas
/// verificam entre plataformas; se qualquer uma divergir, o bug aparece aqui e
/// não como um misterioso "aprovei no celular e o Mac recusou".
final class SignedPayloadTests: XCTestCase {

    private func sha256Hex(_ data: Data) -> String {
        Data(SHA256.hash(data: data)).hexLowercase
    }

    private let sampleContext = SignedPayload.Context(
        host: "MacBook Pro de mpgxc",
        user: "mpgxc",
        service: "sudo",
        reason: "sudo brew install ripgrep",
        processPath: "/usr/bin/sudo",
        tty: "ttys002"
    )

    // MARK: - Contexto

    func testContextMatchesVector() throws {
        let bytes = try SignedPayload.contextBytes(sampleContext)
        XCTAssertEqual(bytes.count, 97)
        XCTAssertEqual(sha256Hex(bytes),
                       "51eae53b67ffb644ba5a20529ad453ccd6e05b61d4832c390c82e33992d52d9b")
    }

    /// Campo vazio não some: a linha continua existindo. Sem isso, um contexto
    /// com `reason` vazio colidiria com outro que tivesse os campos deslocados.
    func testEmptyFieldsKeepTheirLines() throws {
        let ctx = SignedPayload.Context(host: "Mac", user: "root", service: "su",
                                        reason: "", processPath: "", tty: "")
        let bytes = try SignedPayload.contextBytes(ctx)
        XCTAssertEqual(bytes.count, 32)
        XCTAssertEqual(sha256Hex(bytes),
                       "612a5428fbff7ff14778574fdfd1db4788fbabde8a726117fd4039499985fc3d")
    }

    func testContextHashHelperAgreesWithManualHash() throws {
        let manual = sha256Hex(try SignedPayload.contextBytes(sampleContext))
        XCTAssertEqual(try SignedPayload.contextHash(sampleContext), manual)
    }

    // MARK: - Aprovação

    func testAuthPayloadMatchesVector() throws {
        let challenge = Data(0 ..< 32)
        let bytes = try SignedPayload.authBytes(
            requestId: "3F2504E0-4F89-41D3-9A0C-0305E82C3301",
            challengeBase64: challenge.base64EncodedString(),
            contextHash: "51eae53b67ffb644ba5a20529ad453ccd6e05b61d4832c390c82e33992d52d9b",
            channelBinding: String(repeating: "a", count: 64),
            issuedAt: 1_770_000_000,
            decision: .allow
        )
        XCTAssertEqual(bytes.count, 247)
        XCTAssertEqual(sha256Hex(bytes),
                       "d505f91918d1bdb56bb4179a257b1f47e966f739d75c2c31f4303069372529b0")
    }

    /// Uma aprovação e uma negação precisam produzir bytes distintos, ou uma
    /// assinatura de "deny" poderia ser reapresentada como "allow".
    func testDenyProducesDifferentBytesThanAllow() throws {
        func bytes(_ decision: SignedPayload.Decision) throws -> Data {
            try SignedPayload.authBytes(
                requestId: "3F2504E0-4F89-41D3-9A0C-0305E82C3301",
                challengeBase64: Data(0 ..< 32).base64EncodedString(),
                contextHash: "51eae53b67ffb644ba5a20529ad453ccd6e05b61d4832c390c82e33992d52d9b",
                channelBinding: String(repeating: "a", count: 64),
                issuedAt: 1_770_000_000,
                decision: decision
            )
        }
        XCTAssertNotEqual(try bytes(.allow), try bytes(.deny))
        XCTAssertEqual(sha256Hex(try bytes(.deny)),
                       "9f565d0511a5693d209b176a7dfd0a4de6b6145bdd2c19bb69d8bdde8d2904ae")
    }

    // MARK: - Pareamento e sessão

    func testPairPayloadMatchesVector() throws {
        let bytes = try SignedPayload.pairBytes(
            sid: "7B3E1A2C-0000-4000-8000-000000000001",
            spki: String(repeating: "b", count: 64),
            idPublicKeyBase64: Data(repeating: 0x11, count: 91).base64EncodedString(),
            authPublicKeyBase64: Data(repeating: 0x22, count: 91).base64EncodedString(),
            deviceName: "iPhone 15 de mpgxc",
            platform: "ios"
        )
        XCTAssertEqual(bytes.count, 393)
        XCTAssertEqual(sha256Hex(bytes),
                       "6eb2345096b00b95579e96e6a6a7380429a1e987c7e4e4854cabf5e792640d84")
    }

    func testHelloPayloadMatchesVector() throws {
        let bytes = try SignedPayload.helloBytes(
            deviceId: "9C1D2E3F-0000-4000-8000-000000000002",
            nonceBase64: Data(repeating: 0xAA, count: 32).base64EncodedString(),
            channelBinding: String(repeating: "a", count: 64)
        )
        XCTAssertEqual(bytes.count, 166)
        XCTAssertEqual(sha256Hex(bytes),
                       "e2d35c4b5772349157abfd31905482f68b76d05d3d4359b0db30640dcfe74977")
    }

    // MARK: - Rotação de identidade

    /// Hoje só o gêmeo macOS implementa estes domínios. Os vetores existem para
    /// que iOS e Android tenham contra o que conferir quando forem escritos —
    /// sem eles, os gêmeos nasceriam sem rede de proteção, que é exatamente a
    /// falha que `docs/test-vectors.json` previne.
    func testRotatePayloadMatchesVector() throws {
        let bytes = try SignedPayload.rotateBytes(
            rotationId: "5D8C7B6A-0000-4000-8000-000000000003",
            currentSpki: String(repeating: "c", count: 64),
            nextSpki: String(repeating: "d", count: 64),
            announcedAt: 1_770_000_000,
            commitNotBefore: 1_770_086_400,
            expiresAt: 1_770_604_800,
            retirePrevious: true
        )
        XCTAssertEqual(bytes.count, 225)
        XCTAssertEqual(sha256Hex(bytes),
                       "a1d0e476d71f7e9182e2c8a1004f9242c266e634b67110b1def4535d1d33a3a5")
    }

    /// `retirePrevious` vira a string literal "true"/"false" na serialização.
    /// Este teste trava as duas formas, porque cada linguagem formata booleano
    /// do seu jeito e um `False` maiúsculo do Python ou um `1` do C quebrariam
    /// a assinatura sem quebrar nada visível.
    func testRotatePayloadWithoutRetireMatchesVector() throws {
        let bytes = try SignedPayload.rotateBytes(
            rotationId: "5D8C7B6A-0000-4000-8000-000000000003",
            currentSpki: String(repeating: "c", count: 64),
            nextSpki: String(repeating: "d", count: 64),
            announcedAt: 1_770_000_000,
            commitNotBefore: 1_770_086_400,
            expiresAt: 1_770_604_800,
            retirePrevious: false
        )
        XCTAssertEqual(bytes.count, 226)
        XCTAssertEqual(sha256Hex(bytes),
                       "dce03083efc8e9839c57de6329c9ac0ec2c9e668856df97fdc389b2add94c752")
    }

    func testRotateAckPayloadMatchesVector() throws {
        let bytes = try SignedPayload.rotateAckBytes(
            rotationId: "5D8C7B6A-0000-4000-8000-000000000003",
            deviceId: "9C1D2E3F-0000-4000-8000-000000000002",
            adoptedSpki: String(repeating: "d", count: 64),
            channelBinding: String(repeating: "a", count: 64)
        )
        XCTAssertEqual(bytes.count, 228)
        XCTAssertEqual(sha256Hex(bytes),
                       "73f0520475788b394d3149a6b489f7e4a26571f9b12a606501b9fc8be2240279")
    }

    /// Os domínios da rotação são acrescentados, nunca substitutos. Se algum dia
    /// colidirem com os quatro originais, uma assinatura de um contexto poderia
    /// ser reapresentada como anúncio de rotação.
    func testAllDomainsAreDistinct() {
        let domains = [SignedPayload.authDomain, SignedPayload.contextDomain,
                       SignedPayload.pairDomain, SignedPayload.helloDomain,
                       SignedPayload.rotateDomain, SignedPayload.rotateAckDomain]
        XCTAssertEqual(Set(domains).count, domains.count, "domínios duplicados permitiriam confusão de tipo")
    }

    // MARK: - Rejeição de quebra de linha

    /// A regra que impede um `reason` malicioso de injetar linhas e fazer um
    /// pedido se apresentar como algo inofensivo enquanto o hash cobre outra
    /// coisa. Se este teste algum dia falhar, o formato virou ambíguo.
    func testNewlineInAnyFieldIsRejected() {
        let injected = "sudo true\nPHONEAUTH-CTX-V1\nMac"
        let ctx = SignedPayload.Context(host: "Mac", user: "mpgxc", service: "sudo",
                                        reason: injected)
        XCTAssertThrowsError(try SignedPayload.contextBytes(ctx))

        let cr = SignedPayload.Context(host: "Mac\r", user: "u", service: "sudo", reason: "x")
        XCTAssertThrowsError(try SignedPayload.contextBytes(cr))

        XCTAssertThrowsError(try SignedPayload.authBytes(
            requestId: "id\nfalso", challengeBase64: "AA==", contextHash: "00",
            channelBinding: "00", issuedAt: 0, decision: .allow))
    }

    /// CRLF é o caso que quase escapou.
    ///
    /// `String.contains("\n")` resolve para a sobrecarga de `Character`, e
    /// `"\r\n"` é UM único `Character` (regra GB3 do UAX#29 mantém CR e LF no
    /// mesmo grapheme cluster). Com a checagem antiga, `"a\r\nb"` passava aqui
    /// e era rejeitado pelo gêmeo Kotlin, que compara code units — exatamente o
    /// "aprovei no iPhone e no Android quebrou" que estes arquivos existem para
    /// impedir.
    func testCRLFIsRejected() {
        let ctx = SignedPayload.Context(host: "Mac", user: "u", service: "sudo",
                                        reason: "sudo true\r\nlinha falsa")
        XCTAssertThrowsError(try SignedPayload.contextBytes(ctx))
    }

    /// `reason` carrega o argv de quem chamou o `sudo` e é exibido cru na tela
    /// de aprovação. Estes scalars são quebra obrigatória no UAX#14, então sem
    /// rejeitá-los um atacante escreve a segunda linha do que o usuário lê
    /// antes de encostar o dedo.
    func testAllLineBreakingScalarsAreRejected() {
        for scalar in SignedPayload.lineBreakingScalars {
            let reason = "rm -rf /\(Character(scalar))Toque para confirmar"
            let ctx = SignedPayload.Context(host: "Mac", user: "u", service: "sudo", reason: reason)
            XCTAssertThrowsError(try SignedPayload.contextBytes(ctx),
                                 "scalar U+\(String(scalar.value, radix: 16, uppercase: true)) deveria ser rejeitado")
        }
    }

    /// A regra ficou mais estrita; não pode ter ficado estrita demais. Texto
    /// legítimo de linha de comando precisa continuar passando.
    func testLegitimateTextStillPasses() throws {
        for reason in ["sudo brew install ripgrep", "café com acento", "tab\tinterno",
                       "emoji 🔐 no motivo", "chinês 中文", ""] {
            let ctx = SignedPayload.Context(host: "Mac", user: "u", service: "sudo", reason: reason)
            XCTAssertNoThrow(try SignedPayload.contextBytes(ctx), "rejeitou texto legítimo: \(reason)")
        }
    }

    // MARK: - Pareamento: HMAC e SAS

    func testPairingProofMatchesVector() throws {
        let transcript = try SignedPayload.pairBytes(
            sid: "7B3E1A2C-0000-4000-8000-000000000001",
            spki: String(repeating: "b", count: 64),
            idPublicKeyBase64: Data(repeating: 0x11, count: 91).base64EncodedString(),
            authPublicKeyBase64: Data(repeating: 0x22, count: 91).base64EncodedString(),
            deviceName: "iPhone 15 de mpgxc",
            platform: "ios"
        )
        let psk = Data(0 ..< 32)

        XCTAssertEqual(Verifier.pairingProof(transcript: transcript, pairingSecret: psk),
                       "5NKfx1QzKzZ2hezIOWZhpWskuVniqL3bEmygrKEAKwI=")
        XCTAssertTrue(Verifier.verifyPairingProof(
            proofBase64: "5NKfx1QzKzZ2hezIOWZhpWskuVniqL3bEmygrKEAKwI=",
            transcript: transcript, pairingSecret: psk))
        XCTAssertEqual(Verifier.shortAuthString(transcript: transcript, pairingSecret: psk), "561453")
    }

    func testPairingProofRejectsWrongSecret() throws {
        let transcript = Data("qualquer coisa".utf8)
        let proof = Verifier.pairingProof(transcript: transcript, pairingSecret: Data(0 ..< 32))
        XCTAssertFalse(Verifier.verifyPairingProof(
            proofBase64: proof, transcript: transcript, pairingSecret: Data(repeating: 0xFF, count: 32)))
        XCTAssertFalse(Verifier.verifyPairingProof(
            proofBase64: proof, transcript: Data("outra coisa".utf8), pairingSecret: Data(0 ..< 32)))
    }
}
