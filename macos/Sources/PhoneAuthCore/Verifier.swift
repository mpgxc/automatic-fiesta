import Foundation
import CryptoKit

/// Verificação de assinaturas ECDSA P-256 e a lógica de pareamento.
///
/// P-256 não é escolha estética: é o único algoritmo assimétrico que o Secure
/// Enclave suporta. O Android Keystore também o suporta bem, então os dois
/// lados convergem nele.
public enum Verifier {

    public enum Error: Swift.Error, CustomStringConvertible {
        case malformedPublicKey
        case malformedSignature
        case signatureRejected

        public var description: String {
            switch self {
            case .malformedPublicKey:  return "chave pública não é um SubjectPublicKeyInfo P-256 válido"
            case .malformedSignature:  return "assinatura não é ECDSA DER válida"
            case .signatureRejected:   return "assinatura não confere"
            }
        }
    }

    /// `publicKeyBase64` é um SubjectPublicKeyInfo DER; `signatureBase64` é
    /// ECDSA em DER. É o que ambas as plataformas produzem nativamente.
    public static func verify(signatureBase64: String,
                              over message: Data,
                              publicKeyBase64: String) throws {
        guard let keyData = Data(base64Encoded: publicKeyBase64),
              let key = try? P256.Signing.PublicKey(derRepresentation: keyData) else {
            throw Error.malformedPublicKey
        }
        guard let sigData = Data(base64Encoded: signatureBase64),
              let signature = try? P256.Signing.ECDSASignature(derRepresentation: sigData) else {
            throw Error.malformedSignature
        }
        guard key.isValidSignature(signature, for: message) else {
            throw Error.signatureRejected
        }
    }

    // MARK: - Pareamento

    /// Prova que quem está pareando viu o QR na tela do Mac.
    ///
    /// Comparação em tempo constante: `HMAC.isValidAuthenticationCode` já faz
    /// isso. Um `==` entre Data vazaria informação por tempo.
    public static func verifyPairingProof(proofBase64: String,
                                          transcript: Data,
                                          pairingSecret: Data) -> Bool {
        guard let proof = Data(base64Encoded: proofBase64) else { return false }
        let key = SymmetricKey(data: pairingSecret)
        return HMAC<SHA256>.isValidAuthenticationCode(proof, authenticating: transcript, using: key)
    }

    public static func pairingProof(transcript: Data, pairingSecret: Data) -> String {
        let key = SymmetricKey(data: pairingSecret)
        return Data(HMAC<SHA256>.authenticationCode(for: transcript, using: key)).base64EncodedString()
    }

    /// Código de 6 dígitos exibido nos dois lados para confirmação visual.
    ///
    /// Defesa em profundidade contra um intermediário ativo que tenha de alguma
    /// forma obtido o segredo do QR: ele teria que produzir um transcript
    /// diferente, e os códigos divergiriam visivelmente.
    public static func shortAuthString(transcript: Data, pairingSecret: Data) -> String {
        var info = Data("phoneauth-sas-v1".utf8)
        info.append(transcript)

        let derived = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: pairingSecret),
            info: info,
            outputByteCount: 4
        )
        let bytes = derived.withUnsafeBytes { Data($0) }
        let value = bytes.withUnsafeBytes { raw -> UInt32 in
            UInt32(raw[0]) << 24 | UInt32(raw[1]) << 16 | UInt32(raw[2]) << 8 | UInt32(raw[3])
        }
        return String(format: "%06u", value % 1_000_000)
    }

    // MARK: - Pinning

    /// Hash SHA-256 do SubjectPublicKeyInfo do certificado — o valor que o
    /// celular fixa no pareamento.
    ///
    /// Pinar o SPKI e não o certificado inteiro permite renovar o certificado
    /// mantendo a chave, sem obrigar a reparear todos os dispositivos.
    public static func spkiHash(of certificate: SecCertificate) -> String? {
        guard let key = SecCertificateCopyKey(certificate),
              let der = SecKeyCopyExternalRepresentation(key, nil) as Data? else {
            return nil
        }
        // SecKeyCopyExternalRepresentation devolve o ponto EC cru (X9.63), não
        // um SPKI. Reconstituímos o envelope SPKI para que o valor pinado
        // signifique a mesma coisa nas três implementações.
        let spki = Self.wrapP256InSPKI(der)
        return Data(SHA256.hash(data: spki)).hexLowercase
    }

    /// Prefixo DER fixo de um SubjectPublicKeyInfo de chave pública P-256.
    /// Constante porque o algoritmo e a curva são constantes.
    static let p256SPKIPrefix = Data([
        0x30, 0x59,                                             // SEQUENCE, 89 bytes
        0x30, 0x13,                                             // SEQUENCE, 19 bytes
        0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01,   // OID ecPublicKey
        0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, // OID prime256v1
        0x03, 0x42, 0x00,                                       // BIT STRING, 66 bytes, 0 não usados
    ])

    public static func wrapP256InSPKI(_ x963: Data) -> Data {
        guard x963.count == 65, x963.first == 0x04 else { return x963 }
        return p256SPKIPrefix + x963
    }
}
