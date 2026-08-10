import Foundation
import Security
import LocalAuthentication

/// As duas chaves do dispositivo, dentro do Secure Enclave.
///
/// É aqui que mora a garantia de segurança do projeto inteiro. Não estamos
/// perguntando ao iOS "o usuário autenticou?" e reportando a resposta ao Mac —
/// isso seria uma afirmação do app, e um app pode mentir ou ser modificado.
///
/// Em vez disso, a chave privada é criada **dentro** do Secure Enclave com uma
/// política de acesso que o próprio hardware impõe: sem biometria apresentada
/// agora, a chave não assina. A chave nunca sai do enclave e não existe caminho
/// de software que contorne isso. A assinatura, portanto, é prova de que a
/// digital foi apresentada — não um relato de que foi.
enum DeviceKeys {

    private static let idTag   = "dev.phoneauth.key.identity"
    private static let authTag = "dev.phoneauth.key.approval"

    enum Error: Swift.Error, LocalizedError {
        case secureEnclaveUnavailable
        case creationFailed(String)
        case keyMissing
        case signingFailed(String)
        case publicKeyUnavailable

        var errorDescription: String? {
            switch self {
            case .secureEnclaveUnavailable:
                return "Este aparelho não tem Secure Enclave."
            case .creationFailed(let detail):
                return "Não foi possível criar a chave: \(detail)"
            case .keyMissing:
                return "Chave não encontrada. Refaça o pareamento."
            case .signingFailed(let detail):
                return "Falha ao assinar: \(detail)"
            case .publicKeyUnavailable:
                return "Não foi possível ler a chave pública."
            }
        }
    }

    // MARK: - Criação

    /// Cria as duas chaves. Chamado uma vez, no pareamento.
    ///
    /// Se já existirem, são apagadas antes: parear de novo significa começar do
    /// zero, e uma chave órfã de um pareamento anterior só serviria para
    /// confundir.
    static func createKeyPair() throws {
        deleteAll()
        try create(tag: idTag, biometricGated: false)
        try create(tag: authTag, biometricGated: true)
    }

    private static func create(tag: String, biometricGated: Bool) throws {
        var accessError: Unmanaged<CFError>?

        // A diferença entre as duas chaves está exatamente aqui.
        //
        // A chave de identidade só precisa de `.privateKeyUsage` — ela
        // autentica a conexão TCP e é usada toda vez que o app reconecta. Se
        // pedisse biometria, você encostaria o dedo a cada troca de Wi-Fi e
        // aprenderia a fazer isso no automático, que é o hábito que destrói a
        // segurança de todo o sistema.
        //
        // A chave de aprovação leva `.biometryCurrentSet`, que impõe duas
        // coisas: exige biometria a cada assinatura individual (o iOS não
        // reaproveita uma autenticação anterior), e **destrói a chave** se
        // alguém cadastrar uma digital nova no aparelho. Essa segunda
        // propriedade é o que impede o ataque "peguei o celular desbloqueado e
        // cadastrei meu dedo".
        let flags: SecAccessControlCreateFlags = biometricGated
            ? [.privateKeyUsage, .biometryCurrentSet]
            : [.privateKeyUsage]

        guard let access = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            flags,
            &accessError
        ) else {
            throw Error.creationFailed(String(describing: accessError?.takeRetainedValue()))
        }

        let attributes: [String: Any] = [
            kSecAttrKeyType as String:       kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String:       kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String:    true,
                kSecAttrApplicationTag as String: Data(tag.utf8),
                kSecAttrAccessControl as String:  access,
            ],
        ]

        var error: Unmanaged<CFError>?
        guard SecKeyCreateRandomKey(attributes as CFDictionary, &error) != nil else {
            throw Error.creationFailed(String(describing: error?.takeRetainedValue()))
        }
    }

    // MARK: - Acesso

    private static func loadPrivateKey(tag: String, prompt: String?) throws -> SecKey {
        var query: [String: Any] = [
            kSecClass as String:              kSecClassKey,
            kSecAttrKeyType as String:        kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrApplicationTag as String: Data(tag.utf8),
            kSecReturnRef as String:          true,
        ]

        if let prompt {
            // O texto que aparece no Face ID / Touch ID. Deve descrever o que
            // está sendo aprovado, não apenas "autentique-se".
            let context = LAContext()
            context.localizedReason = prompt
            query[kSecUseAuthenticationContext as String] = context
            query[kSecUseOperationPrompt as String] = prompt
        }

        var item: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess else {
            throw Error.keyMissing
        }
        return item as! SecKey
    }

    static func publicKeySPKIBase64(biometric: Bool) throws -> String {
        let key = try loadPrivateKey(tag: biometric ? authTag : idTag, prompt: nil)
        guard let publicKey = SecKeyCopyPublicKey(key),
              let raw = SecKeyCopyExternalRepresentation(publicKey, nil) as Data? else {
            throw Error.publicKeyUnavailable
        }
        // SecKeyCopyExternalRepresentation devolve o ponto EC cru em X9.63.
        // O protocolo pede SubjectPublicKeyInfo DER, que é o que o Android
        // produz nativamente — então envelopamos aqui para os dois lados
        // falarem a mesma coisa.
        return wrapP256InSPKI(raw).base64EncodedString()
    }

    // MARK: - Assinatura

    /// Assina com a chave de aprovação. **Dispara a biometria**, imposta pelo
    /// Secure Enclave e não por este código.
    static func signWithApprovalKey(_ message: Data, prompt: String) throws -> String {
        let key = try loadPrivateKey(tag: authTag, prompt: prompt)
        return try sign(message, with: key)
    }

    /// Assina com a chave de identidade. Não pede biometria — por desenho.
    static func signWithIdentityKey(_ message: Data) throws -> String {
        let key = try loadPrivateKey(tag: idTag, prompt: nil)
        return try sign(message, with: key)
    }

    private static func sign(_ message: Data, with key: SecKey) throws -> String {
        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(
            key,
            .ecdsaSignatureMessageX962SHA256,   // hash SHA-256 + ECDSA, saída DER
            message as CFData,
            &error
        ) as Data? else {
            throw Error.signingFailed(String(describing: error?.takeRetainedValue()))
        }
        return signature.base64EncodedString()
    }

    // MARK: - Remoção

    static func deleteAll() {
        for tag in [idTag, authTag] {
            SecItemDelete([
                kSecClass as String:              kSecClassKey,
                kSecAttrApplicationTag as String: Data(tag.utf8),
            ] as CFDictionary)
        }
    }

    static var hasKeys: Bool {
        (try? loadPrivateKey(tag: idTag, prompt: nil)) != nil
    }

    // MARK: - SPKI

    /// Prefixo DER fixo de um SubjectPublicKeyInfo de chave pública P-256.
    /// Constante porque o algoritmo e a curva são constantes.
    private static let p256SPKIPrefix = Data([
        0x30, 0x59, 0x30, 0x13,
        0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01,
        0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07,
        0x03, 0x42, 0x00,
    ])

    static func wrapP256InSPKI(_ x963: Data) -> Data {
        guard x963.count == 65, x963.first == 0x04 else { return x963 }
        return p256SPKIPrefix + x963
    }
}
