import Foundation
import Security
import CryptoKit
import PhoneAuthCore

/// Carrega a identidade TLS do daemon a partir de um PKCS#12 em disco.
///
/// O par de chaves é gerado pelo `scripts/install.sh` com openssl, não aqui.
/// Construir um certificado auto-assinado em Swift puro exigiria escrever um
/// codificador ASN.1 à mão — muito código delicado para resolver um problema
/// que uma linha de openssl já resolve, e código delicado dentro de um daemon
/// root é exatamente o que não queremos.
///
/// Pelo mesmo motivo, a rotação (`Rotation.swift`) também chama o openssl em
/// vez de gerar a chave em processo. A alternativa seria trazer o codificador
/// ASN.1 para dentro do daemon justamente para uma operação que roda uma vez
/// por ano.
enum Identity {

    /// Nomes dos arquivos no diretório de estado. A rotação mexe em três
    /// gerações ao mesmo tempo, então os nomes viram constantes em vez de
    /// literais espalhados.
    enum Slot: String {
        case live = "identity"
        case next = "identity-next"
        case prev = "identity-prev"

        var bundleName: String { "\(rawValue).p12" }
        var passName:   String { "\(rawValue).pass" }
    }

    enum Error: Swift.Error, CustomStringConvertible {
        case missing(path: String)
        case insecurePermissions(path: String, mode: Int)
        case importFailed(OSStatus)
        case noIdentityInBundle
        case spkiUnavailable
        case privateKeyUnavailable
        case signatureFailed(String)
        case generatorFailed(String)

        var description: String {
            switch self {
            case .missing(let p):
                return "identidade TLS não encontrada em \(p). Rode scripts/install.sh."
            case .insecurePermissions(let p, let m):
                return String(format: "%@ está com modo %o; esperado 0600. Recusando por segurança.", p, m)
            case .importFailed(let status):
                return "SecPKCS12Import falhou com status \(status)"
            case .noIdentityInBundle:
                return "o PKCS#12 não contém identidade"
            case .spkiUnavailable:
                return "não foi possível derivar o hash do SPKI do certificado"
            case .privateKeyUnavailable:
                return "não foi possível extrair a chave privada da identidade"
            case .signatureFailed(let m):
                return "falha ao assinar com a chave TLS: \(m)"
            case .generatorFailed(let m):
                return "falha ao gerar a identidade nova: \(m)"
            }
        }
    }

    struct Loaded {
        let identity: SecIdentity
        let certificate: SecCertificate
        /// Hex do SHA-256 do SubjectPublicKeyInfo. É o valor que o celular
        /// fixa no pareamento e que entra nos bytes assinados como
        /// `channelBinding`.
        let spkiHash: String
        /// O SubjectPublicKeyInfo DER em si. Vai dentro do anúncio de rotação
        /// para que o celular consiga verificar a assinatura mesmo quando o
        /// anúncio não chega pela conexão TLS (o caminho por QR code).
        let spkiDER: Data
        /// Usada para assinar o anúncio de rotação — e para nada mais. Ver a
        /// nota de separação de domínio em `SignedPayload.rotateBytes`.
        let privateKey: SecKey
    }

    // MARK: - Carga

    static func load(directory: URL,
                     slot: Slot = .live,
                     passphrase: String) throws -> Loaded {
        try load(directory: directory, slot: slot, passphraseCandidates: [passphrase])
    }

    /// Tenta mais de uma senha porque o commit da rotação troca dois arquivos
    /// (`.p12` e `.pass`) e o POSIX não renomeia dois de uma vez. Uma queda de
    /// energia no meio deixaria o par desencontrado e o daemon não subiria mais
    /// — o que, num daemon de autenticação, é caro por um motivo tolo.
    ///
    /// Não há custo de segurança: os três arquivos são root-only, e a senha do
    /// PKCS#12 já não acrescenta segurança criptográfica nenhuma (ver
    /// `loadPassphrase`).
    static func load(directory: URL,
                     slot: Slot = .live,
                     passphraseCandidates: [String]) throws -> Loaded {
        let url = directory.appendingPathComponent(slot.bundleName)
        guard FileManager.default.fileExists(atPath: url.path) else {
            throw Error.missing(path: url.path)
        }

        // A chave privada TLS é a única coisa realmente sensível no estado do
        // daemon. Se estiver legível por outros, pare.
        try verifyPermissions(of: url)

        let data = try Data(contentsOf: url)

        var lastStatus: OSStatus = errSecParam
        for passphrase in passphraseCandidates {
            var items: CFArray?
            let options = [kSecImportExportPassphrase as String: passphrase] as CFDictionary
            lastStatus = SecPKCS12Import(data as CFData, options, &items)
            guard lastStatus == errSecSuccess else { continue }

            guard let array = items as? [[String: Any]],
                  let first = array.first,
                  let identityRef = first[kSecImportItemIdentity as String] else {
                throw Error.noIdentityInBundle
            }
            return try describe(identity: identityRef as! SecIdentity)
        }
        throw Error.importFailed(lastStatus)
    }

    private static func describe(identity: SecIdentity) throws -> Loaded {
        var certificate: SecCertificate?
        SecIdentityCopyCertificate(identity, &certificate)
        guard let certificate else { throw Error.noIdentityInBundle }

        guard let publicKey = SecCertificateCopyKey(certificate),
              let x963 = SecKeyCopyExternalRepresentation(publicKey, nil) as Data? else {
            throw Error.spkiUnavailable
        }
        // Mesma reconstituição do envelope SPKI que o `Verifier` faz, para que
        // o valor signifique a mesma coisa nas três implementações.
        let spkiDER = Verifier.wrapP256InSPKI(x963)
        let spkiHash = Data(SHA256.hash(data: spkiDER)).hexLowercase

        var privateKey: SecKey?
        SecIdentityCopyPrivateKey(identity, &privateKey)
        guard let privateKey else { throw Error.privateKeyUnavailable }

        return Loaded(identity: identity,
                      certificate: certificate,
                      spkiHash: spkiHash,
                      spkiDER: spkiDER,
                      privateKey: privateKey)
    }

    private static func verifyPermissions(of url: URL) throws {
        let attrs = try FileManager.default.attributesOfItem(atPath: url.path)
        if let mode = (attrs[.posixPermissions] as? NSNumber)?.intValue, mode & 0o077 != 0 {
            throw Error.insecurePermissions(path: url.path, mode: mode)
        }
    }

    /// A senha do PKCS#12 vive num arquivo root-only ao lado dele.
    ///
    /// Isto não acrescenta segurança criptográfica — quem lê um arquivo lê o
    /// outro. Serve para que a chave não fique como um blob sem senha, o que
    /// simplifica a manipulação com openssl e evita um `.p12` sem proteção
    /// nenhuma numa cópia de backup descuidada.
    static func loadPassphrase(directory: URL, slot: Slot = .live) throws -> String {
        let url = directory.appendingPathComponent(slot.passName)
        let raw = try String(contentsOf: url, encoding: .utf8)
        return raw.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    /// Todas as senhas presentes, na ordem em que fazem sentido tentar.
    static func passphraseCandidates(directory: URL) -> [String] {
        [Slot.live, .next, .prev].compactMap { try? loadPassphrase(directory: directory, slot: $0) }
    }

    // MARK: - Assinatura

    /// Assina com a chave privada TLS. Só o anúncio de rotação usa isto.
    static func sign(_ message: Data, with key: SecKey) throws -> String {
        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(
            key, .ecdsaSignatureMessageX962SHA256, message as CFData, &error
        ) as Data? else {
            let reason = (error?.takeRetainedValue()).map { String(describing: $0) } ?? "erro desconhecido"
            throw Error.signatureFailed(reason)
        }
        // DER, que é o que `Verifier.verify` e as duas implementações de
        // celular esperam.
        return signature.base64EncodedString()
    }

    // MARK: - Geração

    /// Gera um par P-256 novo e um certificado auto-assinado no slot indicado.
    ///
    /// Argumentos idênticos aos do `scripts/install.sh`, de propósito: uma
    /// identidade rotacionada precisa ser indistinguível de uma recém
    /// instalada, ou a rotação vira uma segunda variante de configuração para
    /// depurar.
    @discardableResult
    static func generate(directory: URL, slot: Slot, hostName: String) throws -> Loaded {
        let openssl = "/usr/bin/openssl"
        guard FileManager.default.isExecutableFile(atPath: openssl) else {
            throw Error.generatorFailed("\(openssl) não está disponível")
        }

        let work = directory.appendingPathComponent(".rotate-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: work, withIntermediateDirectories: false,
                                                attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: work) }

        let keyPEM  = work.appendingPathComponent("key.pem")
        let certPEM = work.appendingPathComponent("cert.pem")
        let bundle  = work.appendingPathComponent("identity.p12")
        let passFile = work.appendingPathComponent("pass.txt")

        let passphrase = randomBase64(byteCount: 32)
        // A senha vai por arquivo, e não em `-passout pass:`, porque argv de
        // processo é legível por qualquer um com `ps`. O arquivo nasce 0600
        // dentro de um diretório 0700 e morre com o `defer` acima.
        guard FileManager.default.createFile(atPath: passFile.path,
                                             contents: Data(passphrase.utf8),
                                             attributes: [.posixPermissions: 0o600]) else {
            throw Error.generatorFailed("não foi possível gravar a senha temporária")
        }

        try run(openssl, ["ecparam", "-name", "prime256v1", "-genkey", "-noout",
                          "-out", keyPEM.path])
        try run(openssl, ["req", "-new", "-x509", "-key", keyPEM.path, "-out", certPEM.path,
                          "-days", "3650", "-sha256",
                          "-subj", "/CN=phoneauthd/O=PhoneAuth",
                          "-addext", "subjectAltName=DNS:\(hostName).local,DNS:localhost"])
        try run(openssl, ["pkcs12", "-export", "-out", bundle.path,
                          "-inkey", keyPEM.path, "-in", certPEM.path,
                          "-passout", "file:\(passFile.path)"])

        // Só depois de o material estar completo é que ele entra no diretório
        // de estado: um `identity-next.p12` pela metade seria pior que nenhum.
        try install(bundle, at: directory.appendingPathComponent(slot.bundleName))
        try installData(Data(passphrase.utf8), at: directory.appendingPathComponent(slot.passName))

        return try load(directory: directory, slot: slot, passphrase: passphrase)
    }

    private static func run(_ launchPath: String, _ arguments: [String]) throws {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: launchPath)
        process.arguments = arguments
        // Sem shell e sem herdar stdout/stderr: nada do openssl deve acabar
        // misturado no log do daemon.
        let errPipe = Pipe()
        process.standardOutput = FileHandle.nullDevice
        process.standardError = errPipe

        try process.run()
        let stderrData = errPipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()

        guard process.terminationStatus == 0 else {
            let detail = String(decoding: stderrData.prefix(400), as: UTF8.self)
                .trimmingCharacters(in: .whitespacesAndNewlines)
            throw Error.generatorFailed("openssl \(arguments.first ?? "") saiu com \(process.terminationStatus): \(detail)")
        }
    }

    private static func randomBase64(byteCount: Int) -> String {
        var bytes = Data(count: byteCount)
        bytes.withUnsafeMutableBytes { raw in
            guard let base = raw.baseAddress else { return }
            _ = SecRandomCopyBytes(kSecRandomDefault, byteCount, base)
        }
        return bytes.base64EncodedString()
    }

    // MARK: - Movimentação de arquivos

    /// Grava com 0600 desde o instante da criação. Criar 0644 e apertar depois
    /// deixaria uma janela de leitura para qualquer processo — o mesmo cuidado
    /// que o `DeviceRegistry` toma.
    private static func installData(_ data: Data, at destination: URL) throws {
        let tmp = destination.deletingLastPathComponent()
            .appendingPathComponent(".\(destination.lastPathComponent).\(UUID().uuidString)")
        guard FileManager.default.createFile(atPath: tmp.path, contents: data,
                                             attributes: [.posixPermissions: 0o600]) else {
            throw CocoaError(.fileWriteUnknown)
        }
        try replace(tmp, with: destination)
    }

    private static func install(_ source: URL, at destination: URL) throws {
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: source.path)
        let tmp = destination.deletingLastPathComponent()
            .appendingPathComponent(".\(destination.lastPathComponent).\(UUID().uuidString)")
        try FileManager.default.copyItem(at: source, to: tmp)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: tmp.path)
        try replace(tmp, with: destination)
    }

    private static func replace(_ tmp: URL, with destination: URL) throws {
        do {
            if FileManager.default.fileExists(atPath: destination.path) {
                _ = try FileManager.default.replaceItemAt(destination, withItemAt: tmp)
            } else {
                try FileManager.default.moveItem(at: tmp, to: destination)
            }
        } catch {
            try? FileManager.default.removeItem(at: tmp)
            throw error
        }
    }

    static func copySlot(directory: URL, from: Slot, to: Slot) throws {
        let bundle = try Data(contentsOf: directory.appendingPathComponent(from.bundleName))
        let pass = try loadPassphrase(directory: directory, slot: from)
        try installData(bundle, at: directory.appendingPathComponent(to.bundleName))
        try installData(Data(pass.utf8), at: directory.appendingPathComponent(to.passName))
    }

    static func discardSlot(directory: URL, _ slot: Slot) {
        for name in [slot.bundleName, slot.passName] {
            try? FileManager.default.removeItem(at: directory.appendingPathComponent(name))
        }
    }

    static func slotExists(directory: URL, _ slot: Slot) -> Bool {
        FileManager.default.fileExists(atPath: directory.appendingPathComponent(slot.bundleName).path)
    }
}
