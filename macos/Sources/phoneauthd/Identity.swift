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
enum Identity {

    enum Error: Swift.Error, CustomStringConvertible {
        case missing(path: String)
        case insecurePermissions(path: String, mode: Int)
        case importFailed(OSStatus)
        case noIdentityInBundle
        case spkiUnavailable

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
    }

    static func load(directory: URL, passphrase: String) throws -> Loaded {
        let url = directory.appendingPathComponent("identity.p12")
        guard FileManager.default.fileExists(atPath: url.path) else {
            throw Error.missing(path: url.path)
        }

        // A chave privada TLS é a única coisa realmente sensível no estado do
        // daemon. Se estiver legível por outros, pare.
        let attrs = try FileManager.default.attributesOfItem(atPath: url.path)
        if let mode = (attrs[.posixPermissions] as? NSNumber)?.intValue, mode & 0o077 != 0 {
            throw Error.insecurePermissions(path: url.path, mode: mode)
        }

        let data = try Data(contentsOf: url)
        var items: CFArray?
        let options = [kSecImportExportPassphrase as String: passphrase] as CFDictionary

        let status = SecPKCS12Import(data as CFData, options, &items)
        guard status == errSecSuccess else { throw Error.importFailed(status) }

        guard let array = items as? [[String: Any]],
              let first = array.first,
              let identityRef = first[kSecImportItemIdentity as String] else {
            throw Error.noIdentityInBundle
        }
        let identity = identityRef as! SecIdentity

        var certificate: SecCertificate?
        SecIdentityCopyCertificate(identity, &certificate)
        guard let certificate else { throw Error.noIdentityInBundle }

        guard let spki = Verifier.spkiHash(of: certificate) else {
            throw Error.spkiUnavailable
        }

        return Loaded(identity: identity, certificate: certificate, spkiHash: spki)
    }

    /// A senha do PKCS#12 vive num arquivo root-only ao lado dele.
    ///
    /// Isto não acrescenta segurança criptográfica — quem lê um arquivo lê o
    /// outro. Serve para que a chave não fique como um blob sem senha, o que
    /// simplifica a manipulação com openssl e evita um `.p12` sem proteção
    /// nenhuma numa cópia de backup descuidada.
    static func loadPassphrase(directory: URL) throws -> String {
        let url = directory.appendingPathComponent("identity.pass")
        let raw = try String(contentsOf: url, encoding: .utf8)
        return raw.trimmingCharacters(in: .whitespacesAndNewlines)
    }
}
