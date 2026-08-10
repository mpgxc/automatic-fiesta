import Foundation
import CryptoKit

public struct PairedDevice: Codable, Equatable, Sendable {
    public let id: String
    public var name: String
    public let platform: String
    /// SubjectPublicKeyInfo DER em base64. Autentica a conexão, sem biometria.
    public let idPublicKey: String
    /// SubjectPublicKeyInfo DER em base64. Assina aprovações, exige biometria
    /// a cada uso.
    public let authPublicKey: String
    public let pairedAt: Date
    public var lastSeenAt: Date?
    public var revokedAt: Date?

    public var isActive: Bool { revokedAt == nil }

    public init(id: String, name: String, platform: String,
                idPublicKey: String, authPublicKey: String,
                pairedAt: Date = Date()) {
        self.id = id
        self.name = name
        self.platform = platform
        self.idPublicKey = idPublicKey
        self.authPublicKey = authPublicKey
        self.pairedAt = pairedAt
    }
}

/// Persiste os dispositivos pareados em `devices.json`.
///
/// O arquivo contém **exclusivamente chaves públicas**. Se vazar, o atacante
/// descobre quais celulares você pareou e nada além disso: forjar aprovação
/// exigiria as chaves privadas, que estão dentro do Secure Enclave / StrongBox
/// e não são extraíveis.
///
/// Foi escolhido arquivo em vez de Keychain justamente por isso — o conteúdo é
/// público, um arquivo root-only é auditável com `cat`, e evita-se a dança de
/// ACL de Keychain para um daemon root.
public final class DeviceRegistry: @unchecked Sendable {

    public enum Error: Swift.Error, CustomStringConvertible {
        case insecurePermissions(path: String, mode: Int)
        case corruptStore(underlying: Swift.Error)

        public var description: String {
            switch self {
            case .insecurePermissions(let path, let mode):
                return String(format: "%@ está com modo %o; esperado 0600. Recusando por segurança.", path, mode)
            case .corruptStore(let e):
                return "devices.json ilegível: \(e)"
            }
        }
    }

    private let url: URL
    private let lock = NSLock()
    private var devices: [String: PairedDevice] = [:]

    public init(directory: URL) throws {
        self.url = directory.appendingPathComponent("devices.json")
        try load()
    }

    // MARK: - Leitura

    private func load() throws {
        guard FileManager.default.fileExists(atPath: url.path) else {
            devices = [:]
            return
        }
        try verifyPermissions()

        do {
            let data = try Data(contentsOf: url)
            let decoder = JSONDecoder()
            decoder.dateDecodingStrategy = .iso8601
            let list = try decoder.decode([PairedDevice].self, from: data)
            devices = Dictionary(uniqueKeysWithValues: list.map { ($0.id, $0) })
        } catch {
            throw Error.corruptStore(underlying: error)
        }
    }

    /// Um `devices.json` gravável por outros seria uma porta aberta: bastaria
    /// injetar uma chave pública própria para aprovar qualquer pedido.
    private func verifyPermissions() throws {
        let attrs = try FileManager.default.attributesOfItem(atPath: url.path)
        guard let mode = (attrs[.posixPermissions] as? NSNumber)?.intValue else { return }
        guard mode & 0o077 == 0 else {
            throw Error.insecurePermissions(path: url.path, mode: mode)
        }
    }

    // MARK: - Escrita

    private func persist() throws {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        let data = try encoder.encode(devices.values.sorted { $0.pairedAt < $1.pairedAt })

        // Escrita atômica com permissão restrita desde o instante da criação:
        // criar 0644 e depois apertar deixaria uma janela de leitura por
        // qualquer processo.
        let tmp = url.deletingLastPathComponent()
            .appendingPathComponent(".devices.json.\(UUID().uuidString)")

        guard FileManager.default.createFile(
            atPath: tmp.path,
            contents: data,
            attributes: [.posixPermissions: 0o600]
        ) else {
            throw CocoaError(.fileWriteUnknown)
        }

        do {
            _ = try FileManager.default.replaceItemAt(url, withItemAt: tmp)
        } catch {
            try? FileManager.default.removeItem(at: tmp)
            throw error
        }
    }

    // MARK: - API

    public func all() -> [PairedDevice] {
        lock.lock(); defer { lock.unlock() }
        return devices.values.sorted { $0.pairedAt < $1.pairedAt }
    }

    public func active() -> [PairedDevice] {
        all().filter(\.isActive)
    }

    public func device(id: String) -> PairedDevice? {
        lock.lock(); defer { lock.unlock() }
        return devices[id]
    }

    public func add(_ device: PairedDevice) throws {
        lock.lock(); defer { lock.unlock() }
        devices[device.id] = device
        try persist()
    }

    /// Revoga sem apagar: o histórico de que aquele dispositivo existiu e
    /// quando foi cortado tem valor forense.
    public func revoke(id: String) throws -> Bool {
        lock.lock(); defer { lock.unlock() }
        guard var d = devices[id], d.revokedAt == nil else { return false }
        d.revokedAt = Date()
        devices[id] = d
        try persist()
        return true
    }

    public func remove(id: String) throws -> Bool {
        lock.lock(); defer { lock.unlock() }
        guard devices.removeValue(forKey: id) != nil else { return false }
        try persist()
        return true
    }

    public func touch(id: String) {
        lock.lock(); defer { lock.unlock() }
        guard var d = devices[id] else { return }
        d.lastSeenAt = Date()
        devices[id] = d
        try? persist()   // telemetria; perder isto não afeta a autenticação
    }
}
