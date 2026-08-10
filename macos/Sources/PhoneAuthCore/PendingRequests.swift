import Foundation
import CryptoKit

/// Pedidos de autenticação em voo.
///
/// Duas propriedades sustentam a segurança do replay:
///
/// 1. **Uso único, consumido atomicamente.** `consume` retira o pedido do mapa
///    sob o mesmo lock que o localiza. Isso acontece **antes** da verificação
///    de assinatura, de propósito: duas respostas chegando ao mesmo tempo
///    fazem apenas a primeira encontrar o pedido. Se consumíssemos depois de
///    verificar, uma corrida aceitaria as duas.
///
/// 2. **TTL curto.** Pedido expirado não é aceito nem que a assinatura esteja
///    perfeita.
public final class PendingRequests: @unchecked Sendable {

    public struct Pending {
        public let requestId: String
        public let challenge: Data
        public let context: SignedPayload.Context
        public let contextHash: String
        public let channelBinding: String
        public let deviceId: String
        public let issuedAt: Int64
        public let expiresAt: Int64
    }

    private let lock = NSLock()
    private var pending: [String: Pending] = [:]
    private let ttl: TimeInterval

    /// Um pedido em voo por dispositivo. Impede a enxurrada de notificações
    /// que treinaria o usuário a aprovar no reflexo.
    private var inFlightByDevice: Set<String> = []

    public init(ttl: TimeInterval = 60) {
        self.ttl = ttl
    }

    public enum Error: Swift.Error, CustomStringConvertible {
        case deviceBusy

        public var description: String {
            "já existe um pedido em voo para este dispositivo"
        }
    }

    public func create(context: SignedPayload.Context,
                       channelBinding: String,
                       deviceId: String) throws -> Pending {
        let contextHash = try SignedPayload.contextHash(context)
        var challenge = Data(count: 32)
        challenge.withUnsafeMutableBytes { raw in
            guard let base = raw.baseAddress else { return }
            _ = SecRandomCopyBytes(kSecRandomDefault, 32, base)
        }

        let now = Int64(Date().timeIntervalSince1970)
        let item = Pending(
            requestId: UUID().uuidString,
            challenge: challenge,
            context: context,
            contextHash: contextHash,
            channelBinding: channelBinding,
            deviceId: deviceId,
            issuedAt: now,
            expiresAt: now + Int64(ttl)
        )

        lock.lock(); defer { lock.unlock() }
        purgeExpiredLocked()
        guard !inFlightByDevice.contains(deviceId) else { throw Error.deviceBusy }
        inFlightByDevice.insert(deviceId)
        pending[item.requestId] = item
        return item
    }

    /// Retira o pedido. Retorna nil se desconhecido ou já consumido.
    ///
    /// Chame **antes** de verificar a assinatura — ver a nota no topo.
    public func consume(requestId: String) -> Pending? {
        lock.lock(); defer { lock.unlock() }
        purgeExpiredLocked()
        guard let item = pending.removeValue(forKey: requestId) else { return nil }
        inFlightByDevice.remove(item.deviceId)
        return item
    }

    public func cancel(requestId: String) {
        _ = consume(requestId: requestId)
    }

    /// Libera todos os pedidos de um dispositivo — usado quando a conexão cai,
    /// para não deixar o dispositivo marcado como ocupado para sempre.
    public func cancelAll(deviceId: String) {
        lock.lock(); defer { lock.unlock() }
        for (id, item) in pending where item.deviceId == deviceId {
            pending.removeValue(forKey: id)
        }
        inFlightByDevice.remove(deviceId)
    }

    private func purgeExpiredLocked() {
        let now = Int64(Date().timeIntervalSince1970)
        for (id, item) in pending where item.expiresAt < now {
            pending.removeValue(forKey: id)
            inFlightByDevice.remove(item.deviceId)
        }
    }

    public var count: Int {
        lock.lock(); defer { lock.unlock() }
        return pending.count
    }
}
