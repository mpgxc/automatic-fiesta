import Foundation
import Security
import CryptoKit
import PhoneAuthCore

/// Rotação da identidade TLS do daemon. Desenho completo em
/// `docs/rotacao-de-identidade.md`; o resumo do porquê está abaixo.
///
/// O hash de SPKI do certificado servia a duas coisas com prazos diferentes: o
/// pin que o celular fixa, e o `channelBinding` que entra em toda assinatura.
/// Trocar a chave quebrava as duas de uma vez, e uma chave que nunca pode ser
/// rotacionada é um problema de segurança por si só.
///
/// A saída é anunciar a chave nova **assinada pela chave que está saindo** —
/// a única autoridade que o daemon tem sobre um celular já pareado — e só
/// trocar de fato depois, num segundo comando explícito. Em nenhum instante
/// existem duas identidades TLS vivas.
struct RotationRecord: Codable {

    enum Phase: String, Codable {
        case pending
        case committed
    }

    var rotationId: String
    var phase: Phase
    /// A identidade que assina o anúncio, isto é, a que está saindo.
    var currentSpki: String
    var currentSpkiDer: String
    var nextSpki: String
    var announcedAt: Int64
    var commitNotBefore: Int64
    var expiresAt: Int64
    var retirePrevious: Bool
    var signature: String
    var committedAt: Int64?
    /// Até quando o daemon ainda aceita assinaturas ligadas ao binding
    /// anterior. `nil` quando não há graça (ou quando ela já terminou).
    var previousBindingAcceptedUntil: Int64?
    var acks: [String: Ack] = [:]

    struct Ack: Codable {
        var spki: String
        var at: Int64
    }

    var announcement: Message.RotateAnnounce {
        Message.RotateAnnounce(
            rotationId: rotationId,
            currentSpki: currentSpki,
            currentSpkiDer: currentSpkiDer,
            nextSpki: nextSpki,
            announcedAt: announcedAt,
            commitNotBefore: commitNotBefore,
            expiresAt: expiresAt,
            retirePrevious: retirePrevious,
            signature: signature
        )
    }
}

final class RotationManager: @unchecked Sendable {

    enum Error: Swift.Error, CustomStringConvertible {
        case alreadyPending
        case nothingPending
        case tooEarly(secondsRemaining: Int64)
        case devicesNotReady([String])
        case nextIdentityUnusable(String)
        case noAnnouncement
        case compromisedHasNoRecoveryPath

        var description: String {
            switch self {
            case .alreadyPending:
                return "já existe uma rotação anunciada. Use 'rotate commit' ou 'rotate abort'."
            case .nothingPending:
                return "não há rotação anunciada"
            case .tooEarly(let s):
                return "a janela de anúncio ainda não fechou (faltam \(s)s). Use --force para comitar assim mesmo."
            case .devicesNotReady(let names):
                return "estes dispositivos ativos ainda não confirmaram o pin novo e ficariam trancados para fora: \(names.joined(separator: ", ")). Use --force se for essa a intenção."
            case .nextIdentityUnusable(let m):
                return "a identidade nova não carrega: \(m)"
            case .noAnnouncement:
                return "não há anúncio assinado para exibir"
            case .compromisedHasNoRecoveryPath:
                return "esta rotação foi marcada como comprometida: o anúncio é assinado pela chave que vazou e não vale como caminho de recuperação. Pareie os dispositivos de novo."
            }
        }
    }

    private let directory: URL
    private let config: Config
    private let lock = NSLock()

    private var liveIdentity: Identity.Loaded
    private var record: RotationRecord?

    /// Chamado quando a identidade viva muda. O listener reabre a escuta com o
    /// certificado novo e o broker passa a usar o binding novo.
    var onIdentityChanged: ((Identity.Loaded) -> Void)?

    init(directory: URL, config: Config, identity: Identity.Loaded) {
        self.directory = directory
        self.config = config
        self.liveIdentity = identity
        self.record = Self.loadRecord(directory: directory)
    }

    // MARK: - Estado corrente

    var identity: Identity.Loaded {
        lock.lock(); defer { lock.unlock() }
        return liveIdentity
    }

    /// O binding da identidade viva — o que entra nos pedidos novos e no QR de
    /// pareamento.
    var channelBinding: String {
        lock.lock(); defer { lock.unlock() }
        return liveIdentity.spkiHash
    }

    /// Bindings que o daemon aceita numa assinatura que chega.
    ///
    /// Normalmente é só o corrente. Durante a graça pós-commit também vale o
    /// anterior — e isso **tem custo**: quem tivesse a chave TLS antiga
    /// conseguiria relaiar uma aprovação assinada sob o certificado antigo para
    /// o daemon verdadeiro. Por isso a graça é curta, desligável, e é forçada a
    /// zero numa rotação por comprometimento. Ver §4.6 do documento de desenho.
    func acceptableBindings() -> [String] {
        lock.lock(); defer { lock.unlock() }
        expireGraceIfNeededLocked()
        guard let record,
              record.phase == .committed,
              record.previousBindingAcceptedUntil != nil,
              record.currentSpki != liveIdentity.spkiHash else {
            return [liveIdentity.spkiHash]
        }
        return [liveIdentity.spkiHash, record.currentSpki]
    }

    /// O anúncio a ser reenviado a cada sessão que se autentica.
    ///
    /// Reenviar sempre — em vez de um broadcast único no `begin` — é o que faz
    /// a janela funcionar: cobre reconexão, celular que estava fora do ar e
    /// aparelho pareado no meio da janela.
    func pendingAnnouncement() -> Message.RotateAnnounce? {
        lock.lock(); defer { lock.unlock() }
        guard let record, record.phase == .pending else { return nil }
        guard Int64(Date().timeIntervalSince1970) <= record.expiresAt else { return nil }
        return record.announcement
    }

    /// O anúncio para o caminho fora de banda (QR). Continua valendo depois do
    /// commit: é justamente o aparelho que perdeu a janela inteira que precisa
    /// dele.
    func announcementForOutOfBand() throws -> Message.RotateAnnounce {
        lock.lock(); defer { lock.unlock() }
        guard let record else { throw Error.noAnnouncement }
        guard !record.retirePrevious else { throw Error.compromisedHasNoRecoveryPath }
        guard Int64(Date().timeIntervalSince1970) <= record.expiresAt else { throw Error.noAnnouncement }
        return record.announcement
    }

    // MARK: - Acks

    /// Só conta o ack que fala da rotação corrente e do pin corretos. Um ack de
    /// rotação antiga não pode contar como "este aparelho está pronto".
    func recordAck(deviceId: String, rotationId: String, spki: String) -> Bool {
        lock.lock(); defer { lock.unlock() }
        guard var updated = record,
              updated.rotationId == rotationId,
              updated.nextSpki == spki else { return false }
        updated.acks[deviceId] = RotationRecord.Ack(spki: spki, at: Int64(Date().timeIntervalSince1970))
        record = updated
        persistLocked()
        return true
    }

    func hasAcked(deviceId: String) -> Bool {
        lock.lock(); defer { lock.unlock() }
        return record?.acks[deviceId] != nil
    }

    // MARK: - Começar

    /// Gera a identidade nova, valida, assina o anúncio e passa a divulgá-lo.
    ///
    /// Com `compromised`, faz outra coisa: comita na hora, sem janela e sem
    /// graça. A hipótese que sustenta o anúncio assinado — "a chave antiga não
    /// vazou" — é exatamente a que caiu, então o anúncio não vale como caminho
    /// de recuperação e os dispositivos terão que ser pareados de novo.
    func begin(compromised: Bool) throws -> RotationRecord {
        lock.lock()
        if let existing = record, existing.phase == .pending {
            lock.unlock()
            throw Error.alreadyPending
        }
        let signingIdentity = liveIdentity
        lock.unlock()

        // Uma rotação anterior que ainda tivesse graça aberta perde a graça
        // aqui: manter duas gerações de chave privada em disco por causa de
        // duas rotações encavaladas é acumular risco por conveniência.
        Identity.discardSlot(directory: directory, .prev)
        Identity.discardSlot(directory: directory, .next)

        let next: Identity.Loaded
        do {
            next = try Identity.generate(directory: directory, slot: .next, hostName: Self.shortHostName())
        } catch {
            Identity.discardSlot(directory: directory, .next)
            throw error
        }

        guard next.spkiHash != signingIdentity.spkiHash else {
            Identity.discardSlot(directory: directory, .next)
            throw Error.nextIdentityUnusable("o openssl devolveu a mesma chave")
        }

        let now = Int64(Date().timeIntervalSince1970)
        let window = compromised ? 0 : Int64(config.rotationWindowSeconds)
        var draft = RotationRecord(
            rotationId: UUID().uuidString,
            phase: .pending,
            currentSpki: signingIdentity.spkiHash,
            currentSpkiDer: signingIdentity.spkiDER.base64EncodedString(),
            nextSpki: next.spkiHash,
            announcedAt: now,
            commitNotBefore: now + window,
            // Um anúncio que sobreviva demais é um anúncio que pode reaparecer
            // depois de a rotação ter sido abortada. Duas janelas é folga
            // suficiente para o aparelho que sumiu, e limite suficiente.
            expiresAt: now + max(window * 2, Int64(config.rotationWindowSeconds)),
            retirePrevious: compromised,
            signature: "",
            committedAt: nil,
            previousBindingAcceptedUntil: nil
        )

        let bytes = try SignedPayload.rotateBytes(
            rotationId: draft.rotationId,
            currentSpki: draft.currentSpki,
            nextSpki: draft.nextSpki,
            announcedAt: draft.announcedAt,
            commitNotBefore: draft.commitNotBefore,
            expiresAt: draft.expiresAt,
            retirePrevious: draft.retirePrevious
        )
        draft.signature = try Identity.sign(bytes, with: signingIdentity.privateKey)

        lock.lock()
        record = draft
        persistLocked()
        lock.unlock()

        Log.info("rotação \(draft.rotationId) anunciada: \(draft.currentSpki) -> \(draft.nextSpki)")
        if compromised {
            Log.warn("rotação por comprometimento: comitando imediatamente, sem janela e sem graça")
            return try commit(force: true, activeDeviceNames: [:])
        }
        return draft
    }

    // MARK: - Comitar

    /// Troca a identidade viva pela anunciada.
    ///
    /// O daemon nunca faz isto sozinho. Comitar é a única operação capaz de
    /// trancar um aparelho para fora, e é coerente com o resto do projeto que
    /// ela exija um humano — do mesmo jeito que o pareamento exige a
    /// confirmação do SAS.
    @discardableResult
    func commit(force: Bool, activeDeviceNames: [String: String]) throws -> RotationRecord {
        lock.lock()
        guard var current = record, current.phase == .pending else {
            lock.unlock()
            throw Error.nothingPending
        }
        let now = Int64(Date().timeIntervalSince1970)
        if !force && now < current.commitNotBefore {
            lock.unlock()
            throw Error.tooEarly(secondsRemaining: current.commitNotBefore - now)
        }
        if !force {
            let missing = activeDeviceNames
                .filter { current.acks[$0.key] == nil }
                .map(\.value)
                .sorted()
            if !missing.isEmpty {
                lock.unlock()
                throw Error.devicesNotReady(missing)
            }
        }
        lock.unlock()

        // Carrega antes de mexer em arquivo nenhum. Um `identity-next.p12` que
        // não importa transformaria o commit num daemon que não sobe mais.
        let next: Identity.Loaded
        do {
            next = try Identity.load(directory: directory, slot: .next,
                                     passphrase: try Identity.loadPassphrase(directory: directory, slot: .next))
        } catch {
            throw Error.nextIdentityUnusable("\(error)")
        }
        guard next.spkiHash == current.nextSpki else {
            throw Error.nextIdentityUnusable("o SPKI não confere com o que foi anunciado")
        }

        // A chave que sai só é preservada enquanto houver graça — e só há graça
        // quando a hipótese "ela não vazou" continua de pé. Guardar chave
        // privada antiga além disso é trocar um risco por outro.
        let grace = current.retirePrevious ? 0 : Int64(config.previousBindingGraceSeconds)
        if grace > 0 {
            try Identity.copySlot(directory: directory, from: .live, to: .prev)
        }

        try Identity.copySlot(directory: directory, from: .next, to: .live)
        Identity.discardSlot(directory: directory, .next)

        current.phase = .committed
        current.committedAt = now
        current.previousBindingAcceptedUntil = grace > 0 ? now + grace : nil

        lock.lock()
        liveIdentity = next
        // Um ack pode ter chegado enquanto os arquivos eram trocados. Reler o
        // registro em vez de sobrescrevê-lo com a cópia antiga é o que mantém o
        // `rotate status` honesto sobre quem já sabia do pin novo.
        if var latest = record, latest.rotationId == current.rotationId {
            latest.phase = current.phase
            latest.committedAt = current.committedAt
            latest.previousBindingAcceptedUntil = current.previousBindingAcceptedUntil
            current = latest
        }
        record = current
        persistLocked()
        lock.unlock()

        Log.info("rotação \(current.rotationId) comitada; identidade viva agora é \(next.spkiHash)")
        if grace > 0 {
            Log.warn("binding anterior (\(current.currentSpki)) aceito por mais \(grace)s — ver docs/rotacao-de-identidade.md §4.6")
        }

        onIdentityChanged?(next)
        return current
    }

    // MARK: - Abortar

    func abort() throws {
        lock.lock()
        guard let current = record, current.phase == .pending else {
            lock.unlock()
            throw Error.nothingPending
        }
        record = nil
        lock.unlock()

        Identity.discardSlot(directory: directory, .next)
        try? FileManager.default.removeItem(at: recordURL)
        Log.info("rotação \(current.rotationId) abortada; identidade viva inalterada")
    }

    // MARK: - Status

    func status(deviceNames: [String: String]) -> [String: Any] {
        lock.lock(); defer { lock.unlock() }
        expireGraceIfNeededLocked()

        var out: [String: Any] = [
            "currentSpki": liveIdentity.spkiHash,
            "hasPending": record?.phase == .pending,
        ]
        guard let record else {
            out["state"] = "nenhuma rotação em curso"
            return out
        }

        let acked = record.acks.keys.sorted().map { id in
            ["deviceId": id, "name": deviceNames[id] ?? "?"]
        }
        let waiting = deviceNames.keys.filter { record.acks[$0] == nil }.sorted().map { id in
            ["deviceId": id, "name": deviceNames[id] ?? "?"]
        }

        out["state"] = record.phase.rawValue
        out["rotationId"] = record.rotationId
        out["previousSpki"] = record.currentSpki
        out["nextSpki"] = record.nextSpki
        out["announcedAt"] = record.announcedAt
        out["commitNotBefore"] = record.commitNotBefore
        out["expiresAt"] = record.expiresAt
        out["retirePrevious"] = record.retirePrevious
        out["committedAt"] = record.committedAt ?? 0
        out["previousBindingAcceptedUntil"] = record.previousBindingAcceptedUntil ?? 0
        out["acked"] = acked
        out["waiting"] = waiting
        return out
    }

    // MARK: - Persistência

    private var recordURL: URL { directory.appendingPathComponent("rotation.json") }

    private static func loadRecord(directory: URL) -> RotationRecord? {
        let url = directory.appendingPathComponent("rotation.json")
        guard let data = try? Data(contentsOf: url) else { return nil }
        do {
            return try JSONDecoder().decode(RotationRecord.self, from: data)
        } catch {
            // Estado de rotação ilegível não pode impedir o daemon de subir: o
            // pior caso é perder o rastro de uma rotação, não perder o acesso à
            // máquina.
            Log.warn("rotation.json ilegível, ignorando: \(error)")
            return nil
        }
    }

    /// Só material público: hashes, a chave pública que sai, a assinatura do
    /// anúncio e quem confirmou. Vale a mesma frase do `devices.json`.
    private func persistLocked() {
        guard let record else { return }
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        guard let data = try? encoder.encode(record) else { return }

        let tmp = directory.appendingPathComponent(".rotation.json.\(UUID().uuidString)")
        guard FileManager.default.createFile(atPath: tmp.path, contents: data,
                                             attributes: [.posixPermissions: 0o600]) else { return }
        do {
            if FileManager.default.fileExists(atPath: recordURL.path) {
                _ = try FileManager.default.replaceItemAt(recordURL, withItemAt: tmp)
            } else {
                try FileManager.default.moveItem(at: tmp, to: recordURL)
            }
        } catch {
            try? FileManager.default.removeItem(at: tmp)
            Log.warn("não foi possível gravar rotation.json: \(error)")
        }
    }

    private func expireGraceIfNeededLocked() {
        guard var current = record,
              let until = current.previousBindingAcceptedUntil,
              Int64(Date().timeIntervalSince1970) > until else { return }

        current.previousBindingAcceptedUntil = nil
        record = current
        persistLocked()

        // A chave antiga sai de disco junto com a graça. Ela só existia para o
        // caso de precisar voltar atrás.
        Identity.discardSlot(directory: directory, .prev)
        Log.info("graça do binding anterior encerrada; identity-prev.p12 removida")
    }

    // MARK: - Utilidades

    /// Nome curto do host, saneado para caber num SAN de DNS. O nome amigável
    /// do macOS aceita espaços e acentos; um SAN não.
    static func shortHostName() -> String {
        let raw = ProcessInfo.processInfo.hostName
            .components(separatedBy: ".").first ?? "mac"
        let allowed = raw.unicodeScalars.map { scalar -> Character in
            let isSafe = CharacterSet.alphanumerics.contains(scalar) || scalar == "-"
            return isSafe ? Character(scalar) : "-"
        }
        let cleaned = String(allowed)
        return cleaned.isEmpty ? "mac" : cleaned
    }
}
