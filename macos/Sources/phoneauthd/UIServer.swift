import Foundation
import Darwin
import SystemConfiguration
import PhoneAuthCore

/// Canal de eventos para a interface gráfica.
///
/// Existe um segundo socket porque o de controle é 0600 root:wheel e um app de
/// barra de menu roda como você, não como root. Abrir o socket de controle para
/// não-root seria a solução preguiçosa e errada: ele carrega pareamento,
/// revogação e rotação.
///
/// Este aqui **só publica**. Não existe caminho de entrada além do `ui.hello`
/// inicial; qualquer outro frame recebido derruba a conexão. Uma UI
/// comprometida não consegue aprovar nada, porque aprovar exige uma assinatura
/// do enclave do celular que nunca transita por este socket.
final class UIServer {

    private static let SOL_LOCAL_LEVEL: Int32 = 0
    private static let LOCAL_PEERCRED_OPT: Int32 = 0x001

    /// Quantos eventos ficam guardados para popular a UI que acabou de abrir.
    private static let historyLimit = 40

    private let path: String
    private let queue = DispatchQueue(label: "phoneauth.ui", attributes: .concurrent)
    private var listenFD: Int32 = -1
    private var running = false

    private let lock = NSLock()
    private var subscribers: [Int32] = []
    private var history: [UIEvent.Event] = []

    /// Preenchido pelo `main.swift`: a UI pede um retrato ao se conectar.
    var snapshotProvider: (() -> UIEvent.Snapshot)?

    init(path: String) {
        self.path = path
    }

    // MARK: - Ciclo de vida

    func start() throws {
        unlink(path)

        listenFD = socket(AF_UNIX, SOCK_STREAM, 0)
        guard listenFD >= 0 else { throw POSIXError(.EADDRNOTAVAIL) }

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let bytes = Array(path.utf8)
        guard bytes.count < MemoryLayout.size(ofValue: addr.sun_path) else {
            throw POSIXError(.ENAMETOOLONG)
        }
        withUnsafeMutableBytes(of: &addr.sun_path) { $0.copyBytes(from: bytes) }

        // 0666 no arquivo, mas o portão de verdade é a checagem de credencial no
        // accept. O modo permissivo existe porque não dá para prever o uid de
        // quem vai rodar a UI; quem decide é `isConsoleUser`, não o filesystem.
        let previousMask = umask(0)
        let bound = withUnsafePointer(to: &addr) { ptr -> Int32 in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                bind(listenFD, sa, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        umask(previousMask)

        guard bound == 0, listen(listenFD, 8) == 0 else {
            close(listenFD)
            throw POSIXError(.EADDRINUSE)
        }
        chmod(path, 0o666)

        running = true
        queue.async { [weak self] in self?.acceptLoop() }
        Log.info("socket de eventos da UI em \(path)")
    }

    func stop() {
        running = false
        lock.lock()
        subscribers.forEach { close($0) }
        subscribers.removeAll()
        lock.unlock()
        if listenFD >= 0 { close(listenFD); listenFD = -1 }
        unlink(path)
    }

    private func acceptLoop() {
        while running {
            let fd = accept(listenFD, nil, nil)
            guard fd >= 0 else {
                if errno == EINTR { continue }
                return
            }
            queue.async { [weak self] in self?.admit(fd: fd) }
        }
    }

    // MARK: - Admissão

    /// Só o usuário logado no console vê isto.
    ///
    /// Não é paranoia: o histórico contém o `reason` de cada pedido, que é a
    /// linha de comando que você digitou depois do `sudo`. Num Mac com mais de
    /// uma conta, isso não é da conta das outras.
    private func isConsoleUser(_ uid: uid_t) -> Bool {
        if uid == 0 { return true }
        var consoleUID: uid_t = 0
        let name = SCDynamicStoreCopyConsoleUser(nil, &consoleUID, nil)
        guard name != nil else { return false }
        return uid == consoleUID
    }

    private func peerUID(of fd: Int32) -> uid_t? {
        var cred = xucred()
        var length = socklen_t(MemoryLayout<xucred>.size)
        let ok = withUnsafeMutablePointer(to: &cred) { ptr -> Bool in
            getsockopt(fd, Self.SOL_LOCAL_LEVEL, Self.LOCAL_PEERCRED_OPT, ptr, &length) == 0
        }
        guard ok, cred.cr_version == XUCRED_VERSION else { return nil }
        return cred.cr_uid
    }

    private func admit(fd: Int32) {
        guard let uid = peerUID(of: fd), isConsoleUser(uid) else {
            Log.warn("conexão de UI recusada: não é o usuário do console")
            close(fd)
            return
        }

        // Manda o retrato antes de inscrever, para a UI abrir preenchida em vez
        // de esperar o próximo evento acontecer.
        if let snapshot = snapshotProvider?(), let framed = try? Wire.encode(snapshot) {
            guard writeAll(fd: fd, framed) else { close(fd); return }
        }

        lock.lock()
        subscribers.append(fd)
        let backlog = history
        lock.unlock()

        for event in backlog {
            guard let framed = try? Wire.encode(event), writeAll(fd: fd, framed) else {
                drop(fd: fd)
                return
            }
        }
        Log.info("interface gráfica conectada (uid \(uid))")
    }

    // MARK: - Publicação

    func publish(_ event: UIEvent.Event) {
        lock.lock()
        history.append(event)
        if history.count > Self.historyLimit { history.removeFirst(history.count - Self.historyLimit) }
        let targets = subscribers
        lock.unlock()

        guard let framed = try? Wire.encode(event) else { return }
        for fd in targets where !writeAll(fd: fd, framed) {
            drop(fd: fd)
        }
    }

    private func drop(fd: Int32) {
        lock.lock()
        subscribers.removeAll { $0 == fd }
        lock.unlock()
        close(fd)
    }

    /// Escrita não-bloqueante com desistência.
    ///
    /// Uma UI travada não pode segurar o daemon. Se o buffer do socket encheu, a
    /// assinatura é que aquele assinante morreu — derruba e segue. Perder evento
    /// de UI é irrelevante; travar a autenticação não é.
    private func writeAll(fd: Int32, _ data: Data) -> Bool {
        var offset = 0
        return data.withUnsafeBytes { raw -> Bool in
            guard let base = raw.baseAddress else { return false }
            while offset < data.count {
                let n = send(fd, base.advanced(by: offset), data.count - offset, 0)
                if n > 0 { offset += n; continue }
                if n < 0 && errno == EINTR { continue }
                return false
            }
            return true
        }
    }
}
