import Foundation
import Darwin
import PhoneAuthCore

/// Socket Unix que atende o módulo PAM e a CLI.
///
/// Socket POSIX cru em vez de Network.framework porque precisamos de
/// `LOCAL_PEERCRED`, e a abstração do Network.framework não expõe o fd para
/// isso.
final class ControlServer {

    /// `SOL_LOCAL` e `LOCAL_PEERCRED` não vêm expostos no módulo Darwin do
    /// Swift; os valores vêm de `<sys/un.h>` e são estáveis há décadas.
    private static let SOL_LOCAL_LEVEL: Int32 = 0
    private static let LOCAL_PEERCRED_OPT: Int32 = 0x001

    private let path: String
    private let queue = DispatchQueue(label: "phoneauth.control", attributes: .concurrent)
    private var listenFD: Int32 = -1
    private var running = false

    /// Recebe (pedido, uid do chamador) e devolve se aprovou.
    var onAuthRequest: ((Message.AuthBegin, uid_t) -> Bool)?
    /// Comandos de controle da CLI: recebe o JSON cru e devolve a resposta.
    var onControlCommand: ((Data, uid_t) -> Data?)?

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
        let pathBytes = Array(path.utf8)
        guard pathBytes.count < MemoryLayout.size(ofValue: addr.sun_path) else {
            throw POSIXError(.ENAMETOOLONG)
        }
        withUnsafeMutableBytes(of: &addr.sun_path) { raw in
            raw.copyBytes(from: pathBytes)
        }

        // umask restritiva durante o bind: o socket nasce 0600 e nunca existe
        // um instante em que outro usuário consiga se conectar.
        let previousMask = umask(0o177)
        let bound = withUnsafePointer(to: &addr) { ptr -> Int32 in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                bind(listenFD, sa, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        umask(previousMask)

        guard bound == 0 else {
            close(listenFD)
            throw POSIXError(.EADDRINUSE)
        }
        // Cinto e suspensório: o umask já deveria ter garantido isto.
        chmod(path, 0o600)

        guard listen(listenFD, 16) == 0 else {
            close(listenFD)
            throw POSIXError(.EADDRINUSE)
        }

        running = true
        queue.async { [weak self] in self?.acceptLoop() }
        Log.info("socket de controle escutando em \(path)")
    }

    func stop() {
        running = false
        if listenFD >= 0 { close(listenFD); listenFD = -1 }
        unlink(path)
    }

    private func acceptLoop() {
        while running {
            let fd = accept(listenFD, nil, nil)
            guard fd >= 0 else {
                if errno == EINTR { continue }
                if running { Log.warn("accept falhou: \(String(cString: strerror(errno)))") }
                return
            }
            queue.async { [weak self] in
                self?.handle(fd: fd)
                close(fd)
            }
        }
    }

    // MARK: - Credencial do par

    /// Sem esta checagem, qualquer processo local dispararia notificações no
    /// seu celular à vontade — e o valor de um ataque assim é justamente
    /// cansar o usuário até ele aprovar por reflexo.
    private func peerUID(of fd: Int32) -> uid_t? {
        var cred = xucred()
        var length = socklen_t(MemoryLayout<xucred>.size)
        let ok = withUnsafeMutablePointer(to: &cred) { ptr -> Bool in
            getsockopt(fd, Self.SOL_LOCAL_LEVEL, Self.LOCAL_PEERCRED_OPT, ptr, &length) == 0
        }
        guard ok, cred.cr_version == XUCRED_VERSION else { return nil }
        return cred.cr_uid
    }

    // MARK: - Atendimento

    private func handle(fd: Int32) {
        guard let uid = peerUID(of: fd) else {
            Log.warn("conexão sem credencial de par legível; recusada")
            return
        }

        // Pedidos de autenticação têm timeout curto; comandos de controle
        // incluem a espera pelo pareamento, que é longa por natureza.
        guard let body = readFrame(fd: fd, timeout: 180) else { return }

        // O tipo é lido como string crua, não pelo enum do protocolo: os
        // comandos `ctl.*` da CLI não fazem parte do protocolo com o celular e
        // não têm por que poluir aquele enum.
        struct TypeOnly: Decodable { let type: String }
        guard let envelope = try? Wire.decoder.decode(TypeOnly.self, from: body) else {
            _ = try? writeFrame(fd: fd, Wire.encode(Message.ErrorMessage(.badFrame)))
            return
        }

        if envelope.type == Message.Kind.authBegin.rawValue {
            // Só root pede autenticação. É o `sudo`, já privilegiado, durante o
            // PAM — nenhum outro chamador tem motivo legítimo.
            guard uid == 0 else {
                Log.warn("auth.begin de uid \(uid) não-root; recusado")
                _ = try? writeFrame(fd: fd, Wire.encode(Message.AuthResult(ok: false)))
                return
            }
            guard let request = try? Wire.decoder.decode(Message.AuthBegin.self, from: body) else {
                _ = try? writeFrame(fd: fd, Wire.encode(Message.AuthResult(ok: false)))
                return
            }
            let approved = onAuthRequest?(request, uid) ?? false
            _ = try? writeFrame(fd: fd, Wire.encode(Message.AuthResult(ok: approved)))
            return
        }

        guard let response = onControlCommand?(body, uid),
              let framed = try? Framing.encode(response) else { return }
        _ = try? writeFrame(fd: fd, framed)
    }

    // MARK: - E/S enquadrada

    private func readFrame(fd: Int32, timeout: TimeInterval) -> Data? {
        var tv = timeval(tv_sec: Int(timeout), tv_usec: 0)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))

        var header = [UInt8](repeating: 0, count: 4)
        guard readExactly(fd: fd, into: &header, count: 4) else { return nil }

        let length = Int(header[0]) << 24 | Int(header[1]) << 16 | Int(header[2]) << 8 | Int(header[3])
        guard length > 0, length <= Framing.maxFrameSize else { return nil }

        var body = [UInt8](repeating: 0, count: length)
        guard readExactly(fd: fd, into: &body, count: length) else { return nil }
        return Data(body)
    }

    private func readExactly(fd: Int32, into buffer: inout [UInt8], count: Int) -> Bool {
        var offset = 0
        while offset < count {
            let n = buffer.withUnsafeMutableBytes { raw -> Int in
                guard let base = raw.baseAddress else { return -1 }
                return read(fd, base.advanced(by: offset), count - offset)
            }
            if n > 0 { offset += n; continue }
            if n < 0 && errno == EINTR { continue }
            return false
        }
        return true
    }

    private func writeFrame(fd: Int32, _ framed: Data) throws {
        var offset = 0
        try framed.withUnsafeBytes { raw in
            guard let base = raw.baseAddress else { throw POSIXError(.EINVAL) }
            while offset < framed.count {
                let n = write(fd, base.advanced(by: offset), framed.count - offset)
                if n > 0 { offset += n; continue }
                if n < 0 && errno == EINTR { continue }
                throw POSIXError(.EIO)
            }
        }
    }
}
