import Foundation
import Darwin
import Observation
import PhoneAuthCore

/// Ligação com o `phoneauthd` pelo socket de eventos.
///
/// É só leitura. O cliente não tem método para aprovar nada, e isso é
/// arquitetura, não omissão: a única aprovação que existe é a assinatura que o
/// enclave do celular produz.
@Observable
@MainActor
final class DaemonClient {

    enum Status: Equatable {
        /// Daemon fora do ar. Neste estado o `sudo` pede senha normalmente —
        /// o módulo PAM é `sufficient` e simplesmente cai para o próximo.
        case daemonDown
        /// Daemon de pé, nenhum celular pareado ainda.
        case noDevices
        /// Pareado, mas nenhum celular alcançável agora.
        case disconnected
        /// Pronto: há celular conectado e autenticado.
        case ready
        /// Há um pedido esperando o dedo do usuário.
        case awaiting
    }

    private(set) var status: Status = .daemonDown
    private(set) var hostName = Host.current().localizedName ?? "Mac"
    private(set) var connected: [UIEvent.ConnectedDevice] = []
    private(set) var devicesActive = 0
    private(set) var devicesTotal = 0
    private(set) var rotationPending = false
    private(set) var events: [UIEvent.Event] = []
    /// O pedido em voo, para a UI mostrar o que o celular está exibindo.
    private(set) var inFlight: UIEvent.Event?

    var onEvent: ((UIEvent.Event) -> Void)?

    private let socketPath = "/var/run/phoneauthd-ui.sock"
    private var readerThread: Thread?
    private var fd: Int32 = -1
    private var shouldRun = true
    /// Cresce a cada falha, some ao conectar. Sem isto, um daemon parado viraria
    /// um laço de `connect` a 100% de CPU.
    private var backoff: TimeInterval = 1

    private static let maxEvents = 60

    init() {
        start()
    }

    func start() {
        shouldRun = true
        guard readerThread == nil else { return }
        let thread = Thread { [weak self] in self?.loop() }
        thread.name = "phoneauth.ui.reader"
        thread.start()
        readerThread = thread
    }

    func stop() {
        shouldRun = false
        if fd >= 0 { close(fd); fd = -1 }
    }

    // MARK: - Laço de leitura (fora da main thread)

    private nonisolated func loop() {
        while true {
            let alive = MainActor.assumeIsolated { self.shouldRun }
            guard alive else { return }

            guard let socket = connectToDaemon() else {
                let wait = MainActor.assumeIsolated { () -> TimeInterval in
                    self.status = .daemonDown
                    self.connected = []
                    self.backoff = min(self.backoff * 2, 30)
                    return self.backoff
                }
                Thread.sleep(forTimeInterval: wait)
                continue
            }

            MainActor.assumeIsolated {
                self.fd = socket
                self.backoff = 1
            }
            read(from: socket)
            close(socket)
            MainActor.assumeIsolated {
                self.fd = -1
                self.status = .daemonDown
                self.connected = []
            }
        }
    }

    private nonisolated func connectToDaemon() -> Int32? {
        let sock = socket(AF_UNIX, SOCK_STREAM, 0)
        guard sock >= 0 else { return nil }

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        withUnsafeMutableBytes(of: &addr.sun_path) { $0.copyBytes(from: Array(socketPath.utf8)) }

        let ok = withUnsafePointer(to: &addr) { ptr -> Bool in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                connect(sock, sa, socklen_t(MemoryLayout<sockaddr_un>.size)) == 0
            }
        }
        guard ok else { close(sock); return nil }
        return sock
    }

    private nonisolated func read(from sock: Int32) {
        var decoder = Framing.Decoder()
        var buffer = [UInt8](repeating: 0, count: 16 * 1024)

        while true {
            let n = buffer.withUnsafeMutableBytes { raw -> Int in
                guard let base = raw.baseAddress else { return -1 }
                return recv(sock, base, raw.count, 0)
            }
            guard n > 0 else { return }

            decoder.append(Data(buffer[0 ..< n]))
            while let frame = try? decoder.next(), let frame {
                dispatch(frame)
            }
        }
    }

    /// O tipo vem como string crua porque o socket carrega dois formatos
    /// diferentes — o retrato inicial e os eventos.
    private nonisolated func dispatch(_ frame: Data) {
        struct TypeOnly: Decodable { let type: String }
        guard let envelope = try? JSONDecoder().decode(TypeOnly.self, from: frame) else { return }

        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601

        switch envelope.type {
        case "ui.snapshot":
            guard let snap = try? decoder.decode(UIEvent.Snapshot.self, from: frame) else { return }
            MainActor.assumeIsolated { self.apply(snap) }

        case "ui.event":
            guard let event = try? decoder.decode(UIEvent.Event.self, from: frame) else { return }
            MainActor.assumeIsolated { self.apply(event) }

        default:
            break
        }
    }

    // MARK: - Estado

    private func apply(_ snap: UIEvent.Snapshot) {
        hostName = snap.hostName
        connected = snap.connected
        devicesActive = snap.devicesActive
        devicesTotal = snap.devicesTotal
        rotationPending = snap.rotationPending
        events = snap.recent.suffix(Self.maxEvents)
        recomputeStatus()
    }

    private func apply(_ event: UIEvent.Event) {
        events.append(event)
        if events.count > Self.maxEvents { events.removeFirst(events.count - Self.maxEvents) }

        switch event.kind {
        case .requestSent:
            inFlight = event
        case .requestApproved, .requestDenied, .requestExpired,
             .requestRejected, .requestNoDevice:
            inFlight = nil
        case .deviceConnected:
            if let name = event.deviceName,
               !connected.contains(where: { $0.name == name }) {
                connected.append(UIEvent.ConnectedDevice(
                    id: event.id, name: name, platform: "", since: event.at))
            }
        case .deviceDisconnected:
            connected.removeAll { $0.name == event.deviceName }
            inFlight = nil
        case .devicePaired:
            devicesActive += 1
            devicesTotal += 1
        case .deviceRevoked:
            devicesActive = max(0, devicesActive - 1)
        case .rotationAnnounced:
            rotationPending = true
        case .rotationCommitted:
            rotationPending = false
        }

        recomputeStatus()
        onEvent?(event)
    }

    private func recomputeStatus() {
        if fd < 0 { status = .daemonDown }
        else if inFlight != nil { status = .awaiting }
        else if !connected.isEmpty { status = .ready }
        else if devicesActive == 0 { status = .noDevices }
        else { status = .disconnected }
    }
}
