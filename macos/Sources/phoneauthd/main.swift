import Foundation
import Darwin
import PhoneAuthCore

// phoneauthd — roda como LaunchDaemon, uid 0.
//
// Só root deve conseguir subir isto: ele escuta num socket privilegiado e lê a
// chave privada TLS.
guard getuid() == 0 else {
    Log.error("phoneauthd precisa rodar como root")
    exit(1)
}

let config = Config.load()

let registry: DeviceRegistry
let identity: Identity.Loaded
do {
    try FileManager.default.createDirectory(
        at: Config.stateDirectory,
        withIntermediateDirectories: true,
        attributes: [.posixPermissions: 0o700]
    )
    registry = try DeviceRegistry(directory: Config.stateDirectory)
    // Mais de uma senha candidata porque o commit da rotação troca `.p12` e
    // `.pass` em duas operações; uma queda no meio deixaria o par desencontrado
    // e o daemon sem subir. Ver Identity.load.
    identity = try Identity.load(directory: Config.stateDirectory,
                                 passphraseCandidates: Identity.passphraseCandidates(directory: Config.stateDirectory))
} catch {
    Log.error("falha ao iniciar: \(error)")
    exit(1)
}

Log.info("SPKI do certificado: \(identity.spkiHash)")
Log.info("\(registry.active().count) dispositivo(s) ativo(s)")

let rotation = RotationManager(directory: Config.stateDirectory, config: config, identity: identity)

let broker = Broker(config: config, registry: registry, rotation: rotation)

let listener = PhoneListener(identity: identity.identity,
                             channelBinding: identity.spkiHash,
                             config: config)
listener.onSession = { session in broker.attach(session) }

// O commit da rotação é a única coisa que troca a identidade viva. Reabrir a
// escuta e derrubar as sessões andam juntos: uma sessão estabelecida sob o
// certificado antigo carrega o binding antigo, e é mais limpo forçar todo mundo
// a reconectar do que manter estado misto vivo.
rotation.onIdentityChanged = { updated in
    broker.dropAllSessions()
    do {
        try listener.swapIdentity(updated.identity, channelBinding: updated.spkiHash)
        Log.info("escuta TLS reaberta com a identidade \(updated.spkiHash)")
    } catch {
        Log.error("a identidade foi trocada em disco mas a escuta não reabriu: \(error). Reinicie o daemon.")
    }
}

// Canal de eventos para a interface gráfica. Só publica: não existe caminho
// de entrada por ele, e a UI não consegue aprovar nada.
let ui = UIServer(path: Config.uiSocketPath)
ui.snapshotProvider = {
    UIEvent.Snapshot(hostName: Host.current().localizedName ?? "Mac",
                     devicesActive: registry.active().count,
                     devicesTotal: registry.all().count,
                     connected: broker.connectedDevices(),
                     rotationPending: rotation.pendingAnnouncement() != nil,
                     recent: [])
}
broker.onEvent = { event in ui.publish(event) }

let control = ControlServer(path: Config.socketPath)
control.onAuthRequest = { request, _ in broker.handleAuthRequest(request) }
control.onControlCommand = { body, uid in
    ControlCommands.handle(body, uid: uid, broker: broker, registry: registry, rotation: rotation)
}

do {
    try listener.start()
    try control.start()
    try ui.start()
} catch {
    Log.error("falha ao abrir os listeners: \(error)")
    exit(1)
}

// launchd manda SIGTERM no shutdown; limpar o socket evita um EADDRINUSE na
// próxima subida.
let termSource = DispatchSource.makeSignalSource(signal: SIGTERM, queue: .main)
termSource.setEventHandler {
    Log.info("SIGTERM recebido; encerrando")
    control.stop()
    ui.stop()
    listener.stop()
    exit(0)
}
termSource.resume()
signal(SIGTERM, SIG_IGN)
signal(SIGPIPE, SIG_IGN)   // peer que fecha no meio da escrita não derruba o daemon

Log.info("phoneauthd pronto")
dispatchMain()
