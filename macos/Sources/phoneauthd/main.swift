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
    let passphrase = try Identity.loadPassphrase(directory: Config.stateDirectory)
    identity = try Identity.load(directory: Config.stateDirectory, passphrase: passphrase)
} catch {
    Log.error("falha ao iniciar: \(error)")
    exit(1)
}

Log.info("SPKI do certificado: \(identity.spkiHash)")
Log.info("\(registry.active().count) dispositivo(s) ativo(s)")

let broker = Broker(config: config, registry: registry, channelBinding: identity.spkiHash)

let listener = PhoneListener(identity: identity.identity,
                             channelBinding: identity.spkiHash,
                             config: config)
listener.onSession = { session in broker.attach(session) }

let control = ControlServer(path: Config.socketPath)
control.onAuthRequest = { request, _ in broker.handleAuthRequest(request) }
control.onControlCommand = { body, uid in ControlCommands.handle(body, uid: uid, broker: broker, registry: registry) }

do {
    try listener.start()
    try control.start()
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
    listener.stop()
    exit(0)
}
termSource.resume()
signal(SIGTERM, SIG_IGN)
signal(SIGPIPE, SIG_IGN)   // peer que fecha no meio da escrita não derruba o daemon

Log.info("phoneauthd pronto")
dispatchMain()
