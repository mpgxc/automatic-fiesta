import SwiftUI
import AVFoundation
import Network
import CryptoKit

/// Fluxo de pareamento: escaneia o QR, cria as chaves no Secure Enclave, faz o
/// handshake e mostra o código de 6 dígitos para conferência visual.
@MainActor
final class PairingModel: ObservableObject {

    enum Step: Equatable {
        case scanning
        case connecting
        case confirming(sas: String)
        case done
        case failed(String)
    }

    @Published private(set) var step: Step = .scanning

    private var connection: NWConnection?
    private var decoder = FrameDecoder()
    private var payload: QRPayload?
    var onPaired: ((PhoneAuthClient.Peer) -> Void)?

    struct QRPayload: Codable {
        let v: Int
        let host: String
        let port: UInt16
        let spki: String
        let sid: String
        let psk: String
        let name: String
    }

    private struct PairRequest: Codable {
        let type = "pair.request"
        let sid: String
        let deviceName: String
        let platform: String
        let idPublicKey: String
        let authPublicKey: String
        let proof: String
        let authSignature: String
    }

    private struct PairOk: Codable { let type: String; let deviceId: String }
    private struct TypeOnly: Codable { let type: String }

    func handleScan(_ text: String) {
        guard case .scanning = step else { return }

        // O QR carrega base64url; restaura o alfabeto padrão e o padding.
        var base64 = text.replacingOccurrences(of: "-", with: "+")
                         .replacingOccurrences(of: "_", with: "/")
        while base64.count % 4 != 0 { base64 += "=" }

        guard let data = Data(base64Encoded: base64),
              let payload = try? JSONDecoder().decode(QRPayload.self, from: data),
              payload.v == 1 else {
            step = .failed("QR code não reconhecido")
            return
        }
        self.payload = payload
        step = .connecting
        connect(to: payload)
    }

    private func connect(to payload: QRPayload) {
        let tls = NWProtocolTLS.Options()
        sec_protocol_options_set_min_tls_protocol_version(tls.securityProtocolOptions, .TLSv13)
        sec_protocol_options_set_verify_block(
            tls.securityProtocolOptions,
            { _, trustRef, complete in
                let trust = sec_trust_copy_ref(trustRef).takeRetainedValue()
                guard let chain = SecTrustCopyCertificateChain(trust) as? [SecCertificate],
                      let leaf = chain.first,
                      let hash = PhoneAuthClient.spkiHash(of: leaf) else {
                    complete(false)
                    return
                }
                // Já pinamos aqui, no primeiro contato. O QR é a raiz de
                // confiança e o único momento em que ela se estabelece.
                complete(hash == payload.spki)
            },
            DispatchQueue.global(qos: .userInitiated)
        )

        let connection = NWConnection(
            to: .hostPort(host: NWEndpoint.Host(payload.host),
                          port: NWEndpoint.Port(rawValue: payload.port) ?? 58731),
            using: NWParameters(tls: tls)
        )
        self.connection = connection

        connection.stateUpdateHandler = { [weak self] state in
            Task { @MainActor in
                guard let self else { return }
                switch state {
                case .ready:
                    self.receive()
                    self.sendPairRequest(payload)
                case .failed(let error):
                    self.step = .failed("não foi possível conectar: \(error.localizedDescription)")
                default:
                    break
                }
            }
        }
        connection.start(queue: .global(qos: .userInitiated))
    }

    private func sendPairRequest(_ payload: QRPayload) {
        do {
            guard let psk = Data(base64Encoded: payload.psk) else {
                step = .failed("segredo do QR inválido")
                return
            }

            // Chaves novas a cada pareamento. Reaproveitar chave de um
            // pareamento anterior confundiria a revogação: revogar no Mac
            // deixaria de significar "esta chave não vale mais".
            try DeviceKeys.createKeyPair()

            let idKey   = try DeviceKeys.publicKeySPKIBase64(biometric: false)
            let authKey = try DeviceKeys.publicKeySPKIBase64(biometric: true)
            let deviceName = UIDevice.current.name

            let transcript = try SignedPayload.pairBytes(
                sid: payload.sid,
                spki: payload.spki,
                idPublicKeyBase64: idKey,
                authPublicKeyBase64: authKey,
                deviceName: deviceName,
                platform: "ios"
            )

            // O HMAC prova que vimos o QR na tela do Mac.
            let proof = Data(HMAC<SHA256>.authenticationCode(
                for: transcript,
                using: SymmetricKey(data: psk)
            )).base64EncodedString()

            // A assinatura pela authKey pede a biometria agora. Isso não é
            // burocracia: é a demonstração, para o Mac, de que o portão
            // biométrico existe e funciona — a assinatura não teria como ser
            // produzida sem o dedo.
            let signature = try DeviceKeys.signWithApprovalKey(
                transcript,
                prompt: "Parear com \(payload.name)"
            )

            send(PairRequest(
                sid: payload.sid,
                deviceName: deviceName,
                platform: "ios",
                idPublicKey: idKey,
                authPublicKey: authKey,
                proof: proof,
                authSignature: signature
            ))

            // O SAS é calculado dos dois lados a partir do mesmo transcript.
            // Se os números divergirem, alguém está no meio.
            step = .confirming(sas: Self.shortAuthString(transcript: transcript, secret: psk))
        } catch {
            step = .failed(error.localizedDescription)
        }
    }

    private func send<T: Encodable>(_ message: T) {
        guard let connection, let body = try? JSONEncoder().encode(message) else { return }
        var framed = Data()
        let n = UInt32(body.count)
        framed.append(UInt8((n >> 24) & 0xFF)); framed.append(UInt8((n >> 16) & 0xFF))
        framed.append(UInt8((n >> 8) & 0xFF));  framed.append(UInt8(n & 0xFF))
        framed.append(body)
        connection.send(content: framed, completion: .idempotent)
    }

    private func receive() {
        connection?.receive(minimumIncompleteLength: 1, maximumLength: 16 * 1024) { [weak self] data, _, isComplete, _ in
            Task { @MainActor in
                guard let self else { return }
                if let data {
                    self.decoder.append(data)
                    while let frame = self.decoder.next() { self.handle(frame) }
                }
                if !isComplete { self.receive() }
            }
        }
    }

    private func handle(_ frame: Data) {
        guard let envelope = try? JSONDecoder().decode(TypeOnly.self, from: frame) else { return }

        switch envelope.type {
        case "pair.ok":
            guard let response = try? JSONDecoder().decode(PairOk.self, from: frame),
                  let payload else { return }
            onPaired?(PhoneAuthClient.Peer(
                host: payload.host, port: payload.port, spki: payload.spki,
                name: payload.name, deviceId: response.deviceId
            ))
            step = .done

        case "error":
            // Sem chaves órfãs: o pareamento falhou, então não há motivo para
            // deixar material criptográfico para trás.
            DeviceKeys.deleteAll()
            step = .failed("o Mac recusou o pareamento")

        default:
            break
        }
    }

    static func shortAuthString(transcript: Data, secret: Data) -> String {
        var info = Data("phoneauth-sas-v1".utf8)
        info.append(transcript)
        let derived = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: secret),
            info: info,
            outputByteCount: 4
        )
        let bytes = derived.withUnsafeBytes { Data($0) }
        let value = bytes.withUnsafeBytes { raw -> UInt32 in
            UInt32(raw[0]) << 24 | UInt32(raw[1]) << 16 | UInt32(raw[2]) << 8 | UInt32(raw[3])
        }
        return String(format: "%06u", value % 1_000_000)
    }
}

struct PairingView: View {
    @StateObject private var model = PairingModel()
    @EnvironmentObject var store: PeerStore
    @EnvironmentObject var client: PhoneAuthClient
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            Group {
                switch model.step {
                case .scanning:
                    QRScannerView { model.handleScan($0) }
                        .overlay(alignment: .bottom) {
                            Text("Aponte para o QR code no Mac")
                                .padding()
                                .background(.ultraThinMaterial, in: Capsule())
                                .padding(.bottom, 40)
                        }

                case .connecting:
                    ProgressView("Conectando ao Mac...")

                case .confirming(let sas):
                    VStack(spacing: 20) {
                        Spacer()
                        Text("Confira o código").font(.headline)
                        Text(sas)
                            .font(.system(size: 44, weight: .bold, design: .monospaced))
                            .tracking(6)
                        Text("Confirme no Mac que o número é este.\nSe for diferente, cancele — alguém pode estar no meio.")
                            .font(.callout)
                            .foregroundStyle(.secondary)
                            .multilineTextAlignment(.center)
                        Spacer()
                        ProgressView()
                    }
                    .padding()

                case .done:
                    VStack(spacing: 16) {
                        Image(systemName: "checkmark.circle.fill")
                            .font(.system(size: 56)).foregroundStyle(.green)
                        Text("Pareado").font(.headline)
                    }
                    .task {
                        try? await Task.sleep(for: .seconds(1))
                        dismiss()
                    }

                case .failed(let reason):
                    VStack(spacing: 16) {
                        Image(systemName: "xmark.circle.fill")
                            .font(.system(size: 56)).foregroundStyle(.red)
                        Text(reason).multilineTextAlignment(.center)
                        Button("Fechar") { dismiss() }.buttonStyle(.bordered)
                    }
                    .padding()
                }
            }
            .navigationTitle("Parear")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancelar") { dismiss() }
                }
            }
        }
        .onAppear {
            model.onPaired = { peer in
                store.peer = peer
                client.connect(to: peer)
            }
        }
    }
}

/// Leitor de QR com AVFoundation.
struct QRScannerView: UIViewControllerRepresentable {
    let onScan: (String) -> Void

    func makeUIViewController(context: Context) -> ScannerController {
        let controller = ScannerController()
        controller.onScan = onScan
        return controller
    }

    func updateUIViewController(_ controller: ScannerController, context: Context) {}

    final class ScannerController: UIViewController, AVCaptureMetadataOutputObjectsDelegate {
        var onScan: ((String) -> Void)?
        private let session = AVCaptureSession()
        private var hasScanned = false

        override func viewDidLoad() {
            super.viewDidLoad()
            guard let device = AVCaptureDevice.default(for: .video),
                  let input = try? AVCaptureDeviceInput(device: device),
                  session.canAddInput(input) else { return }
            session.addInput(input)

            let output = AVCaptureMetadataOutput()
            guard session.canAddOutput(output) else { return }
            session.addOutput(output)
            output.setMetadataObjectsDelegate(self, queue: .main)
            output.metadataObjectTypes = [.qr]

            let preview = AVCaptureVideoPreviewLayer(session: session)
            preview.frame = view.bounds
            preview.videoGravity = .resizeAspectFill
            view.layer.addSublayer(preview)

            DispatchQueue.global(qos: .userInitiated).async { [session] in
                session.startRunning()
            }
        }

        func metadataOutput(_ output: AVCaptureMetadataOutput,
                            didOutput objects: [AVMetadataObject],
                            from connection: AVCaptureConnection) {
            guard !hasScanned,
                  let object = objects.first as? AVMetadataMachineReadableCodeObject,
                  let text = object.stringValue else { return }
            hasScanned = true   // um QR só é processado uma vez
            session.stopRunning()
            onScan?(text)
        }
    }
}
