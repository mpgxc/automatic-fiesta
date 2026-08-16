import Foundation
import Darwin
import CoreImage
import PhoneAuthCore

// phoneauthctl — cliente de linha de comando do phoneauthd.

let usage = """
uso: sudo phoneauthctl <comando>

TODO comando exige root. O socket de controle é 0600 root:wheel de propósito:
quem o alcança pode parear e revogar dispositivos, o que é o mesmo que decidir
quem aprova seus sudos.

  status              mostra o estado do daemon
  list                lista os dispositivos pareados
  pair                pareia um novo celular
  revoke <id>         revoga um dispositivo, mantendo o histórico
  remove <id>         apaga um dispositivo do registro

  rotate              mostra o estado da rotação da identidade TLS
  rotate begin        gera uma identidade nova e anuncia aos celulares
       --compromised  a chave antiga vazou: troca na hora, sem janela e sem
                      graça. TODOS os dispositivos terão que parear de novo.
  rotate commit       passa a usar a identidade anunciada
       --force        comita antes da janela fechar ou com dispositivos ainda
                      sem confirmar — eles ficarão trancados para fora
  rotate abort        descarta a rotação anunciada
  rotate qr           mostra o anúncio assinado como QR, para o celular que
                      ficou fora do ar a janela inteira

Uso no dia a dia: docs/uso.md
Rotação, desenho e trade-offs: docs/rotacao-de-identidade.md
"""

// MARK: - Transporte

enum Client {
    static func send(_ payload: [String: Any], timeout: TimeInterval = 200) throws -> [String: Any] {
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw Failure("não foi possível criar o socket") }
        defer { close(fd) }

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        withUnsafeMutableBytes(of: &addr.sun_path) { raw in
            raw.copyBytes(from: Array(Config.socketPath.utf8))
        }

        // O errno é capturado dentro do closure, junto ao `connect`: qualquer
        // chamada entre um e outro poderia sobrescrevê-lo.
        var falha: Int32 = 0
        let connected = withUnsafePointer(to: &addr) { ptr -> Int32 in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                let r = connect(fd, sa, socklen_t(MemoryLayout<sockaddr_un>.size))
                if r != 0 { falha = errno }
                return r
            }
        }
        guard connected == 0 else {
            // Antes, qualquer falha de connect virava "phoneauthd não está
            // rodando". A mais comum é EACCES — o socket é 0600 root:wheel, de
            // propósito, então todo comando exige sudo — e aquela mensagem
            // mandava a pessoa investigar o daemon, que estava perfeitamente no
            // ar. Distinguir os casos é a diferença entre um minuto e uma tarde.
            switch falha {
            case EACCES, EPERM:
                throw Failure("""
                    sem permissão para falar com o phoneauthd.

                    O socket de controle é 0600 root:wheel de propósito: quem o
                    alcança pode parear e revogar dispositivos. Rode com sudo.
                    """)
            case ENOENT:
                throw Failure("phoneauthd não está rodando: não existe socket em \(Config.socketPath)")
            case ECONNREFUSED:
                throw Failure("o socket existe mas ninguém escuta em \(Config.socketPath); o daemon caiu — veja /var/log/phoneauthd.log")
            default:
                throw Failure("não foi possível falar com o phoneauthd em \(Config.socketPath): \(String(cString: strerror(falha)))")
            }
        }

        var tv = timeval(tv_sec: Int(timeout), tv_usec: 0)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))

        let body = try JSONSerialization.data(withJSONObject: payload)
        let framed = try Framing.encode(body)
        _ = framed.withUnsafeBytes { write(fd, $0.baseAddress, framed.count) }

        var header = [UInt8](repeating: 0, count: 4)
        guard readExactly(fd, &header, 4) else { throw Failure("sem resposta do daemon") }
        let length = Int(header[0]) << 24 | Int(header[1]) << 16 | Int(header[2]) << 8 | Int(header[3])
        guard length > 0, length <= Framing.maxFrameSize else { throw Failure("resposta malformada") }

        var buffer = [UInt8](repeating: 0, count: length)
        guard readExactly(fd, &buffer, length) else { throw Failure("resposta truncada") }

        guard let object = try JSONSerialization.jsonObject(with: Data(buffer)) as? [String: Any] else {
            throw Failure("resposta ilegível")
        }
        return object
    }

    private static func readExactly(_ fd: Int32, _ buffer: inout [UInt8], _ count: Int) -> Bool {
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
}

struct Failure: Error, CustomStringConvertible {
    let description: String
    init(_ message: String) { self.description = message }
}

/// Config só para o caminho do socket; o resto é do daemon.
enum Config {
    static let socketPath = "/var/run/phoneauthd.sock"
}

// MARK: - QR no terminal

/// Desenha o QR com meio-bloco Unicode: cada caractere carrega duas linhas de
/// módulos, o que deixa o código com proporção aproximadamente quadrada num
/// terminal, onde as células são mais altas que largas.
enum QRRenderer {
    static func render(_ text: String) -> String? {
        guard let filter = CIFilter(name: "CIQRCodeGenerator") else { return nil }
        filter.setValue(Data(text.utf8), forKey: "inputMessage")
        filter.setValue("M", forKey: "inputCorrectionLevel")
        guard let image = filter.outputImage else { return nil }

        let extent = image.extent
        let width = Int(extent.width)
        let height = Int(extent.height)
        guard width > 0, height > 0 else { return nil }

        var pixels = [UInt8](repeating: 0, count: width * height)
        let colorSpace = CGColorSpaceCreateDeviceGray()
        guard let ctx = CGContext(data: &pixels, width: width, height: height,
                                  bitsPerComponent: 8, bytesPerRow: width,
                                  space: colorSpace,
                                  bitmapInfo: CGImageAlphaInfo.none.rawValue),
              let cg = CIContext().createCGImage(image, from: extent) else { return nil }
        ctx.draw(cg, in: CGRect(x: 0, y: 0, width: width, height: height))

        func isDark(_ x: Int, _ y: Int) -> Bool {
            guard x >= 0, x < width, y >= 0, y < height else { return false }
            return pixels[y * width + x] < 128
        }

        let quiet = 2
        var out = ""
        var y = -quiet
        while y < height + quiet {
            for x in (-quiet) ..< (width + quiet) {
                let top = isDark(x, y)
                let bottom = isDark(x, y + 1)
                // Invertido: terminais escuros precisam do módulo "claro" como
                // fundo para o leitor enxergar contraste.
                switch (top, bottom) {
                case (true, true):   out += " "
                case (true, false):  out += "\u{2584}"
                case (false, true):  out += "\u{2580}"
                case (false, false): out += "\u{2588}"
                }
            }
            out += "\n"
            y += 2
        }
        return out
    }
}

// MARK: - Comandos

func requireOK(_ response: [String: Any]) throws {
    guard response["ok"] as? Bool == true else {
        throw Failure(response["error"] as? String ?? "operação falhou")
    }
}

func commandStatus() throws {
    let response = try Client.send(["type": "ctl.status"], timeout: 5)
    try requireOK(response)
    print("daemon:               rodando")
    print("dispositivos pareados: \(response["devicesTotal"] as? Int ?? 0) (\(response["devicesActive"] as? Int ?? 0) ativos)")
    print("celulares conectados:  \(response["sessionsConnected"] as? Int ?? 0)")
    print("sudo:                  \(descreveLigacaoComSudo())")
}

/// Diz se o `sudo` desta máquina realmente passa pelo módulo.
///
/// Daemon rodando, celular pareado e conectado, e mesmo assim o `sudo` só pede
/// senha: é o modo de falhar mais desagradável do projeto, porque nada está
/// errado — o módulo simplesmente nunca é chamado, e nenhum log registra uma
/// chamada que não aconteceu. Só a inspeção dos arquivos revela.
///
/// Duas condições, e faltar qualquer uma dá no mesmo. O `sudo_local` é um
/// drop-in que chegou no macOS Sonoma; num sistema anterior — e o projeto roda
/// a partir do 13 — o `/etc/pam.d/sudo` não o inclui, e o arquivo fica lá sem
/// efeito nenhum, parecendo configuração feita.
func descreveLigacaoComSudo() -> String {
    let modulo = "/usr/local/lib/pam/pam_phoneauth.so"

    guard FileManager.default.fileExists(atPath: modulo) else {
        return "módulo não instalado em \(modulo)"
    }

    let sudo = (try? String(contentsOfFile: "/etc/pam.d/sudo", encoding: .utf8)) ?? ""
    let local = (try? String(contentsOfFile: "/etc/pam.d/sudo_local", encoding: .utf8)) ?? ""

    let incluiLocal = sudo
        .split(separator: "\n")
        .map { $0.trimmingCharacters(in: .whitespaces) }
        .contains { linha in
            !linha.hasPrefix("#")
                && linha.contains("include")
                && linha.contains("sudo_local")
        }

    let plugado = { (texto: String) in
        texto.split(separator: "\n")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .contains { !$0.hasPrefix("#") && $0.contains("pam_phoneauth") }
    }

    if plugado(sudo) { return "ligado direto em /etc/pam.d/sudo" }

    switch (incluiLocal, plugado(local)) {
    case (true, true):
        return "ligado via /etc/pam.d/sudo_local"
    case (true, false):
        return "NÃO ligado — falta a linha do módulo em /etc/pam.d/sudo_local"
    case (false, true):
        return "NÃO ligado — sudo_local existe mas /etc/pam.d/sudo não o inclui (macOS anterior ao Sonoma)"
    case (false, false):
        return "NÃO ligado — veja docs/instalacao.md, seção 3"
    }
}

func commandList() throws {
    let response = try Client.send(["type": "ctl.list"], timeout: 5)
    try requireOK(response)
    let devices = response["devices"] as? [[String: Any]] ?? []
    guard !devices.isEmpty else {
        print("nenhum dispositivo pareado. Rode: sudo phoneauthctl pair")
        return
    }
    for device in devices {
        let revoked = device["revoked"] as? Bool == true
        print("\(revoked ? "✗" : "✓") \(device["name"] as? String ?? "?")  [\(device["platform"] as? String ?? "?")]")
        print("   id:       \(device["id"] as? String ?? "?")")
        print("   pareado:  \(device["pairedAt"] as? String ?? "?")")
        if let seen = device["lastSeenAt"] as? String, !seen.isEmpty {
            print("   visto em: \(seen)")
        }
        if revoked { print("   REVOGADO") }
    }
}

func commandPair() throws {
    let begin = try Client.send(["type": "ctl.pair.begin"], timeout: 10)
    try requireOK(begin)
    guard let sid = begin["sid"] as? String, let qr = begin["qr"] as? String else {
        throw Failure("o daemon não devolveu uma sessão de pareamento")
    }

    print("\nEscaneie com o app PhoneAuth (válido por 2 minutos):\n")
    if let rendered = QRRenderer.render(qr) {
        print(rendered)
    } else {
        print("(não foi possível desenhar o QR; cole este valor no app)\n")
        print(qr)
    }

    print("Aguardando o celular...")
    let awaited = try Client.send(["type": "ctl.pair.await", "sid": sid], timeout: 130)
    try requireOK(awaited)

    let name = awaited["deviceName"] as? String ?? "?"
    let sas = awaited["sas"] as? String ?? "??????"

    print("\n\(name) quer parear.")
    print("\n    Código no Mac:  \(sas)\n")
    print("Confere com o código na tela do celular? [s/N] ", terminator: "")

    let answer = (readLine() ?? "").trimmingCharacters(in: .whitespaces).lowercased()
    let accept = (answer == "s" || answer == "sim" || answer == "y" || answer == "yes")

    let confirm = try Client.send(["type": "ctl.pair.confirm", "sid": sid, "accept": accept], timeout: 10)
    guard accept else {
        print("pareamento cancelado.")
        return
    }
    try requireOK(confirm)
    print("\nPareado. Teste com: sudo -k && sudo true")
}

func commandRevoke(_ deviceId: String, remove: Bool) throws {
    let response = try Client.send(["type": remove ? "ctl.remove" : "ctl.revoke", "deviceId": deviceId], timeout: 5)
    try requireOK(response)
    print(remove ? "dispositivo removido." : "dispositivo revogado.")
}

// MARK: - Rotação da identidade TLS

func moment(_ value: Any?) -> String {
    guard let seconds = value as? Int, seconds > 0 else { return "—" }
    let formatter = ISO8601DateFormatter()
    formatter.formatOptions = [.withInternetDateTime]
    return formatter.string(from: Date(timeIntervalSince1970: TimeInterval(seconds)))
}

func names(_ value: Any?) -> [String] {
    (value as? [[String: Any]] ?? []).map { $0["name"] as? String ?? "?" }
}

func commandRotateStatus() throws {
    let response = try Client.send(["type": "ctl.rotate.status"], timeout: 5)
    try requireOK(response)

    print("identidade viva:  \(response["currentSpki"] as? String ?? "?")")

    guard let state = response["state"] as? String, state != "nenhuma rotação em curso" else {
        print("rotação:          nenhuma em curso")
        return
    }

    print("rotação:          \(state == "pending" ? "anunciada, aguardando commit" : "comitada")")
    print("  id:             \(response["rotationId"] as? String ?? "?")")
    print("  identidade ant: \(response["previousSpki"] as? String ?? "?")")
    print("  identidade nova:\(response["nextSpki"] as? String ?? "?")")
    print("  anunciada em:   \(moment(response["announcedAt"]))")

    if state == "pending" {
        print("  commit a partir:\(moment(response["commitNotBefore"]))")
    } else {
        print("  comitada em:    \(moment(response["committedAt"]))")
        let until = response["previousBindingAcceptedUntil"] as? Int ?? 0
        if until > 0 {
            // Não é detalhe cosmético: enquanto esta linha aparece, o daemon
            // aceita assinaturas ligadas à identidade antiga. Ver §4.6.
            print("  ATENÇÃO: binding anterior ainda aceito até \(moment(until))")
        }
    }

    let acked = names(response["acked"])
    let waiting = names(response["waiting"])
    print("  confirmaram:    \(acked.isEmpty ? "nenhum" : acked.joined(separator: ", "))")
    print("  faltam:         \(waiting.isEmpty ? "nenhum" : waiting.joined(separator: ", "))")

    if !waiting.isEmpty && state == "pending" {
        print("\nComitar agora trancaria esses aparelhos para fora. Deixe-os conectar")
        print("ao Mac uma vez — o anúncio é reenviado a cada conexão.")
    }
}

func commandRotateBegin(compromised: Bool) throws {
    if compromised {
        print("\nRotação por COMPROMETIMENTO.")
        print("A identidade nova entra em vigor imediatamente. Todos os celulares")
        print("pareados param de conectar e precisarão ser pareados de novo — o")
        print("anúncio assinado não serve aqui, porque quem tem a chave vazada")
        print("assina um anúncio igual apontando para a chave dele.")
        print("\nConfirma? [s/N] ", terminator: "")
        let answer = (readLine() ?? "").trimmingCharacters(in: .whitespaces).lowercased()
        guard answer == "s" || answer == "sim" || answer == "y" || answer == "yes" else {
            print("cancelado.")
            return
        }
    }

    let response = try Client.send(["type": "ctl.rotate.begin", "compromised": compromised], timeout: 60)
    try requireOK(response)

    print("\nidentidade nova gerada: \(response["nextSpki"] as? String ?? "?")")

    guard response["compromised"] as? Bool != true else {
        print("\nTroca feita. Rode agora, em cada aparelho:")
        print("  sudo phoneauthctl pair")
        return
    }

    print("anúncio assinado pela identidade atual e sendo distribuído.")
    print("celulares conectados agora: \(response["connected"] as? Int ?? 0)")
    print("\nA identidade viva continua sendo a ANTIGA. Nada quebra até o commit.")
    print("commit liberado a partir de: \(moment(response["commitNotBefore"]))")
    print("\nDeixe cada celular conectar uma vez, acompanhe com:")
    print("  sudo phoneauthctl rotate")
    print("e então:")
    print("  sudo phoneauthctl rotate commit")
}

func commandRotateCommit(force: Bool) throws {
    let response = try Client.send(["type": "ctl.rotate.commit", "force": force], timeout: 60)
    try requireOK(response)

    print("identidade viva agora: \(response["currentSpki"] as? String ?? "?")")
    let until = response["previousBindingAcceptedUntil"] as? Int ?? 0
    if until > 0 {
        print("binding anterior ainda aceito até \(moment(until)) (docs/rotacao-de-identidade.md §4.6)")
    }
    print("\nAs sessões foram derrubadas; os celulares reconectam sozinhos.")
    print("Confirme com: sudo phoneauthctl status")
}

func commandRotateAbort() throws {
    let response = try Client.send(["type": "ctl.rotate.abort"], timeout: 10)
    try requireOK(response)
    print("rotação descartada. A identidade viva não mudou.")
}

func commandRotateQR() throws {
    let response = try Client.send(["type": "ctl.rotate.status"], timeout: 5)
    try requireOK(response)

    guard let qr = response["qr"] as? String, !qr.isEmpty else {
        throw Failure(response["qrUnavailable"] as? String ?? "não há anúncio para exibir")
    }

    print("\nEscaneie com o app PhoneAuth do aparelho que ficou fora da janela:\n")
    if let rendered = QRRenderer.render(qr) {
        print(rendered)
    } else {
        print("(não foi possível desenhar o QR; cole este valor no app)\n")
        print(qr)
    }
    // Vale dizer em voz alta: quem intercepta este QR aprende a chave pública
    // nova do Mac, que é o que o próprio handshake TLS anuncia para qualquer um.
    print("Este QR não é secreto — é uma declaração pública assinada.")
    print("O aparelho mantém deviceId, chaves e histórico; não é repareamento.")
}

// MARK: - Despacho

let arguments = Array(CommandLine.arguments.dropFirst())
guard let command = arguments.first else {
    print(usage)
    exit(1)
}

do {
    switch command {
    case "status": try commandStatus()
    case "list":   try commandList()
    case "pair":   try commandPair()
    case "revoke", "remove":
        guard arguments.count >= 2 else { throw Failure("informe o id do dispositivo (veja: sudo phoneauthctl list)") }
        try commandRevoke(arguments[1], remove: command == "remove")
    case "rotate":
        let sub = arguments.count >= 2 ? arguments[1] : "status"
        let flags = Set(arguments.dropFirst(2))
        switch sub {
        case "status": try commandRotateStatus()
        case "begin":  try commandRotateBegin(compromised: flags.contains("--compromised"))
        case "commit": try commandRotateCommit(force: flags.contains("--force"))
        case "abort":  try commandRotateAbort()
        case "qr":     try commandRotateQR()
        default:
            throw Failure("subcomando de rotate desconhecido: '\(sub)'. Use status, begin, commit, abort ou qr.")
        }
    case "-h", "--help", "help":
        print(usage)
    default:
        print(usage)
        exit(1)
    }
} catch {
    FileHandle.standardError.write(Data("erro: \(error)\n".utf8))
    exit(1)
}
