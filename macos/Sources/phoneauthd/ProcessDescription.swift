import Foundation
import Darwin

/// Descobre a linha de comando de um processo pelo pid.
///
/// O módulo PAM manda só o pid e deixa a resolução aqui, de propósito: ler
/// memória de outro processo é código que não queremos rodando dentro do
/// contexto setuid do `sudo`.
///
/// Isto funciona porque, durante a autenticação, o `sudo` ainda não fez exec do
/// comando alvo — seu argv ainda contém a linha inteira que você digitou. É
/// exatamente o que precisa aparecer no celular.
enum ProcessDescription {

    struct Info {
        let executablePath: String
        let arguments: [String]

        /// Uma linha legível para o usuário decidir se aprova.
        var summary: String {
            let joined = arguments.dropFirst().joined(separator: " ")
            let name = (executablePath as NSString).lastPathComponent
            let text = joined.isEmpty ? name : "\(name) \(joined)"
            return text.count > 200 ? String(text.prefix(197)) + "..." : text
        }
    }

    static func lookup(pid: Int32) -> Info? {
        var argmax: Int32 = 0
        var size = MemoryLayout<Int32>.size
        var mibMax: [Int32] = [CTL_KERN, KERN_ARGMAX]
        guard sysctl(&mibMax, 2, &argmax, &size, nil, 0) == 0, argmax > 0 else { return nil }

        var buffer = [UInt8](repeating: 0, count: Int(argmax))
        var bufferSize = Int(argmax)
        var mib: [Int32] = [CTL_KERN, KERN_PROCARGS2, pid]

        let ok = buffer.withUnsafeMutableBytes { raw -> Bool in
            guard let base = raw.baseAddress else { return false }
            return sysctl(&mib, 3, base, &bufferSize, nil, 0) == 0
        }
        guard ok, bufferSize > MemoryLayout<Int32>.size else { return nil }

        return parse(buffer: Array(buffer.prefix(bufferSize)))
    }

    /// Layout do KERN_PROCARGS2:
    ///   [0..3]   argc, Int32 na ordem do host
    ///   depois   caminho do executável, terminado em NUL
    ///   depois   padding de NULs de alinhamento
    ///   depois   argc strings terminadas em NUL — o argv
    ///   depois   o ambiente, que ignoramos: pode conter segredos e não tem
    ///            nada a ver com a decisão do usuário
    static func parse(buffer: [UInt8]) -> Info? {
        let intSize = MemoryLayout<Int32>.size
        guard buffer.count > intSize else { return nil }

        let argc = buffer.withUnsafeBytes { $0.loadUnaligned(as: Int32.self) }
        guard argc >= 0, argc < 4096 else { return nil }

        var cursor = intSize

        func readCString() -> String? {
            guard cursor < buffer.count else { return nil }
            let start = cursor
            while cursor < buffer.count && buffer[cursor] != 0 { cursor += 1 }
            guard cursor <= buffer.count else { return nil }
            let bytes = Array(buffer[start ..< cursor])
            cursor += 1   // consome o NUL
            return String(decoding: bytes, as: UTF8.self)
        }

        guard let execPath = readCString(), !execPath.isEmpty else { return nil }

        // Pula o padding de NULs entre o caminho e o argv.
        while cursor < buffer.count && buffer[cursor] == 0 { cursor += 1 }

        var args: [String] = []
        for _ in 0 ..< Int(argc) {
            guard let arg = readCString() else { break }
            args.append(arg)
        }

        return Info(executablePath: execPath, arguments: args)
    }
}
