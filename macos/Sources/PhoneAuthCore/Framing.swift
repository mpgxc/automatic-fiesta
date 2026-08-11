import Foundation

/// Enquadramento: 4 bytes de comprimento big-endian, seguidos do corpo JSON.
///
/// Usado tanto no socket Unix (PAM) quanto no TLS (celular). Deliberadamente
/// simples: rede não é o lugar de ser esperto.
public enum Framing {
    public static let maxFrameSize = 65_536

    public enum Error: Swift.Error, CustomStringConvertible {
        case frameTooLarge(Int)
        case emptyFrame

        public var description: String {
            switch self {
            case .frameTooLarge(let n): return "frame de \(n) bytes excede o limite de \(maxFrameSize)"
            case .emptyFrame:           return "frame de comprimento zero"
            }
        }
    }

    public static func encode(_ body: Data) throws -> Data {
        guard !body.isEmpty else { throw Error.emptyFrame }
        guard body.count <= maxFrameSize else { throw Error.frameTooLarge(body.count) }

        var out = Data(capacity: body.count + 4)
        let n = UInt32(body.count)
        out.append(UInt8((n >> 24) & 0xFF))
        out.append(UInt8((n >> 16) & 0xFF))
        out.append(UInt8((n >> 8)  & 0xFF))
        out.append(UInt8( n        & 0xFF))
        out.append(body)
        return out
    }

    /// Acumula bytes de um stream e entrega frames completos.
    ///
    /// Um stream TCP não respeita fronteiras de mensagem: um `read` pode trazer
    /// meio frame ou três frames. Isto normaliza isso.
    public struct Decoder {
        private var buffer = Data()

        public init() {}

        public mutating func append(_ data: Data) {
            buffer.append(data)
        }

        /// Retira o próximo frame completo, ou nil se ainda faltam bytes.
        /// Lança se o comprimento declarado for absurdo — sinal de peer com
        /// defeito ou hostil, e o chamador deve derrubar a conexão.
        public mutating func next() throws -> Data? {
            guard buffer.count >= 4 else { return nil }

            // `reduce` e não `withUnsafeBytes`: o subscript de Data é ambíguo
            // entre UnsafePointer e UnsafeRawBufferPointer, e o compilador
            // recusa. Aqui não há ponteiro nenhum, o que também apaga a classe
            // inteira de erro que ponteiro traz.
            let length = buffer.prefix(4).reduce(0) { ($0 << 8) | Int($1) }

            guard length > 0 else { throw Error.emptyFrame }
            guard length <= maxFrameSize else { throw Error.frameTooLarge(length) }
            guard buffer.count >= 4 + length else { return nil }

            let body = buffer.subdata(in: 4 ..< (4 + length))
            buffer.removeSubrange(0 ..< (4 + length))
            return body
        }

        public var pendingByteCount: Int { buffer.count }
    }
}
