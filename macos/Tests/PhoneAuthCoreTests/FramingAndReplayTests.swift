import XCTest
@testable import PhoneAuthCore

final class FramingTests: XCTestCase {

    func testRoundTrip() throws {
        let body = Data("{\"type\":\"ping\"}".utf8)
        var decoder = Framing.Decoder()
        decoder.append(try Framing.encode(body))
        XCTAssertEqual(try decoder.next(), body)
        XCTAssertNil(try decoder.next())
    }

    /// TCP não respeita fronteiras de mensagem. Um frame partido byte a byte
    /// precisa reconstituir corretamente.
    func testFrameSplitAcrossManyReads() throws {
        let body = Data("{\"type\":\"pong\"}".utf8)
        let framed = try Framing.encode(body)

        var decoder = Framing.Decoder()
        for byte in framed.dropLast() {
            decoder.append(Data([byte]))
            XCTAssertNil(try decoder.next(), "não deve entregar frame incompleto")
        }
        decoder.append(Data([framed.last!]))
        XCTAssertEqual(try decoder.next(), body)
    }

    func testMultipleFramesInOneRead() throws {
        let a = Data("primeiro".utf8), b = Data("segundo".utf8)
        var decoder = Framing.Decoder()
        decoder.append(try Framing.encode(a) + Framing.encode(b))
        XCTAssertEqual(try decoder.next(), a)
        XCTAssertEqual(try decoder.next(), b)
        XCTAssertNil(try decoder.next())
    }

    /// Um comprimento absurdo no cabeçalho é peer com defeito ou hostil. Tem
    /// que lançar, para o chamador derrubar a conexão em vez de tentar alocar
    /// gigabytes.
    func testOversizedLengthHeaderThrows() {
        var decoder = Framing.Decoder()
        decoder.append(Data([0x7F, 0xFF, 0xFF, 0xFF]))
        XCTAssertThrowsError(try decoder.next())
    }

    func testZeroLengthFrameThrows() {
        var decoder = Framing.Decoder()
        decoder.append(Data([0, 0, 0, 0]))
        XCTAssertThrowsError(try decoder.next())
    }

    func testEncodeRejectsOversizedBody() {
        XCTAssertThrowsError(try Framing.encode(Data(count: Framing.maxFrameSize + 1)))
        XCTAssertThrowsError(try Framing.encode(Data()))
    }
}

final class PendingRequestsTests: XCTestCase {

    private let context = SignedPayload.Context(
        host: "Mac", user: "mpgxc", service: "sudo", reason: "sudo true")

    func testConsumeIsSingleUse() throws {
        let store = PendingRequests()
        let item = try store.create(context: context, channelBinding: "aa", deviceId: "dev1")

        XCTAssertNotNil(store.consume(requestId: item.requestId))
        XCTAssertNil(store.consume(requestId: item.requestId),
                     "um pedido consumido não pode ser aceito de novo — isso é a defesa de replay")
    }

    func testUnknownRequestIdIsRejected() {
        let store = PendingRequests()
        XCTAssertNil(store.consume(requestId: UUID().uuidString))
    }

    /// Um pedido em voo por dispositivo. Sem isso, um processo malicioso
    /// enche seu celular de notificações até você aprovar por reflexo.
    func testSecondInFlightRequestIsRefused() throws {
        let store = PendingRequests()
        _ = try store.create(context: context, channelBinding: "aa", deviceId: "dev1")
        XCTAssertThrowsError(try store.create(context: context, channelBinding: "aa", deviceId: "dev1"))
    }

    func testDifferentDevicesDoNotBlockEachOther() throws {
        let store = PendingRequests()
        _ = try store.create(context: context, channelBinding: "aa", deviceId: "dev1")
        XCTAssertNoThrow(try store.create(context: context, channelBinding: "aa", deviceId: "dev2"))
    }

    func testConsumingFreesTheDeviceSlot() throws {
        let store = PendingRequests()
        let first = try store.create(context: context, channelBinding: "aa", deviceId: "dev1")
        _ = store.consume(requestId: first.requestId)
        XCTAssertNoThrow(try store.create(context: context, channelBinding: "aa", deviceId: "dev1"))
    }

    /// Conexão caindo não pode deixar o dispositivo travado como "ocupado"
    /// para sempre.
    func testCancelAllFreesTheDevice() throws {
        let store = PendingRequests()
        _ = try store.create(context: context, channelBinding: "aa", deviceId: "dev1")
        store.cancelAll(deviceId: "dev1")
        XCTAssertEqual(store.count, 0)
        XCTAssertNoThrow(try store.create(context: context, channelBinding: "aa", deviceId: "dev1"))
    }

    func testExpiredRequestIsNotConsumable() throws {
        let store = PendingRequests(ttl: 0)
        let item = try store.create(context: context, channelBinding: "aa", deviceId: "dev1")
        Thread.sleep(forTimeInterval: 1.1)
        XCTAssertNil(store.consume(requestId: item.requestId),
                     "TTL vencido não é aceito nem com assinatura perfeita")
    }

    func testChallengesAreUnique() throws {
        let store = PendingRequests()
        var seen = Set<Data>()
        for index in 0 ..< 50 {
            let item = try store.create(context: context, channelBinding: "aa", deviceId: "dev\(index)")
            XCTAssertEqual(item.challenge.count, 32)
            XCTAssertTrue(seen.insert(item.challenge).inserted, "desafio repetido quebra a defesa de replay")
        }
    }
}
