import Foundation
import Darwin
import PhoneAuthCore

/// Comandos vindos do `phoneauthctl` pelo socket Unix.
///
/// Não fazem parte do protocolo com o celular e por isso ficam fora de
/// `Message.Kind`.
enum ControlCommands {

    struct Request: Decodable {
        let type: String
        let sid: String?
        let deviceId: String?
        let accept: Bool?
    }

    static func handle(_ body: Data, uid: uid_t, broker: Broker, registry: DeviceRegistry) -> Data? {
        guard let request = try? JSONDecoder().decode(Request.self, from: body) else {
            return json(["ok": false, "error": "comando inválido"])
        }

        // Parear e revogar mudam quem pode destravar sua máquina. Só root.
        //
        // A CLI pede sudo para essas operações, o que soa circular — mas o
        // pareamento acontece uma vez, quando o PhoneAuth ainda não está no
        // caminho, e revogar precisa funcionar exatamente quando o celular
        // sumiu. Nenhum dos dois pode depender do celular.
        let privileged = ["ctl.pair.begin", "ctl.pair.await", "ctl.pair.confirm", "ctl.revoke", "ctl.remove"]
        if privileged.contains(request.type) && uid != 0 {
            return json(["ok": false, "error": "esta operação exige root (use sudo)"])
        }

        switch request.type {
        case "ctl.status":
            return json([
                "ok": true,
                "devicesTotal": registry.all().count,
                "devicesActive": registry.active().count,
                "sessionsConnected": broker.connectedDeviceCount,
            ])

        case "ctl.list":
            let devices = registry.all().map { device -> [String: Any] in
                [
                    "id": device.id,
                    "name": device.name,
                    "platform": device.platform,
                    "pairedAt": ISO8601DateFormatter().string(from: device.pairedAt),
                    "lastSeenAt": device.lastSeenAt.map { ISO8601DateFormatter().string(from: $0) } ?? "",
                    "revoked": !device.isActive,
                ]
            }
            return json(["ok": true, "devices": devices])

        case "ctl.pair.begin":
            let (sid, qr) = broker.beginPairing()
            return json(["ok": true, "sid": sid, "qr": qr])

        case "ctl.pair.await":
            guard let sid = request.sid else { return json(["ok": false, "error": "sid ausente"]) }
            guard let pairing = broker.awaitPairing(sid: sid),
                  let pairRequest = pairing.request,
                  let sas = pairing.sas else {
                return json(["ok": false, "error": "nenhum dispositivo pareou dentro do prazo"])
            }
            return json([
                "ok": true,
                "sas": sas,
                "deviceName": pairRequest.deviceName,
                "platform": pairRequest.platform,
            ])

        case "ctl.pair.confirm":
            guard let sid = request.sid else { return json(["ok": false, "error": "sid ausente"]) }
            do {
                guard let deviceId = try broker.confirmPairing(sid: sid, accept: request.accept ?? false) else {
                    return json(["ok": false, "error": "pareamento cancelado"])
                }
                return json(["ok": true, "deviceId": deviceId])
            } catch {
                return json(["ok": false, "error": "\(error)"])
            }

        case "ctl.revoke":
            guard let deviceId = request.deviceId else { return json(["ok": false, "error": "deviceId ausente"]) }
            do {
                let changed = try registry.revoke(id: deviceId)
                return json(["ok": changed, "error": changed ? "" : "dispositivo não encontrado ou já revogado"])
            } catch {
                return json(["ok": false, "error": "\(error)"])
            }

        case "ctl.remove":
            guard let deviceId = request.deviceId else { return json(["ok": false, "error": "deviceId ausente"]) }
            do {
                let removed = try registry.remove(id: deviceId)
                return json(["ok": removed, "error": removed ? "" : "dispositivo não encontrado"])
            } catch {
                return json(["ok": false, "error": "\(error)"])
            }

        default:
            return json(["ok": false, "error": "comando desconhecido"])
        }
    }

    private static func json(_ object: [String: Any]) -> Data {
        (try? JSONSerialization.data(withJSONObject: object)) ?? Data("{\"ok\":false}".utf8)
    }
}
