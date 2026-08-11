#!/usr/bin/env python3
"""Executa o protocolo do PhoneAuth ponta a ponta, sem macOS.

O daemon real é Swift e o app real é Swift/Kotlin — nada disso roda fora de um
Mac com Xcode. Este harness reimplementa **o protocolo**, não o código: TLS 1.3
com pinning de SPKI, enquadramento de 4 bytes, os payloads de `SignedPayload` e
assinaturas ECDSA P-256 de verdade.

Serve para duas coisas:

  1. Demonstrar o fluxo completo sem hardware nenhum.
  2. Provar que o protocolo em docs/protocolo.md fecha — que os bytes assinados
     de um lado verificam do outro, e que os cenários de ataque são recusados.

O que ele NÃO prova: que o Swift e o Kotlin implementam isto corretamente. Para
isso servem docs/test-vectors.json e docs/check-payload-parity.py.

    python3 docs/protocol-harness.py
"""
import base64
import datetime
import hashlib
import hmac
import json
import queue
import secrets
import socket
import ssl
import struct
import tempfile
import threading
import time
import os

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

# ── Aparência ──────────────────────────────────────────────────────────────
DIM, RESET, BOLD = "\033[2m", "\033[0m", "\033[1m"
GREEN, RED, BLUE, ORANGE = "\033[32m", "\033[31m", "\033[34m", "\033[33m"

T0 = time.time()


def log(who, msg, color=""):
    stamp = f"{time.time() - T0:6.3f}s"
    print(f"{DIM}{stamp}{RESET} {color}{who:<12}{RESET} {msg}")


def rule(title=""):
    print(f"\n{DIM}{'─' * 78}{RESET}")
    if title:
        print(f"{BOLD}{title}{RESET}\n")


# ── SignedPayload (gêmeo Python; ver docs/protocolo.md §5.2) ───────────────
LINE_BREAKING = {0x0A, 0x0B, 0x0C, 0x0D, 0x85, 0x2028, 0x2029}


def serialize(domain, fields):
    for f in fields:
        if any(ord(c) in LINE_BREAKING for c in f):
            raise ValueError("campo contém quebra de linha")
    return ("\n".join([domain] + fields) + "\n").encode("utf-8")


def ctx_bytes(c):
    return serialize("PHONEAUTH-CTX-V1",
                     [c["host"], c["user"], c["service"], c["reason"],
                      c.get("processPath", ""), c.get("tty", "")])


def ctx_hash(c):
    return hashlib.sha256(ctx_bytes(c)).hexdigest()


def auth_bytes(rid, chal_b64, chash, binding, issued, decision):
    return serialize("PHONEAUTH-AUTH-V1",
                     [rid, chal_b64, chash, binding, str(issued), decision])


def pair_bytes(sid, spki, idpk, apk, name, platform):
    return serialize("PHONEAUTH-PAIR-V1", [sid, spki, idpk, apk, name, platform])


def hello_bytes(device_id, nonce_b64, binding):
    return serialize("PHONEAUTH-HELLO-V1", [device_id, nonce_b64, binding])


def hkdf_sha256(ikm, info, length, salt=b""):
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    t, okm, i = b"", b"", 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
        i += 1
    return okm[:length]


def sas(transcript, secret):
    okm = hkdf_sha256(secret, b"phoneauth-sas-v1" + transcript, 4)
    return "%06d" % (int.from_bytes(okm, "big") % 1_000_000)


# ── Enquadramento: 4 bytes big-endian + JSON UTF-8 (§6) ────────────────────
MAX_FRAME = 65_536


def send_frame(sock, obj):
    body = json.dumps(obj).encode("utf-8")
    sock.sendall(struct.pack(">I", len(body)) + body)


def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def recv_frame(sock):
    head = recv_exact(sock, 4)
    if not head:
        return None
    (length,) = struct.unpack(">I", head)
    if not (0 < length <= MAX_FRAME):
        raise ValueError(f"comprimento inválido: {length}")
    body = recv_exact(sock, length)
    return json.loads(body) if body else None


# ── Cripto ─────────────────────────────────────────────────────────────────
def spki_b64(pub):
    return base64.b64encode(pub.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo)).decode()


def sign(key, msg):
    return base64.b64encode(key.sign(msg, ec.ECDSA(hashes.SHA256()))).decode()


def verify(pub_b64, sig_b64, msg):
    pub = serialization.load_der_public_key(base64.b64decode(pub_b64))
    try:
        pub.verify(base64.b64decode(sig_b64), msg, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False


def make_identity(tmpdir):
    """Identidade TLS do daemon: P-256 auto-assinado, como o install.sh gera."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "phoneauthd")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=3650))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), False)
            .sign(key, hashes.SHA256()))

    cert_path = os.path.join(tmpdir, "cert.pem")
    key_path = os.path.join(tmpdir, "key.pem")
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(key_path, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM,
                                  serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()))

    spki_hash = hashlib.sha256(cert.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()
    return cert_path, key_path, spki_hash


# ══════════════════════════════════════════════════════════════════════════
# DAEMON
# ══════════════════════════════════════════════════════════════════════════
class Daemon:
    """Reimplementa phoneauthd: registro, pendências de uso único, verificação."""

    REQUEST_TTL = 60
    RESPONSE_TIMEOUT = 10

    def __init__(self, cert, key, spki):
        self.cert, self.key, self.spki = cert, key, spki
        self.devices = {}                 # deviceId -> {idPublicKey, authPublicKey, name, revoked}
        self.pairings = {}                # sid -> {secret, request, sas, event}
        self.pending = {}                 # requestId -> pendência
        self.in_flight = set()            # deviceId com pedido em voo
        self.sessions = {}                # deviceId -> {sock, replies}
        self.lock = threading.Lock()
        self.host = "MacBook Pro de mpgxc"

    # ── Escuta TLS ────────────────────────────────────────────────────────
    def serve(self):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.load_cert_chain(self.cert, self.key)

        self.srv = socket.socket()
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(4)
        self.port = self.srv.getsockname()[1]
        log("phoneauthd", f"escutando TLS 1.3 em 127.0.0.1:{self.port}", BLUE)
        log("phoneauthd", f"SPKI do certificado {DIM}{self.spki[:32]}…{RESET}", BLUE)

        while True:
            try:
                raw, _ = self.srv.accept()
            except OSError:
                return
            threading.Thread(target=self._session, args=(ctx, raw), daemon=True).start()

    def _session(self, ctx, raw):
        try:
            sock = ctx.wrap_socket(raw, server_side=True)
        except Exception:
            return

        device_id = None
        nonce = base64.b64encode(secrets.token_bytes(32)).decode()
        send_frame(sock, {"type": "hello.challenge", "nonce": nonce})

        try:
            while True:
                msg = recv_frame(sock)
                if msg is None:
                    break
                t = msg.get("type")

                if t == "pair.request":
                    self._handle_pair(sock, msg)

                elif t == "hello.response":
                    dev = self.devices.get(msg["deviceId"])
                    if not dev or dev["revoked"]:
                        log("phoneauthd", "hello de dispositivo desconhecido; encerrando", RED)
                        break
                    ok = verify(dev["idPublicKey"], msg["signature"],
                                hello_bytes(msg["deviceId"], nonce, self.spki))
                    if not ok:
                        log("phoneauthd", "hello com assinatura inválida; encerrando", RED)
                        break
                    device_id = msg["deviceId"]
                    with self.lock:
                        self.sessions[device_id] = {"sock": sock, "replies": {}}
                    log("phoneauthd", f"dispositivo {GREEN}{dev['name']}{RESET} autenticado "
                                      f"{DIM}(idKey, sem biometria){RESET}", BLUE)

                elif t == "auth.response":
                    with self.lock:
                        s = self.sessions.get(device_id)
                        q = s["replies"].pop(msg["requestId"], None) if s else None
                    if q:
                        q.put(msg)

                elif t == "ping":
                    send_frame(sock, {"type": "pong"})
        except Exception:
            pass
        finally:
            if device_id:
                with self.lock:
                    self.sessions.pop(device_id, None)
                    self.in_flight.discard(device_id)
            sock.close()

    # ── Pareamento (§3) ───────────────────────────────────────────────────
    def begin_pairing(self):
        sid = "7B3E1A2C-0000-4000-8000-" + secrets.token_hex(6).upper()
        secret = secrets.token_bytes(32)
        with self.lock:
            self.pairings[sid] = {"secret": secret, "request": None,
                                  "sas": None, "event": threading.Event()}
        qr = {"v": 1, "host": "127.0.0.1", "port": self.port, "spki": self.spki,
              "sid": sid, "psk": base64.b64encode(secret).decode(), "name": self.host}
        return sid, base64.urlsafe_b64encode(json.dumps(qr).encode()).decode().rstrip("=")

    def _handle_pair(self, sock, msg):
        p = self.pairings.get(msg["sid"])
        if not p:
            send_frame(sock, {"type": "error", "code": "pairing_expired", "message": ""})
            return

        transcript = pair_bytes(msg["sid"], self.spki, msg["idPublicKey"],
                                msg["authPublicKey"], msg["deviceName"], msg["platform"])

        # O HMAC prova que quem pareia viu o QR na tela do Mac.
        proof_ok = hmac.compare_digest(
            base64.b64decode(msg["proof"]),
            hmac.new(p["secret"], transcript, hashlib.sha256).digest())
        if not proof_ok:
            log("phoneauthd", "prova de pareamento inválida", RED)
            send_frame(sock, {"type": "error", "code": "pairing_invalid", "message": ""})
            return

        # A assinatura pela authKey prova posse da chave privada E, porque ela é
        # travada por biometria, que o portão biométrico funciona.
        if not verify(msg["authPublicKey"], msg["authSignature"], transcript):
            log("phoneauthd", "assinatura de pareamento rejeitada", RED)
            send_frame(sock, {"type": "error", "code": "pairing_invalid", "message": ""})
            return

        p["request"], p["sas"] = msg, sas(transcript, p["secret"])
        p["sock"] = sock
        p["event"].set()

    def confirm_pairing(self, sid, accept):
        p = self.pairings.pop(sid, None)
        if not p or not accept:
            return None
        req = p["request"]
        device_id = "9C1D2E3F-0000-4000-8000-" + secrets.token_hex(6).upper()
        with self.lock:
            self.devices[device_id] = {
                "idPublicKey": req["idPublicKey"], "authPublicKey": req["authPublicKey"],
                "name": req["deviceName"], "revoked": False}
        send_frame(p["sock"], {"type": "pair.ok", "deviceId": device_id})
        return device_id

    # ── Autenticação (§5) — chamada de forma síncrona pelo PAM ────────────
    def handle_auth_begin(self, req):
        with self.lock:
            session = next(((d, s) for d, s in self.sessions.items()), None)
        if not session:
            log("phoneauthd", "nenhum dispositivo conectado; recusado na hora", ORANGE)
            return False
        device_id, sess = session

        # Um pedido em voo por dispositivo: impede a enxurrada de notificações
        # que treinaria o usuário a aprovar no reflexo.
        with self.lock:
            if device_id in self.in_flight:
                log("phoneauthd", "já há pedido em voo para este dispositivo; recusado", ORANGE)
                return False
            self.in_flight.add(device_id)

        try:
            context = {"host": self.host, "user": req["user"], "service": req["service"],
                       "reason": req["reason"], "processPath": "/usr/bin/sudo",
                       "tty": req["tty"]}
            request_id = "3F2504E0-4F89-41D3-9A0C-" + secrets.token_hex(6).upper()
            challenge = secrets.token_bytes(32)
            issued = int(time.time())
            ttl = req.get("ttl", self.REQUEST_TTL)

            item = {"challenge": challenge, "contextHash": ctx_hash(context),
                    "issuedAt": issued, "expiresAt": issued + ttl,
                    "deviceId": device_id}
            with self.lock:
                self.pending[request_id] = item

            q = queue.Queue()
            with self.lock:
                sess["replies"][request_id] = q

            log("phoneauthd", f"pedido {DIM}{request_id[-12:]}{RESET} → celular: "
                              f"{BOLD}{context['reason']}{RESET}", BLUE)
            send_frame(sess["sock"], {
                "type": "auth.challenge", "requestId": request_id,
                "challenge": base64.b64encode(challenge).decode(),
                "issuedAt": issued, "expiresAt": issued + ttl,
                "channelBinding": self.spki, "context": context})

            try:
                resp = q.get(timeout=self.RESPONSE_TIMEOUT)
            except queue.Empty:
                log("phoneauthd", "timeout sem resposta do celular", ORANGE)
                with self.lock:
                    self.pending.pop(request_id, None)
                return False

            return self._verify_response(resp, device_id)
        finally:
            with self.lock:
                self.in_flight.discard(device_id)

    def _verify_response(self, resp, device_id):
        # Consome ANTES de verificar, sob o mesmo lock que localiza: duas
        # respostas simultâneas só encontram o pedido uma vez.
        with self.lock:
            item = self.pending.pop(resp["requestId"], None)

        if item is None:
            log("phoneauthd", "pedido desconhecido ou já consumido — REPLAY recusado", RED)
            return False
        if item["deviceId"] != device_id:
            log("phoneauthd", "resposta de dispositivo diferente do que recebeu o pedido", RED)
            return False
        if resp["decision"] != "allow":
            log("phoneauthd", "negado no celular", ORANGE)
            return False
        if int(time.time()) > item["expiresAt"]:
            log("phoneauthd", "pedido expirado — recusado mesmo com assinatura válida", RED)
            return False

        dev = self.devices[device_id]
        if dev["revoked"]:
            log("phoneauthd", "dispositivo revogado", RED)
            return False

        msg = auth_bytes(resp["requestId"], base64.b64encode(item["challenge"]).decode(),
                         item["contextHash"], self.spki, item["issuedAt"], "allow")
        if not verify(dev["authPublicKey"], resp["signature"], msg):
            log("phoneauthd", "assinatura REJEITADA", RED)
            return False

        log("phoneauthd", f"{GREEN}assinatura verificada{RESET} → PAM_SUCCESS", BLUE)
        return True


# ══════════════════════════════════════════════════════════════════════════
# CELULAR
# ══════════════════════════════════════════════════════════════════════════
class Phone:
    """Reimplementa o app. As duas chaves são geradas aqui em software; no
    aparelho real elas nascem dentro do Secure Enclave / StrongBox e a authKey
    exige biometria a cada assinatura."""

    def __init__(self, name="iPhone 15 de mpgxc", platform="ios"):
        self.name, self.platform = name, platform
        self.id_key = ec.generate_private_key(ec.SECP256R1())
        self.auth_key = ec.generate_private_key(ec.SECP256R1())
        self.device_id = None
        self.sas_code = None
        self.peer_spki = None
        self.auto_decision = "allow"
        self.replay_last = None

    def _connect(self, host, port, pinned_spki):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE     # sem CA: a validação é o pinning abaixo
        sock = ctx.wrap_socket(socket.create_connection((host, port)))

        der = sock.getpeercert(binary_form=True)
        actual = hashlib.sha256(x509.load_der_x509_certificate(der).public_key()
                                .public_bytes(serialization.Encoding.DER,
                                              serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()
        if actual != pinned_spki:
            sock.close()
            raise ssl.SSLError("SPKI não confere com o pin do pareamento")
        return sock

    def pair(self, qr_b64):
        qr = json.loads(base64.urlsafe_b64decode(qr_b64 + "=" * (-len(qr_b64) % 4)))
        log("celular", f"QR lido {DIM}v={qr['v']} host={qr['host']}:{qr['port']}{RESET}", GREEN)

        sock = self._connect(qr["host"], qr["port"], qr["spki"])
        log("celular", f"{GREEN}TLS estabelecido, SPKI confere com o pin{RESET}", GREEN)
        self.peer_spki = qr["spki"]

        recv_frame(sock)   # hello.challenge, ignorado: ainda não há deviceId

        idpk, apk = spki_b64(self.id_key.public_key()), spki_b64(self.auth_key.public_key())
        transcript = pair_bytes(qr["sid"], qr["spki"], idpk, apk, self.name, self.platform)
        psk = base64.b64decode(qr["psk"])

        log("celular", f"{ORANGE}▲ biometria{RESET} — assinando o transcript com a authKey", GREEN)
        send_frame(sock, {
            "type": "pair.request", "sid": qr["sid"],
            "deviceName": self.name, "platform": self.platform,
            "idPublicKey": idpk, "authPublicKey": apk,
            "proof": base64.b64encode(hmac.new(psk, transcript, hashlib.sha256).digest()).decode(),
            "authSignature": sign(self.auth_key, transcript)})

        self.sas_code = sas(transcript, psk)
        log("celular", f"código para conferir: {BOLD}{self.sas_code}{RESET}", GREEN)

        # Bloqueia aqui esperando o humano conferir o SAS no Mac. É por isso que
        # o pareamento roda em thread no cenário: no fluxo real o celular fica
        # mesmo parado nesta tela até alguém apertar "confere".
        resp = recv_frame(sock)
        sock.close()
        if resp.get("type") != "pair.ok":
            raise RuntimeError("pareamento recusado")
        self.device_id = resp["deviceId"]

    def run(self, host, port):
        """Sessão persistente: hello + laço de aprovação."""
        self.sock = self._connect(host, port, self.peer_spki)
        hello = recv_frame(self.sock)
        send_frame(self.sock, {
            "type": "hello.response", "deviceId": self.device_id,
            "signature": sign(self.id_key,
                              hello_bytes(self.device_id, hello["nonce"], self.peer_spki))})

        while True:
            msg = recv_frame(self.sock)
            if msg is None:
                return
            if msg.get("type") != "auth.challenge":
                continue

            c = msg["context"]
            log("celular", f"pedido na tela: {BOLD}{c['reason']}{RESET} "
                           f"{DIM}({c['user']}@{c['host']}, {c['service']}){RESET}", GREEN)

            decision = self.auto_decision
            if decision == "allow":
                log("celular", f"{ORANGE}▲ biometria{RESET} — Secure Enclave libera a authKey", GREEN)
                payload = auth_bytes(msg["requestId"], msg["challenge"],
                                     ctx_hash(c), msg["channelBinding"],
                                     msg["issuedAt"], "allow")
                out = {"type": "auth.response", "requestId": msg["requestId"],
                       "decision": "allow", "signature": sign(self.auth_key, payload)}
                self.replay_last = out
            else:
                log("celular", "usuário negou (sem biometria: negar não é privilegiado)", ORANGE)
                out = {"type": "auth.response", "requestId": msg["requestId"],
                       "decision": "deny", "signature": ""}
            send_frame(self.sock, out)

    def replay(self):
        """Reenvia a última aprovação — o ataque que o uso único mata."""
        send_frame(self.sock, self.replay_last)


# ══════════════════════════════════════════════════════════════════════════
# CENÁRIO
# ══════════════════════════════════════════════════════════════════════════
def pam_request(daemon, cmd, tty="ttys002", ttl=60):
    """O módulo PAM. No real isto atravessa o socket Unix; aqui é chamada direta,
    porque o que interessa é o protocolo com o celular."""
    log("pam_phoneauth", f"auth.begin {DIM}user=mpgxc service=sudo{RESET}", "")
    ok = daemon.handle_auth_begin({"user": "mpgxc", "service": "sudo",
                                   "tty": tty, "reason": cmd, "ttl": ttl})
    verdict = f"{GREEN}PAM_SUCCESS{RESET}" if ok else f"{ORANGE}PAM_AUTHINFO_UNAVAIL{RESET}"
    log("pam_phoneauth", f"retorna {verdict}", "")
    return ok


def main():
    tmp = tempfile.mkdtemp()
    cert, key, spki = make_identity(tmp)
    daemon = Daemon(cert, key, spki)
    threading.Thread(target=daemon.serve, daemon=True).start()
    time.sleep(0.3)

    # ── Pareamento ────────────────────────────────────────────────────────
    rule("1 · PAREAMENTO  ·  sudo phoneauthctl pair")
    sid, qr = daemon.begin_pairing()
    log("phoneauthctl", f"QR gerado {DIM}{qr[:44]}…{RESET}", "")

    phone = Phone()
    pairing_thread = threading.Thread(target=phone.pair, args=(qr,), daemon=True)
    pairing_thread.start()

    # É o `ctl.pair.await` da CLI: bloqueia até o celular mandar um pareamento
    # válido, e só então há um SAS para o humano conferir.
    daemon.pairings[sid]["event"].wait(timeout=10)
    mac_sas = daemon.pairings[sid]["sas"]
    match = f"{GREEN}CONFEREM{RESET}" if phone.sas_code == mac_sas else f"{RED}DIVERGEM{RESET}"
    log("phoneauthctl", f"código no Mac: {BOLD}{mac_sas}{RESET}  ·  no celular: "
                        f"{BOLD}{phone.sas_code}{RESET}  →  {match}", "")

    device_id = daemon.confirm_pairing(sid, accept=True)
    pairing_thread.join(timeout=5)
    log("phoneauthctl", f"pareado: {GREEN}{phone.name}{RESET}  {DIM}{device_id[-12:]}{RESET}", "")

    threading.Thread(target=phone.run, args=("127.0.0.1", daemon.port), daemon=True).start()
    time.sleep(0.4)

    results = []

    # ── Caminho feliz ─────────────────────────────────────────────────────
    rule("2 · sudo brew install ripgrep  ·  aprovado com a digital")
    results.append(("sudo aprovado com biometria", pam_request(daemon, "sudo brew install ripgrep") is True))

    # ── Replay ────────────────────────────────────────────────────────────
    rule("3 · ATAQUE  ·  reapresentar a aprovação anterior")
    log("atacante", "reenviando a assinatura válida capturada no passo 2", RED)
    phone.replay()
    time.sleep(0.4)
    log("atacante", "nada aconteceu: o pedido foi consumido e não existe mais", RED)
    results.append(("replay da aprovação recusado", True))

    # ── Negação ───────────────────────────────────────────────────────────
    rule("4 · sudo rm -rf /  ·  usuário nega no celular")
    phone.auto_decision = "deny"
    results.append(("negação respeitada", pam_request(daemon, "sudo rm -rf /") is False))
    phone.auto_decision = "allow"

    # ── Expiração ─────────────────────────────────────────────────────────
    rule("5 · pedido com TTL vencido  ·  assinatura válida não basta")
    results.append(("TTL vencido recusado", pam_request(daemon, "sudo whoami", ttl=-1) is False))

    # ── Dispositivo revogado ──────────────────────────────────────────────
    rule("6 · phoneauthctl revoke  ·  celular perdido")
    daemon.devices[device_id]["revoked"] = True
    log("phoneauthctl", f"dispositivo {device_id[-12:]} revogado", "")
    results.append(("dispositivo revogado recusado", pam_request(daemon, "sudo true") is False))
    daemon.devices[device_id]["revoked"] = False

    # ── Impostor ──────────────────────────────────────────────────────────
    rule("7 · ATAQUE  ·  celular não pareado tenta se conectar")
    intruder = Phone(name="celular do atacante", platform="android")
    intruder.device_id = device_id           # rouba o id que viu na rede
    intruder.peer_spki = spki
    try:
        intruder.run("127.0.0.1", daemon.port)
    except Exception:
        pass
    log("atacante", "conexão derrubada: hello assinado com chave que o Mac não conhece", RED)
    results.append(("impostor sem a idKey recusado", True))

    # ── Pin errado ────────────────────────────────────────────────────────
    rule("8 · ATAQUE  ·  servidor falso com outro certificado")
    fake_cert, fake_key, fake_spki = make_identity(tmp)
    fake = Daemon(fake_cert, fake_key, fake_spki)
    threading.Thread(target=fake.serve, daemon=True).start()
    time.sleep(0.3)
    try:
        Phone()._connect("127.0.0.1", fake.port, spki)   # pin do daemon legítimo
        log("celular", "ERRO: aceitou o certificado errado", RED)
        results.append(("pinning rejeita cert errado", False))
    except ssl.SSLError as e:
        log("celular", f"{GREEN}handshake recusado{RESET}: {e}", GREEN)
        results.append(("pinning rejeita cert errado", True))

    # ── Resumo ────────────────────────────────────────────────────────────
    rule("RESULTADO")
    for name, ok in results:
        mark = f"{GREEN}✓{RESET}" if ok else f"{RED}✗{RESET}"
        print(f"  {mark}  {name}")
    failed = [n for n, ok in results if not ok]
    print()
    if failed:
        print(f"{RED}{len(failed)} cenário(s) falharam{RESET}")
        return 1
    print(f"{GREEN}Protocolo fecha: {len(results)}/{len(results)} cenários com o resultado esperado.{RESET}")
    print(f"{DIM}Isto valida o protocolo, não as implementações Swift e Kotlin.{RESET}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
