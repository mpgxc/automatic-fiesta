import hashlib, hmac, base64, json

def ser(domain, fields):
    for f in fields:
        assert '\n' not in f and '\r' not in f, f
    return ("\n".join([domain] + fields) + "\n").encode('utf-8')

def sha(b): return hashlib.sha256(b).hexdigest()

def hkdf_sha256(ikm, info, length, salt=b""):
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    t, okm, i = b"", b"", 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t; i += 1
    return okm[:length]

V = {}

# --- Contexto ---
ctx_fields = ["MacBook Pro de mpgxc","mpgxc","sudo","sudo brew install ripgrep","/usr/bin/sudo","ttys002"]
ctx_bytes = ser("PHONEAUTH-CTX-V1", ctx_fields)
ctx_hash = sha(ctx_bytes)
V['context'] = {'fields': ctx_fields, 'bytesLen': len(ctx_bytes), 'sha256': ctx_hash}

# Contexto com campos vazios (linhas continuam existindo)
ctx2 = ser("PHONEAUTH-CTX-V1", ["Mac","root","su","","",""])
V['contextEmptyFields'] = {'fields': ["Mac","root","su","","",""], 'bytesLen': len(ctx2), 'sha256': sha(ctx2)}

# --- Aprovação ---
challenge = bytes(range(32))
challenge_b64 = base64.b64encode(challenge).decode()
binding = "a"*64
auth_bytes = ser("PHONEAUTH-AUTH-V1", ["3F2504E0-4F89-41D3-9A0C-0305E82C3301", challenge_b64, ctx_hash, binding, "1770000000", "allow"])
V['auth'] = {'requestId':"3F2504E0-4F89-41D3-9A0C-0305E82C3301", 'challengeB64':challenge_b64,
             'contextHash':ctx_hash, 'channelBinding':binding, 'issuedAt':1770000000,
             'decision':'allow', 'bytesLen':len(auth_bytes), 'sha256': sha(auth_bytes)}

deny_bytes = ser("PHONEAUTH-AUTH-V1", ["3F2504E0-4F89-41D3-9A0C-0305E82C3301", challenge_b64, ctx_hash, binding, "1770000000", "deny"])
V['authDeny'] = {'sha256': sha(deny_bytes)}

# --- Pareamento ---
idpk = base64.b64encode(b'\x11'*91).decode()
apk  = base64.b64encode(b'\x22'*91).decode()
pair_fields = ["7B3E1A2C-0000-4000-8000-000000000001", "b"*64, idpk, apk, "iPhone 15 de mpgxc", "ios"]
pair_bytes = ser("PHONEAUTH-PAIR-V1", pair_fields)
V['pair'] = {'sid':pair_fields[0],'spki':pair_fields[1],'idPublicKey':idpk,'authPublicKey':apk,
             'deviceName':pair_fields[4],'platform':'ios','bytesLen':len(pair_bytes),'sha256': sha(pair_bytes)}

# --- Hello ---
nonce_b64 = base64.b64encode(bytes([0xAA]*32)).decode()
hello_bytes = ser("PHONEAUTH-HELLO-V1", ["9C1D2E3F-0000-4000-8000-000000000002", nonce_b64, binding])
V['hello'] = {'deviceId':"9C1D2E3F-0000-4000-8000-000000000002",'nonceB64':nonce_b64,
              'channelBinding':binding,'bytesLen':len(hello_bytes),'sha256': sha(hello_bytes)}

# --- Rotação de identidade ---
#
# Domínios acrescentados por docs/rotacao-de-identidade.md. Hoje só o gêmeo
# macOS os implementa; estes vetores existem para que os gêmeos iOS e Android
# tenham contra o que conferir quando forem escritos — que é exatamente a falha
# que este arquivo previne.
#
# `retirePrevious` entra como a string literal "true"/"false", não como booleano
# JSON: a serialização é linha a linha, e cada linguagem formata booleano do seu
# jeito.
rot_id = "5D8C7B6A-0000-4000-8000-000000000003"
cur_spki = "c"*64
next_spki = "d"*64
rot_fields = [rot_id, cur_spki, next_spki, "1770000000", "1770086400", "1770604800", "true"]
rot_bytes = ser("PHONEAUTH-ROTATE-V1", rot_fields)
V['rotate'] = {'rotationId':rot_id, 'currentSpki':cur_spki, 'nextSpki':next_spki,
               'announcedAt':1770000000, 'commitNotBefore':1770086400, 'expiresAt':1770604800,
               'retirePrevious':True, 'bytesLen':len(rot_bytes), 'sha256': sha(rot_bytes)}

# Com retirePrevious=false, para travar a formatação do booleano nos dois casos.
rot_false = ser("PHONEAUTH-ROTATE-V1", rot_fields[:-1] + ["false"])
V['rotateNoRetire'] = {'retirePrevious':False, 'bytesLen':len(rot_false), 'sha256': sha(rot_false)}

ack_dev = "9C1D2E3F-0000-4000-8000-000000000002"
ack_bytes = ser("PHONEAUTH-ROTATE-ACK-V1", [rot_id, ack_dev, next_spki, binding])
V['rotateAck'] = {'rotationId':rot_id, 'deviceId':ack_dev, 'adoptedSpki':next_spki,
                  'channelBinding':binding, 'bytesLen':len(ack_bytes), 'sha256': sha(ack_bytes)}

# --- HMAC de pareamento e SAS ---
psk = bytes(range(32))
proof = hmac.new(psk, pair_bytes, hashlib.sha256).digest()
V['pairingProof'] = {'pskB64': base64.b64encode(psk).decode(), 'proofB64': base64.b64encode(proof).decode()}

info = b"phoneauth-sas-v1" + pair_bytes
okm = hkdf_sha256(psk, info, 4)
val = int.from_bytes(okm, 'big') % 1000000
V['sas'] = {'okmHex': okm.hex(), 'code': "%06d" % val}

# Confirma que HMAC com chave vazia == chave de 32 zeros (importante porque
# CryptoKit usa salt vazio e queremos que Python/Kotlin batam).
a = hmac.new(b"", psk, hashlib.sha256).digest()
b = hmac.new(b"\x00"*32, psk, hashlib.sha256).digest()
V['_hkdfSaltEquivalence'] = (a == b)

print(json.dumps(V, indent=2, ensure_ascii=False))
