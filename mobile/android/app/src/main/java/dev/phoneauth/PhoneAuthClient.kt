package dev.phoneauth

import android.util.Base64
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.DataInputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.security.MessageDigest
import java.security.cert.X509Certificate
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.X509TrustManager

/**
 * Conexão com o Mac: TLS 1.3 com pinning de SPKI.
 *
 * O certificado do daemon é auto-assinado, então não há CA nem cadeia para
 * validar. A confiança vem inteiramente do hash de SPKI capturado no QR durante
 * o pareamento — o que é mais forte que a PKI pública, porque não depende de
 * nenhuma autoridade terceira em quem você não escolheu confiar.
 */
class PhoneAuthClient(private val scope: CoroutineScope) {

    data class Peer(
        val host: String,
        val port: Int,
        val spki: String,       // hex do SHA-256 do SPKI; o valor pinado
        val name: String,
        val deviceId: String?,
    )

    data class AuthChallenge(
        val requestId: String,
        val challenge: String,
        val issuedAt: Long,
        val expiresAt: Long,
        val channelBinding: String,
        val context: SignedPayload.Context,
    ) {
        val isExpired: Boolean get() = System.currentTimeMillis() / 1000 > expiresAt
        val secondsRemaining: Int
            get() = maxOf(0, (expiresAt - System.currentTimeMillis() / 1000).toInt())
    }

    sealed interface State {
        data object Idle : State
        data object Connecting : State
        data object Connected : State
        data class Failed(val reason: String) : State
    }

    private val _state = MutableStateFlow<State>(State.Idle)
    val state: StateFlow<State> = _state

    private val _pending = MutableStateFlow<AuthChallenge?>(null)
    val pending: StateFlow<AuthChallenge?> = _pending

    private var socket: SSLSocket? = null
    private var output: OutputStream? = null
    private var peer: Peer? = null

    // MARK: - Pinning

    /**
     * Aceita exatamente uma chave pública: a que foi vista no QR. Substitui
     * inteiramente a validação de cadeia.
     */
    class PinnedTrustManager(private val expectedSpkiHex: String) : X509TrustManager {
        override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {
            val leaf = chain.firstOrNull()
                ?: throw java.security.cert.CertificateException("cadeia vazia")
            val actual = MessageDigest.getInstance("SHA-256")
                .digest(leaf.publicKey.encoded)
                .joinToString("") { "%02x".format(it) }
            if (actual != expectedSpkiHex) {
                throw java.security.cert.CertificateException(
                    "chave do servidor não confere com a pinada no pareamento"
                )
            }
        }

        // Nunca somos servidor TLS; um cliente pedindo confiança aqui é um bug.
        override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) =
            throw java.security.cert.CertificateException("não suportado")

        override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
    }

    companion object {
        fun openPinnedSocket(host: String, port: Int, spkiHex: String, timeoutMs: Int = 10_000): SSLSocket {
            val context = SSLContext.getInstance("TLSv1.3").apply {
                init(null, arrayOf(PinnedTrustManager(spkiHex)), java.security.SecureRandom())
            }
            val raw = Socket()
            raw.connect(InetSocketAddress(host, port), timeoutMs)
            return (context.socketFactory.createSocket(raw, host, port, true) as SSLSocket).apply {
                enabledProtocols = arrayOf("TLSv1.3")
                startHandshake()
            }
        }
    }

    // MARK: - Conexão

    fun connect(peer: Peer) {
        disconnect()
        this.peer = peer
        _state.value = State.Connecting

        scope.launch(Dispatchers.IO) {
            try {
                val ssl = openPinnedSocket(peer.host, peer.port, peer.spki)
                socket = ssl
                output = ssl.outputStream
                readLoop(DataInputStream(ssl.inputStream))
            } catch (e: Exception) {
                _state.value = State.Failed(e.message ?: "falha na conexão")
            }
        }
    }

    fun disconnect() {
        runCatching { socket?.close() }
        socket = null
        output = null
        _state.value = State.Idle
    }

    private suspend fun readLoop(input: DataInputStream) {
        val header = ByteArray(4)
        while (true) {
            input.readFully(header)
            val length = ((header[0].toInt() and 0xFF) shl 24) or
                ((header[1].toInt() and 0xFF) shl 16) or
                ((header[2].toInt() and 0xFF) shl 8) or
                (header[3].toInt() and 0xFF)

            // Comprimento absurdo é peer com defeito ou hostil; derruba em vez
            // de tentar alocar.
            if (length <= 0 || length > 65_536) {
                disconnect()
                return
            }
            val body = ByteArray(length)
            input.readFully(body)
            handle(JSONObject(String(body, Charsets.UTF_8)))
        }
    }

    private suspend fun handle(message: JSONObject) {
        when (message.optString("type")) {
            "hello.challenge" -> {
                val peer = peer ?: return
                val deviceId = peer.deviceId ?: return
                try {
                    val bytes = SignedPayload.helloBytes(
                        deviceId = deviceId,
                        nonceBase64 = message.getString("nonce"),
                        channelBinding = peer.spki,
                    )
                    // Chave de identidade: sem biometria, de propósito.
                    // Reconectar não pode custar um toque do dedo.
                    send(
                        JSONObject()
                            .put("type", "hello.response")
                            .put("deviceId", deviceId)
                            .put("signature", DeviceKeys.signWithIdentityKey(bytes))
                    )
                    _state.value = State.Connected
                } catch (e: Exception) {
                    _state.value = State.Failed(e.message ?: "falha ao autenticar a sessão")
                }
            }

            "auth.challenge" -> {
                val ctx = message.getJSONObject("context")
                val challenge = AuthChallenge(
                    requestId = message.getString("requestId"),
                    challenge = message.getString("challenge"),
                    issuedAt = message.getLong("issuedAt"),
                    expiresAt = message.getLong("expiresAt"),
                    channelBinding = message.getString("channelBinding"),
                    context = SignedPayload.Context(
                        host = ctx.optString("host"),
                        user = ctx.optString("user"),
                        service = ctx.optString("service"),
                        reason = ctx.optString("reason"),
                        processPath = ctx.optString("processPath"),
                        tty = ctx.optString("tty"),
                    ),
                )
                if (!challenge.isExpired) _pending.value = challenge
            }

            "ping" -> send(JSONObject().put("type", "pong"))
        }
    }

    private suspend fun send(message: JSONObject) = withContext(Dispatchers.IO) {
        val body = message.toString().toByteArray(Charsets.UTF_8)
        val framed = ByteArray(4 + body.size)
        framed[0] = (body.size shr 24).toByte()
        framed[1] = (body.size shr 16).toByte()
        framed[2] = (body.size shr 8).toByte()
        framed[3] = body.size.toByte()
        body.copyInto(framed, 4)
        runCatching {
            output?.write(framed)
            output?.flush()
        }
    }

    // MARK: - Decisão do usuário

    /**
     * Aprova o pedido. A biometria é disparada dentro de
     * `signWithApprovalKey` — imposta pelo Keystore, não por este código. Se o
     * usuário cancelar ou falhar, não existe assinatura para enviar.
     */
    suspend fun approve(activity: androidx.fragment.app.FragmentActivity, challenge: AuthChallenge) {
        val peer = peer ?: return
        val bytes = SignedPayload.authBytes(
            requestId = challenge.requestId,
            challengeBase64 = challenge.challenge,
            contextHash = SignedPayload.contextHash(challenge.context),
            channelBinding = peer.spki,
            issuedAt = challenge.issuedAt,
            decision = SignedPayload.Decision.ALLOW,
        )
        val signature = DeviceKeys.signWithApprovalKey(
            activity = activity,
            message = bytes,
            title = "Liberar em ${challenge.context.host}",
            subtitle = challenge.context.reason,
        )
        send(
            JSONObject()
                .put("type", "auth.response")
                .put("requestId", challenge.requestId)
                .put("decision", "allow")
                .put("signature", signature)
        )
        _pending.value = null
    }

    /**
     * Negar não exige biometria: recusar não é uma ação privilegiada, e pedir
     * o dedo para dizer "não" treinaria justamente o reflexo que queremos
     * evitar.
     */
    suspend fun deny(challenge: AuthChallenge) {
        send(
            JSONObject()
                .put("type", "auth.response")
                .put("requestId", challenge.requestId)
                .put("decision", "deny")
                .put("signature", "")
        )
        _pending.value = null
    }

    // MARK: - Pareamento

    /**
     * Handshake de pareamento. Retorna o par e o SAS de 6 dígitos para o
     * usuário conferir com o que o Mac exibe.
     */
    suspend fun pair(
        activity: androidx.fragment.app.FragmentActivity,
        qrText: String,
        deviceName: String,
        onSas: (String) -> Unit,
    ): Peer = withContext(Dispatchers.IO) {
        // O QR carrega base64url; restaura o alfabeto padrão.
        val json = String(Base64.decode(qrText, Base64.URL_SAFE or Base64.NO_PADDING), Charsets.UTF_8)
        val qr = JSONObject(json)
        require(qr.getInt("v") == 1) { "versão de QR não suportada" }

        val host = qr.getString("host")
        val port = qr.getInt("port")
        val spki = qr.getString("spki")
        val sid = qr.getString("sid")
        val psk = Base64.decode(qr.getString("psk"), Base64.DEFAULT)
        val name = qr.getString("name")

        // Chaves novas a cada pareamento. Reaproveitar chave de um pareamento
        // anterior confundiria a revogação.
        DeviceKeys.createKeyPair()
        val idKey = DeviceKeys.publicKeySpkiBase64(biometric = false)
        val authKey = DeviceKeys.publicKeySpkiBase64(biometric = true)

        val transcript = SignedPayload.pairBytes(
            sid = sid, spki = spki,
            idPublicKeyBase64 = idKey, authPublicKeyBase64 = authKey,
            deviceName = deviceName, platform = "android",
        )

        // O HMAC prova que vimos o QR na tela do Mac.
        val proof = javax.crypto.Mac.getInstance("HmacSHA256").run {
            init(javax.crypto.spec.SecretKeySpec(psk, "HmacSHA256"))
            Base64.encodeToString(doFinal(transcript), Base64.NO_WRAP)
        }

        // A assinatura pela authKey pede a biometria agora. É a demonstração,
        // para o Mac, de que o portão biométrico existe e funciona — a
        // assinatura não teria como ser produzida sem o dedo.
        val signature = withContext(Dispatchers.Main) {
            DeviceKeys.signWithApprovalKey(activity, transcript, "Parear com $name", deviceName)
        }

        onSas(Sas.compute(transcript, psk))

        val ssl = openPinnedSocket(host, port, spki)
        try {
            val request = JSONObject()
                .put("type", "pair.request").put("sid", sid)
                .put("deviceName", deviceName).put("platform", "android")
                .put("idPublicKey", idKey).put("authPublicKey", authKey)
                .put("proof", proof).put("authSignature", signature)

            val body = request.toString().toByteArray(Charsets.UTF_8)
            ssl.outputStream.apply {
                write(byteArrayOf(
                    (body.size shr 24).toByte(), (body.size shr 16).toByte(),
                    (body.size shr 8).toByte(), body.size.toByte(),
                ))
                write(body)
                flush()
            }

            val input = DataInputStream(ssl.inputStream)
            val header = ByteArray(4)
            input.readFully(header)
            val length = ((header[0].toInt() and 0xFF) shl 24) or
                ((header[1].toInt() and 0xFF) shl 16) or
                ((header[2].toInt() and 0xFF) shl 8) or (header[3].toInt() and 0xFF)
            require(length in 1..65_536) { "resposta malformada" }

            val responseBytes = ByteArray(length)
            input.readFully(responseBytes)
            val response = JSONObject(String(responseBytes, Charsets.UTF_8))

            if (response.optString("type") != "pair.ok") {
                // Sem chaves órfãs: o pareamento falhou, então não há motivo
                // para deixar material criptográfico para trás.
                DeviceKeys.deleteAll()
                throw IllegalStateException("o Mac recusou o pareamento")
            }
            Peer(host, port, spki, name, response.getString("deviceId"))
        } finally {
            runCatching { ssl.close() }
        }
    }
}

/** Código de 6 dígitos para conferência visual no pareamento. */
object Sas {
    fun compute(transcript: ByteArray, secret: ByteArray): String {
        val info = "phoneauth-sas-v1".toByteArray(Charsets.UTF_8) + transcript
        val okm = hkdfSha256(secret, info, 4)
        val value = ((okm[0].toLong() and 0xFF) shl 24) or
            ((okm[1].toLong() and 0xFF) shl 16) or
            ((okm[2].toLong() and 0xFF) shl 8) or (okm[3].toLong() and 0xFF)
        return "%06d".format(value % 1_000_000)
    }

    /**
     * HKDF-SHA256 com salt vazio, para bater com o `HKDF.deriveKey` do
     * CryptoKit. Salt vazio e salt de 32 zeros produzem o mesmo PRK, porque o
     * HMAC preenche a chave com zeros até o tamanho do bloco de qualquer forma.
     */
    private fun hkdfSha256(ikm: ByteArray, info: ByteArray, length: Int): ByteArray {
        val mac = javax.crypto.Mac.getInstance("HmacSHA256")
        mac.init(javax.crypto.spec.SecretKeySpec(ByteArray(32), "HmacSHA256"))
        val prk = mac.doFinal(ikm)

        val out = ByteArray(length)
        var t = ByteArray(0)
        var filled = 0
        var counter = 1
        while (filled < length) {
            mac.init(javax.crypto.spec.SecretKeySpec(prk, "HmacSHA256"))
            mac.update(t); mac.update(info); mac.update(counter.toByte())
            t = mac.doFinal()
            val take = minOf(t.size, length - filled)
            t.copyInto(out, filled, 0, take)
            filled += take
            counter++
        }
        return out
    }
}
