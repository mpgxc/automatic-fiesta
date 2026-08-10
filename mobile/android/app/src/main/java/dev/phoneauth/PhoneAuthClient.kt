package dev.phoneauth

import android.app.Activity
import android.app.Application
import android.content.Context
import android.os.Bundle
import android.os.SystemClock
import android.util.Base64
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.DataInputStream
import java.io.IOException
import java.io.OutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.security.MessageDigest
import java.security.cert.X509Certificate
import java.util.concurrent.atomic.AtomicInteger
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
 *
 * O endereço do Mac, esse sim, é descartável: vem da descoberta mDNS, do cache
 * ou do QR, e nenhuma das três origens vale como identidade. Trocar de IP não
 * afrouxa nada — quem apresentar outra chave pública apanha do
 * [PinnedTrustManager] igual, venha de onde vier.
 *
 * O [context] é opcional só para não quebrar quem já constrói o cliente sem
 * ele; sem contexto não há como falar com o `NsdManager`, e aí sobra o endereço
 * salvo no pareamento.
 */
class PhoneAuthClient(
    private val scope: CoroutineScope,
    context: Context? = null,
) {

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

    private val appContext = context?.applicationContext
    private val discovery = appContext?.let { NsdDiscovery(it) }
    private val addressCache =
        appContext?.getSharedPreferences("dev.phoneauth.address", Context.MODE_PRIVATE)

    // Tocados pela thread de UI (connect/disconnect, ciclo de vida) e pela
    // corrotina de IO ao mesmo tempo.
    @Volatile private var socket: SSLSocket? = null
    @Volatile private var output: OutputStream? = null
    @Volatile private var peer: Peer? = null
    @Volatile private var supervisor: Job? = null
    @Volatile private var currentTarget: Target? = null
    @Volatile private var sessionAuthenticated = false

    /**
     * Um único escritor por vez no socket. Com o keepalive rodando em paralelo
     * com aprovação e resposta ao ping, dois `write` concorrentes intercalariam
     * os bytes e o Mac veria um quadro corrompido.
     */
    private val sendGate = Mutex()

    /**
     * Geração do supervisor. Quem manda parar incrementa; tentativas velhas
     * comparam antes de publicar estado, para não escreverem "falhou" por cima
     * do Idle de quem acabou de desconectar.
     */
    private val supervisorGeneration = AtomicInteger(0)

    /** Um endereço para tentar. Nada aqui é credencial — só onde discar. */
    private class Target(val host: String, val address: InetAddress?, val port: Int)

    private class SessionOutcome(val authenticated: Boolean, val reason: String)

    init {
        // Sem ninguém olhando a tela não há quem aprove nada; manter TLS aberto
        // e reconectar em loop no background é bateria queimada à toa. Se der
        // para observar o ciclo de vida do processo, o cliente se pausa
        // sozinho — o app não precisa lembrar de fazer isso.
        val application = appContext as? Application
        if (application != null) {
            val watcher = ForegroundWatcher()
            application.registerActivityLifecycleCallbacks(watcher)
            // A Application vive para sempre e seguraria este cliente junto.
            // O escopo de quem nos criou (o `lifecycleScope` da Activity) morre
            // com a tela, e é esse o momento de soltar o watcher.
            scope.coroutineContext[Job]?.invokeOnCompletion {
                application.unregisterActivityLifecycleCallbacks(watcher)
            }
        }
    }

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
        /** Tudo é LAN aqui; esperar mais que isto por um candidato é só atrasar o próximo. */
        private const val CONNECT_TIMEOUT_MS = 4_000

        /** Pareamento espera o humano confirmar o SAS no Mac, então a mão é mais leve. */
        private const val PAIRING_TIMEOUT_MS = 10_000

        private const val KEEPALIVE_MS = 30_000L
        private const val SESSION_READ_TIMEOUT_MS = 90_000
        private const val BACKOFF_BASE_MS = 1_000L
        private const val BACKOFF_CAP_MS = 30_000L

        /** Abaixo disto a sessão não conta como saudável para zerar o backoff. */
        private const val HEALTHY_SESSION_MS = 10_000L

        fun openPinnedSocket(host: String, port: Int, spkiHex: String, timeoutMs: Int = 10_000): SSLSocket =
            openPinnedSocket(InetSocketAddress(host, port), host, spkiHex, timeoutMs)

        /**
         * Mesma coisa a partir de um endereço já resolvido — o caminho da
         * descoberta, que evita mandar o resolvedor do sistema tentar de novo um
         * IP que o mDNS acabou de entregar (e evita perder o escopo de um
         * endereço IPv6 link-local no caminho).
         */
        fun openPinnedSocket(address: InetAddress, port: Int, spkiHex: String, timeoutMs: Int = 10_000): SSLSocket =
            openPinnedSocket(
                InetSocketAddress(address, port),
                address.hostAddress ?: address.toString(),
                spkiHex,
                timeoutMs,
            )

        private fun openPinnedSocket(
            endpoint: InetSocketAddress,
            sniHost: String,
            spkiHex: String,
            timeoutMs: Int,
        ): SSLSocket {
            val context = SSLContext.getInstance("TLSv1.3").apply {
                init(null, arrayOf(PinnedTrustManager(spkiHex)), java.security.SecureRandom())
            }
            val raw = Socket()
            raw.connect(endpoint, timeoutMs)
            return (context.socketFactory.createSocket(raw, sniHost, endpoint.port, true) as SSLSocket).apply {
                enabledProtocols = arrayOf("TLSv1.3")
                // Um host que aceita o TCP e depois emudece no meio do
                // handshake travaria a tentativa para sempre. Depois do
                // handshake o limite volta a ser infinito: quem quiser prazo de
                // leitura define o seu.
                soTimeout = timeoutMs
                startHandshake()
                soTimeout = 0
            }
        }
    }

    // MARK: - Conexão

    /**
     * Passa a manter a conexão com [peer] de pé: tenta, e se cair tenta de
     * novo, com backoff. Chamar de novo (o botão "Reconectar") zera o backoff e
     * força uma tentativa imediata.
     */
    fun connect(peer: Peer) {
        this.peer = peer
        startSupervisor(peer)
    }

    /**
     * Para de vez e **esquece o alvo** — é o que o "Esquecer este Mac" precisa.
     * Sem esquecer, uma volta ao primeiro plano ressuscitaria a conexão com um
     * Mac que o usuário acabou de desparear.
     */
    fun disconnect() {
        peer = null
        stopSupervisor()
        _state.value = State.Idle
    }

    private fun startSupervisor(peer: Peer) {
        stopSupervisor()
        val generation = supervisorGeneration.incrementAndGet()
        _state.value = State.Connecting
        supervisor = scope.launch(Dispatchers.IO) { supervise(peer, generation) }
    }

    private fun stopSupervisor() {
        supervisorGeneration.incrementAndGet()
        supervisor?.cancel()
        supervisor = null
        // Fechar o socket na mão não é redundante com o cancel: o `readFully`
        // está parado numa chamada bloqueante, e cancelamento de corrotina não
        // interrompe I/O de socket. É o close que estoura a leitura e deixa a
        // corrotina perceber que foi cancelada.
        closeSocket()
    }

    private fun closeSocket() {
        runCatching { socket?.close() }
        socket = null
        output = null
        currentTarget = null
        sessionAuthenticated = false
        // Pedido pendente não sobrevive à sessão: a resposta iria para um socket
        // morto e o usuário teria encostado o dedo à toa.
        _pending.value = null
    }

    private suspend fun CoroutineScope.supervise(peer: Peer, generation: Int) {
        var attempt = 0
        while (isActive) {
            publish(generation, State.Connecting)

            val startedAt = SystemClock.elapsedRealtime()
            val outcome = runSession(peer)
            if (!isActive) return

            // O backoff só zera depois de uma sessão que de fato viveu. Se o Mac
            // aceita o TLS e derruba logo em seguida — dispositivo revogado, por
            // exemplo — zerar aqui viraria martelada de segundo em segundo para
            // sempre.
            val lasted = SystemClock.elapsedRealtime() - startedAt
            if (outcome.authenticated && lasted >= HEALTHY_SESSION_MS) attempt = 0

            val wait = backoffMillis(attempt)
            attempt++
            publish(generation, State.Failed("${outcome.reason} · nova tentativa em ${wait / 1000}s"))
            delay(wait)
        }
    }

    /** 1s, 2s, 4s... com teto de 30s. */
    private fun backoffMillis(attempt: Int): Long =
        minOf(BACKOFF_BASE_MS shl minOf(attempt, 16), BACKOFF_CAP_MS)

    private fun publish(generation: Int, state: State) {
        if (generation == supervisorGeneration.get()) _state.value = state
    }

    /** Abre uma sessão, roda até ela morrer, e conta como foi. */
    private suspend fun CoroutineScope.runSession(peer: Peer): SessionOutcome {
        val opened = try {
            openBestEffort(peer)
        } catch (cancelled: CancellationException) {
            // Mandaram parar no meio da procura. Não é sinal de que o endereço
            // guardado está ruim, então ele fica.
            throw cancelled
        } catch (e: Exception) {
            // Ninguém respondeu: o endereço lembrado, se havia, está velho.
            forgetRememberedAddress()
            return SessionOutcome(false, e.message ?: "não foi possível alcançar ${peer.name}")
        }

        val ssl = opened.first
        currentTarget = opened.second
        socket = ssl
        output = ssl.outputStream
        sessionAuthenticated = false

        // Publicar o socket antes de checar o cancelamento é de propósito: se
        // mandaram parar bem no meio disto, ou o `closeSocket` de lá já viu
        // este socket, ou fechamos aqui. Sem essa ordem sobraria uma conexão
        // aberta em background que ninguém mais tem como fechar.
        if (!isActive) {
            closeSocket()
            return SessionOutcome(false, "cancelado")
        }

        var reason = "conexão encerrada pelo Mac"
        try {
            // Silêncio prolongado é conexão morta que ninguém avisou (Mac
            // dormiu, Wi-Fi trocou de AP). Sem prazo de leitura o app ficaria
            // "conectado" para sempre num socket que não entrega mais nada, e a
            // reconexão nunca dispararia. 90s é o mesmo limite que o Mac usa.
            ssl.soTimeout = SESSION_READ_TIMEOUT_MS
            coroutineScope {
                val keepaliveJob = launch { keepalive() }
                try {
                    readLoop(DataInputStream(ssl.inputStream))
                } finally {
                    keepaliveJob.cancel()
                }
            }
        } catch (e: Exception) {
            reason = e.message ?: "conexão perdida"
        }

        val authenticated = sessionAuthenticated
        closeSocket()
        return SessionOutcome(authenticated, reason)
    }

    /**
     * Keepalive do protocolo: `ping` a cada 30 s. Serve para o Mac saber que
     * seguimos vivos e, principalmente, para o silêncio do outro lado virar
     * timeout de leitura aqui em vez de conexão zumbi.
     */
    private suspend fun keepalive() {
        while (true) {
            delay(KEEPALIVE_MS)
            send(JSONObject().put("type", "ping"))
        }
    }

    private fun openFirst(targets: List<Target>, spkiHex: String, timeoutMs: Int): Pair<SSLSocket, Target> {
        var last: Exception? = null
        for (target in targets) {
            try {
                val ssl = if (target.address != null) {
                    openPinnedSocket(target.address, target.port, spkiHex, timeoutMs)
                } else {
                    openPinnedSocket(target.host, target.port, spkiHex, timeoutMs)
                }
                return ssl to target
            } catch (e: Exception) {
                // Reprovar no pinning cai aqui: existe *algo* naquele endereço,
                // mas não é o Mac pareado. Segue para o próximo candidato — e é
                // justamente por tentar os outros que alguém anunciando o mesmo
                // nome no mDNS não consegue nem enganar nem travar o app.
                last = e
            }
        }
        throw last ?: IOException("nenhum endereço para tentar")
    }

    /**
     * Procura o Mac do mais barato para o mais caro.
     *
     * Primeiro o endereço que funcionou da última vez e o host do QR: são
     * tentativas diretas, sem acordar o rádio de ninguém. A descoberta entra
     * como último recurso, que é justamente o caso em que ela serve para
     * alguma coisa — o IP mudou. Fazer multicast antes disso seria pagar
     * bateria (e latência na tela de aprovação) em toda reconexão de rotina.
     */
    private suspend fun openBestEffort(peer: Peer): Pair<SSLSocket, Target> {
        val direct = LinkedHashMap<String, Target>()
        rememberedAddress(peer)?.let { direct["${it.host}:${it.port}"] = it }
        // O host do QR é um nome mDNS (`mac.local`), que boa parte dos aparelhos
        // Android não resolve pelo resolvedor do sistema. Falha barato quando é
        // o caso, e funciona de graça quando o aparelho resolve.
        direct.getOrPut("${peer.host}:${peer.port}") { Target(peer.host, null, peer.port) }

        return try {
            openFirst(direct.values.toList(), peer.spki, CONNECT_TIMEOUT_MS)
        } catch (unreachable: Exception) {
            val discovered = discovery?.find(preferredName = peer.name).orEmpty()
                .map { Target(it.address.hostAddress ?: it.address.toString(), it.address, it.port) }
                .filterNot { direct.containsKey("${it.host}:${it.port}") }
            // Sem nada novo para tentar, o erro que interessa é o da tentativa
            // direta — "não achei ninguém" esconderia o motivo real.
            if (discovered.isEmpty()) throw unreachable
            openFirst(discovered, peer.spki, CONNECT_TIMEOUT_MS)
        }
    }

    // MARK: - Cache de endereço

    /**
     * Último endereço que rendeu uma sessão autenticada.
     *
     * É cache de **endereço**, não de confiança: se alguém trocar isto por um
     * host hostil, o pinning reprova o handshake e o candidato cai fora na
     * mesma tentativa. Fica preso ao SPKI do pareamento só para não sobrar
     * lixo de um Mac antigo depois de reparear.
     */
    private fun rememberedAddress(peer: Peer): Target? {
        val prefs = addressCache ?: return null
        if (prefs.getString("spki", null) != peer.spki) return null
        val host = prefs.getString("host", null) ?: return null
        val port = prefs.getInt("port", 0)
        if (port <= 0) return null
        return Target(host, null, port)
    }

    private fun rememberAddress(host: String, port: Int, spki: String) {
        val prefs = addressCache ?: return
        prefs.edit().putString("spki", spki).putString("host", host).putInt("port", port).apply()
    }

    private fun forgetRememberedAddress() {
        addressCache?.edit()?.remove("host")?.apply()
    }

    // MARK: - Primeiro plano

    private fun onEnterForeground() {
        val peer = peer ?: return
        // Já tentando: deixa o supervisor em paz, senão a volta para a tela
        // abortaria uma tentativa que estava a meio caminho.
        if (supervisor?.isActive == true) return
        startSupervisor(peer)
    }

    private fun onEnterBackground() {
        stopSupervisor()
        _state.value = State.Idle
    }

    private inner class ForegroundWatcher : Application.ActivityLifecycleCallbacks {
        private var visible = 0

        override fun onActivityStarted(activity: Activity) {
            if (visible++ == 0) onEnterForeground()
        }

        override fun onActivityStopped(activity: Activity) {
            // Girar a tela passa por stop/start com a contagem zerando no meio.
            // Sem esta checagem, toda rotação derrubaria a conexão — e o
            // decremento acontece de qualquer jeito, senão a contagem
            // desandava e nunca mais chegaria a zero de verdade.
            val changingConfiguration = activity.isChangingConfigurations
            if (--visible <= 0) {
                visible = 0
                if (!changingConfiguration) onEnterBackground()
            }
        }

        override fun onActivityCreated(activity: Activity, savedInstanceState: Bundle?) {}
        override fun onActivityResumed(activity: Activity) {}
        override fun onActivityPaused(activity: Activity) {}
        override fun onActivitySaveInstanceState(activity: Activity, outState: Bundle) {}
        override fun onActivityDestroyed(activity: Activity) {}
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
            // de tentar alocar. Quem decide se e quando tentar de novo é o
            // supervisor — com backoff, para não virar laço apertado contra um
            // servidor quebrado.
            if (length <= 0 || length > 65_536) {
                throw IOException("quadro com tamanho inválido")
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
                    sessionAuthenticated = true
                    // Endereço que rendeu sessão de verdade: guarda para a
                    // próxima tentativa começar por ele, sem multicast.
                    currentTarget?.let { rememberAddress(it.host, it.port, peer.spki) }
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
        sendGate.withLock {
            runCatching {
                output?.write(framed)
                output?.flush()
            }
        }
        Unit
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

        // O QR traz `<nome>.local`, que boa parte dos aparelhos Android não
        // resolve pelo resolvedor do sistema — sem plano B o pareamento morreria
        // antes de começar. A descoberta só entra se o nome falhar; o `spki` que
        // veio no próprio QR continua sendo quem decide se do outro lado está o
        // Mac certo, então tentar outro endereço não abre brecha nenhuma.
        val opened = try {
            openFirst(listOf(Target(host, null, port)), spki, PAIRING_TIMEOUT_MS)
        } catch (unreachable: Exception) {
            val discovered = discovery?.find(preferredName = name).orEmpty()
                .map { Target(it.address.hostAddress ?: it.address.toString(), it.address, it.port) }
            if (discovered.isEmpty()) throw unreachable
            openFirst(discovered, spki, PAIRING_TIMEOUT_MS)
        }
        val ssl = opened.first
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
            // O `Peer` guarda o nome do QR, que sobrevive a troca de IP; o
            // endereço que acabou de funcionar vai para o cache, para a
            // primeira conexão depois do pareamento ser instantânea.
            rememberAddress(opened.second.host, opened.second.port, spki)
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
