package dev.phoneauth

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.nsd.NsdManager
import android.net.nsd.NsdServiceInfo
import android.net.wifi.WifiManager
import android.os.SystemClock
import kotlinx.coroutines.delay
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withTimeoutOrNull
import java.net.InetAddress
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.coroutines.resume

/**
 * Acha o Mac na LAN por mDNS, o mesmo `_phoneauth._tcp` que o `PhoneListener`
 * anuncia via Bonjour.
 *
 * Isto resolve **endereço**, e nada além de endereço. Não autentica, não
 * escolhe em quem confiar e não tem opinião sobre quem está do outro lado: um
 * serviço que se anuncie com o nome do seu Mac ainda vai levar tranco no
 * handshake, porque quem decide isso é o hash de SPKI pinado no pareamento.
 * Trate tudo que sai daqui como uma dica, não como uma credencial.
 */
class NsdDiscovery(context: Context) {

    data class Endpoint(val address: InetAddress, val port: Int, val serviceName: String)

    private val appContext = context.applicationContext
    private val nsd = appContext.getSystemService(Context.NSD_SERVICE) as? NsdManager
    private val wifi = appContext.getSystemService(Context.WIFI_SERVICE) as? WifiManager
    private val connectivity =
        appContext.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager

    /** Uma rodada de descoberta por vez: multicast é caro e não se ganha nada em paralelizar. */
    private val browseGate = Mutex()

    /**
     * Resumo da última rodada, em uma linha, para a tela de erro mostrar.
     *
     * Sem isto toda falha de rede chega ao usuário como "não foi possível
     * conectar", que não distingue enlace sem multicast, descoberta que nem
     * começou, ninguém anunciando, ou anúncio que não resolve — quatro causas
     * com quatro consertos diferentes. O texto é curto de propósito: cabe numa
     * captura de tela, que é como esta informação costuma chegar a quem pode
     * consertar.
     */
    @Volatile
    var ultimoDiagnostico: String = "descoberta ainda não rodou"
        private set

    /**
     * O `resolveService` clássico atende **um** pedido de cada vez no
     * framework; dois ao mesmo tempo devolvem `FAILURE_ALREADY_ACTIVE`.
     */
    private val resolveGate = Mutex()

    /**
     * Procura serviços e devolve os endereços resolvidos, com [preferredName]
     * na frente quando aparecer.
     *
     * O nome é só ordenação — vem do QR e serve para tentar primeiro o Mac que
     * você pareou em vez de outro que esteja anunciando o mesmo tipo. Escolher
     * errado não é falha de segurança, é só uma tentativa desperdiçada.
     */
    suspend fun find(
        preferredName: String? = null,
        windowMs: Long = BROWSE_WINDOW_MS,
        limit: Int = MAX_CANDIDATES,
    ): List<Endpoint> = browseGate.withLock {
        val nsd = nsd ?: run {
            ultimoDiagnostico = "mDNS indisponível neste aparelho"
            return emptyList()
        }

        // Sem enlace que carregue multicast (celular puro, avião), mDNS não vai
        // a lugar nenhum: melhor devolver vazio na hora e deixar o chamador ir
        // direto para o endereço salvo do que segurar o rádio por segundos.
        if (!hasMulticastCapableLink()) {
            ultimoDiagnostico = "sem Wi-Fi nem cabo: mDNS não roda em rede móvel"
            return emptyList()
        }

        // Sem o MulticastLock o Wi-Fi de muitos aparelhos descarta os pacotes
        // multicast antes de eles chegarem ao app, e a descoberta simplesmente
        // não acha nada. Ele fica de pé durante a busca **e** durante o resolve,
        // porque as respostas do resolve também chegam por multicast — e cai
        // logo depois, antes mesmo de abrir o TLS, que não precisa dele.
        val lock = runCatching {
            wifi?.createMulticastLock(MULTICAST_TAG)?.apply {
                setReferenceCounted(true)
                acquire()
            }
        }.getOrNull()

        val endpoints = ArrayList<Endpoint>()
        var anunciados = 0
        var falhaAoIniciar: Int? = null
        var tipoQueFuncionou: String? = null
        try {
            // Teto duro para a rodada inteira. O lock é caro demais para ficar
            // de pé enquanto um resolve emperrado decide se responde; o que já
            // tiver resolvido até aqui vale, o resto fica para a próxima.
            withTimeoutOrNull(BUDGET_MS) {
                val rodada = browse(nsd, preferredName, windowMs)
                anunciados = rodada.servicos.size
                falhaAoIniciar = rodada.erroAoIniciar
                tipoQueFuncionou = rodada.tipo
                for (service in rodada.servicos.take(limit)) {
                    val resolved = resolve(nsd, service) ?: continue
                    @Suppress("DEPRECATION") // getHostAddresses() só existe da API 34 em diante.
                    val address = resolved.host ?: continue
                    val port = resolved.port
                    if (port <= 0) continue
                    endpoints += Endpoint(address, port, resolved.serviceName ?: "")
                }
            }
        } finally {
            runCatching { if (lock != null && lock.isHeld) lock.release() }
        }

        ultimoDiagnostico = when {
            falhaAoIniciar != null -> "busca mDNS recusada pelo sistema (código $falhaAoIniciar)"
            anunciados == 0 -> "ninguém anunciando $SERVICE_TYPE na rede"
            endpoints.isEmpty() -> "$anunciados anúncio(s), nenhum resolveu para endereço"
            else -> "$anunciados anúncio(s), ${endpoints.size} resolvido(s)" +
                (tipoQueFuncionou?.let { if (it.endsWith(".")) " [tipo com ponto]" else "" } ?: "")
        }
        endpoints
    }

    // MARK: - Busca

    /** O que uma rodada de busca produziu, incluindo por que não produziu nada. */
    private class Rodada(
        val servicos: List<NsdServiceInfo>,
        val erroAoIniciar: Int?,
        val tipo: String?,
    )

    /**
     * Busca com o tipo canônico e, se o sistema **recusar a busca**, repete com
     * a forma terminada em ponto.
     *
     * O exemplo oficial de NSD do Android declara o tipo como `_http._tcp.`,
     * com ponto final, enquanto o registro DNS-SD canônico — o que o daemon
     * anuncia — não leva ponto. Aparelhos discordam sobre qual aceitar, e
     * quando recusam, recusam de imediato, com `onStartDiscoveryFailed`.
     *
     * A segunda tentativa só acontece nesse caso justamente porque falhar ao
     * iniciar é instantâneo: não custa janela nenhuma. Se a busca *começou* e
     * não achou nada, o tipo não é o problema e repetir só gastaria mais seis
     * segundos com o rádio ligado.
     */
    private suspend fun browse(
        nsd: NsdManager,
        preferredName: String?,
        windowMs: Long,
    ): Rodada {
        val primeira = browseComTipo(nsd, SERVICE_TYPE, preferredName, windowMs)
        if (primeira.erroAoIniciar == null) return primeira
        return browseComTipo(nsd, SERVICE_TYPE_COM_PONTO, preferredName, windowMs)
    }

    private suspend fun browseComTipo(
        nsd: NsdManager,
        tipo: String,
        preferredName: String?,
        windowMs: Long,
    ): Rodada {
        val found = CopyOnWriteArrayList<NsdServiceInfo>()
        val startFailed = AtomicBoolean(false)
        val startErrorCode = java.util.concurrent.atomic.AtomicInteger(0)

        // Listener novo a cada rodada, sempre. Reaproveitar o objeto antes de o
        // `stopServiceDiscovery` anterior ter completado rende
        // IllegalArgumentException ("listener already in use").
        val listener = object : NsdManager.DiscoveryListener {
            override fun onDiscoveryStarted(serviceType: String) {}
            override fun onDiscoveryStopped(serviceType: String) {}
            override fun onStartDiscoveryFailed(serviceType: String, errorCode: Int) {
                startErrorCode.set(errorCode)
                startFailed.set(true)
            }
            override fun onStopDiscoveryFailed(serviceType: String, errorCode: Int) {}
            override fun onServiceFound(serviceInfo: NsdServiceInfo) {
                found.add(serviceInfo)
            }
            // Serviço perdido não é removido de propósito: se sumiu mesmo, o
            // resolve falha e o candidato cai fora sozinho, sem mexer numa
            // lista que está sendo iterada de outra thread.
            override fun onServiceLost(serviceInfo: NsdServiceInfo) {}
        }

        val started = runCatching {
            nsd.discoverServices(tipo, NsdManager.PROTOCOL_DNS_SD, listener)
        }.isSuccess
        // Recusa síncrona (o framework lança em vez de chamar o callback) não
        // tem código de erro para reportar; -1 a distingue de uma recusa
        // assíncrona, que traz o código do Android.
        if (!started) return Rodada(emptyList(), erroAoIniciar = -1, tipo = tipo)

        try {
            val startedAt = SystemClock.elapsedRealtime()
            while (true) {
                val elapsed = SystemClock.elapsedRealtime() - startedAt
                if (elapsed >= windowMs || startFailed.get()) break
                // Achou o nome que veio do pareamento: não há o que esperar.
                if (found.any { it.serviceName == preferredName }) break
                // Achou *alguma* coisa: dá um tempinho para os outros anúncios
                // chegarem e segue. Esperar a janela inteira à toa é latência
                // que o usuário sente na tela de aprovação.
                if (found.isNotEmpty() && elapsed >= SETTLE_MS) break
                delay(POLL_MS)
            }
        } finally {
            // Precisa rodar mesmo se a corrotina for cancelada (app foi para
            // background no meio da busca), senão a descoberta segue queimando
            // rádio sem ninguém escutando.
            runCatching { nsd.stopServiceDiscovery(listener) }
        }

        return Rodada(
            servicos = found
                .distinctBy { it.serviceName }
                // Ordenação estável: o preferido sobe, o resto mantém a ordem em
                // que apareceu.
                .sortedByDescending { it.serviceName == preferredName },
            erroAoIniciar = if (startFailed.get()) startErrorCode.get() else null,
            tipo = tipo,
        )
    }

    // MARK: - Resolução

    private suspend fun resolve(nsd: NsdManager, service: NsdServiceInfo): NsdServiceInfo? =
        resolveGate.withLock {
            repeat(RESOLVE_ATTEMPTS) {
                var errorCode = 0
                val resolved = withTimeoutOrNull(RESOLVE_TIMEOUT_MS) {
                    suspendCancellableCoroutine<NsdServiceInfo?> { continuation ->
                        @Suppress("DEPRECATION") // registerServiceInfoCallback() é API 34+.
                        nsd.resolveService(service, object : NsdManager.ResolveListener {
                            override fun onResolveFailed(info: NsdServiceInfo, code: Int) {
                                errorCode = code
                                if (continuation.isActive) continuation.resume(null)
                            }

                            override fun onServiceResolved(info: NsdServiceInfo) {
                                if (continuation.isActive) continuation.resume(info)
                            }
                        })
                    }
                }
                if (resolved != null) return resolved
                // Só vale insistir se o framework estava ocupado; qualquer outro
                // erro vai dar no mesmo na segunda tentativa.
                if (errorCode != NsdManager.FAILURE_ALREADY_ACTIVE) return null
                delay(RESOLVE_RETRY_DELAY_MS)
            }
            null
        }

    // MARK: - Enlace

    private fun hasMulticastCapableLink(): Boolean {
        val connectivity = connectivity ?: return true // sem como saber: tenta.
        val capabilities = runCatching {
            connectivity.getNetworkCapabilities(connectivity.activeNetwork)
        }.getOrNull() ?: return false
        return capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) ||
            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)
    }

    companion object {
        /** O mesmo tipo anunciado pelo daemon em `PhoneListener.swift`. */
        const val SERVICE_TYPE = "_phoneauth._tcp"

        /** A forma que o exemplo oficial de NSD do Android usa. Ver [browse]. */
        const val SERVICE_TYPE_COM_PONTO = "$SERVICE_TYPE."

        private const val MULTICAST_TAG = "phoneauth-nsd"
        private const val BROWSE_WINDOW_MS = 6_000L
        private const val BUDGET_MS = 12_000L
        private const val SETTLE_MS = 1_500L
        private const val POLL_MS = 150L
        private const val MAX_CANDIDATES = 4
        private const val RESOLVE_TIMEOUT_MS = 4_000L
        private const val RESOLVE_RETRY_DELAY_MS = 350L
        private const val RESOLVE_ATTEMPTS = 3
    }
}
