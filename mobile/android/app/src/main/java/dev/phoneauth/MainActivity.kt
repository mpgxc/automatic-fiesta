package dev.phoneauth

import android.os.Build
import android.os.Bundle
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

/**
 * FragmentActivity e não ComponentActivity: o BiometricPrompt exige um host de
 * fragmentos.
 */
class MainActivity : FragmentActivity() {

    private val client by lazy { PhoneAuthClient(lifecycleScope) }
    private val store by lazy { PeerStore(this) }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        store.load()?.let { client.connect(it) }

        setContent {
            MaterialTheme(colorScheme = if (isSystemInDarkThemeCompat()) darkColorScheme() else lightColorScheme()) {
                Surface(Modifier.fillMaxSize()) {
                    val pending by client.pending.collectAsState()
                    val state by client.state.collectAsState()
                    val peer = remember { mutableStateOf(store.load()) }

                    when {
                        pending != null -> ApprovalScreen(
                            challenge = pending!!,
                            onApprove = {
                                lifecycleScope.launch {
                                    // Cancelar a biometria cai aqui. Não é
                                    // erro: é o usuário decidindo não aprovar.
                                    runCatching { client.approve(this@MainActivity, it) }
                                }
                            },
                            onDeny = { lifecycleScope.launch { client.deny(it) } },
                        )

                        peer.value != null -> IdleScreen(
                            peer = peer.value!!,
                            state = state,
                            onReconnect = { client.connect(peer.value!!) },
                            onForget = {
                                client.disconnect()
                                DeviceKeys.deleteAll()
                                store.clear()
                                peer.value = null
                            },
                        )

                        else -> UnpairedScreen()
                    }
                }
            }
        }
    }

    @Composable
    private fun isSystemInDarkThemeCompat(): Boolean =
        androidx.compose.foundation.isSystemInDarkTheme()
}

/**
 * A tela que carrega o peso da segurança do sistema.
 *
 * A defesa contra um processo malicioso disparando `sudo` e torcendo pela
 * aprovação por reflexo é o usuário **ler** isto. Por isso o motivo vem grande
 * e primeiro, e o botão de aprovar não é o mais proeminente da tela.
 */
@Composable
fun ApprovalScreen(
    challenge: PhoneAuthClient.AuthChallenge,
    onApprove: (PhoneAuthClient.AuthChallenge) -> Unit,
    onDeny: (PhoneAuthClient.AuthChallenge) -> Unit,
) {
    var remaining by remember { mutableIntStateOf(challenge.secondsRemaining) }
    LaunchedEffect(challenge.requestId) {
        while (remaining > 0) {
            delay(1000)
            remaining = challenge.secondsRemaining
        }
    }

    Column(
        modifier = Modifier.fillMaxSize().padding(24.dp).verticalScroll(rememberScrollState()),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(20.dp),
    ) {
        Spacer(Modifier.height(32.dp))

        Text(challenge.context.host, style = MaterialTheme.typography.titleLarge)
        Text("pede autenticação", color = MaterialTheme.colorScheme.onSurfaceVariant)

        Card(Modifier.fillMaxWidth()) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Text(
                    challenge.context.reason,
                    fontFamily = FontFamily.Monospace,
                    style = MaterialTheme.typography.bodyMedium,
                )
                HorizontalDivider()
                Row(Modifier.fillMaxWidth(), Arrangement.SpaceBetween) {
                    Text("usuário", color = MaterialTheme.colorScheme.onSurfaceVariant)
                    Text(challenge.context.user)
                }
                Row(Modifier.fillMaxWidth(), Arrangement.SpaceBetween) {
                    Text("serviço", color = MaterialTheme.colorScheme.onSurfaceVariant)
                    Text(challenge.context.service)
                }
                if (challenge.context.tty.isNotEmpty()) {
                    Row(Modifier.fillMaxWidth(), Arrangement.SpaceBetween) {
                        Text("terminal", color = MaterialTheme.colorScheme.onSurfaceVariant)
                        Text(challenge.context.tty)
                    }
                }
            }
        }

        Text(
            "expira em ${remaining}s",
            style = MaterialTheme.typography.labelMedium,
            color = if (remaining < 10) MaterialTheme.colorScheme.error
                    else MaterialTheme.colorScheme.onSurfaceVariant,
        )

        Spacer(Modifier.weight(1f))

        Button(
            onClick = { onApprove(challenge) },
            modifier = Modifier.fillMaxWidth().height(52.dp),
            enabled = remaining > 0,
        ) { Text("Aprovar com biometria") }

        OutlinedButton(
            onClick = { onDeny(challenge) },
            modifier = Modifier.fillMaxWidth().height(52.dp),
        ) { Text("Negar") }
    }
}

@Composable
fun IdleScreen(
    peer: PhoneAuthClient.Peer,
    state: PhoneAuthClient.State,
    onReconnect: () -> Unit,
    onForget: () -> Unit,
) {
    Column(
        modifier = Modifier.fillMaxSize().padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) {
        Text(peer.name, style = MaterialTheme.typography.titleLarge)
        Spacer(Modifier.height(8.dp))
        Text(
            when (state) {
                is PhoneAuthClient.State.Connected -> "pronto para aprovar"
                is PhoneAuthClient.State.Connecting -> "conectando..."
                is PhoneAuthClient.State.Failed -> state.reason
                is PhoneAuthClient.State.Idle -> "desconectado"
            },
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            textAlign = TextAlign.Center,
        )
        Spacer(Modifier.height(32.dp))
        if (state is PhoneAuthClient.State.Failed || state is PhoneAuthClient.State.Idle) {
            Button(onClick = onReconnect) { Text("Reconectar") }
        }
        Spacer(Modifier.height(16.dp))
        TextButton(onClick = onForget) { Text("Esquecer este Mac") }
    }
}

@Composable
fun UnpairedScreen() {
    Column(
        modifier = Modifier.fillMaxSize().padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) {
        Text("Nenhum Mac pareado", style = MaterialTheme.typography.titleLarge)
        Spacer(Modifier.height(12.dp))
        Text(
            "No Mac, rode `sudo phoneauthctl pair` e escaneie o código com este app.",
            textAlign = TextAlign.Center,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(Modifier.height(24.dp))
        Text(
            "O leitor de QR está em PairingActivity.",
            fontSize = 12.sp,
            fontWeight = FontWeight.Light,
        )
    }
}

/**
 * Guarda o Mac pareado. Só material público — o hash de SPKI e o endereço. As
 * chaves privadas vivem no Keystore e nunca passam por aqui.
 */
class PeerStore(context: android.content.Context) {
    private val prefs = context.getSharedPreferences("dev.phoneauth", android.content.Context.MODE_PRIVATE)

    fun save(peer: PhoneAuthClient.Peer) {
        prefs.edit()
            .putString("host", peer.host)
            .putInt("port", peer.port)
            .putString("spki", peer.spki)
            .putString("name", peer.name)
            .putString("deviceId", peer.deviceId)
            .apply()
    }

    fun load(): PhoneAuthClient.Peer? {
        val host = prefs.getString("host", null) ?: return null
        return PhoneAuthClient.Peer(
            host = host,
            port = prefs.getInt("port", 58731),
            spki = prefs.getString("spki", "") ?: "",
            name = prefs.getString("name", "Mac") ?: "Mac",
            deviceId = prefs.getString("deviceId", null),
        )
    }

    fun clear() = prefs.edit().clear().apply()
}
