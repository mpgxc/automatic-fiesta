package dev.phoneauth

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.view.WindowManager
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.camera.core.CameraSelector
import androidx.camera.core.ExperimentalGetImage
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.ImageProxy
import androidx.camera.core.Preview
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.lifecycleScope
import com.google.mlkit.vision.barcode.BarcodeScanner
import com.google.mlkit.vision.barcode.BarcodeScannerOptions
import com.google.mlkit.vision.barcode.BarcodeScanning
import com.google.mlkit.vision.barcode.common.Barcode
import com.google.mlkit.vision.common.InputImage
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Leitor de QR do pareamento.
 *
 * Todo o handshake já está em `PhoneAuthClient.pair()`; esta tela só entrega o
 * texto do QR, mostra o SAS que a função devolve e grava o par no fim. A
 * sequência de estados é a mesma do `PairingView` do iOS — escaneando →
 * conectando → conferindo o SAS → pareado/falhou — porque as duas telas
 * conferem o mesmo código de 6 dígitos contra o mesmo Mac, e divergir aqui só
 * criaria dois fluxos para explicar ao usuário.
 *
 * `FragmentActivity` e não `ComponentActivity`: `pair()` assina com a chave de
 * aprovação, o que dispara o `BiometricPrompt`, que exige um host de fragmentos.
 */
class PairingActivity : FragmentActivity() {

    sealed interface Step {
        /** Ainda sem permissão de câmera. Sem ela não há como ler o QR. */
        data class NeedsCamera(val permanentlyDenied: Boolean) : Step
        data object Scanning : Step
        data object Connecting : Step
        data class Confirming(val sas: String) : Step
        data object Done : Step
        data class Failed(val reason: String) : Step
    }

    private val client by lazy { PhoneAuthClient(lifecycleScope) }
    private val store by lazy { PeerStore(this) }

    private var step: Step by mutableStateOf(Step.NeedsCamera(permanentlyDenied = false))

    // Só QR: restringir o formato deixa o detector mais rápido e evita que um
    // código de barras qualquer no enquadramento vire uma leitura.
    private val scanner: BarcodeScanner = BarcodeScanning.getClient(
        BarcodeScannerOptions.Builder()
            .setBarcodeFormats(Barcode.FORMAT_QR_CODE)
            .build()
    )

    private val analysisExecutor = Executors.newSingleThreadExecutor()
    private var cameraProvider: ProcessCameraProvider? = null

    /**
     * O analisador dispara várias vezes por segundo e o mesmo QR continua na
     * frente da câmera depois da primeira leitura. Processar duas vezes não
     * seria só redundante: o `sid` do QR vale uma vez só, e a segunda tentativa
     * recriaria as chaves — destruindo o pareamento que a primeira acabou de
     * concluir.
     */
    private val handled = AtomicBoolean(false)

    private val requestCamera =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
            step = if (granted) {
                Step.Scanning
            } else {
                // `shouldShowRequestPermissionRationale` só volta `true`
                // enquanto o sistema ainda deixa perguntar. Logo depois de um
                // "não", `false` significa que o usuário marcou "não perguntar
                // de novo" — insistir com o diálogo não abriria nada, e o único
                // caminho passa a ser os Ajustes.
                Step.NeedsCamera(
                    permanentlyDenied = !shouldShowRequestPermissionRationale(Manifest.permission.CAMERA)
                )
            }
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // O usuário passa esta tela olhando para o Mac, não para o celular: ele
        // aponta a câmera e depois compara seis dígitos com a tela do outro
        // lado. Deixar o aparelho apagar no meio disso cancelaria o handshake,
        // e a sessão de pareamento é de uso único.
        window.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)

        if (hasCameraPermission()) {
            step = Step.Scanning
        } else {
            requestCamera.launch(Manifest.permission.CAMERA)
        }

        setContent {
            val dark = androidx.compose.foundation.isSystemInDarkTheme()
            MaterialTheme(colorScheme = if (dark) darkColorScheme() else lightColorScheme()) {
                Surface(Modifier.fillMaxSize()) { PairingScreen(step) }
            }
        }
    }

    override fun onResume() {
        super.onResume()
        // Quem foi conceder a permissão nos Ajustes volta para cá sem que o
        // launcher de permissão seja notificado — ele só entrega o resultado do
        // diálogo que ele mesmo abriu. Sem esta releitura a tela ficaria presa
        // pedindo algo que já foi concedido.
        if (step is Step.NeedsCamera && hasCameraPermission()) step = Step.Scanning
    }

    override fun onDestroy() {
        super.onDestroy()
        runCatching { cameraProvider?.unbindAll() }
        analysisExecutor.shutdown()
        runCatching { scanner.close() }
    }

    private fun hasCameraPermission(): Boolean =
        ContextCompat.checkSelfPermission(this, Manifest.permission.CAMERA) ==
            PackageManager.PERMISSION_GRANTED

    // MARK: - Câmera

    private fun bindCamera(previewView: PreviewView) {
        val future = ProcessCameraProvider.getInstance(this)
        future.addListener({
            val provider = runCatching { future.get() }.getOrNull()
            if (provider == null) {
                step = Step.Failed("Não foi possível abrir a câmera.")
                return@addListener
            }
            cameraProvider = provider

            val preview = Preview.Builder().build()
                .apply { setSurfaceProvider(previewView.surfaceProvider) }

            val analysis = ImageAnalysis.Builder()
                // O ML Kit é mais lento que a câmera. Enfileirar quadros só
                // atrasaria a leitura do QR que está na frente da lente agora.
                .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                .build()
                .apply { setAnalyzer(analysisExecutor, QrAnalyzer(scanner, ::onQrText)) }

            runCatching {
                provider.unbindAll()
                provider.bindToLifecycle(
                    this@PairingActivity,
                    CameraSelector.DEFAULT_BACK_CAMERA,
                    preview,
                    analysis,
                )
            }.onFailure {
                step = Step.Failed("Não foi possível abrir a câmera.")
            }
        }, ContextCompat.getMainExecutor(this))
    }

    private fun onQrText(text: String) {
        if (!handled.compareAndSet(false, true)) return

        // A câmera já entregou o que precisávamos; manter o analisador rodando
        // durante o handshake só gastaria bateria e daria a impressão de que a
        // tela ainda está procurando algo.
        runCatching { cameraProvider?.unbindAll() }

        step = Step.Connecting
        startPairing(text)
    }

    /**
     * Um quadro por vez para o ML Kit.
     *
     * O `ImageProxy` precisa ser fechado em **todos** os caminhos: sem isso o
     * CameraX simplesmente para de entregar quadros e a tela congela sem
     * mensagem de erro nenhuma — uma falha que se parece com câmera quebrada.
     */
    @androidx.annotation.OptIn(markerClass = [ExperimentalGetImage::class])
    private class QrAnalyzer(
        private val scanner: BarcodeScanner,
        private val onText: (String) -> Unit,
    ) : ImageAnalysis.Analyzer {

        override fun analyze(proxy: ImageProxy) {
            val frame = proxy.image
            if (frame == null) {
                proxy.close()
                return
            }
            val image = InputImage.fromMediaImage(frame, proxy.imageInfo.rotationDegrees)
            runCatching {
                scanner.process(image)
                    // Os listeners do ML Kit rodam na thread principal, que é
                    // onde o estado do Compose é lido.
                    .addOnSuccessListener { codes ->
                        codes.firstNotNullOfOrNull { it.rawValue }?.let(onText)
                    }
                    .addOnCompleteListener { proxy.close() }
            }.onFailure { proxy.close() }
        }
    }

    // MARK: - Pareamento

    private fun startPairing(qrText: String) {
        lifecycleScope.launch {
            val keyBefore = identityKeyFingerprint()

            val peer = try {
                client.pair(
                    activity = this@PairingActivity,
                    qrText = qrText,
                    deviceName = deviceName(),
                    // `pair()` roda em `Dispatchers.IO` e chama isto de lá.
                    onSas = { sas -> runOnUiThread { step = Step.Confirming(sas) } },
                )
            } catch (e: Exception) {
                // `CancellationException` também cai aqui, de propósito: se a
                // activity morreu no meio do handshake, as chaves recém-criadas
                // ficariam órfãs do mesmo jeito. A limpeza é síncrona e curta,
                // então roda mesmo com o escopo já cancelado.
                discardOrphanKeys(keyBefore)
                step = Step.Failed(describe(e))
                return@launch
            }

            // Só material público. As chaves privadas ficam no Keystore.
            store.save(peer)
            setResult(RESULT_OK)
            step = Step.Done

            // Conectar é responsabilidade da MainActivity: o `PhoneAuthClient`
            // daqui vive no `lifecycleScope` desta tela e a conexão morreria
            // junto com ela no `finish()` abaixo.
            delay(1200)   // um instante para o "Pareado" ser lido
            finish()
        }
    }

    /**
     * `pair()` só chama `DeviceKeys.createKeyPair()` depois de decodificar o QR.
     * Se a falha veio antes disso — um QR ilegível, por exemplo — as chaves que
     * estão no Keystore são de um pareamento anterior que continua valendo, e
     * apagá-las quebraria um pareamento íntegro. Comparar a chave de identidade
     * antes e depois é como saber, de fora, se esta tentativa chegou a criar
     * material novo.
     */
    private fun identityKeyFingerprint(): String? =
        runCatching { DeviceKeys.publicKeySpkiBase64(biometric = false) }.getOrNull()

    private fun discardOrphanKeys(before: String?) {
        if (identityKeyFingerprint() == before) return
        // Sem chaves órfãs: o pareamento falhou, então não há motivo para
        // deixar material criptográfico para trás.
        runCatching { DeviceKeys.deleteAll() }
    }

    private fun deviceName(): String {
        // O nome que o usuário deu ao aparelho é o que ele vai reconhecer na
        // lista do Mac; marca e modelo são só o plano B.
        val chosen = runCatching {
            Settings.Global.getString(contentResolver, Settings.Global.DEVICE_NAME)
        }.getOrNull()?.takeIf { it.isNotBlank() }
            ?: "${Build.MANUFACTURER} ${Build.MODEL}"

        // O transcript é delimitado por `\n` (protocolo §5.2) e o
        // `SignedPayload` rejeita campo com quebra de linha — mas rejeitaria
        // depois de as chaves já terem sido criadas, transformando um nome
        // esquisito de aparelho em pareamento perdido.
        return chosen.replace('\n', ' ').replace('\r', ' ').trim()
    }

    private fun describe(error: Throwable): String = when {
        error is DeviceKeys.BiometricFailedException ->
            // A assinatura biométrica *é* a prova, para o Mac, de que o portão
            // existe neste aparelho. Sem ela não há pareamento — e cancelar é
            // uma decisão legítima do usuário, não defeito do sistema. A frase
            // do Android já explica o motivo (cancelou, errou demais, etc.).
            error.message?.takeIf { it.isNotBlank() }
                ?.let { "Pareamento não concluído: $it" }
                ?: "Pareamento não concluído: a biometria não foi confirmada."

        error is DeviceKeys.KeyMissingException ->
            "Não foi possível criar as chaves neste aparelho."

        isPinningFailure(error) ->
            // O único caso desta lista que merece alarme: o certificado
            // apresentado não é o do QR code.
            "O certificado do Mac não confere com o do QR code.\n" +
                "Não tente de novo: alguém pode estar no meio."

        error is org.json.JSONException || error is IllegalArgumentException ->
            "QR code não reconhecido."

        error is java.io.IOException ->
            "Não foi possível conectar ao Mac. Confira se ele está na mesma rede."

        else -> error.message?.takeIf { it.isNotBlank() } ?: "Falha no pareamento."
    }

    /**
     * O `PinnedTrustManager` recusa com `CertificateException`, mas o JSSE a
     * embrulha numa `SSLHandshakeException` antes de chegar aqui — testar só o
     * tipo do topo faria a falha de pinning se apresentar como erro de rede
     * genérico, que é exatamente o que ela não é.
     */
    private fun isPinningFailure(error: Throwable): Boolean {
        var current: Throwable? = error
        var hops = 0
        while (current != null && hops < 8) {
            if (current is java.security.cert.CertificateException) return true
            current = current.cause
            hops++
        }
        return false
    }

    // MARK: - Telas

    @Composable
    private fun PairingScreen(step: Step) {
        when (step) {
            is Step.NeedsCamera -> NeedsCameraScreen(step.permanentlyDenied)
            Step.Scanning -> ScannerScreen()
            Step.Connecting -> ConnectingScreen()
            is Step.Confirming -> ConfirmingScreen(step.sas)
            Step.Done -> DoneScreen()
            is Step.Failed -> FailedScreen(step.reason)
        }
    }

    @Composable
    private fun NeedsCameraScreen(permanentlyDenied: Boolean) {
        Centered {
            Text("Preciso da câmera", style = MaterialTheme.typography.titleLarge)
            Spacer(Modifier.height(12.dp))
            val explanation = if (permanentlyDenied) {
                "A permissão está negada nos Ajustes. Sem câmera não há como ler o QR code do Mac."
            } else {
                "O QR code do pareamento é lido pela câmera. Nada é gravado nem enviado: " +
                    "a imagem só é analisada aqui no aparelho, à procura do código."
            }
            Text(
                explanation,
                textAlign = TextAlign.Center,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(Modifier.height(24.dp))
            if (permanentlyDenied) {
                Button(onClick = { openAppSettings() }) { Text("Abrir Ajustes") }
            } else {
                Button(onClick = { requestCamera.launch(Manifest.permission.CAMERA) }) {
                    Text("Permitir câmera")
                }
            }
            Spacer(Modifier.height(8.dp))
            TextButton(onClick = { finish() }) { Text("Cancelar") }
        }
    }

    @Composable
    private fun ScannerScreen() {
        Box(Modifier.fillMaxSize()) {
            AndroidView(
                modifier = Modifier.fillMaxSize(),
                factory = { context ->
                    PreviewView(context).also { view ->
                        view.scaleType = PreviewView.ScaleType.FILL_CENTER
                        bindCamera(view)
                    }
                },
            )

            Column(
                modifier = Modifier.align(Alignment.BottomCenter).padding(bottom = 40.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                Surface(
                    color = MaterialTheme.colorScheme.surface.copy(alpha = 0.9f),
                    shape = MaterialTheme.shapes.extraLarge,
                ) {
                    Text(
                        "Aponte para o QR code no Mac",
                        modifier = Modifier.padding(horizontal = 20.dp, vertical = 12.dp),
                    )
                }
                Spacer(Modifier.height(8.dp))
                TextButton(onClick = { finish() }) { Text("Cancelar") }
            }
        }
    }

    @Composable
    private fun ConnectingScreen() {
        Centered {
            CircularProgressIndicator()
            Spacer(Modifier.height(20.dp))
            Text("Conectando ao Mac...", style = MaterialTheme.typography.titleMedium)
            Spacer(Modifier.height(8.dp))
            Text(
                "Confirme com a digital quando o aparelho pedir.",
                textAlign = TextAlign.Center,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }

    /**
     * O código existe para ser **comparado**, então ele é a única coisa grande
     * na tela e o aviso do que fazer quando divergir vem logo abaixo — quem lê
     * um número de seis dígitos no reflexo não protege ninguém.
     */
    @Composable
    private fun ConfirmingScreen(sas: String) {
        Centered {
            Text("Confira o código", style = MaterialTheme.typography.titleMedium)
            Spacer(Modifier.height(16.dp))
            Text(
                sas,
                fontFamily = FontFamily.Monospace,
                fontSize = 44.sp,
                fontWeight = FontWeight.Bold,
                letterSpacing = 6.sp,
            )
            Spacer(Modifier.height(16.dp))
            Text(
                "Confirme no Mac que o número é este.\n" +
                    "Se for diferente, cancele — alguém pode estar no meio.",
                textAlign = TextAlign.Center,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(Modifier.height(32.dp))
            // O Mac só responde depois da confirmação humana (protocolo §3.3),
            // então esta espera pode ser longa e precisa parecer proposital.
            CircularProgressIndicator()
        }
    }

    @Composable
    private fun DoneScreen() {
        Centered {
            Text("Pareado", style = MaterialTheme.typography.headlineSmall)
            Spacer(Modifier.height(8.dp))
            Text(
                "Este Mac já pode pedir sua digital.",
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }

    @Composable
    private fun FailedScreen(reason: String) {
        Centered {
            Text(
                "Não pareou",
                style = MaterialTheme.typography.titleLarge,
                color = MaterialTheme.colorScheme.error,
            )
            Spacer(Modifier.height(12.dp))
            Text(reason, textAlign = TextAlign.Center)
            Spacer(Modifier.height(24.dp))
            Button(onClick = { retry() }) { Text("Tentar de novo") }
            Spacer(Modifier.height(8.dp))
            TextButton(onClick = { finish() }) { Text("Fechar") }
        }
    }

    @Composable
    private fun Centered(content: @Composable ColumnScope.() -> Unit) {
        Column(
            modifier = Modifier.fillMaxSize().padding(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center,
            content = content,
        )
    }

    private fun retry() {
        // O QR anterior já foi consumido (ou nem chegou a valer); a sessão de
        // pareamento no Mac é de uso único, então tentar de novo significa
        // escanear um código novo, não repetir o mesmo.
        handled.set(false)
        step = if (hasCameraPermission()) Step.Scanning else Step.NeedsCamera(false)
    }

    private fun openAppSettings() {
        runCatching {
            startActivity(
                Intent(
                    Settings.ACTION_APPLICATION_DETAILS_SETTINGS,
                    Uri.fromParts("package", packageName, null),
                )
            )
        }
    }
}
