package dev.phoneauth

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import androidx.biometric.BiometricPrompt
import androidx.fragment.app.FragmentActivity
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlinx.coroutines.suspendCancellableCoroutine

/**
 * As duas chaves do dispositivo, dentro do Android Keystore (StrongBox quando
 * disponível).
 *
 * É aqui que mora a garantia de segurança do projeto inteiro. Não estamos
 * perguntando ao Android "o usuário autenticou?" e reportando a resposta ao Mac
 * — isso seria uma afirmação do app, e um app pode ser modificado ou rodar num
 * aparelho com root.
 *
 * Em vez disso, a chave privada é criada **dentro** do hardware seguro com
 * `setUserAuthenticationRequired(true)`. O Keystore só libera a operação de
 * assinatura depois que o `BiometricPrompt` autenticou, e a chave nunca sai do
 * hardware. A assinatura, portanto, é prova de que a digital foi apresentada —
 * não um relato de que foi.
 */
object DeviceKeys {

    private const val KEYSTORE = "AndroidKeyStore"
    private const val ID_ALIAS = "dev.phoneauth.key.identity"
    private const val AUTH_ALIAS = "dev.phoneauth.key.approval"

    class KeyMissingException : Exception("chave não encontrada; refaça o pareamento")
    class BiometricFailedException(message: String) : Exception(message)

    private val keyStore: KeyStore
        get() = KeyStore.getInstance(KEYSTORE).apply { load(null) }

    // MARK: - Criação

    /**
     * Cria as duas chaves. Chamado uma vez, no pareamento.
     *
     * Se já existirem, são apagadas antes: parear de novo significa começar do
     * zero, e uma chave órfã de um pareamento anterior só serviria para
     * confundir.
     */
    fun createKeyPair() {
        deleteAll()
        create(ID_ALIAS, biometricGated = false)
        create(AUTH_ALIAS, biometricGated = true)
    }

    private fun create(alias: String, biometricGated: Boolean) {
        // StrongBox é um elemento seguro dedicado, separado do processador
        // principal. Nem todo aparelho tem, então tentamos e caímos para o TEE
        // quando não houver — que ainda é hardware, só menos isolado.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            try {
                generate(alias, biometricGated, strongBox = true)
                return
            } catch (_: Exception) {
                // Sem StrongBox neste aparelho; segue para o TEE.
            }
        }
        generate(alias, biometricGated, strongBox = false)
    }

    private fun generate(alias: String, biometricGated: Boolean, strongBox: Boolean) {
        val builder = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)

        if (strongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            builder.setIsStrongBoxBacked(true)
        }

        if (biometricGated) {
            // A diferença entre as duas chaves está aqui.
            //
            // `setUserAuthenticationRequired(true)` com timeout 0 significa que
            // cada assinatura exige uma autenticação nova — o Keystore não
            // reaproveita uma anterior. É por isso que a assinatura vale como
            // prova.
            builder.setUserAuthenticationRequired(true)

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                builder.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
            } else {
                @Suppress("DEPRECATION")
                builder.setUserAuthenticationValidityDurationSeconds(-1)
            }

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                // Se alguém cadastrar uma digital nova, o Android **destrói** a
                // chave. É o que impede o ataque "peguei o celular desbloqueado
                // e cadastrei meu dedo". O dispositivo passa a falhar toda
                // aprovação e precisa ser pareado de novo, o que exige acesso
                // físico ao Mac desbloqueado.
                builder.setInvalidatedByBiometricEnrollment(true)
            }
        }
        // A chave de identidade fica sem exigência de autenticação, de
        // propósito: ela autentica a conexão TCP e é usada a cada reconexão. Se
        // pedisse biometria, o usuário encostaria o dedo a cada troca de Wi-Fi
        // e aprenderia a fazer isso no automático — o hábito que destrói a
        // segurança de todo o sistema.

        KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, KEYSTORE).run {
            initialize(builder.build())
            generateKeyPair()
        }
    }

    // MARK: - Chave pública

    /**
     * `getEncoded()` de uma chave pública já devolve SubjectPublicKeyInfo DER,
     * que é exatamente o formato do protocolo. No iOS é preciso envelopar o
     * ponto cru; aqui não.
     */
    fun publicKeySpkiBase64(biometric: Boolean): String {
        val alias = if (biometric) AUTH_ALIAS else ID_ALIAS
        val certificate = keyStore.getCertificate(alias) ?: throw KeyMissingException()
        return Base64.encodeToString(certificate.publicKey.encoded, Base64.NO_WRAP)
    }

    fun hasKeys(): Boolean = keyStore.containsAlias(ID_ALIAS)

    fun deleteAll() {
        val store = keyStore
        listOf(ID_ALIAS, AUTH_ALIAS).forEach {
            if (store.containsAlias(it)) store.deleteEntry(it)
        }
    }

    // MARK: - Assinatura

    /** Assina com a chave de identidade. Não pede biometria — por desenho. */
    fun signWithIdentityKey(message: ByteArray): String {
        val entry = keyStore.getEntry(ID_ALIAS, null) as? KeyStore.PrivateKeyEntry
            ?: throw KeyMissingException()
        val signature = Signature.getInstance("SHA256withECDSA").apply {
            initSign(entry.privateKey)
            update(message)
        }
        return Base64.encodeToString(signature.sign(), Base64.NO_WRAP)
    }

    /**
     * Assina com a chave de aprovação. **Dispara a biometria.**
     *
     * O `CryptoObject` é o ponto central: o objeto `Signature` é entregue ao
     * `BiometricPrompt` sem estar autorizado, e o Keystore só o destrava depois
     * da autenticação bem-sucedida. Não existe caminho em que este código
     * consiga assinar sem o prompt ter passado — não é uma checagem que
     * poderíamos "esquecer" de fazer.
     */
    suspend fun signWithApprovalKey(
        activity: FragmentActivity,
        message: ByteArray,
        title: String,
        subtitle: String,
    ): String = suspendCancellableCoroutine { continuation ->
        val entry = keyStore.getEntry(AUTH_ALIAS, null) as? KeyStore.PrivateKeyEntry
        if (entry == null) {
            continuation.resumeWithException(KeyMissingException())
            return@suspendCancellableCoroutine
        }

        val signature = Signature.getInstance("SHA256withECDSA").apply {
            initSign(entry.privateKey)
        }

        val prompt = BiometricPrompt(
            activity,
            androidx.core.content.ContextCompat.getMainExecutor(activity),
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    try {
                        val authorized = result.cryptoObject?.signature
                            ?: throw BiometricFailedException("o prompt não devolveu o objeto de assinatura")
                        authorized.update(message)
                        continuation.resume(Base64.encodeToString(authorized.sign(), Base64.NO_WRAP))
                    } catch (e: Exception) {
                        continuation.resumeWithException(e)
                    }
                }

                override fun onAuthenticationError(code: Int, message: CharSequence) {
                    // Cancelar não é erro do sistema: é o usuário decidindo não
                    // aprovar. Sem assinatura, o Mac não libera nada.
                    continuation.resumeWithException(BiometricFailedException(message.toString()))
                }
            }
        )

        val info = BiometricPrompt.PromptInfo.Builder()
            .setTitle(title)
            .setSubtitle(subtitle)
            .setNegativeButtonText("Negar")
            .setAllowedAuthenticators(androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG)
            .build()

        prompt.authenticate(info, BiometricPrompt.CryptoObject(signature))
        continuation.invokeOnCancellation { prompt.cancelAuthentication() }
    }
}
