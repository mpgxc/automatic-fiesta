package dev.phoneauth

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertThrows
import org.junit.Test

/**
 * Os mesmos vetores de resposta conhecida que o daemon macOS e o app iOS
 * rodam. Calculados de forma independente por `docs/generate-test-vectors.py` e
 * fixados em `docs/test-vectors.json`.
 *
 * Se as três implementações baterem contra os mesmos valores, as assinaturas
 * verificam entre plataformas. Se qualquer uma divergir, o bug aparece aqui e
 * não como um misterioso "aprovei no celular e o Mac recusou".
 */
class SignedPayloadTest {

    /**
     * java.util.Base64 e não android.util.Base64: este é um teste JVM puro, e o
     * android.util no classpath de teste é um stub sem implementação. Trocar
     * evita arrastar o Robolectric só para codificar bytes.
     */
    private fun b64(bytes: ByteArray): String = java.util.Base64.getEncoder().encodeToString(bytes)

    private val sampleContext = SignedPayload.Context(
        host = "MacBook Pro de mpgxc",
        user = "mpgxc",
        service = "sudo",
        reason = "sudo brew install ripgrep",
        processPath = "/usr/bin/sudo",
        tty = "ttys002",
    )

    @Test
    fun `contexto bate com o vetor`() {
        val bytes = SignedPayload.contextBytes(sampleContext)
        assertEquals(97, bytes.size)
        assertEquals(
            "51eae53b67ffb644ba5a20529ad453ccd6e05b61d4832c390c82e33992d52d9b",
            SignedPayload.sha256Hex(bytes),
        )
    }

    /**
     * Campo vazio não some: a linha continua existindo. Sem isso, um contexto
     * com `reason` vazio colidiria com outro que tivesse os campos deslocados.
     */
    @Test
    fun `campos vazios mantêm suas linhas`() {
        val bytes = SignedPayload.contextBytes(
            SignedPayload.Context(host = "Mac", user = "root", service = "su", reason = "")
        )
        assertEquals(32, bytes.size)
        assertEquals(
            "612a5428fbff7ff14778574fdfd1db4788fbabde8a726117fd4039499985fc3d",
            SignedPayload.sha256Hex(bytes),
        )
    }

    @Test
    fun `aprovação bate com o vetor`() {
        val bytes = SignedPayload.authBytes(
            requestId = "3F2504E0-4F89-41D3-9A0C-0305E82C3301",
            challengeBase64 = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
            contextHash = "51eae53b67ffb644ba5a20529ad453ccd6e05b61d4832c390c82e33992d52d9b",
            channelBinding = "a".repeat(64),
            issuedAt = 1_770_000_000L,
            decision = SignedPayload.Decision.ALLOW,
        )
        assertEquals(247, bytes.size)
        assertEquals(
            "d505f91918d1bdb56bb4179a257b1f47e966f739d75c2c31f4303069372529b0",
            SignedPayload.sha256Hex(bytes),
        )
    }

    /**
     * Aprovação e negação precisam produzir bytes distintos, ou uma assinatura
     * de "deny" poderia ser reapresentada como "allow".
     */
    @Test
    fun `negação difere de aprovação`() {
        fun bytes(decision: SignedPayload.Decision) = SignedPayload.authBytes(
            requestId = "3F2504E0-4F89-41D3-9A0C-0305E82C3301",
            challengeBase64 = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
            contextHash = "51eae53b67ffb644ba5a20529ad453ccd6e05b61d4832c390c82e33992d52d9b",
            channelBinding = "a".repeat(64),
            issuedAt = 1_770_000_000L,
            decision = decision,
        )
        assertNotEquals(
            SignedPayload.sha256Hex(bytes(SignedPayload.Decision.ALLOW)),
            SignedPayload.sha256Hex(bytes(SignedPayload.Decision.DENY)),
        )
        assertEquals(
            "9f565d0511a5693d209b176a7dfd0a4de6b6145bdd2c19bb69d8bdde8d2904ae",
            SignedPayload.sha256Hex(bytes(SignedPayload.Decision.DENY)),
        )
    }

    @Test
    fun `pareamento bate com o vetor`() {
        val idKey = b64(ByteArray(91) { 0x11 })
        val authKey = b64(ByteArray(91) { 0x22 })
        val bytes = SignedPayload.pairBytes(
            sid = "7B3E1A2C-0000-4000-8000-000000000001",
            spki = "b".repeat(64),
            idPublicKeyBase64 = idKey,
            authPublicKeyBase64 = authKey,
            deviceName = "iPhone 15 de mpgxc",
            platform = "ios",
        )
        assertEquals(393, bytes.size)
        assertEquals(
            "6eb2345096b00b95579e96e6a6a7380429a1e987c7e4e4854cabf5e792640d84",
            SignedPayload.sha256Hex(bytes),
        )
    }

    @Test
    fun `hello bate com o vetor`() {
        val nonce = b64(ByteArray(32) { 0xAA.toByte() })
        val bytes = SignedPayload.helloBytes(
            deviceId = "9C1D2E3F-0000-4000-8000-000000000002",
            nonceBase64 = nonce,
            channelBinding = "a".repeat(64),
        )
        assertEquals(166, bytes.size)
        assertEquals(
            "e2d35c4b5772349157abfd31905482f68b76d05d3d4359b0db30640dcfe74977",
            SignedPayload.sha256Hex(bytes),
        )
    }

    /**
     * A regra que impede um `reason` malicioso de injetar linhas e fazer um
     * pedido se apresentar como algo inofensivo enquanto o hash cobre outra
     * coisa. Se este teste algum dia falhar, o formato virou ambíguo.
     */
    @Test
    fun `quebra de linha em qualquer campo é rejeitada`() {
        assertThrows(SignedPayload.NewlineInFieldException::class.java) {
            SignedPayload.contextBytes(
                SignedPayload.Context(
                    host = "Mac", user = "mpgxc", service = "sudo",
                    reason = "sudo true\nPHONEAUTH-CTX-V1\nMac",
                )
            )
        }
        assertThrows(SignedPayload.NewlineInFieldException::class.java) {
            SignedPayload.contextBytes(
                SignedPayload.Context(host = "Mac\r", user = "u", service = "sudo", reason = "x")
            )
        }
        assertThrows(SignedPayload.NewlineInFieldException::class.java) {
            SignedPayload.authBytes(
                requestId = "id\nfalso", challengeBase64 = "AA==", contextHash = "00",
                channelBinding = "00", issuedAt = 0, decision = SignedPayload.Decision.ALLOW,
            )
        }
    }

    /**
     * CRLF é o caso que quase escapou — do lado Swift, não daqui.
     *
     * `String.contains("\n")` em Swift resolve para a sobrecarga de `Character`,
     * e `"\r\n"` é UM único `Character` (GB3 do UAX#29). Com a checagem antiga o
     * Swift aceitava e o Kotlin rejeitava, produzindo o "aprovei no iPhone e no
     * Android quebrou" que estes gêmeos existem para impedir. Este teste trava
     * o comportamento dos dois lados.
     */
    @Test
    fun `CRLF é rejeitado`() {
        assertThrows(SignedPayload.NewlineInFieldException::class.java) {
            SignedPayload.contextBytes(
                SignedPayload.Context(
                    host = "Mac", user = "u", service = "sudo",
                    reason = "sudo true\r\nlinha falsa",
                )
            )
        }
    }

    /**
     * `reason` carrega o argv de quem chamou o `sudo` e é exibido cru na tela de
     * aprovação. Estes são quebra obrigatória no UAX#14, então sem rejeitá-los
     * um atacante escreve a segunda linha do que o usuário lê antes de aprovar.
     */
    @Test
    fun `todo caractere que quebra linha é rejeitado`() {
        for (code in listOf(0x000A, 0x000B, 0x000C, 0x000D, 0x0085, 0x2028, 0x2029)) {
            assertThrows(
                "U+%04X deveria ser rejeitado".format(code),
                SignedPayload.NewlineInFieldException::class.java,
            ) {
                SignedPayload.contextBytes(
                    SignedPayload.Context(
                        host = "Mac", user = "u", service = "sudo",
                        reason = "rm -rf /${code.toChar()}Toque para confirmar",
                    )
                )
            }
        }
    }

    /** A regra ficou mais estrita; não pode ter ficado estrita demais. */
    @Test
    fun `texto legítimo continua passando`() {
        for (reason in listOf(
            "sudo brew install ripgrep", "café com acento", "tab\tinterno",
            "emoji 🔐 no motivo", "chinês 中文", "",
        )) {
            SignedPayload.contextBytes(
                SignedPayload.Context(host = "Mac", user = "u", service = "sudo", reason = reason)
            )
        }
    }

    // ── Rotação de identidade ────────────────────────────────────────────
    //
    // Hoje só macOS e Android implementam estes domínios. Os vetores garantem
    // que os dois produzem os mesmos bytes — sem eles, o gêmeo escrito depois
    // nasceria sem rede de proteção.

    @Test
    fun `anúncio de rotação bate com o vetor`() {
        val bytes = SignedPayload.rotateBytes(
            rotationId = "5D8C7B6A-0000-4000-8000-000000000003",
            currentSpki = "c".repeat(64),
            nextSpki = "d".repeat(64),
            announcedAt = 1_770_000_000L,
            commitNotBefore = 1_770_086_400L,
            expiresAt = 1_770_604_800L,
            retirePrevious = true,
        )
        assertEquals(225, bytes.size)
        assertEquals(
            "a1d0e476d71f7e9182e2c8a1004f9242c266e634b67110b1def4535d1d33a3a5",
            SignedPayload.sha256Hex(bytes),
        )
    }

    /**
     * `retirePrevious` vira string literal. As duas formas ficam travadas
     * porque cada linguagem formata booleano do seu jeito, e um `False`
     * maiúsculo quebraria a assinatura sem quebrar nada visível.
     */
    @Test
    fun `anúncio sem aposentar o pin antigo bate com o vetor`() {
        val bytes = SignedPayload.rotateBytes(
            rotationId = "5D8C7B6A-0000-4000-8000-000000000003",
            currentSpki = "c".repeat(64),
            nextSpki = "d".repeat(64),
            announcedAt = 1_770_000_000L,
            commitNotBefore = 1_770_086_400L,
            expiresAt = 1_770_604_800L,
            retirePrevious = false,
        )
        assertEquals(226, bytes.size)
        assertEquals(
            "dce03083efc8e9839c57de6329c9ac0ec2c9e668856df97fdc389b2add94c752",
            SignedPayload.sha256Hex(bytes),
        )
    }

    @Test
    fun `ack de rotação bate com o vetor`() {
        val bytes = SignedPayload.rotateAckBytes(
            rotationId = "5D8C7B6A-0000-4000-8000-000000000003",
            deviceId = "9C1D2E3F-0000-4000-8000-000000000002",
            adoptedSpki = "d".repeat(64),
            channelBinding = "a".repeat(64),
        )
        assertEquals(228, bytes.size)
        assertEquals(
            "73f0520475788b394d3149a6b489f7e4a26571f9b12a606501b9fc8be2240279",
            SignedPayload.sha256Hex(bytes),
        )
    }

    /**
     * O Sas do PhoneAuthClient.kt é HKDF escrito à mão e é a criptografia de
     * maior risco do app Android — e não havia nada exercitando. O vetor vem de
     * docs/test-vectors.json, o mesmo que o teste macOS afirma.
     */
    @Test
    fun `SAS bate com o vetor`() {
        val transcript = SignedPayload.pairBytes(
            sid = "7B3E1A2C-0000-4000-8000-000000000001",
            spki = "b".repeat(64),
            idPublicKeyBase64 = b64(ByteArray(91) { 0x11 }),
            authPublicKeyBase64 = b64(ByteArray(91) { 0x22 }),
            deviceName = "iPhone 15 de mpgxc",
            platform = "ios",
        )
        val psk = ByteArray(32) { it.toByte() }
        assertEquals("561453", Sas.compute(transcript, psk))
    }
}
