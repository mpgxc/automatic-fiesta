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
}
