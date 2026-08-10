package dev.phoneauth

import java.security.MessageDigest

/**
 * Gêmeo de `macos/Sources/PhoneAuthCore/SignedPayload.swift` e de
 * `mobile/ios/PhoneAuth/SignedPayload.swift`.
 *
 * Os três precisam produzir bytes idênticos. Os testes das três implementações
 * rodam os mesmos vetores de `docs/test-vectors.json`, então uma divergência
 * aparece como teste vermelho e não como um misterioso "aprovei e o Mac
 * recusou".
 *
 * Se você mudar este arquivo, mude os outros dois na mesma mudança.
 */
object SignedPayload {

    const val AUTH_DOMAIN = "PHONEAUTH-AUTH-V1"
    const val CONTEXT_DOMAIN = "PHONEAUTH-CTX-V1"
    const val PAIR_DOMAIN = "PHONEAUTH-PAIR-V1"
    const val HELLO_DOMAIN = "PHONEAUTH-HELLO-V1"

    class NewlineInFieldException(field: String) :
        IllegalArgumentException("campo '$field' contém quebra de linha, o que tornaria o payload ambíguo")

    /**
     * Caracteres que quebram linha de verdade quando renderizados.
     *
     * Vai além de `\n` e `\r` porque a regra existe para proteger a **tela**,
     * não só a serialização. O campo `reason` carrega o argv de quem chamou o
     * `sudo` — texto controlado pelo atacante — e é exibido cru na tela de
     * aprovação. Todos são classe BK/NL no UAX#14, ou seja, quebra obrigatória
     * no line-breaker do ICU que o Android usa.
     *
     * Sem VT/FF/NEL/LS/PS na lista, um `reason` com U+000B aparece no celular
     * como duas linhas, a segunda escrita pelo atacante.
     *
     * Todos são BMP, então comparar `Char` (code unit UTF-16) basta.
     */
    private val LINE_BREAKING = charArrayOf(
        '\u000A',  // LF
        '\u000B',  // VT
        '\u000C',  // FF
        '\u000D',  // CR
        '\u0085',  // NEL
        '\u2028',  // LINE SEPARATOR
        '\u2029',  // PARAGRAPH SEPARATOR
    )

    private fun serialize(fields: List<Pair<String, String>>): ByteArray {
        fields.forEach { (name, value) ->
            if (value.any { it in LINE_BREAKING }) throw NewlineInFieldException(name)
        }
        return (fields.joinToString("\n") { it.second } + "\n").toByteArray(Charsets.UTF_8)
    }

    data class Context(
        val host: String,
        val user: String,
        val service: String,
        val reason: String,
        val processPath: String = "",
        val tty: String = "",
    )

    fun contextBytes(ctx: Context): ByteArray = serialize(
        listOf(
            "domain" to CONTEXT_DOMAIN,
            "host" to ctx.host,
            "user" to ctx.user,
            "service" to ctx.service,
            "reason" to ctx.reason,
            "processPath" to ctx.processPath,
            "tty" to ctx.tty,
        )
    )

    fun contextHash(ctx: Context): String = sha256Hex(contextBytes(ctx))

    enum class Decision(val wire: String) {
        ALLOW("allow"),
        DENY("deny"),
    }

    fun authBytes(
        requestId: String,
        challengeBase64: String,
        contextHash: String,
        channelBinding: String,
        issuedAt: Long,
        decision: Decision,
    ): ByteArray = serialize(
        listOf(
            "domain" to AUTH_DOMAIN,
            "requestId" to requestId,
            "challenge" to challengeBase64,
            "contextHash" to contextHash,
            "channelBinding" to channelBinding,
            "issuedAt" to issuedAt.toString(),
            "decision" to decision.wire,
        )
    )

    fun pairBytes(
        sid: String,
        spki: String,
        idPublicKeyBase64: String,
        authPublicKeyBase64: String,
        deviceName: String,
        platform: String,
    ): ByteArray = serialize(
        listOf(
            "domain" to PAIR_DOMAIN,
            "sid" to sid,
            "spki" to spki,
            "idPublicKey" to idPublicKeyBase64,
            "authPublicKey" to authPublicKeyBase64,
            "deviceName" to deviceName,
            "platform" to platform,
        )
    )

    fun helloBytes(
        deviceId: String,
        nonceBase64: String,
        channelBinding: String,
    ): ByteArray = serialize(
        listOf(
            "domain" to HELLO_DOMAIN,
            "deviceId" to deviceId,
            "nonce" to nonceBase64,
            "channelBinding" to channelBinding,
        )
    )

    fun sha256Hex(data: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(data)
            .joinToString("") { "%02x".format(it) }
}
