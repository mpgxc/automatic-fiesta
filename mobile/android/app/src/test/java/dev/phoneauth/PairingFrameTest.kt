package dev.phoneauth

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.DataInputStream
import java.io.EOFException

/**
 * O pareamento quebrava porque o cliente lia **um** quadro depois de mandar o
 * `pair.request` e presumia que era a resposta.
 *
 * Não era: o daemon manda um `hello.challenge` assim que a conexão fica pronta,
 * antes de qualquer pedido, porque naquele momento ainda não sabe se quem
 * conectou vem parear ou autenticar. O celular lia o desafio, via que não era
 * `pair.ok` e desistia — enquanto o Mac, do outro lado, já tinha validado tudo
 * e estava mostrando o SAS na tela, esperando confirmação.
 *
 * O que estes testes fixam é a ordem: o que vem antes da resposta se descarta,
 * a resposta se devolve.
 */
class PairingFrameTest {

    private fun fluxo(vararg quadros: String): DataInputStream {
        val saida = java.io.ByteArrayOutputStream()
        for (q in quadros) {
            val corpo = q.toByteArray(Charsets.UTF_8)
            saida.write(
                byteArrayOf(
                    (corpo.size shr 24).toByte(), (corpo.size shr 16).toByte(),
                    (corpo.size shr 8).toByte(), corpo.size.toByte(),
                )
            )
            saida.write(corpo)
        }
        return DataInputStream(ByteArrayInputStream(saida.toByteArray()))
    }

    @Test
    fun `pula o hello_challenge que o daemon manda antes de tudo`() {
        val lido = PhoneAuthClient.lerAteRespostaDoPareamento(
            fluxo(
                """{"type":"hello.challenge","nonce":"YWJj"}""",
                """{"type":"pair.ok","deviceId":"dev-1"}""",
            )
        )
        assertEquals("pair.ok", lido.optString("type"))
        assertEquals("dev-1", lido.optString("deviceId"))
    }

    @Test
    fun `devolve o erro com o codigo, sem confundir com o desafio`() {
        val lido = PhoneAuthClient.lerAteRespostaDoPareamento(
            fluxo(
                """{"type":"hello.challenge","nonce":"YWJj"}""",
                """{"type":"error","code":"pairing_expired","message":""}""",
            )
        )
        assertEquals("error", lido.optString("type"))
        assertEquals("pairing_expired", lido.optString("code"))
    }

    /**
     * O protocolo pode ganhar quadros novos sem que o pareamento saiba deles.
     * Ignorar o desconhecido é o que impede que um acréscimo lá na frente
     * reintroduza exatamente este defeito.
     */
    @Test
    fun `ignora quadros desconhecidos ate a resposta`() {
        val lido = PhoneAuthClient.lerAteRespostaDoPareamento(
            fluxo(
                """{"type":"hello.challenge","nonce":"YWJj"}""",
                """{"type":"ping"}""",
                """{"type":"algo.que.ainda.nao.existe"}""",
                """{"type":"pair.ok","deviceId":"dev-2"}""",
            )
        )
        assertEquals("dev-2", lido.optString("deviceId"))
    }

    /**
     * Sem resposta e sem mais bytes, a leitura tem de terminar em erro em vez
     * de girar: o `readFully` do quadro seguinte encontra o fim do fluxo.
     */
    @Test(expected = EOFException::class)
    fun `estoura quando a conexao acaba antes da resposta`() {
        PhoneAuthClient.lerAteRespostaDoPareamento(
            fluxo("""{"type":"hello.challenge","nonce":"YWJj"}""")
        )
    }

    @Test(expected = IllegalArgumentException::class)
    fun `recusa quadro com tamanho absurdo`() {
        val bytes = byteArrayOf(0x7F, 0x7F, 0x7F, 0x7F) + "x".toByteArray()
        PhoneAuthClient.lerAteRespostaDoPareamento(
            DataInputStream(ByteArrayInputStream(bytes))
        )
    }

    /** A resposta que chega primeiro é a que vale, sem depender de haver desafio. */
    @Test
    fun `aceita a resposta como primeiro quadro`() {
        val lido = PhoneAuthClient.lerAteRespostaDoPareamento(
            fluxo("""{"type":"pair.ok","deviceId":"dev-3"}""")
        )
        assertEquals("dev-3", lido.optString("deviceId"))
    }
}
