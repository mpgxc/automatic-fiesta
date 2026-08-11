# Status: o que foi verificado e o que não foi

Este projeto foi desenvolvido num container Linux **sem Swift, sem Xcode e sem
SDK do Android**. Esta página existe para não deixar dúvida sobre onde está a
fronteira entre "verificado" e "escrito com cuidado".

## Verificado por execução

### Módulo PAM — a peça mais crítica, e a mais testada

`macos/pam/pam_phoneauth.c` roda como root dentro do `sudo`. Compila limpo sob
`-Wall -Wextra -Wconversion -Wshadow -Wpointer-arith -Wwrite-strings`, e a suíte
de **~130 checagens** passa sob AddressSanitizer e UndefinedBehaviorSanitizer.

```sh
cd macos/pam && make test
```

Uma auditoria adversarial encontrou **quatro defeitos reais**, todos
reproduzidos antes de corrigir e todos corrigidos:

| | Defeito | Efeito |
|---|---|---|
| 1 | `POLLHUP` tratado como erro | O daemon responde e fecha na linha seguinte, então o `poll` via `POLLIN\|POLLHUP` com o frame inteiro no buffer — e a resposta era descartada. **A aprovação da digital era jogada fora e o `sudo` caía na senha, em silêncio.** |
| 2 | `write()` sem `SO_NOSIGPIPE` | Escrever num socket cujo par fechou levanta SIGPIPE, que termina o processo — e o processo é o `sudo` do usuário. O defeito 1 mascarava este, porque desistia antes de chegar ao `write`. |
| 3 | Scanner JSON não falhava sempre negando | `{"ok":true,"ok":false}` devolvia sucesso. Não explorável (forjar o daemon já exige root), mas era invariante declarada e violada. |
| 4 | Scanner recusava espaço em branco JSON legal | Funcionava só porque o `JSONEncoder` escreve compacto. Ligar `.prettyPrinted` num refactor transformaria 100% das aprovações em prompt de senha. |

A suíte cobre o scanner exaustivamente — `truex`, `true1`, `truthy`, `"true"`
como string, chave prefixo/sufixo de outra, entrada truncada em cada posição,
chave escondida em valor escapado — mais E/S real sobre `socketpair`, teste de
SIGPIPE em processo filho e higiene de descritores.

**Resíduo conhecido:** restam 6 casos fail-open em 60k entradas de fuzz (era
142), todos de uma classe só — `ok` existindo *apenas* aninhado, sem `ok` de
topo. Fechar exigiria rastrear profundidade e estado de string, ou seja,
exatamente o parser completo que o arquivo se recusa a colocar num processo
setuid. A alternativa é exigir também `"type":"auth.result"`, o que muda o
protocolo aceito.

### Serialização assinada

`docs/test-vectors.json` traz **9 vetores** calculados de forma independente por
`docs/generate-test-vectors.py`, em Python, sem passar por nenhuma das três
implementações.

O gêmeo **Kotlin foi validado contra eles** por um espelho Java executável —
todos batem, incluindo o `Sas.compute` (HKDF escrito à mão, a criptografia de
maior risco do app Android). O script também confirma que HMAC-SHA256 com chave
vazia é idêntico a HMAC com 32 zeros, suposição de que o código depende porque o
CryptoKit usa salt vazio e o Kotlin usa 32 zeros explícitos.

```sh
python3 docs/generate-test-vectors.py    # regenera; a saída tem que bater
python3 docs/check-payload-parity.py     # ordem de campos entre os 3 gêmeos
```

O `check-payload-parity.py` é análise de texto do fonte e roda **sem toolchain
nenhuma**. Os vetores pegam divergência de bytes só onde alguém lembrou de
cobrir; a paridade pega divergência estrutural em todos os payloads, inclusive
nos que ainda não têm vetor. Verifiquei que ele detecta divergência injetada de
propósito.

### Cliente Android

Um type-check real foi feito com `kotlinc` 2.0.21 sobre `PhoneAuthClient.kt`,
`NsdDiscovery.kt` e `SignedPayload.kt`, contra stubs Java escritos à mão das
APIs Android: zero erros, zero warnings. Valida sintaxe, inferência, resolução
de sobrecarga, assinaturas de `override` e uso de corrotinas. **Não** valida que
os stubs batem com o `android.jar` real, e não valida nada de runtime. As telas
Compose não foram compiladas.

## Escrito, mas nunca compilado

| Componente | Risco esperado na primeira compilação |
|---|---|
| `macos/Sources/PhoneAuthCore` | Baixo. Foundation e CryptoKit padrão. |
| `macos/Sources/phoneauthd` | **Alto.** As chamadas `sec_protocol_*` do Network.framework são mal documentadas. Reabrir o `NWListener` na mesma porta após `cancel()` (rotação) é o ponto mais arriscado, seguido de `SecPKCS12Import` e o `Process` do openssl. |
| `macos/Sources/phoneauthctl` | Médio. O `CGContext` do `CIQRCodeGenerator` pode precisar de ajuste. |
| `mobile/ios` | **Alto.** Flags de `SecAccessControl` e `kSecUseAuthenticationContext` só se exercitam em aparelho físico — o simulador não tem Secure Enclave real. Capturar `[weak self]` em closures `@Sendable` é aviso no Swift 5 e **erro** no Swift 6. |
| `mobile/android` (Compose) | Médio. Pacotes do ML Kit (`Barcode` está em `...barcode.common`) e superfície do CameraX 1.3.4. |

## Ordem sugerida para a primeira passada num Mac

Cada etapa deixa algo demonstrável antes da seguinte.

1. `cd macos/pam && make test` — deve passar já.
2. `python3 docs/check-payload-parity.py` — deve passar já.
3. `cd macos && swift build` — espere erros; comece por `PhoneListener.swift`,
   `Rotation.swift` e `Identity.swift`.
4. `cd macos && swift test` — se os vetores passarem, a serialização está
   correta e as outras duas implementações têm um alvo confiável.
5. **Rode `print("a\r\nb".contains("\n"))` num playground.** Se imprimir
   `false`, confirma a hipótese que motivou a validação por `unicodeScalars`
   (`"\r\n"` é um único `Character` pela regra GB3 do UAX#29).
6. `scripts/install.sh` e `phoneauthctl status` — daemon de pé, sem celular.
7. Build do iOS **em aparelho físico**: vetores, depois criação de chave, depois
   pareamento.
8. `sudo phoneauthctl pair` e o fluxo completo.
9. Só então plugue no `/etc/pam.d/sudo_local`.
10. Android por último, com os vetores já validados pelos outros dois.

## O que falta implementar

- **Rotação nos clientes.** O lado macOS está completo (`Rotation.swift`, CLI
  `phoneauthctl rotate`, mensagens `rotate.announce`/`rotate.ack`), mas iOS e
  Android ainda não tratam o anúncio nem guardam o pin como conjunto. Os vetores
  dos dois domínios novos já existem, então os gêmeos têm contra o que conferir.
  Checklist por plataforma em `docs/rotacao-de-identidade.md` §8.
- **Notificação em background.** O app precisa estar aberto ou em background
  acordável. É a limitação prática mais séria da v1.
- **Persistir o endereço aprendido no iOS** — só depois do handshake pinado,
  para um anúncio hostil não envenenar o cache. O Android já faz.
- **`NWPathMonitor` no iOS** para reconectar no instante da troca de rede. Hoje
  custa no máximo 30 s de espera.

## Nenhuma auditoria externa foi feita

A auditoria adversarial que encontrou os quatro defeitos do PAM foi feita dentro
deste mesmo projeto. Ela achou coisas reais e o módulo está bem melhor, mas isso
não é o mesmo que revisão independente.

O módulo PAM roda como root dentro do `sudo`; um bug de memória ali é escalação
de privilégio local. Ele foi mantido curto, testado sob sanitizers e auditado
adversarialmente por esse motivo — mas se você não vai ler o `pam_phoneauth.c`
antes de instalar, é melhor não instalar.
