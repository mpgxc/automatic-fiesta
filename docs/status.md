# Status: o que foi verificado e o que não foi

Este projeto foi desenvolvido num container Linux **sem Swift, sem Xcode e sem
SDK do Android**. Isso limita fortemente o que pôde ser verificado, e esta
página existe para não deixar dúvida sobre onde está a fronteira.

## Verificado de verdade

**Módulo PAM (`macos/pam/pam_phoneauth.c`)** — compila limpo com clang sob
`-Wall -Wextra -Wconversion -Wshadow -Wpointer-arith -Wwrite-strings`, usando
headers PAM de shim. Os 46 testes em `test_pam_phoneauth.c` passam sob
AddressSanitizer e UndefinedBehaviorSanitizer, sem erro de memória.

O que os testes cobrem, e por que esses e não outros:

- **O scanner JSON**, exaustivamente, porque é a função que decide entre
  autenticar e não autenticar. Casos adversariais: `truex`, `true1`, `truthy`,
  `tru`, `"true"` como string, chave que é prefixo ou sufixo de outra
  (`okay`/`notok`), capitalização diferente, entrada truncada em cada posição,
  e a chave aparecendo dentro de um valor de string escapado.
- **O escritor JSON**, incluindo a neutralização de uma tentativa de injeção
  via newline no campo de motivo, e o comportamento de overflow (marca a flag,
  para de escrever, não estoura o buffer).
- **O clamp de timeout**, incluindo entradas não numéricas, negativas e com
  lixo à direita.

**Vetores de teste (`docs/test-vectors.json`)** — calculados de forma
independente por `docs/generate-test-vectors.py`, em Python, sem passar por
nenhuma das três implementações. É o que dá alguma confiança de que a
serialização está bem definida, já que as três implementações não puderam ser
executadas lado a lado.

O script também confirma uma suposição que o código depende: que HMAC-SHA256
com chave vazia é idêntico a HMAC com 32 bytes zerados. Isso importa porque o
`HKDF.deriveKey` do CryptoKit usa salt vazio e a implementação Kotlin usa 32
zeros explícitos — se não fossem equivalentes, o código SAS divergiria entre
iOS e Android.

## Escrito, mas nunca compilado

Todo o resto:

| Componente | Risco esperado na primeira compilação |
|---|---|
| `macos/Sources/PhoneAuthCore` | Baixo. É Foundation e CryptoKit padrão. |
| `macos/Sources/phoneauthd` | **Alto.** Network.framework tem uma API de TLS pouco documentada, e as chamadas `sec_protocol_*` são fáceis de errar. `SecPKCS12Import` e o layout de `xucred` também precisam de conferência. |
| `macos/Sources/phoneauthctl` | Médio. O caminho do `CIQRCodeGenerator` pode precisar de ajuste no `CGContext`. |
| `macos/Tests` | Baixo, mas os vetores é que importam — se falharem, o bug é real. |
| `mobile/ios` | **Alto.** As flags de `SecAccessControl` e o comportamento de `kSecUseAuthenticationContext` precisam ser exercitados em aparelho físico; o simulador não tem Secure Enclave de verdade. |
| `mobile/android` | **Alto.** `setUserAuthenticationParameters` mudou entre versões de API, e `setIsStrongBoxBacked` falha de formas específicas por fabricante. Falta o `PairingActivity` com o leitor de QR. |

## Ordem sugerida para dar a primeira passada

Cada etapa deixa algo demonstrável antes da seguinte.

1. `cd macos/pam && make test` — deve passar já, é o que foi verificado aqui.
2. `cd macos && swift build` — espere erros de compilação; concentre-se em
   `PhoneListener.swift` e `Identity.swift`.
3. `cd macos && swift test` — se os vetores passarem, a serialização está
   correta e as outras duas implementações têm um alvo confiável.
4. `scripts/install.sh` e `phoneauthctl status` — o daemon sobe e responde,
   ainda sem nenhum celular.
5. Build do iOS **em aparelho físico**. Verifique que o teste de vetores passa,
   depois que a criação de chave funciona, depois o pareamento.
6. `sudo phoneauthctl pair` e o fluxo completo.
7. Só então plugue no `/etc/pam.d/sudo_local`.
8. Android por último, com os vetores já validados pelas outras duas
   implementações.

## O que falta implementar

- **`PairingActivity`** no Android — leitor de QR. O handshake de pareamento já
  está pronto em `PhoneAuthClient.pair()`; falta só a tela da câmera.
- **Descoberta por Bonjour no cliente.** Hoje o celular guarda o host do QR e
  conecta direto. Funciona, mas quebra se o IP mudar. `NWBrowser` no iOS e
  `NsdManager` no Android resolvem.
- **Reconexão automática** com backoff. O cliente atual desconecta e espera
  ação do usuário.
- **Notificação em background.** Hoje o app precisa estar aberto ou em
  background acordável. É a limitação prática mais séria da v1.
- **Rotação da identidade TLS.** Trocar `identity.p12` hoje invalida todos os
  pareamentos, porque o hash de SPKI é o `channelBinding`.

## Nenhuma auditoria de segurança foi feita

O desenho foi pensado com cuidado e as decisões estão justificadas nos
documentos e nos comentários. Isso não é auditoria.

O módulo PAM roda como root dentro do `sudo`; um bug de memória ali é escalação
de privilégio local. Ele foi mantido curto e testado sob sanitizers exatamente
por isso, mas foi testado por quem o escreveu — o que vale bem menos do que
soa.

Se você não vai ler o `pam_phoneauth.c` antes de instalar, é melhor não
instalar.
