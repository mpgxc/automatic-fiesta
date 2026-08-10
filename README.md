# PhoneAuth

Usa a digital do seu celular para aprovar os pedidos de senha do macOS.

Quando o Mac pede autenticação (`sudo`, desbloqueio de tela), em vez de digitar a
senha você recebe uma notificação no celular com o contexto do pedido — quem
está pedindo, para quê — e aprova com o leitor biométrico. O Mac só libera
depois de verificar uma assinatura criptográfica que **só existe** se a
biometria tiver sido apresentada ao hardware seguro do telefone.

```
┌──────────────────────────┐                    ┌─────────────────────────┐
│  macOS                   │                    │  iOS / Android          │
│                          │                    │                         │
│  sudo ──▶ PAM            │                    │                         │
│           │              │   TLS 1.3 pinado   │   ┌─────────────────┐   │
│           ▼              │   sobre a LAN      │   │  Secure Enclave │   │
│      phoneauthd  ◀───────┼────────────────────┼──▶│  / StrongBox    │   │
│           │              │   (Bonjour)        │   │                 │   │
│           │              │                    │   │  chave que só   │   │
│  verifica assinatura     │                    │   │  assina com     │   │
│  P-256 contra a chave    │                    │   │  digital fresca │   │
│  pareada                 │                    │   └─────────────────┘   │
└──────────────────────────┘                    └─────────────────────────┘
```

## A ideia central

O que **não** fazemos: o app pergunta a digital, o celular manda `{"ok": true}`,
o Mac confia. Isso é teatro de segurança — qualquer um que consiga forjar ou
reproduzir aquele pacote entra, e um celular com root desliga a checagem.

O que fazemos: no pareamento, o celular gera um par de chaves **dentro** do
Secure Enclave (iOS) ou do Android Keystore/StrongBox, com a flag de que a
chave privada só pode ser usada mediante autenticação biométrica imediata. A
chave privada nunca sai do hardware e não existe caminho de software que a use
sem passar pelo sensor. O Mac guarda só a chave pública.

A biometria vira, então, uma **precondição de hardware para a assinatura
existir** — não uma afirmação do app sobre o que o usuário fez. É a diferença
entre "confie em mim, ele encostou o dedo" e "esta assinatura é matematicamente
impossível sem o dedo dele".

## Estado atual

| Componente | O que é | Situação |
|---|---|---|
| `macos/pam/pam_phoneauth.c` | Módulo PAM que intercepta `sudo`/`su`/screensaver | Escrito, não compilado |
| `macos/Sources/PhoneAuthCore` | Protocolo, payloads assinados, registro de dispositivos | Escrito, não compilado |
| `macos/Sources/phoneauthd` | Daemon: socket Unix + listener TLS + Bonjour | Escrito, não compilado |
| `macos/Sources/phoneauthctl` | CLI: parear, listar, revogar, status | Escrito, não compilado |
| `mobile/ios` | SwiftUI + Secure Enclave | Escrito, não compilado |
| `mobile/android` | Compose + Keystore/StrongBox | Escrito, não compilado |

> **Nada disto foi compilado ou executado.** Foi desenvolvido num container
> Linux sem Swift, sem Xcode e sem SDK do Android. Trate como um primeiro corte
> revisável: o desenho e o protocolo estão fechados, o código precisa da
> primeira passada de compilação num Mac. Veja [docs/status.md](docs/status.md)
> para a lista do que exatamente falta verificar.

## Documentação

- [docs/protocolo.md](docs/protocolo.md) — o contrato entre os três lados: formato
  das mensagens, bytes exatos que são assinados, máquina de estados. **Leia isto
  antes de mexer em qualquer implementação**, porque os três lados precisam
  produzir os mesmos bytes.
- [docs/arquitetura.md](docs/arquitetura.md) — por que cada peça existe, como o
  macOS é interceptado, o que roda como root e o que não roda.
- [docs/modelo-de-ameacas.md](docs/modelo-de-ameacas.md) — o que este desenho
  defende, o que ele explicitamente não defende, e os riscos que você aceita ao
  instalar.
- [docs/instalacao.md](docs/instalacao.md) — instalação, pareamento e, mais
  importante, como desinstalar quando der errado.

## Segurança: a regra que não se quebra

O módulo PAM é instalado como `sufficient`, nunca `required`:

```
auth  sufficient  pam_phoneauth.so
```

`sufficient` significa: se aprovar, pronto; se falhar **por qualquer motivo** —
daemon fora do ar, celular sem bateria, você em outra rede, bug no código — o
PAM simplesmente segue para o próximo módulo e você digita a senha como sempre.

Nunca existe um estado em que este projeto te tranca fora da sua própria
máquina. Todo caminho de erro no módulo PAM retorna `PAM_AUTHINFO_UNAVAIL`, e
qualquer patch que introduza um `PAM_SUCCESS` fora do caminho de assinatura
verificada é um bug de severidade máxima.

## Escopo

**Funciona:** `sudo`, `su`, e qualquer serviço PAM; desbloqueio de protetor de
tela (opcional, exige alterar o authorization database).

**Não funciona, por construção:**

- **FileVault no pré-boot e a tela de login inicial.** Ainda não existe rede,
  nem sessão de usuário, nem daemon rodando. Nenhuma solução deste tipo cobre
  isso.
- **Diálogos gráficos** do tipo "Os Ajustes do Sistema querem fazer alterações".
  Passam pelo `SecurityAgent`, não pelo PAM. Exige um Authorization Plugin —
  planejado para a fase 2, ver [docs/arquitetura.md](docs/arquitetura.md).
- **Apps que chamam `LAContext.evaluatePolicy` direto** (1Password, apps
  bancários). Falam com o Secure Enclave do próprio Mac; não há ponto de
  interceptação sem código não suportado.
- **Celular fora da LAN.** A v1 é só rede local, sem relay em nuvem, de
  propósito: nenhum servidor para manter e nenhum dado saindo da sua rede.

## Licença

MIT
