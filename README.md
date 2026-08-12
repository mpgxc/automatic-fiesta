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
| `macos/pam/pam_phoneauth.c` | Módulo PAM que intercepta `sudo`/`su`/screensaver | **Compilado, ~130 testes sob ASan+UBSan** |
| `docs/test-vectors.json` | 9 vetores da serialização assinada | **Calculados e conferidos** |
| `macos/Sources/PhoneAuthCore` | Protocolo, payloads assinados, registro de dispositivos | **Compila e testa no CI** |
| `macos/Sources/phoneauthd` | Daemon: socket Unix + TLS + Bonjour + rotação de identidade | **Compila e testa no CI** (macOS 15) |
| `macos/Sources/phoneauthctl` | CLI: parear, listar, revogar, rotacionar, status | **Compila no CI** |
| `macos/ui` | App de barra de menu: SwiftUI, Liquid Glass, notificações | **Fora do escopo atual** · escrito, fora do CI |
| `mobile/ios` | SwiftUI + Secure Enclave + descoberta Bonjour | **Fora do escopo atual** · escrito, fora do CI |
| `mobile/android` | Compose + Keystore/StrongBox + descoberta NSD | **Construído no CI** · APK de debug como artefato |

> **Escopo atual: daemon macOS + app Android.** O app iOS e a interface de barra
> de menu estão escritos e no repositório, mas fora do CI — e código sem CI
> apodrece, então trate os dois como material a religar, não como pronto.
>
> O que o CI cobre de fato está em [docs/status.md](docs/status.md). Compilar não
> é o mesmo que funcionar: nada disto rodou ainda contra hardware real, e nenhuma
> auditoria externa foi feita.

## Instalar e usar

Baixe o `.pkg` da [última release](https://github.com/mpgxc/automatic-fiesta/releases/latest)
e abra. Ele é universal (arm64 + x86_64), pede macOS 13 ou mais novo, e **não é
assinado nem notarizado** — o Gatekeeper vai barrar o duplo-clique, então ou
remova a quarentena depois de olhar o que baixou, ou instale pelo terminal:

```sh
sudo installer -pkg phoneauth-*.pkg -target /
```

Instalar não ativa nada. Faltam dois passos, nesta ordem:

```sh
sudo phoneauthctl pair      # 1. escaneie o QR, confira o código de 6 dígitos
                            # 2. edite /etc/pam.d/sudo_local — ver docs/instalacao.md
sudo -k && sudo true        # 3. teste, com outra janela de terminal aberta
```

O passo 2 é manual de propósito e o passo 3 pede uma janela reserva com `sudo`
válido: mexer em `/etc/pam.d` é a única etapa capaz de estragar a sua
autenticação, e você deve estar olhando quando acontecer.

**Não há aplicativo com janela.** O que roda é um daemon e a CLI
`phoneauthctl` — a interface de barra de menu existe no repositório mas não é
distribuída. E todo comando da CLI exige `sudo`, porque o socket de controle é
`0600 root:wheel`: quem o alcança decide quem aprova os seus `sudo`.

O dia a dia, a referência de comandos, a configuração e o diagnóstico estão em
**[docs/uso.md](docs/uso.md)**.

## Documentação

- [docs/android.md](docs/android.md) — **o app Android**: por que o APK
  publicado não instala e como resolver, o requisito de biometria Classe 3
  que faz o app não funcionar em alguns aparelhos, e o pareamento.
- [docs/uso.md](docs/uso.md) — **como usar depois de instalado.** Comandos,
  `config.json`, os dois timeouts e por que a ordem entre eles importa,
  diagnóstico, e o que fazer em cada situação do dia a dia.
- [docs/arquitetura-visual.html](docs/arquitetura-visual.html) — **comece aqui
  para entender o desenho.** Diagrama de arquitetura e comunicação, mais a
  organização do código de cada um dos quatro projetos. Abra no navegador.
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
