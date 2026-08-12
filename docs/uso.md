# Uso no dia a dia

Como operar o PhoneAuth depois de instalado no macOS. Para instalar pela
primeira vez, veja [instalacao.md](instalacao.md).

## O que o instalador deixou na máquina

Não há aplicativo com janela. O que roda é um daemon e uma CLI — a interface de
barra de menu existe no repositório (`macos/ui`) mas **não é distribuída**, está
fora do escopo atual e fora do CI. Se você procurou um ícone e não achou, é isso.

| Caminho | O que é |
|---|---|
| `/usr/local/bin/phoneauthd` | o daemon; sobe pelo launchd, roda como root |
| `/usr/local/bin/phoneauthctl` | a CLI que você usa |
| `/usr/local/lib/pam/pam_phoneauth.so` | o módulo que o `sudo` carrega |
| `/Library/LaunchDaemons/dev.phoneauth.daemon.plist` | o que faz o daemon subir no boot |
| `/Library/Application Support/PhoneAuth/` | estado: identidade TLS, dispositivos, config |
| `/var/log/phoneauthd.log` | o log |

Não fica em `/usr/lib/pam` porque aquele diretório é protegido pelo SIP. O
OpenPAM aceita caminho absoluto no `/etc/pam.d`, então nada exige desabilitar o
SIP — o que seria um preço absurdo por uma conveniência de autenticação.

## Todo comando exige sudo

O socket de controle é `0600 root:wheel`. Quem o alcança pode parear e revogar
dispositivos, o que é o mesmo que decidir quem aprova os seus `sudo`. Então:

```sh
sudo phoneauthctl status
```

Sem o `sudo`, você recebe um erro de permissão explícito. Se em vez disso vier
"phoneauthd não está rodando", é outro problema — veja
[Diagnóstico](#diagnóstico).

## Primeiro uso

```sh
sudo phoneauthctl pair      # 1. escaneie o QR, confira o código de 6 dígitos
                            # 2. edite /etc/pam.d/sudo_local (ver instalacao.md)
sudo -k && sudo true        # 3. teste com outra janela de terminal aberta
```

O lado do celular — instalar o APK, permissões e requisitos do aparelho —
está em [android.md](android.md).

O QR vale 2 minutos. Durante o pareamento, o Mac mostra um código de seis
dígitos e o celular mostra outro: **eles têm de ser iguais**. Esse código é
derivado do segredo do QR e das chaves públicas dos dois lados, então um
atacante no meio da rede não consegue fazer os dois baterem. Se divergirem,
recuse.

O passo 2 é manual de propósito, e o passo 3 pede uma janela de terminal
reserva com `sudo` ainda válido. Editar `/etc/pam.d` é a única etapa capaz de
estragar a sua autenticação, e você deve estar olhando quando acontecer.

## O dia a dia

Você digita `sudo algo`. Em vez de o terminal pedir senha:

```
$ sudo softwareupdate -i -a
⌁ aguardando aprovação no iPhone de mpgxc…
```

O celular acorda mostrando **o comando exato** que pediu privilégio, o usuário,
o serviço e o terminal. Você encosta o dedo. O `sudo` segue.

Se nada acontecer em 30 segundos, o terminal volta a pedir a senha. Nada
quebrou: o módulo entra como `sufficient` e simplesmente cai para o próximo.

### A tela do celular é onde a segurança mora

O que impede um processo malicioso de disparar `sudo` e torcer pela sua
aprovação por reflexo não é criptografia — é você **ler** o que está na tela.

Por isso o pedido mostra o comando, e não um "aprovar?" genérico. Se apareceu
uma aprovação que você não pediu, ou um comando que você não reconhece,
**negue**. Uma negação não custa nada: o `sudo` volta a pedir senha.

## Referência de comandos

### Estado

```sh
sudo phoneauthctl status
```

```
daemon:               rodando
dispositivos pareados: 2 (2 ativos)
celulares conectados:  1
```

"Conectados" é o número que importa no momento de aprovar. Zero significa que
nenhum celular está alcançável — o app precisa estar aberto ou em background
acordável, e os dois na mesma rede.

### Dispositivos

```sh
sudo phoneauthctl list             # lista, com id, data de pareamento e último visto
sudo phoneauthctl revoke <id>      # revoga, preservando o histórico
sudo phoneauthctl remove <id>      # apaga do registro
```

Prefira `revoke` a `remove`. Ele mantém o registro de que aquele aparelho
existiu e quando foi desligado, que é o que torna um incidente investigável.

Para **adicionar um segundo celular**, rode `pair` de novo; os pareamentos são
independentes e qualquer um dos aparelhos ativos pode aprovar.

**Perdeu o celular?** `sudo phoneauthctl revoke <id>`. Se você não estiver perto
do Mac, não há urgência operacional: sem o aparelho ninguém aprova nada, e o
`sudo` continua funcionando com a senha.

### Rotação da identidade TLS

```sh
sudo phoneauthctl rotate           # em que pé está
sudo phoneauthctl rotate begin     # gera a identidade nova e anuncia
sudo phoneauthctl rotate commit    # passa a usá-la
sudo phoneauthctl rotate abort     # descarta o anúncio
sudo phoneauthctl rotate qr        # para o aparelho que ficou fora da janela
```

Serve para trocar a chave TLS do Mac **sem repareamento**. Entre `begin` e
`commit` há uma janela — sete dias por padrão — em que a identidade viva ainda é
a antiga e nada quebra; é o prazo para cada celular conectar uma vez e aprender
o pin novo. `rotate` mostra quem já confirmou e quem falta.

`--compromised` existe para o caso em que a chave vazou: troca na hora, e
**todos** os aparelhos precisam parear de novo. Isso não é rigor excessivo —
quem tem a chave vazada consegue assinar um anúncio de rotação igualzinho
apontando para a chave dele, então o mecanismo de anúncio não serve aqui.

Desenho completo e trade-offs: [rotacao-de-identidade.md](rotacao-de-identidade.md).

## Configuração

`/Library/Application Support/PhoneAuth/config.json`. O arquivo não existe por
padrão; crie-o só com as chaves que quiser mudar. Reinicie o daemon depois.

| Chave | Padrão | O que faz |
|---|---|---|
| `port` | `58731` | porta TLS que o daemon escuta |
| `serviceName` | nome do Mac | como o Mac aparece no Bonjour e no celular |
| `requestTTLSeconds` | `60` | validade do pedido no celular |
| `responseTimeoutSeconds` | `25` | quanto o daemon espera pelo celular |
| `allowedServices` | `["sudo","sudo_local","su"]` | serviços PAM atendidos |
| `rotationWindowSeconds` | `604800` | janela mínima entre `begin` e `commit` |
| `previousBindingGraceSeconds` | `86400` | graça para o binding anterior após o commit |

Reiniciar:

```sh
sudo launchctl kickstart -k system/dev.phoneauth.daemon
```

### Há dois timeouts, e a ordem entre eles importa

O `timeout=` da linha do `/etc/pam.d/sudo_local` (padrão 30s, limitado entre 5 e
120) é quanto o **módulo PAM** espera. O `responseTimeoutSeconds` (padrão 25s) é
quanto o **daemon** espera. O do daemon é deliberadamente menor: assim quem
desiste primeiro é ele, e o terminal cai limpo no próximo módulo em vez de ser
cortado no meio. Se você aumentar um, aumente o outro na mesma proporção.

`previousBindingGraceSeconds` tem custo de segurança real e é muleta de
compatibilidade com prazo — enquanto vale, quem tivesse a chave TLS antiga
conseguiria relaiar uma aprovação assinada sob o certificado antigo. Está
documentado em [rotacao-de-identidade.md](rotacao-de-identidade.md) §4.6.

## Diagnóstico

```sh
sudo phoneauthctl status                         # o daemon responde?
sudo launchctl print system/dev.phoneauth.daemon # o launchd o mantém no ar?
tail -f /var/log/phoneauthd.log                  # o que ele está fazendo
```

O log registra o contexto dos pedidos, porque é o que torna um incidente
investigável — e aquele contexto já aparece na tela do celular de qualquer
forma. **Nunca** registra desafios, assinaturas ou material de chave.

Se o daemon não sobe, quase sempre é a identidade TLS ausente ou ilegível: o
`ThrottleInterval` de 10s no plist existe para que uma falha assim não vire um
laço apertado de respawn.

## Situações do dia a dia

| O que você vê | O que é |
|---|---|
| `sudo` pede senha e o celular não reage | daemon fora do ar, celular em outra rede, ou app fechado. É o `sufficient` funcionando — nada quebrou. |
| "celulares conectados: 0" | o app precisa estar aberto ou acordável, e na mesma rede. É a limitação prática mais séria da v1. |
| o celular parou de aprovar depois de eu cadastrar uma digital nova | **comportamento correto.** O SO destrói a chave quando o conjunto de biometrias muda, para impedir que alguém cadastre o próprio dedo num aparelho desbloqueado. Pareie de novo. |
| aprovei no celular e o Mac recusou | divergência de bytes entre implementações do `SignedPayload`. Rode os vetores dos dois lados; ver [status.md](status.md). |
| erro de permissão ao rodar `phoneauthctl` | faltou `sudo`. |

## O que continua não funcionando

Nada disto muda com o uso, é por construção: FileVault no pré-boot e a tela de
login inicial (ainda não há rede nem daemon), diálogos gráficos do
`SecurityAgent` do tipo "Os Ajustes do Sistema querem fazer alterações", apps
que chamam `LAContext` direto, e celular fora da LAN.

Detalhe de cada um em [arquitetura.md](arquitetura.md); o que é ameaça e o que
não é, em [modelo-de-ameacas.md](modelo-de-ameacas.md).

## Desinstalar

```sh
sudo ./scripts/uninstall.sh
```

Remove a linha do `/etc/pam.d` **primeiro**, depois o resto. `--keep-devices`
preserva os pareamentos. Se você instalou pelo `.pkg` e não tem o repositório à
mão, a tela final do instalador lista os comandos equivalentes.
