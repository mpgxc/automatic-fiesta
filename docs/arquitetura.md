# Arquitetura

## Onde exatamente se enfia o gancho no macOS

O macOS não tem *um* prompt de senha. Tem quatro caminhos diferentes, com
mecanismos de extensão diferentes, e é isso que define o escopo do projeto.

### 1. PAM — `sudo`, `su`, `login`, `screensaver`

O caminho clássico do Unix. `/etc/pam.d/<serviço>` lista módulos empilhados, e o
macOS carrega `.so` de `/usr/lib/pam/`. **É a rota que a v1 usa.**

A partir do macOS Sonoma existe `/etc/pam.d/sudo_local`, um arquivo de drop-in
que sobrevive a atualizações do sistema — `/etc/pam.d/sudo` é substituído a cada
update, `sudo_local` não. Instalamos ali:

```
# /etc/pam.d/sudo_local
auth       sufficient     pam_phoneauth.so    timeout=30
auth       sufficient     pam_tid.so
```

O empilhamento é intencional: tenta o celular; se não der, tenta o Touch ID do
próprio Mac; se não der, cai no `pam_opendirectory.so` que o `/etc/pam.d/sudo`
já traz, e você digita a senha.

### 2. Authorization Services — os diálogos gráficos

"Os Ajustes do Sistema querem fazer alterações." Esses **não passam por PAM**.
Vão pelo `SecurityAgent`, um processo separado que consulta o *authorization
database* (`/var/db/auth.db`) para saber quais "mecanismos" rodar para cada
direito nomeado (`system.preferences`, `system.install.app`, ...).

Dá para plugar um bundle em `/Library/Security/SecurityAgentPlugins/` que
implementa a API C `AuthorizationPlugin` e registrar seu mecanismo:

```sh
security authorizationdb read system.preferences > /tmp/r.plist
# insere "PhoneAuth:check,privileged" na lista de mechanisms
security authorizationdb write system.preferences < /tmp/r.plist
```

**Fase 2, e com duas ressalvas honestas.** Primeira: para *preencher* o prompt,
o plugin precisa injetar a senha da conta no contexto de autorização — ou seja,
o Mac tem que ter a senha guardada. Isso é um problema de segurança de natureza
diferente do resto do projeto, discutido no
[modelo de ameaças](modelo-de-ameacas.md). Segunda: nas versões recentes do
macOS vários painéis do System Settings vêm com o direito fixado em
`use-login-window-ui`, que ignora mecanismos de terceiros. A cobertura será
parcial e vai variar por versão do macOS.

### 3. `LAContext.evaluatePolicy` — apps chamando Touch ID direto

1Password, apps de banco, qualquer app que peça Touch ID por conta própria.
Falam direto com o Secure Enclave do Mac. **Não há ponto de interceptação** sem
injeção de código, que o SIP e o hardened runtime bloqueiam — e com razão.
Fora de escopo permanentemente.

### 4. FileVault pré-boot e a tela de login inicial

Rodam antes de existir sessão de usuário, antes da pilha de rede subir, antes de
qualquer daemon. **Impossível por construção**, para este e para qualquer
projeto do gênero. O desbloqueio de *protetor de tela* é diferente — a sessão já
existe — e por isso é suportado.

## Os processos

```
    ┌── sudo (setuid root) ───────────────────┐
    │     └─ libpam ─┐                        │
    └────────────────┼────────────────────────┘
                     │  socket Unix, 0600 root:wheel
                     │  /var/run/phoneauthd.sock
                     ▼
    ┌─────────────────────────────────────────┐
    │  phoneauthd   (LaunchDaemon, root)      │
    │                                         │
    │  ├─ ControlServer  ← socket Unix        │
    │  ├─ PhoneListener  ← TLS 1.3 + Bonjour  │
    │  ├─ Broker         orquestra os dois    │
    │  ├─ DeviceRegistry devices.json         │
    │  └─ PendingStore   nonce, TTL, uso único│
    └─────────────────────────────────────────┘
                     ▲
                     │  mesmo socket, comandos de controle
                     │
    ┌────────────────┴────────────────────────┐
    │  phoneauthctl  (CLI, roda como você)    │
    │  pair · list · revoke · status          │
    └─────────────────────────────────────────┘
```

### Por que um daemon root separado, e não código dentro do PAM

Três razões, e a terceira é a que decide.

O módulo PAM roda dentro do `sudo`, com privilégio total, uma vez por
autenticação. Colocar rede, TLS e parsing de JSON ali dentro significaria rodar
esse código todo em processo setuid — a pior superfície de ataque possível para
código que fala com a rede.

O daemon é persistente, então mantém a conexão TLS com o celular aberta. Um
handshake TLS por `sudo` acrescentaria segundos de latência.

E o módulo PAM precisa ser **pequeno o bastante para ser auditável por
inspeção**. Ele conecta num socket, escreve um JSON, lê um JSON, retorna. Uns
300 linhas de C que um revisor consegue ler inteiro e se convencer de que não há
caminho para `PAM_SUCCESS` sem uma resposta positiva do daemon. Toda a
complexidade — rede, criptografia, estado — fica do lado não-privilegiado dessa
fronteira.

### A interface gráfica é observadora, nunca decisora

O app de barra de menu (`macos/ui`) roda como você, num processo separado, e
fala com o daemon por um **segundo socket** — `/var/run/phoneauthd-ui.sock`.

Existem dois sockets porque o de controle é 0600 root:wheel e um app de usuário
não alcança. Abrir aquele para não-root seria a saída preguiçosa e errada: ele
carrega pareamento, revogação e rotação.

O socket da UI só publica. Não há caminho de entrada por ele, e é isso que
sustenta a regra mais importante da interface:

> **Nenhuma notificação do Mac tem botão de aprovar.**

Se fosse possível liberar um `sudo` clicando no Mac, a biometria do celular
viraria decoração — quem já comprometeu a sessão para disparar o `sudo`
malicioso também consegue clicar naquele botão. A única aprovação que vale é a
assinatura que o enclave do celular produz, e ela nunca transita por este canal.
Um patch que acrescente uma ação de aprovar na notificação é bug de severidade
máxima, não melhoria de usabilidade.

O arquivo é 0666, mas o portão é a checagem de credencial no `accept`: só o
usuário logado no console é atendido. Não é excesso de zelo — o histórico
carrega o `reason` de cada pedido, que é a linha de comando digitada depois do
`sudo`, e num Mac com mais de uma conta isso não é da conta das outras.

Parear e revogar continuam exigindo root, então os botões da UI abrem o Terminal
com o comando do `phoneauthctl`. É deliberado: você vê exatamente o que vai
rodar e digita a própria senha, em vez de um app de barra de menu carregar um
atalho de privilégio escondido. Um helper privilegiado por XPC é o caminho
correto e fica para a fase 2.

**Quando notificar.** A regra é notificar o que o usuário não perceberia
sozinho. Aprovação não notifica — o terminal simplesmente seguiu, e a evidência
está na tela. Pedido enviado também não — ele acabou de digitar `sudo` e está
olhando para o cursor; o ícone pulsando basta. Notificam-se negação, expiração,
ausência de celular, revogação e assinatura inválida.

Notificar tudo produziria uma enxurrada a cada `sudo`, e um usuário treinado a
dispensar avisos no reflexo já perdeu a defesa que o contexto na tela deveria
dar. É o mesmo raciocínio do limite de um pedido em voo por dispositivo.

### Verificação de credencial do par no socket

O daemon confere `LOCAL_PEERCRED` em cada conexão do socket Unix. Pedidos de
autenticação só são aceitos de **uid 0**, porque só código já rodando como root
(o `sudo` durante o PAM) tem motivo para pedir. Comandos de controle (parear,
listar) são aceitos de uid não-root, mas apenas do dono da sessão do console.

Sem essa checagem, qualquer processo local poderia disparar notificações no seu
celular à vontade — e o valor de um ataque assim é justamente cansar o usuário
até ele aprovar por reflexo.

## Estado em disco

```
/Library/Application Support/PhoneAuth/     0700 root:wheel
├── devices.json      0600  chaves públicas dos pareados — sem segredos
├── identity.p12      0600  chave privada TLS do daemon
└── config.json       0600  porta, timeouts, flags
```

`devices.json` contém **exclusivamente material público**. Se vazar, o atacante
descobre quais celulares você pareou e nada além disso — não dá para forjar
aprovação, porque as chaves privadas estão dentro do hardware dos telefones.

`identity.p12` é a única coisa realmente sensível, e o pior caso ao perdê-la é
um atacante conseguir se passar pelo seu Mac para o seu celular: ele receberia
pedidos de aprovação falsos. O contexto exibido é o que te protege aí — um
pedido que você não iniciou aparece do nada e você nega.

Formato de arquivo em vez de Keychain foi escolha deliberada para a v1: o
conteúdo é público, arquivo root-only é auditável com `cat`, e não há a dança de
ACL de Keychain para um daemon root. Migrar `identity.p12` para o System
Keychain é uma melhoria válida da fase 2.

## O caminho completo de um `sudo`

1. Você digita `sudo brew install ripgrep`.
2. `sudo` entra na pilha PAM; `sudo_local` chama `pam_phoneauth.so`.
3. O módulo lê `PAM_USER`, `PAM_SERVICE`, `PAM_TTY`, monta o motivo a partir da
   linha de comando e conecta em `/var/run/phoneauthd.sock`.
   *Daemon fora do ar → retorna `PAM_AUTHINFO_UNAVAIL` na hora, sem espera.*
4. O daemon confere o peer cred, checa se há sessão de celular ativa.
   *Sem celular conectado → resposta negativa imediata. Você não fica olhando
   para um terminal travado enquanto o celular está na outra sala.*
5. Gera `requestId` + 32 bytes de desafio, guarda como pendente com TTL de 60 s,
   envia pelo TLS.
6. O celular exibe o contexto. Você encosta o dedo. O Secure Enclave libera a
   `authKey` e assina.
7. O daemon consome o pendente (uso único, atômico), verifica a assinatura
   P-256, e responde `{"ok": true}`.
8. O módulo retorna `PAM_SUCCESS`. O `sudo` segue.

Em qualquer ponto: timeout, negação, assinatura inválida, celular sumiu — o
módulo retorna erro, o `sudo` cai para `pam_tid.so` e depois para a senha. O
timeout padrão de 30 s tem um teto rígido de 120 s, para que um daemon com bug
não consiga travar seu terminal indefinidamente.

## Descoberta na rede

O daemon anuncia `_phoneauth._tcp` via Bonjour. O celular usa `NWBrowser` (iOS)
ou `NsdManager` (Android).

O anúncio expõe o nome do host e a porta na LAN. Isso é informação de rede
comum — quem está na sua rede já enxerga o Mac. O anúncio **não** carrega
identificador de dispositivo, chave, nem se há dispositivos pareados. Conectar
sem ser um par registrado te dá um desafio de sessão que você não consegue
assinar, e a conexão morre.

## Fase 2

- **Authorization Plugin** para os prompts gráficos, com os poréns da seção 2.
- **App de barra de menu** para parear e ver o histórico, no lugar da CLI.
- **Wake por push** (APNs/FCM) para funcionar fora da LAN — precisa de um relay,
  e o relay muda o modelo de ameaças o suficiente para merecer decisão à parte.
- **Presença por BLE** como sinal adicional, jamais como substituto da digital.
