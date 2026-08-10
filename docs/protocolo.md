# Protocolo PhoneAuth v1

Contrato entre o daemon macOS (`phoneauthd`) e o app celular. Três
implementações independentes precisam produzir **exatamente os mesmos bytes**
para as assinaturas baterem: o verificador em Swift no daemon, o assinante em
Swift no iOS e o assinante em Kotlin no Android.

Qualquer divergência de um único byte — um `\n` a mais, um campo em outra ordem,
base64 sem padding — produz falha de assinatura que se manifesta como "aprovei
no celular e o Mac recusou". Por isso a serialização abaixo é linha a linha e
não JSON canônico: JSON canônico é fácil de errar entre três linguagens.

## 1. Primitivas

| Função | Algoritmo | Por quê |
|---|---|---|
| Chaves do dispositivo | ECDSA P-256 | Único algoritmo assimétrico que o Secure Enclave suporta. O Android Keystore também suporta bem. |
| Assinatura | ECDSA-SHA256, formato DER | Padrão em ambas as plataformas |
| Transporte | TLS 1.3, certificado auto-assinado com pinning de SPKI | Sem CA, sem cadeia, sem confiar em ninguém além do que foi visto no pareamento |
| Prova de pareamento | HMAC-SHA256 | Liga o pareamento ao segredo do QR code |
| Hash | SHA-256 | — |

Base64 neste documento é sempre o **alfabeto padrão RFC 4648 com padding**
(`+`, `/`, `=`). Hex é sempre **minúsculo**.

## 2. Duas chaves por dispositivo

Cada celular pareado registra **duas** chaves. A separação é essencial:

**`idKey` — chave de identidade.** Em hardware, mas *não* travada por
biometria. Usada para autenticar a conexão TLS a cada reconexão. Se ela fosse
biométrica, o celular pediria sua digital toda vez que trocasse de Wi-Fi ou
saísse do sleep — o app ficaria insuportável e você aprenderia a encostar o dedo
no automático, que é exatamente o hábito que destrói a segurança.

**`authKey` — chave de aprovação.** Em hardware **e** travada por biometria, com
`.biometryCurrentSet` (iOS) / `setInvalidatedByBiometricEnrollment(true)`
(Android). Cada assinatura individual exige uma apresentação nova do dedo — o
sistema operacional não deixa reutilizar uma autenticação anterior. Se alguém
cadastrar uma digital nova no celular, a chave é **destruída** pelo próprio SO e
o dispositivo precisa ser pareado de novo.

Essa segunda propriedade é o que impede o ataque "peguei o celular
desbloqueado e cadastrei meu dedo".

## 3. Pareamento

### 3.1 O QR code

O Mac gera uma sessão de pareamento válida por **120 segundos**, de uso único. O
QR carrega o JSON abaixo em base64url:

```json
{
  "v": 1,
  "host": "macbook-de-mpgxc.local",
  "port": 58731,
  "spki": "<base64 do SHA-256 do SubjectPublicKeyInfo DER do cert do daemon>",
  "sid": "<UUID da sessão de pareamento>",
  "psk": "<base64 de 32 bytes aleatórios>",
  "name": "MacBook Pro de mpgxc"
}
```

O `psk` é o segredo que prova que quem está pareando **viu a tela do Mac**. Sem
ele não há pareamento, mesmo que o atacante alcance a porta TLS.

### 3.2 Troca

O celular conecta, valida o certificado por SPKI pinning contra `spki` (o
certificado é auto-assinado; a validação de cadeia é substituída inteiramente
por esta comparação) e envia:

```json
{
  "type": "pair.request",
  "sid": "<sid do QR>",
  "deviceName": "iPhone 15 de mpgxc",
  "platform": "ios",
  "idPublicKey":   "<base64 do DER SubjectPublicKeyInfo>",
  "authPublicKey": "<base64 do DER SubjectPublicKeyInfo>",
  "proof": "<base64 do HMAC>",
  "authSignature": "<base64 da assinatura DER>"
}
```

**`proof`** = `HMAC-SHA256(chave: psk, mensagem: transcript)` onde o transcript é
a serialização da seção 5.1. Prova posse do segredo do QR.

**`authSignature`** = assinatura do mesmo transcript pela `authKey` recém-criada.
Isso serve a dois propósitos ao mesmo tempo: prova que o celular realmente
possui a chave privada correspondente à `authPublicKey` declarada, e — porque a
`authKey` é biometricamente travada — **prova que o portão biométrico está
funcionando**, já que a assinatura não teria como existir sem o dedo. O
pareamento pede a digital uma vez, e essa digital é a demonstração.

### 3.3 Confirmação visual (SAS)

Antes de gravar o dispositivo, os dois lados calculam e exibem um código de
6 dígitos:

```
sas = HKDF-SHA256(ikm: psk, salt: "", info: "phoneauth-sas-v1" || transcript, L: 4)
código = (uint32_big_endian(sas) mod 1_000_000), com zeros à esquerda até 6 dígitos
```

O usuário confirma no Mac que os números batem. Isso é defesa em profundidade
contra um intermediário ativo que tenha de alguma forma obtido o `psk`: ele
teria que produzir um transcript diferente, e os códigos divergiriam
visivelmente.

O Mac só grava o dispositivo depois da confirmação humana. Resposta:

```json
{ "type": "pair.ok", "deviceId": "<UUID atribuído pelo Mac>" }
```

O Mac persiste `deviceId`, as duas chaves públicas, nome, plataforma e a data.
**Só chaves públicas** — não há segredo do dispositivo guardado no Mac.

## 4. Sessão

O app mantém uma conexão TLS aberta enquanto está em primeiro plano ou em
background acordável. O Mac descobre nada — é o celular que encontra o Mac via
Bonjour (`_phoneauth._tcp`) e conecta.

Ao conectar, o Mac envia um desafio de sessão:

```json
{ "type": "hello.challenge", "nonce": "<base64 de 32 bytes>" }
```

O celular responde assinando com a **`idKey`** (sem biometria):

```json
{
  "type": "hello.response",
  "deviceId": "<UUID>",
  "signature": "<base64 DER>"
}
```

O Mac verifica contra a `idPublicKey` registrada. A partir daí a conexão está
autenticada como aquele dispositivo. Se a verificação falhar, a conexão é
encerrada sem detalhes de erro.

Keepalive: `{"type":"ping"}` / `{"type":"pong"}` a cada 30 s. O Mac considera
morta uma conexão sem `pong` em 90 s.

## 5. Autenticação

### 5.1 O desafio

O PAM aciona o daemon, que envia à sessão autenticada:

```json
{
  "type": "auth.challenge",
  "requestId": "<UUID maiúsculo>",
  "challenge": "<base64 de 32 bytes aleatórios>",
  "issuedAt": 1770000000,
  "expiresAt": 1770000060,
  "channelBinding": "<hex do SHA-256 do SPKI do cert do servidor>",
  "context": {
    "host": "MacBook Pro de mpgxc",
    "user": "mpgxc",
    "service": "sudo",
    "reason": "sudo: /opt/homebrew/bin/brew install ripgrep",
    "processPath": "/usr/bin/sudo",
    "tty": "ttys002"
  }
}
```

O `context` **não é decoração**. É o que o usuário lê antes de encostar o dedo,
e é a única defesa contra o ataque mais realista deste sistema: um processo
malicioso no Mac dispara um `sudo` e torce para você aprovar no reflexo. Por
isso o contexto entra nos bytes assinados — o Mac consegue provar depois que a
aprovação foi para *aquele* pedido, e não pode trocar o pedido depois de
exibido.

### 5.2 Bytes assinados

Duas serializações encadeadas. Todos os campos em UTF-8, linhas unidas por `\n`
**com `\n` final**. Campo ausente vira string vazia — a linha continua existindo.

**Contexto:**

```
PHONEAUTH-CTX-V1
<host>
<user>
<service>
<reason>
<processPath>
<tty>
```

`contextHash` = hex minúsculo do SHA-256 desses bytes.

**Aprovação:**

```
PHONEAUTH-AUTH-V1
<requestId>
<challenge em base64>
<contextHash>
<channelBinding>
<issuedAt em decimal>
<decision>
```

`decision` é literalmente `allow` ou `deny`. A assinatura é
ECDSA-P256-SHA256 sobre esses bytes, feita pela **`authKey`**.

**Transcript de pareamento** (seção 3), mesma disciplina:

```
PHONEAUTH-PAIR-V1
<sid>
<spki>
<idPublicKey em base64>
<authPublicKey em base64>
<deviceName>
<platform>
```

> **Regra de construção:** nenhum campo pode conter `\n` ou `\r`. Quem monta a
> estrutura valida isso e rejeita antes de assinar. Sem essa regra o formato
> vira ambíguo e um `reason` malicioso conseguiria forjar linhas — um pedido que
> se apresenta como um `sudo` inofensivo enquanto o hash cobre outra coisa.

### 5.3 A resposta

```json
{
  "type": "auth.response",
  "requestId": "<UUID>",
  "decision": "allow",
  "signature": "<base64 DER>"
}
```

O daemon aceita **somente se todas** as condições valerem:

1. `requestId` existe entre os pedidos pendentes;
2. ainda não foi consumido — é marcado como consumido **antes** da verificação,
   de modo atômico, para que uma corrida não gere duas aceitações;
3. `now <= expiresAt`;
4. a assinatura confere contra a `authPublicKey` do dispositivo **daquela
   conexão** — não de qualquer dispositivo pareado;
5. o dispositivo não está revogado;
6. `decision == "allow"`.

Falhando qualquer uma, o resultado é negativo e o PAM cai para o próximo módulo.
O daemon não informa ao celular *qual* condição falhou.

### 5.4 Encerramento

O daemon responde ao módulo PAM pelo socket Unix:

```json
{ "type": "auth.result", "ok": true }
```

## 6. Enquadramento

Todas as mensagens, no socket Unix e no TLS: **4 bytes de comprimento em
big-endian, seguidos do JSON em UTF-8**. Tamanho máximo de 64 KiB; acima disso a
conexão é derrubada sem ler o corpo.

## 7. Erros

```json
{ "type": "error", "code": "pairing_expired", "message": "..." }
```

Códigos: `bad_frame`, `unknown_type`, `pairing_expired`, `pairing_invalid`,
`not_paired`, `device_revoked`, `unauthenticated`, `rate_limited`, `internal`.

As mensagens são deliberadamente vagas. O celular do usuário legítimo não
precisa saber por que falhou — ele tenta de novo — e um atacante sondando o
daemon também não.

## 8. Limites de taxa

- No máximo **1 pedido de autenticação em voo** por dispositivo. Um segundo
  pedido enquanto o primeiro está pendente é recusado com `rate_limited`. Isso
  impede a enxurrada de notificações que treina o usuário a aprovar no
  automático.
- No máximo **5 tentativas de pareamento por minuto**, por IP de origem.
- No máximo **10 pedidos de autenticação por minuto**, no total.
