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
  "spki": "<hex minúsculo do SHA-256 do SubjectPublicKeyInfo DER do cert do daemon>",
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

> O celular guarda o pin como um **conjunto** de no máximo dois hashes, não um
> valor único: é o que permite rotacionar a identidade do daemon sem repareamento
> (§9). No pareamento o conjunto tem um elemento só, o `spki` do QR.

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

**De onde sai o `channelBinding`.** Sempre do certificado **apresentado nesta
conexão TLS** — hex do SHA-256 do SubjectPublicKeyInfo dele — e nunca de um
valor lido do armazenamento do pareamento. Enquanto houver um pin só os dois
coincidem, mas são coisas diferentes: o pin diz em quem confiar, o binding diz
com quem se está falando agora. Confundir os dois é o que tornava a rotação da
identidade impossível (§9).

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
  "channelBinding": "<hex do SHA-256 do SPKI do cert apresentado nesta conexão>",
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

**Anúncio e reconhecimento de rotação** (seção 9), mesma disciplina. Estes dois
foram **acrescentados**; os quatro acima não mudaram um byte, e os vetores em
`docs/test-vectors.json` continuam valendo como estão.

```
PHONEAUTH-ROTATE-V1
<rotationId>
<currentSpki>
<nextSpki>
<announcedAt em decimal>
<commitNotBefore em decimal>
<expiresAt em decimal>
<retirePrevious>            ← literalmente "true" ou "false"
```

```
PHONEAUTH-ROTATE-ACK-V1
<rotationId>
<deviceId>
<adoptedSpki>
<channelBinding>
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

## 9. Rotação da identidade TLS

Troca a chave TLS do daemon sem invalidar os pareamentos. O desenho completo,
com as opções consideradas e os trade-offs, está em
[rotacao-de-identidade.md](rotacao-de-identidade.md) — aqui ficam só os bytes.

Duas fases, e **em nenhum instante existem duas identidades TLS vivas**. Entre
o anúncio e o commit, a identidade viva continua sendo a antiga: nada quebra.

### 9.1 `rotate.announce` — Mac → celular

Enviado a **toda sessão logo depois de ela se autenticar**, enquanto houver
rotação anunciada. Reenviar sempre, em vez de um broadcast único, é o que faz a
janela funcionar: cobre reconexão, celular que estava fora do ar e aparelho
pareado no meio da janela.

```json
{
  "type": "rotate.announce",
  "rotationId": "<UUID>",
  "currentSpki": "<hex do SPKI da identidade que está saindo>",
  "currentSpkiDer": "<base64 do SubjectPublicKeyInfo DER dessa mesma chave>",
  "nextSpki": "<hex do SPKI da identidade que entra>",
  "announcedAt": 1770000000,
  "commitNotBefore": 1770604800,
  "expiresAt": 1771209600,
  "retirePrevious": false,
  "signature": "<base64 DER>"
}
```

`signature` é ECDSA-P256-SHA256 sobre `PHONEAUTH-ROTATE-V1` (§5.2), feita com a
**chave privada TLS atual** — a que está saindo. É a única autoridade que o
daemon tem sobre um celular já pareado: a chave que sai assina a que entra.

Reusar a chave TLS para assinar dados de aplicação é seguro por separação de
domínio: o `CertificateVerify` do TLS 1.3 (RFC 8446 §4.4.3) cobre bytes que
começam obrigatoriamente com 64 bytes `0x20`; este payload começa com
`PHONEAUTH-ROTATE-V1\n`. Isso depende de o daemon só falar TLS 1.3, que é o caso.

**O celular só adota depois de todas estas verificações, nesta ordem:**

1. `sha256(currentSpkiDer)` é igual a `currentSpki`;
2. `currentSpki` está no conjunto de pins que o celular já tem;
3. chegando pela conexão TLS: `currentSpki` é o hash do certificado **desta**
   conexão. Isso mata a reapresentação de um anúncio gravado noutra conexão;
4. `signature` verifica sob a chave pública contida em `currentSpkiDer`;
5. `announcedAt <= agora <= expiresAt`;
6. `nextSpki` tem 64 hex minúsculos e é diferente de `currentSpki`.

Falhando qualquer uma: **ignorar em silêncio**. Não desconectar, não responder.

Adotando: `pins ← {currentSpki, nextSpki}`. O conjunto tem teto de dois — um pin
que aceita cinco chaves não é mais um pin; adotar uma terceira substitui a mais
antiga.

E o conjunto volta a ter um sozinho, sem mensagem nenhuma:

> Depois de um `ping`/`pong` completo sob o pin X, o celular descarta os demais.

O `pong` é a primeira evidência positiva de que o daemon aceitou a sessão — ele
encerra sem detalhes quando o `hello` não confere. A regra vale nos dois
sentidos: rotação comitada colapsa em `{novo}`, rotação abortada colapsa de
volta em `{antigo}`. Sem ela o celular passaria a confiar em duas chaves para
sempre por causa de uma janela de dias.

Com `retirePrevious == true` o celular descarta `currentSpki` na hora **e
derruba a conexão**: ela está sob um certificado que acabou de deixar de ser
confiável. Reconecta com backoff.

### 9.2 `rotate.ack` — celular → Mac

```json
{
  "type": "rotate.ack",
  "rotationId": "<UUID>",
  "deviceId": "<UUID>",
  "adoptedSpki": "<hex, igual ao nextSpki>",
  "signature": "<base64 DER>"
}
```

Assinatura pela **`idKey`**, sem biometria, sobre `PHONEAUTH-ROTATE-ACK-V1`
(§5.2). O `channelBinding` daquela serialização é o da conexão que carrega o
ack — o da identidade **antiga**, já que o commit ainda não aconteceu.

Não usa a `authKey` de propósito: o anúncio chega quando chega, com o app em
background, e a autoridade sobre o conteúdo é a chave TLS, não o usuário. Pedir
o dedo aqui não verificaria nada e treinaria exatamente o toque reflexo que o
[modelo de ameaças](modelo-de-ameacas.md) trata como a ameaça mais realista.

O ack não autoriza nada. Ele responde à pergunta que decide se comitar tranca
alguém para fora: **quem já sabe do pin novo?** É assinado porque um ack forjado
convenceria o operador a comitar cedo demais, e leva o `channelBinding` para que
um ack gravado não sirva numa rotação futura.

O daemon aceita `rotate.ack` **só de sessão autenticada**, e não responde nada —
nem sucesso, nem erro. Ack inválido é registrado no log e descartado.

### 9.3 O commit

Não é mensagem. O daemon troca os arquivos, reabre a escuta com o certificado
novo e **derruba todas as sessões**. Os celulares reconectam; quem adotou passa
no pinning, quem não adotou não passa. O daemon nunca comita sozinho — é sempre
um comando explícito do operador (`phoneauthctl rotate commit`).

Por uma janela configurável depois do commit, o daemon aceita assinaturas de
`hello.response` e `auth.response` calculadas com o binding **anterior**. Isso é
uma muleta de compatibilidade com custo de segurança real e prazo para acabar —
ver §4.6 do documento de desenho. Numa rotação por comprometimento a janela é
zero, sem opção.

### 9.4 Fora de banda

O mesmo objeto de §9.1, em base64url (mesmo empacotamento do QR de pareamento),
pode ser exibido como QR pelo Mac para um aparelho que ficou fora do ar a janela
inteira. As verificações são as mesmas, com a regra 3 trocada por "`currentSpki`
está entre os meus pins" — não há conexão TLS de onde tirar o certificado.

Não é repareamento: `deviceId`, chaves e histórico ficam intactos, e não há
apresentação biométrica. O QR não é secreto.

Este caminho **não vale** para rotação por comprometimento: o anúncio é assinado
pela chave que vazou, então quem a tem assina um anúncio igual apontando para a
chave dele. Nesse cenário a única remediação é parear de novo.
