# Rotação da identidade TLS do daemon

Como trocar `identity.p12` sem obrigar todos os celulares a parear de novo — e
por que a solução óbvia (deixar o `channelBinding` fixo) é pior do que não ter
rotação nenhuma.

## 1. O problema

O hash SHA-256 do SubjectPublicKeyInfo do certificado do daemon é hoje um valor
só, servindo a **dois propósitos com prazos de validade diferentes**:

**(a) É o pin.** O celular guarda esse hash no pareamento e recusa qualquer
certificado TLS que não bata com ele. Substitui inteiramente a validação de
cadeia — não há CA, e é isso que torna o desenho auto-suficiente.

**(b) É o `channelBinding`.** O mesmo hash entra nos bytes assinados do
`hello` (§5.2 do protocolo) e de toda aprovação, para que uma aprovação
capturada não possa ser reapresentada em outra conexão TLS.

Trocar `identity.p12` quebra os dois de uma vez, em quatro lugares:

| Onde | O que acontece |
|---|---|
| Handshake TLS | O celular recusa o certificado novo. Não chega nem a haver conexão. |
| `PHONEAUTH-HELLO-V1` | O celular assina com o hash antigo; o daemon confere com o novo. |
| `PHONEAUTH-AUTH-V1` | Idem — "aprovei no celular e o Mac recusou". |
| `PHONEAUTH-PAIR-V1` | Só afeta pareamentos novos, mas o transcript passa a fixar outro valor. |

O resultado prático está escrito no `install.sh`: *"apagar identity.p12 força
repareamento de TODOS os dispositivos"*.

Uma chave que nunca pode ser rotacionada é um problema de segurança por si só.
Ela acumula exposição indefinidamente (backups, cópias de Time Machine, um
`sudo cat` distraído) e não existe caminho de remediação que não seja "vá até o
Mac com cada aparelho na mão".

## 2. O que o `channelBinding` precisa garantir, exatamente

Vale reler a promessa do [modelo de ameaças](modelo-de-ameacas.md):

> O `channelBinding` inclui o SPKI do certificado do servidor nos bytes
> assinados, então uma aprovação capturada também não pode ser reapresentada em
> outra conexão TLS.

A propriedade é: **a assinatura só vale para quem apresenta aquela chave TLS.**
Um intermediário que consiga um celular assinando para *ele* não consegue
reapresentar a assinatura para o Mac verdadeiro, porque os dois têm chaves TLS
diferentes e o valor assinado difere.

Repare no que a propriedade **não** exige: ela não exige que o valor seja
estável ao longo do tempo. Exige apenas que **as duas pontas da conexão viva
concordem sobre ele**.

E aqui está a raiz do acoplamento: hoje o celular não deriva esse valor da
conexão viva — ele lê o `peer.spki` que guardou no pareamento
(`mobile/ios/PhoneAuth/PhoneAuthClient.swift`, `channelBinding: peer.spki`).
Como o pin obriga o certificado apresentado a ser exatamente aquele, os dois
valores coincidem hoje por construção. É uma coincidência, não um requisito — e
é ela que transforma "trocar a chave" em "invalidar todo pareamento".

## 3. Opções consideradas

### 3.1 Não rotacionar (status quo)

Custo zero, e é onde estamos. O preço é que qualquer suspeita sobre a chave TLS
só tem uma resposta: reparear tudo. Como reparear exige acesso físico ao Mac
desbloqueado *e* uma nova apresentação biométrica em cada aparelho, na prática
ninguém rotaciona — o que significa que a chave vive dez anos (`-days 3650`).

Rejeitado, mas serve de linha de base: **qualquer desenho aqui tem que ser
melhor do que "reparear tudo", senão não vale o código.**

### 3.2 `channelBinding` estável, desligado do canal

O conserto ingênuo: gerar um identificador aleatório de 32 bytes no pareamento,
guardar nos dois lados, e usar *ele* como `channelBinding` para sempre. A
rotação passa a não tocar em nada assinado.

**Rejeitado, e é importante entender por quê.** Um valor que não deriva do
certificado apresentado não liga a assinatura a canal nenhum. Ele liga a
assinatura ao *pareamento*, que é outra coisa. Um intermediário com a chave TLS
antiga apresentaria a chave antiga, o celular assinaria com o mesmo
identificador de sempre, e a assinatura serviria igualmente bem no Mac
verdadeiro. Isso apaga a linha do modelo de ameaças citada acima em troca de
conveniência operacional — exatamente a troca que não se faz.

### 3.3 Exporter de TLS 1.3 (RFC 5705 / RFC 8446 §7.5)

A resposta de livro-texto. O exporter deriva material de chave do handshake
concreto, então liga a assinatura à *sessão* e não apenas à identidade — mais
forte do que temos hoje, e completamente indiferente a rotação de certificado.

**Rejeitado por indisponibilidade, não por desenho.** O Network.framework não
expõe o exporter (não há equivalente de `SSL_export_keying_material` nas APIs
`sec_protocol_metadata_*`), e do lado Android o `SSLSession` padrão também não
o expõe sem descer para APIs específicas do Conscrypt. Um binding que só uma
das três implementações consegue calcular não é um binding.

Fica registrado como o alvo certo caso alguma dessas plataformas passe a expor
a primitiva.

### 3.4 Âncora de assinatura separada (mini-CA)

Introduzir uma chave de longa duração do daemon, distinta da chave TLS. O
celular fixaria a **âncora** no pareamento; o certificado TLS seria emitido (ou
apenas anunciado) pela âncora e poderia ser trocado à vontade. Rotação de TLS
vira operação de rotina, sem protocolo nenhum.

É o desenho certo a longo prazo, e é o que faríamos se estivéssemos começando.
Foi adiado por três razões:

1. **Não elimina o problema, muda de lugar.** A âncora passa a ser a chave que
   nunca rotaciona. Ganhamos porque ela é usada muito menos (nunca vai para a
   rede em handshake), mas o mesmo documento precisaria ser escrito para ela.
2. **Muda o pareamento nas três implementações.** O QR, o `PHONEAUTH-PAIR-V1` e
   a validação TLS do cliente mudariam juntos. Os apps iOS e Android estão em
   desenvolvimento paralelo; uma mudança dessas obriga as três a virarem no
   mesmo commit.
3. **Traz validação de cadeia de volta para o cliente.** O pin de folha existe
   justamente para não ter cadeia — e "validar cadeia contra uma âncora
   própria" é o tipo de código que dá errado silenciosamente.

Registrado como fase 2, com este documento como pré-requisito.

### 3.5 Escolhida: binding derivado da conexão + anúncio assinado, em duas fases

Desfaz a coincidência da seção 2 em vez de contorná-la, e usa a única
autoridade que o daemon tem sobre o celular — a chave TLS que ele *ainda* tem —
para transportar o pin novo de forma autenticada.

## 4. A decisão

### 4.1 O `channelBinding` passa a ser derivado da conexão viva

Regra nova, nas três implementações:

> `channelBinding` é o hex do SHA-256 do SubjectPublicKeyInfo do certificado
> **apresentado nesta conexão TLS**, e nunca um valor lido de armazenamento.

Hoje isso produz exatamente os mesmos bytes que a regra antiga — o pin obriga a
igualdade. A diferença aparece só na rotação, e é toda a diferença: as duas
pontas continuam concordando porque as duas olham para o mesmo certificado, não
para o mesmo registro em disco.

Os quatro payloads de `SignedPayload` ficam **byte a byte inalterados**. Os
vetores em `docs/test-vectors.json` continuam válidos. O que muda é de onde o
cliente tira o valor que preenche o campo.

### 4.2 O pin vira um conjunto, com no máximo dois elementos

O celular deixa de guardar `spki: String` e passa a guardar `pins: [String]`,
ordenado, com **no máximo dois**: o corrente e, durante a transição, o próximo.
O `TrustManager` / `verify_block` aceita se o hash do certificado apresentado
estiver no conjunto.

O teto de dois é deliberado. Um conjunto que só cresce vira um alargamento
progressivo da superfície de confiança — e um pin que aceita cinco chaves não é
mais um pin. Adotar uma terceira substitui a mais antiga.

### 4.3 O anúncio de rotação, assinado pela chave TLS atual

O daemon não tem chave de assinatura de aplicação. Tem exatamente uma coisa que
o celular já confia: **a chave privada TLS que ele está usando agora**. É ela
que assina o anúncio da chave nova. É o mesmo mecanismo de qualquer rollover de
chave (DNSSEC, TUF, o backup pin do HPKP): a chave que sai assina a chave que
entra.

Formato dos bytes assinados — domínio **novo**, `PHONEAUTH-ROTATE-V1`, mesma
disciplina de linhas de §5.2 do protocolo:

```
PHONEAUTH-ROTATE-V1
<rotationId>
<currentSpki>
<nextSpki>
<announcedAt>
<commitNotBefore>
<expiresAt>
<retirePrevious>          ← "true" ou "false", literal
```

Os quatro domínios existentes não foram tocados.

**Sobre reusar a chave TLS para assinar dados de aplicação.** É uma prática que
merece desconfiança — assinaturas cruzadas entre protocolos são uma família
inteira de ataques. Aqui é seguro por separação de domínio explícita: o que o
TLS 1.3 assina em `CertificateVerify` (RFC 8446 §4.4.3) começa obrigatoriamente
com 64 bytes `0x20`, seguidos de uma string de contexto e de um `0x00`. Nosso
payload começa com `PHONEAUTH-ROTATE-V1\n`. Não há entrada que um lado aceite e
o outro interprete. Isso depende de o daemon **só** falar TLS 1.3 — que já é o
caso, e a linha `set_min_tls_protocol_version(.TLSv13)` no `PhoneListener`
passa a ter uma segunda razão de existir.

**O que o cliente confere antes de adotar** (nesta ordem, tudo obrigatório):

1. `sha256(currentSpkiDer)` bate com `currentSpki`;
2. `currentSpki` está no conjunto de pins que o cliente já tem;
3. quando o anúncio chega **pela conexão TLS**: `currentSpki` é o hash do
   certificado *desta* conexão. Isso mata a reapresentação de um anúncio
   gravado em outra conexão;
4. a assinatura verifica sob a chave pública contida em `currentSpkiDer`
   (ECDSA-P256-SHA256, DER);
5. `announcedAt <= agora <= expiresAt`;
6. `nextSpki` tem 64 caracteres hex minúsculos e é diferente de `currentSpki`.

Só então `pins ← {currentSpki, nextSpki}`.

### 4.4 O reconhecimento, assinado pela `idKey`

O celular responde com `rotate.ack`, assinado pela `idKey`. Domínio novo,
`PHONEAUTH-ROTATE-ACK-V1`:

```
PHONEAUTH-ROTATE-ACK-V1
<rotationId>
<deviceId>
<adoptedSpki>
<channelBinding>          ← binding da conexão que carrega o ack
```

O ack não autoriza nada. Serve para uma pergunta operacional que decide se a
rotação é indolor ou não: **quais dispositivos já sabem do pin novo?** Sem essa
resposta, comitar é apostar.

Ele é assinado, e não um simples "ok", porque um ack forjado teria consequência
real: convenceria o operador a comitar e deixaria um aparelho de fora. A
assinatura pela `idKey` custa nada (é a mesma chave do `hello`, sem biometria) e
elimina a classe inteira. O `channelBinding` na última linha amarra o ack à
conexão, para que um ack gravado não seja reapresentado numa rotação futura.

**Por que `idKey` e não `authKey` (biometria).** Adotar um pin é uma mudança de
confiança, e a tentação é pedir o dedo. Três razões para não pedir:

- O anúncio chega quando chega — com o app em background, no meio da noite.
  Exigir presença do usuário transformaria a rotação num evento que trava até
  alguém olhar o celular.
- A autoridade aqui não é o usuário, é a chave TLS antiga. O dedo não
  acrescenta verificação nenhuma sobre o conteúdo do anúncio; só acrescentaria
  um toque reflexo a mais, que é precisamente o hábito que o
  [modelo de ameaças](modelo-de-ameacas.md) trata como a ameaça mais realista
  do sistema.
- Um Mac com root comprometido já tem a chave TLS. Pedir biometria não protege
  contra ele, e a seção "contra o que não protege" já é explícita sobre isso.

O cliente **deve** mostrar um aviso não bloqueante ("o Mac trocou de identidade
TLS"), para que a rotação não seja invisível. Aviso, não portão.

### 4.5 Duas fases: anunciar e comitar

Em nenhum instante existem duas identidades TLS vivas. Isso é decisão de
desenho, não limitação: servir dois certificados ao mesmo tempo exigiria dois
listeners em duas portas (o Network.framework amarra uma identidade por
`NWListener`) e manteria a chave velha em uso por mais tempo, que é o oposto do
objetivo.

```
        identidade A viva                    │      identidade B viva
 ───────────────────────────────────────────►│──────────────────────────────►
                                             │
  rotate begin                         rotate commit              graça acaba
      │                                      │                         │
      ▼                                      ▼                         ▼
      t0 ──── janela de anúncio (7 d) ───── t1 ─── graça (24 h) ─────  t2
      │                                      │                         │
      │  anúncio assinado por A, reenviado   │  sessões derrubadas;    │
      │  a CADA sessão que se autentica      │  todos reconectam com B │
      │                                      │                         │
 pins  {A}  ──────────► {A, B} ───────────► {A, B} ─────────────────► {B}
```

**Fase 1 — `phoneauthctl rotate begin`.** O daemon gera a identidade nova
(`identity-next.p12`), **carrega e valida** antes de qualquer outra coisa,
assina o anúncio com a chave atual, persiste o estado e passa a mandar o
anúncio para toda sessão que se autenticar. A identidade viva continua sendo a
antiga: nada quebra, e um celular que reconecta três dias depois recebe o
anúncio na hora em que aparece.

Reenviar a cada autenticação, em vez de fazer um broadcast único no momento do
`begin`, é o que faz a janela funcionar de verdade — cobre reconexão, celular
que estava fora, e até aparelho pareado *durante* a janela.

**Fase 2 — `phoneauthctl rotate commit`.** Troca os arquivos, reinicia o
listener com a identidade nova e **derruba todas as sessões**. Derrubar é
intencional: força todo mundo a reconectar e re-derivar o binding da conexão
nova, em vez de deixar sessões com estado misto vivas.

O daemon **não comita sozinho**. Recusa comitar antes de `commitNotBefore`, e
recusa comitar enquanto houver dispositivo ativo sem ack — ambos vencíveis com
`--force`. Comitar é a operação que pode trancar um aparelho para fora; é
coerente com o resto do projeto que ela exija um humano, do mesmo jeito que o
pareamento exige a confirmação do SAS.

### 4.6 A janela de graça do binding anterior, e o que ela custa

Depois do commit, por `previousBindingGraceSeconds` (24 h por padrão), o daemon
aceita assinaturas de `hello` e de aprovação calculadas **ou** com o binding
novo **ou** com o anterior. É a "janela configurável" pedida: cobre um cliente
que já adotou o pin novo mas ainda preenche o campo a partir do pin guardado, e
cobre um rollback (`identity-prev.p12` ainda existe durante a graça).

**Essa janela tem custo, e ele precisa estar escrito.** Aceitar dois bindings
reabre parcialmente o buraco que o binding fecha:

> Um atacante de posse da chave TLS **antiga** levanta um daemon falso com o
> certificado antigo. O celular ainda aceita esse pin. O atacante relaia, em
> tempo real, o desafio do daemon verdadeiro; o celular assina com o binding
> antigo, porque é o certificado que ele está vendo; o atacante reapresenta a
> assinatura ao daemon verdadeiro, que a aceita durante a graça.

Ou seja: **a graça só é aceitável sob a hipótese de que a chave antiga não
vazou.** Ela existe para rotação de higiene, não para remediação. Por isso:

- o padrão é curto (24 h) e é configurável para baixo, inclusive zero;
- `rotate begin --compromised` força a graça a zero, sem opção de ligá-la;
- enquanto uma graça está ativa o daemon registra um `warn` a cada
  autenticação aceita pelo binding anterior, para que o estado não passe
  despercebido no log;
- assim que os apps passarem a derivar o binding da conexão viva (§4.1), o
  padrão deve virar zero. A graça é uma muleta de compatibilidade com prazo.

### 4.7 Rotação por comprometimento é outra operação

Se a hipótese "a chave antiga não vazou" cai, **o anúncio assinado deixa de
valer alguma coisa**: quem tem a chave antiga assina um anúncio apontando para
a chave *dele*. Não existe conserto criptográfico para isso dentro do
protocolo — a autoridade que transportaria a confiança é justamente a que
vazou.

`phoneauthctl rotate begin --compromised` portanto faz o honesto:

1. gera e comita a identidade nova **na hora**, sem janela;
2. apaga `identity-prev.p12` imediatamente (sem rollback);
3. fixa a graça em zero;
4. imprime, em letras grandes, que **todos os dispositivos precisam ser
   pareados de novo**, e que o anúncio assinado *não* deve ser usado como
   caminho de recuperação neste caso.

Reparear é caro de propósito: exige acesso físico ao Mac desbloqueado, um `psk`
novo lido da tela e a confirmação do SAS nos dois lados. Nada disso deriva da
chave vazada. É a única raiz de confiança que sobrevive a esse cenário, e é a
mesma que o pareamento original usa.

## 5. O celular que ficou offline

Três níveis, do barato ao caro:

**Offline durante parte da janela.** Nada a fazer: o anúncio é reenviado em toda
autenticação. O aparelho aparece, recebe, ack, pronto.

**Offline a janela inteira, rotação de higiene.** `phoneauthctl rotate qr`
imprime o **mesmo objeto assinado** como QR code (base64url, o mesmo alfabeto do
QR de pareamento). O celular escaneia e roda exatamente as verificações de §4.3,
com a regra 3 substituída por "`currentSpki` está entre os meus pins" — não há
conexão TLS de onde tirar o certificado. Adota o pin novo, guarda, e reconecta.

Isso não é um repareamento: `deviceId`, `idKey`, `authKey`, data de pareamento e
histórico ficam intactos, e não há apresentação biométrica. O custo é uma ida ao
Mac com o celular na mão — o mesmo custo do pareamento, sem a cerimônia.

O QR não é secreto. É uma declaração pública assinada; quem a interceptar
aprende qual é a chave pública nova do seu Mac, que é o que o próprio handshake
TLS anuncia para qualquer um que conectar.

**Offline a janela inteira, e o anúncio expirou ou a rotação foi por
comprometimento.** Reparear. `phoneauthctl rotate qr` recusa emitir o QR para
uma rotação `--compromised`, para não oferecer um caminho que a própria seção
4.7 diz não valer.

## 6. Estado em disco

Acrescenta ao que a [arquitetura](arquitetura.md) descreve:

```
/Library/Application Support/PhoneAuth/     0700 root:wheel
├── devices.json          0600  inalterado
├── identity.p12          0600  identidade TLS viva
├── identity.pass         0600
├── identity-next.p12     0600  só existe entre `begin` e `commit`/`abort`
├── identity-next.pass    0600
├── identity-prev.p12     0600  só existe entre `commit` e o fim da graça
├── identity-prev.pass    0600
├── rotation.json         0600  estado da rotação + acks recebidos
└── config.json           0600
```

`rotation.json` contém apenas material público — hashes, o SPKI DER da chave
que sai, a assinatura do anúncio e quais dispositivos deram ack. Vale a mesma
frase do `devices.json`: se vazar, o atacante aprende que houve uma rotação e
nada além disso.

`identity-prev.p12` é o único acréscimo com peso real: é uma segunda chave
privada em disco. Ela existe apenas durante a graça e é apagada quando a graça
termina — ou imediatamente, numa rotação `--compromised`. Manter chave privada
antiga viva por mais tempo do que o necessário seria trocar um risco por outro.

**Se `identity.p12` não carregar na subida**, o daemon falha como já falha hoje.
Não há rollback automático: um daemon que troca de identidade sozinho, na
inicialização, com base numa heurística de erro, é exatamente o tipo de
esperteza que a gente não quer num processo root. O conserto é manual e cabe
numa linha:

```sh
sudo mv "/Library/Application Support/PhoneAuth/identity-prev.p12" \
        "/Library/Application Support/PhoneAuth/identity.p12"
```

## 7. O que isto muda no modelo de ameaças

**O que melhora.** Existe agora um caminho de remediação para a suspeita sobre
a chave TLS que não é "reparear tudo". O item *"Perda do `identity.p12`"* da
lista de "contra o que não protege" continua verdadeiro, mas deixa de ser
permanente: dá para trocar a chave e seguir.

**O que não muda.** Root no Mac continua sendo jogo perdido. Root gera a
rotação que quiser — mas root já tinha a chave TLS, então não ganha capacidade
nova. O `context` exibido no celular continua sendo a defesa nesse cenário.

**O que piora, e por quanto tempo.** A janela de graça de §4.6, e só ela. É o
único acréscimo de superfície, está limitado no tempo, é desligável, e é zero no
único cenário em que importaria.

**Ataques novos que o desenho fecha explicitamente:**

| Tentativa | O que impede |
|---|---|
| Anúncio forjado apontando para a chave do atacante | Assinatura pela chave TLS atual, verificada contra o pin que o celular já tem |
| Anúncio gravado e reapresentado em outra conexão | Regra 3 de §4.3: `currentSpki` tem que ser o certificado *desta* conexão |
| Anúncio antigo reapresentado depois de uma rotação posterior | `expiresAt`, e o fato de `currentSpki` já não estar mais nos pins do celular |
| Ack forjado para forçar um commit prematuro | Assinatura pela `idKey`, amarrada ao `rotationId` e ao binding da conexão |
| Alargar o pin do celular indefinidamente | Teto de dois pins (§4.2) |
| Pedir aprovação com contexto trocado durante a rotação | Nada aqui toca em `contextHash`; a defesa é a mesma de sempre |

## 8. O que os clientes precisam implementar (tarefa de follow-up)

**Nada em `mobile/` foi alterado por este trabalho.** O daemon foi escrito para
ser compatível com os clientes atuais até o momento do commit: enquanto a
rotação está apenas anunciada, um cliente que ignora `rotate.announce` continua
funcionando normalmente. Ele só é trancado para fora quando o commit acontece —
que é o comportamento correto, e é por isso que o daemon recusa comitar sem os
acks.

### 8.1 Comum às duas plataformas

1. **Guardar `pins: [String]` em vez de `spki: String`**, com no máximo dois
   elementos, e aceitar o certificado se o hash estiver no conjunto
   (`PinnedTrustManager` no Android, `sec_protocol_options_set_verify_block` no
   iOS). Migração do estado antigo: `pins = [spki]`.
2. **Derivar o `channelBinding` da conexão viva** (§4.1), em `hello.response` e
   em `auth.response`. Hoje os dois usam `peer.spki`. No iOS o certificado da
   folha já passa pelo `verify_block`; guarde o hash calculado ali na sessão. No
   Android, `socket.session.peerCertificates[0]`.
3. **Implementar `PHONEAUTH-ROTATE-V1` e `PHONEAUTH-ROTATE-ACK-V1`** em
   `SignedPayload.swift` / `SignedPayload.kt`, com a mesma disciplina dos
   quatro existentes (UTF-8, `\n` entre campos e no final, campo ausente vira
   linha vazia, rejeitar `\n`/`\r` em qualquer campo).
4. **Tratar `rotate.announce`**: as seis verificações de §4.3, nesta ordem,
   todas obrigatórias. Falhando qualquer uma, ignorar em silêncio — não
   desconectar, não avisar o servidor.
5. **Responder `rotate.ack`** assinado pela `idKey`. Sem biometria.
6. **Se `retirePrevious == true`**: adotar o pin novo, remover o antigo do
   conjunto **e desconectar imediatamente** — a conexão atual está sob um
   certificado que acabou de deixar de ser confiável. Reconectar com backoff.
7. **Avisar o usuário**, sem bloquear.
8. **Ler o QR de re-pin** (§5): mesmo objeto, mesmas verificações, regra 3
   trocada por "`currentSpki` está entre os meus pins". Reaproveita o leitor de
   QR do pareamento.

### 8.2 Vetores de teste

`docs/generate-test-vectors.py` precisa ganhar os dois domínios novos, e os
vetores resultantes entram em `docs/test-vectors.json`. Os quatro vetores
existentes **não mudam** — nenhum payload antigo foi tocado. Esse é o critério
de aceitação mais barato de verificar: se algum dos quatro mudar, alguém
quebrou compatibilidade sem perceber.

### 8.3 Ordem sugerida

Passos 1 e 2 primeiro, e só eles, num commit isolado: eles são invisíveis
(produzem exatamente os mesmos bytes de hoje) e destravam poder zerar a graça
de §4.6. O resto vem depois.

## 9. Limitações conhecidas

- **A graça de §4.6 é uma muleta.** Enquanto ela existir com valor diferente de
  zero, o binding não é tão forte quanto o documento de ameaças afirma. O
  caminho para removê-la está em §8.3.
- **Nada disto protege a chave TLS.** Ela continua num `.p12` em disco, com
  senha guardada ao lado. Migrar para o System Keychain continua sendo a
  melhoria de fase 2 que a [arquitetura](arquitetura.md) já cita — e a rotação
  torna essa migração *mais* fácil, porque agora existe uma operação que troca a
  chave sem trauma.
- **A rotação é manual.** Não há política de "rotacione a cada N dias". Achamos
  cedo demais para automatizar uma operação que pode trancar um aparelho para
  fora; primeiro que ela exista e seja usada algumas vezes.
- **Um único Mac.** Nada aqui considera dois Macs pareados com o mesmo celular
  compartilhando estado de rotação. Cada Mac é uma identidade independente e o
  celular guarda um `Peer` por Mac.
- **Nada foi compilado.** Ver [status](status.md): este container não tem Swift.
