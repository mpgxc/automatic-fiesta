# Modelo de ameaças

## Contra o que este desenho protege

**Atacante na sua rede local.** Vê o anúncio Bonjour e alcança a porta TLS. Não
consegue nada: pareamento exige o `psk` que só aparece no QR da sua tela, e
conectar sem ser um par registrado só rende um desafio de sessão que ele não
sabe assinar.

**Captura e reprodução de tráfego.** Cada desafio tem 32 bytes aleatórios, TTL
de 60 s e é de uso único, consumido atomicamente antes da verificação. Uma
aprovação gravada não vale para o próximo pedido. O `channelBinding` inclui o
SPKI do certificado do servidor nos bytes assinados, então uma aprovação
capturada também não pode ser reapresentada em outra conexão TLS.

**Comprometimento do lado do Mac.** É o mais interessante. Um atacante com root
no seu Mac lê o `devices.json` inteiro e não ganha capacidade de forjar
aprovação — as chaves privadas estão no hardware do celular. O que ele
*consegue* é disparar pedidos, e é por isso que o contexto exibido no celular
importa tanto: um `sudo` que você não iniciou aparece na sua mão e você nega.

Vale ser claro sobre o limite disso: root no Mac já é jogo perdido por outras
vias — ele espera você aprovar um `sudo` legítimo e usa a janela de graça do
`sudo` para o que quiser. PhoneAuth não conserta isso e nada neste nível
conserta.

**Celular roubado, bloqueado.** A `authKey` exige biometria a cada assinatura, e
a chave privada não é extraível do Secure Enclave/StrongBox. Sem o seu dedo, não
há assinatura.

**Digital nova cadastrada no celular roubado.** É o ataque que a flag
`.biometryCurrentSet` / `setInvalidatedByBiometricEnrollment(true)` mata: o
próprio SO **destrói a chave** quando o conjunto de biometrias cadastradas muda.
O dispositivo passa a falhar toda aprovação e precisa ser pareado de novo — o
que exige acesso físico ao seu Mac desbloqueado.

**Um app malicioso no celular.** Não consegue usar a `authKey`: ela pertence ao
nosso app e o acesso é mediado pelo SO.

## Contra o que não protege

**Celular desbloqueado nas mãos de outra pessoa, com a digital dela cadastrada
antes.** Se o atacante já estava no conjunto de biometrias quando você pareou,
ele aprova. Coação física idem — este é um sistema de autenticação, não de
resistência a coação.

**Root no Mac,** conforme acima.

**Você aprovando sem ler.** A defesa central contra pedidos maliciosos é o
contexto na tela do celular. Se o hábito virar "vibrou, encosta o dedo", a
proteção evapora. O limite de um pedido em voo por dispositivo existe
exatamente para dificultar a criação desse hábito por enxurrada de notificações,
mas nenhuma medida técnica conserta aprovação por reflexo.

**Perda do `identity.p12`.** Um atacante que a obtenha se passa pelo seu Mac
para o seu celular e envia pedidos falsos. De novo: o contexto é a defesa.

**Análise de tráfego.** Um observador na LAN vê que houve um evento de
autenticação, quando, e o tamanho aproximado. O conteúdo é opaco. Não achamos
isso relevante o suficiente para adicionar padding.

## O problema da fase 2 que merece destaque

Para preencher os **diálogos gráficos** (`SecurityAgent`), o plugin de
autorização precisa injetar a senha da conta no contexto. Isso significa que o
Mac tem que **guardar a sua senha em algum lugar** — e esse lugar teria que ser
legível por um daemon root sem intervenção humana, o que na prática significa
uma senha em claro atrás de uma permissão de arquivo.

Isso é qualitativamente pior do que tudo na v1. Hoje o Mac não guarda segredo
nenhum: só chaves públicas. A fase 2 introduziria a sua senha de login como
alvo em disco.

Não há saída elegante. O prompt do `SecurityAgent` quer uma senha, ponto — e a
raiz do problema é que a chave do FileVault deriva dessa senha, então ela não
pode ser substituída por um fator biométrico remoto sem quebrar a criptografia
do disco. As opções são: aceitar o risco de forma consciente e documentada, ou
manter a fase 2 restrita aos direitos que aceitam um mecanismo dizendo apenas
"permitido" sem fornecer credencial. A segunda cobre menos, e é a que
pretendemos tentar primeiro.

## Instalar isto tem custos

Você adiciona: um daemon root permanente, um módulo de terceiros na sua pilha
PAM, e uma porta de escuta na sua LAN.

O módulo PAM é a peça mais sensível do projeto, porque roda dentro do `sudo`,
como root. Um bug de memória ali é escalação de privilégio local. Ele foi
mantido curto e sem alocação dinâmica no caminho crítico por esse motivo — mas
"foi escrito com cuidado" não é o mesmo que "foi auditado", e este código **não
foi auditado nem sequer compilado ainda**.

Se você não vai ler o `pam_phoneauth.c` antes de instalar, é melhor não
instalar.

## A regra de ouro

O módulo PAM é sempre `sufficient`, nunca `required`. Todo caminho de erro
retorna `PAM_AUTHINFO_UNAVAIL`, e o PAM segue para o próximo módulo.

Não existe estado em que este projeto te tranque fora da sua máquina. Um patch
que introduza `PAM_SUCCESS` fora do caminho de assinatura verificada, ou que
sugira instalar como `required`, é um bug de severidade máxima.
