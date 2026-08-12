# O app Android

Instalar, parear e o que precisa estar presente no aparelho para funcionar.

## O APK publicado não instala, e o motivo é a assinatura

O arquivo se chama `phoneauth-<versão>-SEM-ASSINATURA.apk` e o nome é literal:
ele não tem assinatura v1 nem v2/v3. O Android recusa no parse, com
`INSTALL_PARSE_FAILED_NO_CERTIFICATES` — que a interface mostra como um genérico
"app não instalado".

**Não é** "fontes desconhecidas", **não é** a versão do Android e **não é** falta
de espaço. São as três coisas que se tenta antes de desconfiar da assinatura.

Ele sai assim porque o repositório não tem uma keystore configurada, e assinar
com uma chave descartável a cada build seria pior: a assinatura é a identidade
do app, e trocá-la impede qualquer atualização futura sobre a instalação
existente.

Há dois caminhos. O primeiro resolve agora, na sua máquina; o segundo resolve
para sempre, no CI.

### Caminho 1 — assinar você mesmo, agora

Precisa do `apksigner`, que vem no *build-tools* do SDK do Android (com o Android
Studio instalado, algo como
`~/Library/Android/sdk/build-tools/35.0.0/apksigner`).

```sh
# Uma vez: crie a chave. Guarde o arquivo e as senhas.
keytool -genkeypair -v -keystore release.jks -alias phoneauth \
        -keyalg RSA -keysize 4096 -validity 10000

# A cada versão baixada:
apksigner sign --ks release.jks \
          --out phoneauth-assinado.apk \
          phoneauth-0.1.2-SEM-ASSINATURA.apk

# Confirme antes de instalar:
apksigner verify --print-certs phoneauth-assinado.apk
```

Depois instale com `adb install phoneauth-assinado.apk`, ou transfira o arquivo
para o aparelho e abra.

### Caminho 2 — deixar o CI assinar

A mesma chave do caminho 1, guardada em secrets. Feito uma vez, toda release
seguinte sai instalável.

```sh
base64 -i release.jks | pbcopy
```

Em **Settings → Secrets and variables → Actions**, crie quatro:

| Secret | Valor |
|---|---|
| `ANDROID_KEYSTORE_BASE64` | o que está na área de transferência |
| `ANDROID_KEYSTORE_PASSWORD` | a senha da keystore |
| `ANDROID_KEY_ALIAS` | `phoneauth` |
| `ANDROID_KEY_PASSWORD` | a senha da chave |

O próximo merge em `main` publica um APK assinado, e o nome deixa de ter
`SEM-ASSINATURA`. Se a assinatura falhar em silêncio — alias errado, senha
errada — o release **quebra** em vez de publicar um instalável que não instala:
o workflow verifica o artefato com `apksigner` antes de anexá-lo.

> **Guarde o `release.jks` e as senhas.** Perder a chave impede qualquer
> atualização futura sobre as instalações existentes, e não existe recuperação:
> um APK assinado com outra chave é, para o Android, outro app.

## O que o aparelho precisa ter

**Android 10 ou mais novo** (`minSdk 29`).

**Uma biometria Classe 3 (BIOMETRIC_STRONG) cadastrada.** Isto não é detalhe: as
chaves são criadas com `setAllowedAuthenticators(BIOMETRIC_STRONG)` e
`setUserAuthenticationParameters(0, AUTH_BIOMETRIC_STRONG)`, então o app não
funciona com biometria Classe 2. Na prática, leitor de digital costuma ser
Classe 3; **reconhecimento facial por câmera, na maioria dos Androids, é Classe
2** e não serve. Se o aparelho só tem face unlock, cadastre uma digital.

O `0` naquele parâmetro quer dizer que a autenticação vale para **um** uso — cada
assinatura exige uma apresentação nova. Não há janela de carência.

## As permissões, e por que cada uma

| Permissão | Para quê |
|---|---|
| `INTERNET` | falar com o Mac pela rede local |
| `USE_BIOMETRIC` | o prompt biométrico que destrava a chave |
| `ACCESS_NETWORK_STATE` | saber quando a rede volta, para reconectar |
| `CHANGE_WIFI_MULTICAST_STATE` | descobrir o Mac via mDNS |
| `CAMERA` | ler o QR do pareamento |

Só a câmera é pedida em tempo de execução, e só na tela de pareamento. As outras
são concedidas na instalação.

O multicast merece explicação: o Wi-Fi de muitos aparelhos descarta pacotes
multicast para poupar bateria, e sem eles o mDNS não enxerga o Mac. O app adquire
um `MulticastLock` durante a descoberta — é por isso que a permissão existe.

Não há tráfego em texto claro. `usesCleartextTraffic` fica desligado e toda a
comunicação é TLS 1.3 com o certificado do Mac fixado no pareamento.

## Primeiro pareamento

1. No Mac: `sudo phoneauthctl pair` — um QR aparece no terminal, válido por 2 minutos.
2. No celular: abra o app, toque em **Escanear QR code**, autorize a câmera.
3. Os dois lados mostram um código de **seis dígitos**. Eles têm de ser iguais.
4. Confirme no Mac digitando `s`.

O código de seis dígitos não é enfeite. Ele deriva do segredo do QR e das chaves
públicas dos dois lados, então alguém no meio da rede não consegue fazer os dois
baterem. **Se divergirem, recuse** — é a única indicação que você teria.

Depois disso, falta ligar o módulo ao `sudo` no Mac: veja
[instalacao.md](instalacao.md) e [uso.md](uso.md).

## Quando não funciona

| Sintoma | O que é |
|---|---|
| "app não instalado" ao abrir o APK | falta assinatura — veja o topo deste documento |
| o app abre mas não acha o Mac | os dois precisam estar na mesma rede; redes de convidados e isolamento de clientes (AP isolation) bloqueiam mDNS |
| erro ao criar as chaves no pareamento | nenhuma biometria Classe 3 cadastrada; cadastre uma digital |
| parou de aprovar depois de cadastrar uma digital nova | **correto.** O sistema destrói a chave quando o conjunto de biometrias muda, para impedir que alguém cadastre o próprio dedo num aparelho desbloqueado. Pareie de novo. |
| o Mac pede senha e o celular não reage | o app precisa estar aberto ou em background acordável. É a limitação prática mais séria da v1. |
| aprovei e o Mac recusou | divergência de bytes entre as implementações; ver [status.md](status.md) |

## O que ainda não foi provado

Nada disto rodou contra hardware real. O APK é construído e o R8 é exercitado a
cada push, mas nenhum pareamento aconteceu entre um Mac e um Android de verdade.
[status.md](status.md) mantém essa fronteira registrada.
