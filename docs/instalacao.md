# Instalação

> Leia [status.md](status.md) antes. Nada além do módulo PAM foi compilado, e
> este projeto mexe na sua pilha de autenticação.

## Requisitos

- macOS 13 ou mais novo, com Xcode Command Line Tools
- iPhone com Face ID/Touch ID, ou Android 9+ com biometria forte
- Os dois na mesma rede local

Não é preciso desabilitar o SIP. O módulo vai para `/usr/local/lib/pam` e é
referenciado por caminho absoluto, coisa que o OpenPAM aceita — desabilitar o
SIP seria um preço absurdo por uma conveniência de autenticação.

## 1. Instalar o lado macOS

```sh
git clone https://github.com/mpgxc/automatic-fiesta.git
cd automatic-fiesta
sudo ./scripts/install.sh
```

Isso constrói tudo, gera a identidade TLS P-256, instala os binários e sobe o
LaunchDaemon. **Não toca em `/etc/pam.d`** — essa etapa fica manual e explícita,
porque é a única que pode estragar o `sudo`.

Confirme:

```sh
sudo phoneauthctl status
```

## 2. Parear o celular

```sh
sudo phoneauthctl pair
```

Aparece um QR no terminal, válido por 2 minutos. Escaneie com o app. O celular
vai pedir a biometria uma vez — essa digital é o que prova ao Mac que o portão
biométrico existe e funciona.

Os dois lados exibem um código de 6 dígitos. **Confira que são iguais.** Se
divergirem, cancele: alguém está no meio.

```sh
sudo phoneauthctl list
```

## 3. Plugar no sudo

Só depois de parear. Crie ou edite `/etc/pam.d/sudo_local`:

```
auth  sufficient  /usr/local/lib/pam/pam_phoneauth.so  timeout=30
```

`sudo_local` é um drop-in que sobrevive a atualizações do macOS. Editar
`/etc/pam.d/sudo` direto seria desfeito no próximo update do sistema.

### A parte que não dá para pular

**Abra uma segunda janela de terminal** e rode `sudo true`. Confirme que
funciona antes de fechar a primeira.

A primeira janela ainda tem uma sessão `sudo` válida. Se algo der errado, é por
ela que você conserta:

```sh
sudo rm /etc/pam.d/sudo_local
```

O módulo é `sufficient`, então mesmo completamente quebrado ele apenas cai para
o próximo módulo e você digita a senha. Mas um erro de digitação no arquivo
`sudo_local` é outra história, e a janela reserva custa nada.

Teste:

```sh
sudo -k && sudo true
```

O celular deve vibrar mostrando `sudo true`.

## 4. Desbloqueio de tela (opcional)

Por padrão o protetor de tela usa a UI da janela de login, que não passa por
PAM. Dá para mudar:

```sh
sudo security authorizationdb write system.login.screensaver \
    authenticate-session-owner-or-admin
```

E acrescentar o módulo em `/etc/pam.d/screensaver`, além de `screensaver` à
lista `allowedServices` em
`/Library/Application Support/PhoneAuth/config.json`.

Para reverter:

```sh
sudo security authorizationdb write system.login.screensaver \
    use-login-window-ui
```

Isto é mais invasivo que o `sudo` — mexe no authorization database do sistema.
Deixe para depois de o `sudo` estar funcionando há alguns dias.

## Desinstalar

```sh
sudo ./scripts/uninstall.sh
```

Remove a linha do `/etc/pam.d` **primeiro**, depois o resto. Use
`--keep-devices` para preservar os pareamentos.

## Quando não funciona

**"nenhum dispositivo conectado"** — o app precisa estar aberto ou em background
acordável, e os dois na mesma rede. É a limitação prática mais séria da v1.

**`sudo` pede senha e o celular não vibra** — o daemon está fora do ar ou o
`sudo_local` não foi lido. Nada quebrou; é o `sufficient` fazendo o trabalho
dele. Veja:

```sh
sudo phoneauthctl status
tail -f /var/log/phoneauthd.log
```

**"aprovei no celular e o Mac recusou"** — quase sempre é divergência de bytes
entre as implementações do `SignedPayload`. Rode os testes de vetores nos dois
lados; ver [status.md](status.md).

**O celular parou de aprovar depois de eu cadastrar uma digital nova** — é o
comportamento correto. A chave de aprovação é destruída pelo SO quando o
conjunto de biometrias muda, exatamente para impedir que alguém cadastre o
próprio dedo num aparelho desbloqueado. Pareie de novo.

**Perdi o celular** — `sudo phoneauthctl revoke <id>`. Se não conseguir chegar
ao Mac, o `sudo` continua funcionando com a senha normalmente: o módulo é
`sufficient` e simplesmente falha para o próximo.
