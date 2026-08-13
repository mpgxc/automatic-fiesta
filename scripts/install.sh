#!/bin/bash
#
# Instala o PhoneAuth. Rode com sudo, a partir da raiz do repositório.
#
# Este script NÃO toca em /etc/pam.d. A última etapa — plugar o módulo na sua
# pilha de autenticação — fica manual e explícita, porque é a única com
# potencial de estragar o `sudo`, e você deve estar olhando quando acontecer.

set -euo pipefail

STATE_DIR="/Library/Application Support/PhoneAuth"
PAM_DIR="/usr/local/lib/pam"
BIN_DIR="/usr/local/bin"
MAN_DIR="/usr/local/share/man/man1"
PLIST="/Library/LaunchDaemons/dev.phoneauth.daemon.plist"
LABEL="dev.phoneauth.daemon"

if [[ $EUID -ne 0 ]]; then
    echo "erro: rode com sudo" >&2
    exit 1
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# ---------------------------------------------------------------------------
# Construir ou usar o que já veio pronto
#
# O mesmo script serve a dois contextos: um checkout do repositório, onde há
# fontes e toolchain, e o tarball de release, que traz só os binários. A
# distinção é a presença das fontes — não uma flag, porque flag esquecida vira
# erro confuso ("swift: command not found") em vez de comportamento correto.
# ---------------------------------------------------------------------------
if [[ -f macos/Package.swift ]]; then
    echo "==> Construindo o daemon e a CLI"
    (cd macos && swift build -c release)
else
    echo "==> Usando o daemon e a CLI pré-construídos"
fi

if [[ -f macos/pam/Makefile ]]; then
    echo "==> Construindo o módulo PAM"
    (cd macos/pam && make)
else
    echo "==> Usando o módulo PAM pré-construído"
fi

for artefato in macos/.build/release/phoneauthd \
                macos/.build/release/phoneauthctl \
                macos/pam/pam_phoneauth.so \
                macos/LaunchDaemon/dev.phoneauth.daemon.plist \
                macos/man/phoneauthctl.1; do
    if [[ ! -f "$artefato" ]]; then
        echo "erro: $artefato não existe — pacote incompleto ou build falhou" >&2
        exit 1
    fi
done

echo "==> Criando $STATE_DIR"
install -d -o root -g wheel -m 0700 "$STATE_DIR"

# ---------------------------------------------------------------------------
# Identidade TLS
#
# Gerada com openssl e não em Swift: construir um certificado auto-assinado em
# Swift puro exigiria um codificador ASN.1 escrito à mão, e código delicado
# dentro de um daemon root é exatamente o que não queremos.
#
# O certificado é auto-assinado de propósito. O celular fixa o hash do SPKI no
# pareamento, então não há CA nem cadeia para validar — a confiança vem do que
# foi visto no QR e de nada mais.
# ---------------------------------------------------------------------------
if [[ -f "$STATE_DIR/identity.p12" ]]; then
    echo "==> Identidade TLS já existe; preservando"
    echo "    (apagar identity.p12 força repareamento de TODOS os dispositivos)"
else
    echo "==> Gerando identidade TLS P-256"
    PASSPHRASE="$(openssl rand -base64 32)"
    TMP="$(mktemp -d)"
    trap 'rm -rf "$TMP"' EXIT

    openssl ecparam -name prime256v1 -genkey -noout -out "$TMP/key.pem" 2>/dev/null
    openssl req -new -x509 -key "$TMP/key.pem" -out "$TMP/cert.pem" \
        -days 3650 -sha256 \
        -subj "/CN=phoneauthd/O=PhoneAuth" \
        -addext "subjectAltName=DNS:$(hostname -s).local,DNS:localhost" 2>/dev/null

    openssl pkcs12 -export -out "$TMP/identity.p12" \
        -inkey "$TMP/key.pem" -in "$TMP/cert.pem" \
        -passout "pass:$PASSPHRASE" 2>/dev/null

    install -o root -g wheel -m 0600 "$TMP/identity.p12" "$STATE_DIR/identity.p12"
    printf '%s' "$PASSPHRASE" > "$TMP/identity.pass"
    install -o root -g wheel -m 0600 "$TMP/identity.pass" "$STATE_DIR/identity.pass"

    rm -rf "$TMP"
    trap - EXIT
fi

echo "==> Instalando binários"
install -o root -g wheel -m 0755 macos/.build/release/phoneauthd   "$BIN_DIR/phoneauthd"
install -o root -g wheel -m 0755 macos/.build/release/phoneauthctl "$BIN_DIR/phoneauthctl"

echo "==> Instalando o módulo PAM em $PAM_DIR"
install -d -o root -g wheel -m 0755 "$PAM_DIR"
install -o root -g wheel -m 0444 macos/pam/pam_phoneauth.so "$PAM_DIR/pam_phoneauth.so"

echo "==> Instalando a man page"
install -d -o root -g wheel -m 0755 "$MAN_DIR"
install -o root -g wheel -m 0644 macos/man/phoneauthctl.1 "$MAN_DIR/phoneauthctl.1"

echo "==> Instalando o LaunchDaemon"
install -o root -g wheel -m 0644 macos/LaunchDaemon/dev.phoneauth.daemon.plist "$PLIST"

launchctl bootout "system/$LABEL" 2>/dev/null || true

# Mesma espera-e-insiste do macos/installer/scripts/postinstall, e pelo mesmo
# motivo: `bootout` retorna antes de o serviço sumir, e um `bootstrap` imediato
# dá "Operation already in progress". Aqui, com `set -e`, isso abortaria o
# script no meio — com os binários já instalados e o daemon fora do ar.
for _ in $(seq 1 50); do
    launchctl print "system/$LABEL" >/dev/null 2>&1 || break
    sleep 0.2
done

tentativa=1
until saida="$(launchctl bootstrap system "$PLIST" 2>&1)"; do
    if [[ $tentativa -ge 5 ]]; then
        echo "erro: launchctl bootstrap falhou após $tentativa tentativas" >&2
        echo "      launchctl disse: ${saida:-(nada)}" >&2
        exit 1
    fi
    tentativa=$((tentativa + 1))
    sleep 1
done

sleep 1
if phoneauthctl status >/dev/null 2>&1; then
    echo "==> Daemon rodando"
else
    echo "!!! O daemon não respondeu. Veja /var/log/phoneauthd.log" >&2
    exit 1
fi

cat <<'EOF'

────────────────────────────────────────────────────────────────────────
Instalado, mas ainda NÃO ativo. Faltam dois passos, nesta ordem.

1. Pareie o celular:

     sudo phoneauthctl pair

2. Só depois de parear, plugue o módulo no sudo. Crie ou edite
   /etc/pam.d/sudo_local e ponha esta linha ANTES das outras:

     auth  sufficient  /usr/local/lib/pam/pam_phoneauth.so  timeout=30

   sudo_local é um drop-in que sobrevive a atualizações do macOS; editar
   /etc/pam.d/sudo direto seria desfeito no próximo update.

────────────────────────────────────────────────────────────────────────
ANTES DE FECHAR ESTE TERMINAL

Abra OUTRA janela de terminal e rode `sudo true`. Confirme que funciona.

Se algo der errado, esta janela ainda tem sudo válido e você conserta com:

     sudo rm /etc/pam.d/sudo_local

O módulo é `sufficient`, então mesmo quebrado ele apenas cai para o
próximo módulo e você digita a senha. Mas um erro de digitação no
sudo_local é outra história — daí a janela reserva.
────────────────────────────────────────────────────────────────────────
EOF
