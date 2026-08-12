#!/bin/bash
#
# Constrói o instalador .pkg do PhoneAuth.
#
#     ./build-pkg.sh <versão> <diretório-com-phoneauthd-e-phoneauthctl> [saída.pkg]
#
# É .pkg e não .dmg de propósito. Um .dmg só arrasta um .app para /Applications,
# e o PhoneAuth não é um .app: são dois binários em /usr/local/bin, um módulo PAM
# em /usr/local/lib/pam, um LaunchDaemon e um diretório de estado com a chave TLS
# gerada na máquina. Nada disso um .dmg faria — sobraria para o usuário, à mão,
# como root. O .pkg faz, e faz sempre igual.
#
# O que este instalador deliberadamente NÃO faz é tocar em /etc/pam.d. Plugar o
# módulo na pilha de autenticação é a única etapa com potencial de estragar o
# `sudo`, e o usuário precisa estar olhando quando acontecer. Fica manual, e a
# tela final do instalador explica como.

set -euo pipefail

VERSAO="${1:?uso: build-pkg.sh <versão> <dir-binários> [saída.pkg]}"
BINDIR="${2:?uso: build-pkg.sh <versão> <dir-binários> [saída.pkg]}"
SAIDA="${3:-phoneauth-$VERSAO.pkg}"

AQUI="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RAIZ="$(cd "$AQUI/../.." && pwd)"
IDENT="dev.phoneauth"

for exigido in "$BINDIR/phoneauthd" "$BINDIR/phoneauthctl" \
               "$RAIZ/macos/pam/pam_phoneauth.so" \
               "$RAIZ/macos/LaunchDaemon/dev.phoneauth.daemon.plist" \
               "$RAIZ/macos/man/phoneauthctl.1"; do
    if [[ ! -f "$exigido" ]]; then
        echo "erro: $exigido não existe" >&2
        exit 1
    fi
done

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# ── Payload ────────────────────────────────────────────────────────────────
#
# Os caminhos abaixo do stage viram caminhos absolutos no disco de destino, já
# que a instalação é em `/`.
STAGE="$TMP/stage"
install -d "$STAGE/usr/local/bin" "$STAGE/usr/local/lib/pam" \
            "$STAGE/Library/LaunchDaemons" "$STAGE/usr/local/share/man/man1"

install -m 0755 "$BINDIR/phoneauthd"   "$STAGE/usr/local/bin/phoneauthd"
install -m 0755 "$BINDIR/phoneauthctl" "$STAGE/usr/local/bin/phoneauthctl"

# 0444: o módulo é carregado pelo `sudo` rodando como root. Gravável por
# qualquer outro caminho seria escalação de privilégio local disfarçada de
# detalhe de permissão.
install -m 0444 "$RAIZ/macos/pam/pam_phoneauth.so" "$STAGE/usr/local/lib/pam/pam_phoneauth.so"
install -m 0644 "$RAIZ/macos/LaunchDaemon/dev.phoneauth.daemon.plist" \
                "$STAGE/Library/LaunchDaemons/dev.phoneauth.daemon.plist"

# Depois de instalar não havia documento nenhum na máquina. `man phoneauthctl`
# é o que alguém tenta primeiro, e é onde a resposta deve estar.
install -m 0644 "$RAIZ/macos/man/phoneauthctl.1" \
                "$STAGE/usr/local/share/man/man1/phoneauthctl.1"

# ── Componente ─────────────────────────────────────────────────────────────
#
# `--ownership recommended` porque o runner do CI é `runner:staff` e o destino
# precisa ser root:wheel. Sem isto o módulo PAM chegaria pertencendo a um
# usuário comum — o mesmo problema de permissão, por outra porta.
pkgbuild \
    --root "$STAGE" \
    --scripts "$AQUI/scripts" \
    --identifier "$IDENT" \
    --version "$VERSAO" \
    --install-location / \
    --ownership recommended \
    "$TMP/componente.pkg"

# ── Produto ────────────────────────────────────────────────────────────────
sed "s/__VERSAO__/$VERSAO/g" "$AQUI/distribution.xml" > "$TMP/distribution.xml"

productbuild \
    --distribution "$TMP/distribution.xml" \
    --resources "$AQUI/resources" \
    --package-path "$TMP" \
    "$TMP/produto.pkg"

# ── Assinatura, se houver ──────────────────────────────────────────────────
#
# Exige conta paga no Apple Developer Program. Sem ela o pacote sai sem
# assinatura e o Gatekeeper barra o duplo-clique; `sudo installer -pkg` no
# terminal continua funcionando. Preferimos isso a fingir que está assinado.
if [[ -n "${MACOS_INSTALLER_IDENTITY:-}" ]]; then
    echo "==> Assinando com $MACOS_INSTALLER_IDENTITY"
    productsign --sign "$MACOS_INSTALLER_IDENTITY" "$TMP/produto.pkg" "$SAIDA"
else
    echo "==> Sem MACOS_INSTALLER_IDENTITY; o pacote sai SEM assinatura"
    cp "$TMP/produto.pkg" "$SAIDA"
fi

echo "==> $SAIDA"
pkgutil --check-signature "$SAIDA" 2>/dev/null || true
