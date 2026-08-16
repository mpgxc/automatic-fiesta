#!/bin/bash
#
# Constrói o tarball de release do PhoneAuth — a alternativa ao .pkg para quem
# prefere script a instalador gráfico.
#
#     ./build-tarball.sh <versão> <diretório-com-phoneauthd-e-phoneauthctl> [saída.tar.gz]
#
# O layout do repositório é preservado de propósito: o install.sh procura
# `macos/.build/release/...`, e assim o mesmo script serve o checkout e o
# tarball. As fontes ficam de fora — é a ausência delas que faz o install.sh
# pular a compilação em vez de tentar rodar o swift que não existe ali.
#
# Este arquivo existe como script, e não como um punhado de `cp` dentro do
# release.yml, pelo mesmo motivo que o build-pkg.sh: assim o CI exercita o
# caminho de empacotamento a cada push, em vez de ele acordar só na hora de
# publicar — quando a tag já saiu e não se reaproveita.

set -euo pipefail

VERSAO="${1:?uso: build-tarball.sh <versão> <dir-binários> [saída.tar.gz]}"
BINDIR="${2:?uso: build-tarball.sh <versão> <dir-binários> [saída.tar.gz]}"

AQUI="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RAIZ="$(cd "$AQUI/../.." && pwd)"

NOME="phoneauth-$VERSAO-macos"
SAIDA="${3:-$NOME.tar.gz}"

for exigido in "$BINDIR/phoneauthd" "$BINDIR/phoneauthctl" \
               "$RAIZ/macos/pam/pam_phoneauth.so" \
               "$RAIZ/macos/authplugin/PhoneAuth" \
               "$RAIZ/macos/authplugin/Info.plist" \
               "$RAIZ/macos/LaunchDaemon/dev.phoneauth.daemon.plist" \
               "$RAIZ/macos/man/phoneauthctl.1" \
               "$RAIZ/scripts/install.sh" "$RAIZ/scripts/uninstall.sh"; do
    if [[ ! -f "$exigido" ]]; then
        echo "erro: $exigido não existe" >&2
        exit 1
    fi
done

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

STAGE="$TMP/$NOME"
mkdir -p "$STAGE/macos/.build/release" "$STAGE/macos/pam" \
         "$STAGE/macos/authplugin" \
         "$STAGE/macos/LaunchDaemon" "$STAGE/macos/man" "$STAGE/scripts"

cp "$BINDIR/phoneauthd"   "$STAGE/macos/.build/release/"
cp "$BINDIR/phoneauthctl" "$STAGE/macos/.build/release/"
cp "$RAIZ/macos/pam/pam_phoneauth.so"                     "$STAGE/macos/pam/"
# Sem o plugin aqui, o install.sh do tarball aborta na verificação de
# artefatos — ele exige os dois desde que o plugin passou a ser instalado.
cp "$RAIZ/macos/authplugin/PhoneAuth"                     "$STAGE/macos/authplugin/"
cp "$RAIZ/macos/authplugin/Info.plist"                    "$STAGE/macos/authplugin/"
cp "$RAIZ/macos/LaunchDaemon/dev.phoneauth.daemon.plist"  "$STAGE/macos/LaunchDaemon/"
cp "$RAIZ/macos/man/phoneauthctl.1"                       "$STAGE/macos/man/"

# uninstall.sh viaja junto porque instalacao.md — que vai neste mesmo tarball —
# manda rodar `sudo ./scripts/uninstall.sh` quando der errado. Documentar a
# saída de emergência e não embarcá-la é pior do que não documentar: a pessoa
# procura o arquivo justamente no momento em que o `sudo` parou de funcionar.
cp "$RAIZ/scripts/install.sh" "$RAIZ/scripts/uninstall.sh" "$STAGE/scripts/"
cp "$RAIZ/docs/instalacao.md" "$RAIZ/docs/modelo-de-ameacas.md" "$STAGE/"
chmod +x "$STAGE/scripts/install.sh" "$STAGE/scripts/uninstall.sh"

# ── Guarda: o tarball satisfaz o install.sh? ───────────────────────────────
#
# A lista de exigidos sai do próprio install.sh, não de uma cópia escrita à mão
# aqui. Foi exatamente essa duplicação que quebrou a 0.1.4: a man page entrou
# na lista do install.sh e não na montagem do tarball, e o script passou a
# abortar com "pacote incompleto" antes de instalar coisa alguma. Duas listas
# do mesmo fato divergem; uma lista derivada da outra, não.
EXIGIDOS="$(sed -n '/^for artefato in/,/; do$/p' "$RAIZ/scripts/install.sh" \
            | tr -d '\\' | sed 's/^for artefato in//; s/; do$//')"

# `printf` sobre a expansão sem aspas: se a extração só trouxe espaço em
# branco, o word splitting não deixa argumento nenhum e a saída é vazia. Vale
# no bash 3.2 que o macOS ainda embarca, que é onde este script roda.
if [[ -z "$(printf '%s' $EXIGIDOS)" ]]; then
    echo "erro: não consegui extrair a lista de artefatos do install.sh" >&2
    echo "      o laço 'for artefato in ... ; do' mudou de forma; conserte" >&2
    echo "      esta extração em vez de deixar a guarda passar vazia." >&2
    exit 1
fi

falhou=0
for artefato in $EXIGIDOS; do
    if [[ ! -f "$STAGE/$artefato" ]]; then
        echo "erro: $artefato é exigido pelo install.sh e não está no tarball" >&2
        falhou=1
    fi
done
[[ $falhou -eq 0 ]] || exit 1

# ── LEIA-ME ────────────────────────────────────────────────────────────────
cat > "$STAGE/LEIA-ME.txt" <<TXT
PhoneAuth $VERSAO — daemon macOS, CLI e módulo PAM

    sudo ./scripts/install.sh

Binários universais (arm64 + x86_64), macOS 13 ou superior.

NÃO SÃO ASSINADOS NEM NOTARIZADOS. O macOS põe em quarentena o que
vem da internet; se o Gatekeeper reclamar, remova o atributo antes
de instalar:

    xattr -dr com.apple.quarantine .

Faça isso só depois de conferir o que baixou. Este pacote contém um
módulo PAM, que roda como root dentro do sudo.

Depois de instalar faltam dois passos, nesta ordem: parear o celular
com 'sudo phoneauthctl pair' e só então plugar o módulo no
/etc/pam.d/sudo_local. O install.sh explica ambos ao terminar, e
instalacao.md tem o detalhe.

A partir daí a documentação está na própria máquina:

    man phoneauthctl

O módulo entra como 'sufficient', jamais 'required' — daemon fora do
ar ou celular sem bateria fazem o macOS voltar a pedir a senha.

Para desinstalar:

    sudo ./scripts/uninstall.sh
TXT

tar -czf "$SAIDA" -C "$TMP" "$NOME"

echo "==> $SAIDA"
tar tzf "$SAIDA" | sort
