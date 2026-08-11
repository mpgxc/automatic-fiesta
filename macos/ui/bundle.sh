#!/bin/bash
#
# Empacota o executável do SwiftPM num .app.
#
# Não é cosmético. O UNUserNotificationCenter exige um bundle identifier
# registrado, e um binário solto não tem bundle: as notificações falham em
# silêncio, sem erro e sem prompt de permissão. O MenuBarExtra também precisa do
# LSUIElement do Info.plist para não plantar um ícone no Dock.
#
#   ./bundle.sh              constrói e empacota em .build/PhoneAuth.app
#   ./bundle.sh --install    copia para /Applications e abre
#   ./bundle.sh --sign ID    assina com a identidade dada

set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

APP=".build/PhoneAuth.app"
SIGN_ID=""
INSTALL=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --install) INSTALL=1; shift ;;
        --sign)    SIGN_ID="${2:?--sign precisa de uma identidade}"; shift 2 ;;
        *) echo "opção desconhecida: $1" >&2; exit 1 ;;
    esac
done

echo "==> Construindo"
swift build -c release

echo "==> Montando $APP"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp .build/release/PhoneAuthUI "$APP/Contents/MacOS/PhoneAuthUI"
cp Resources/Info.plist "$APP/Contents/Info.plist"

if [[ -n "$SIGN_ID" ]]; then
    echo "==> Assinando com $SIGN_ID"
    codesign --force --options runtime --sign "$SIGN_ID" "$APP"
else
    # Assinatura ad-hoc: o suficiente para o app rodar e para o sistema
    # atribuir uma identidade estável ao registro de notificações. Sem nenhuma
    # assinatura, a permissão de notificação pode ser esquecida a cada build.
    echo "==> Assinando ad-hoc (sem Developer ID)"
    codesign --force --sign - "$APP"
fi

if [[ $INSTALL -eq 1 ]]; then
    echo "==> Instalando em /Applications"
    rm -rf /Applications/PhoneAuth.app
    cp -R "$APP" /Applications/PhoneAuth.app
    open /Applications/PhoneAuth.app
    echo
    echo "O ícone deve aparecer na barra de menu. Na primeira execução o macOS"
    echo "vai pedir permissão para enviar notificações."
else
    echo
    echo "Pronto: $APP"
    echo "Rode com: open $APP"
fi
