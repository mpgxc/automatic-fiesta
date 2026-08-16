#!/bin/bash
#
# Remove o PhoneAuth por completo.
#
# A ordem importa: a linha do /etc/pam.d sai PRIMEIRO. Remover o módulo
# deixando a referência para trás faria o OpenPAM tentar carregar um arquivo
# inexistente a cada sudo. Como a entrada é `sufficient` isso ainda cai para o
# próximo módulo, mas não há razão para deixar essa bagunça.

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "erro: rode com sudo" >&2
    exit 1
fi

LABEL="dev.phoneauth.daemon"
STATE_DIR="/Library/Application Support/PhoneAuth"
KEEP_STATE=0
[[ "${1:-}" == "--keep-devices" ]] && KEEP_STATE=1

echo "==> Removendo o módulo da pilha PAM"
for file in /etc/pam.d/sudo_local /etc/pam.d/sudo /etc/pam.d/su /etc/pam.d/screensaver; do
    [[ -f "$file" ]] || continue
    if grep -q 'pam_phoneauth' "$file"; then
        cp "$file" "$file.phoneauth-backup"
        grep -v 'pam_phoneauth' "$file" > "$file.tmp"
        mv "$file.tmp" "$file"
        chmod 0644 "$file"
        echo "    limpo: $file (backup em $file.phoneauth-backup)"
    fi
done

# sudo_local vazio é ruído; some com ele.
if [[ -f /etc/pam.d/sudo_local ]] && ! grep -qv '^\s*\(#.*\)\?$' /etc/pam.d/sudo_local; then
    rm -f /etc/pam.d/sudo_local
    echo "    removido: /etc/pam.d/sudo_local (ficou vazio)"
fi

echo "==> Verificando se o sudo ainda funciona"
if ! sudo -n true 2>/dev/null; then
    echo "    (sessão sudo expirada — não é problema, mas teste em outra janela)"
fi

echo "==> Parando o daemon"
launchctl bootout "system/$LABEL" 2>/dev/null || true
rm -f "/Library/LaunchDaemons/$LABEL.plist"

echo "==> Removendo binários e o módulo"
rm -f /usr/local/bin/phoneauthd /usr/local/bin/phoneauthctl
rm -f /usr/local/lib/pam/pam_phoneauth.so
rm -rf /Library/Security/SecurityAgentPlugins/PhoneAuth.bundle
rm -f /usr/local/share/man/man1/phoneauthctl.1
rmdir /usr/local/lib/pam 2>/dev/null || true
rm -f /var/run/phoneauthd.sock

if [[ $KEEP_STATE -eq 1 ]]; then
    echo "==> Preservando $STATE_DIR (--keep-devices)"
else
    echo "==> Removendo $STATE_DIR"
    rm -rf "$STATE_DIR"
    echo "    dispositivos pareados apagados; reinstalar exige parear de novo"
fi

echo
echo "Desinstalado. Confirme numa janela nova: sudo true"
