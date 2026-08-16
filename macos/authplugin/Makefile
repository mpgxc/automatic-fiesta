# phoneauth_authplugin — plugin de autorização do SecurityAgent
#
#   make            constrói o bundle (só no macOS)
#   make test       roda os testes da lógica (funciona fora do macOS, com o shim)
#   make install    instala em /Library/Security/SecurityAgentPlugins
#
# Instalar NÃO ativa. O plugin só passa a ser consultado depois de
# `sudo phoneauthctl authplugin enable`, que edita o authorization database —
# e essa separação é proposital, porque um mecanismo de autorização não tem o
# degrau `sufficient` do PAM: enquanto ativo para um direito, ele decide
# sozinho, e um daemon fora do ar torna aquele direito indisponível.

CC      ?= clang
CFLAGS  ?= -Wall -Wextra -Wconversion -Wshadow -Wpointer-arith -Wwrite-strings \
           -O2 -std=gnu11 -fstack-protector-strong

BUNDLE   = PhoneAuth
PLUGDIR ?= /Library/Security/SecurityAgentPlugins
DEST     = $(PLUGDIR)/$(BUNDLE).bundle

.PHONY: all test clean install uninstall

all: $(BUNDLE)

$(BUNDLE): phoneauth_authplugin.c ../common/phoneauth_wire.h
	$(CC) $(CFLAGS) -bundle -o $@ phoneauth_authplugin.c \
		-framework Security -framework CoreFoundation

# O teste inclui o .c direto para alcançar as funções static, e usa o shim de
# Security/ para rodar onde não há macOS. O socket é redirecionado para /tmp
# porque o caminho real exige root — e um teste que precisa de root é um teste
# que ninguém roda.
test: test_phoneauth_authplugin.c phoneauth_authplugin.c ../common/phoneauth_wire.h
	$(CC) -Wall -Wextra -O1 -g -fsanitize=address,undefined -std=gnu11 \
		-Ishim -I. -DPA_SOCKET_PATH='"/tmp/pa_authplugin_test.sock"' \
		-o test_phoneauth_authplugin test_phoneauth_authplugin.c -lpthread
	./test_phoneauth_authplugin

install: $(BUNDLE)
	install -d -o root -g wheel -m 0755 $(DEST)/Contents/MacOS
	install -o root -g wheel -m 0444 $(BUNDLE) $(DEST)/Contents/MacOS/$(BUNDLE)
	install -o root -g wheel -m 0444 Info.plist $(DEST)/Contents/Info.plist
	@echo "Plugin instalado, mas INATIVO."
	@echo "Para ativar:   sudo phoneauthctl authplugin enable"
	@echo "Para desfazer: sudo phoneauthctl authplugin disable"

uninstall:
	rm -rf $(DEST)

clean:
	rm -rf $(BUNDLE) test_phoneauth_authplugin test_phoneauth_authplugin.dSYM
