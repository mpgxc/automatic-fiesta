# pam_phoneauth
#
#   make            constrói o módulo (só no macOS)
#   make test       roda os testes unitários das funções puras
#   make install    instala em /usr/local/lib/pam
#
# Instalamos em /usr/local/lib/pam e não em /usr/lib/pam porque este último é
# protegido pelo SIP. O OpenPAM aceita caminho absoluto no /etc/pam.d, então
# referenciamos o módulo por caminho completo e ninguém precisa desabilitar o
# SIP para usar isto — o que seria um preço absurdo por uma conveniência de
# autenticação.
#
# gnu11, não c11: clock_gettime fica escondido sob o modo ISO estrito.

CC      ?= clang
CFLAGS  ?= -Wall -Wextra -Wconversion -Wshadow -Wpointer-arith -Wwrite-strings \
           -O2 -std=gnu11 -fstack-protector-strong
MODULE   = pam_phoneauth.so
PAMDIR  ?= /usr/local/lib/pam

.PHONY: all test clean install uninstall

all: $(MODULE)

$(MODULE): pam_phoneauth.c
	$(CC) $(CFLAGS) -bundle -o $@ $< -lpam

# Os testes incluem o .c direto para alcançar as funções static. Precisam de
# stubs das entradas PAM, que vivem em test_pam_phoneauth.c.
#
# Fora do macOS, aponte -I para um diretório com headers PAM de shim; o objetivo
# ali é só exercitar o scanner JSON e o escritor, que não dependem de PAM.
test: test_pam_phoneauth.c pam_phoneauth.c
	$(CC) -Wall -Wextra -O1 -g -fsanitize=address,undefined -std=gnu11 \
		$(EXTRA_INCLUDES) -o test_pam_phoneauth test_pam_phoneauth.c
	./test_pam_phoneauth

install: $(MODULE)
	install -d -o root -g wheel -m 0755 $(PAMDIR)
	install -o root -g wheel -m 0444 $(MODULE) $(PAMDIR)/$(MODULE)
	@echo "Módulo instalado. Agora edite /etc/pam.d/sudo_local — veja docs/instalacao.md"
	@echo "Lembre: 'sufficient', NUNCA 'required'."

uninstall:
	rm -f $(PAMDIR)/$(MODULE)

clean:
	rm -rf $(MODULE) test_pam_phoneauth test_pam_phoneauth.dSYM
