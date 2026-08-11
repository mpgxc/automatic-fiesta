/*
 * Headers PAM mínimos para rodar os testes fora do macOS.
 *
 * A suíte em test_pam_phoneauth.c exercita o scanner JSON, o escritor e a E/S
 * enquadrada — nada disso depende do PAM de verdade. Mas o arquivo inclui
 * pam_phoneauth.c inteiro para alcançar as funções `static`, e aquele inclui
 * estes headers.
 *
 * No macOS os headers reais existem e este diretório é ignorado. Aqui ele
 * permite que o CI em Linux rode a suíte sob ASan+UBSan, que é onde os quatro
 * defeitos da auditoria foram encontrados.
 *
 * Os valores vêm do OpenPAM. Não precisam bater com o macOS para os testes
 * valerem: o que importa é PAM_SUCCESS ser distinto de PAM_AUTHINFO_UNAVAIL.
 */
#ifndef PHONEAUTH_SHIM_PAM_APPL_H
#define PHONEAUTH_SHIM_PAM_APPL_H

typedef struct pam_handle pam_handle_t;

#define PAM_SUCCESS           0
#define PAM_AUTHINFO_UNAVAIL  9
#define PAM_IGNORE           25

#define PAM_SERVICE  1
#define PAM_USER     2
#define PAM_TTY      3
#define PAM_RHOST    4
#define PAM_CONV     5
#define PAM_RUSER    8

int pam_get_item(const pam_handle_t *pamh, int item_type, const void **item);
int pam_get_user(pam_handle_t *pamh, const char **user, const char *prompt);

#endif
