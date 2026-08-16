/*
 * pam_phoneauth — aprova pedidos de autenticação do macOS pela digital do
 * celular pareado.
 *
 * Este módulo roda dentro de processos setuid root (sudo). Isso governa cada
 * decisão de estilo aqui:
 *
 *   - Nenhuma alocação dinâmica no caminho crítico. Buffers fixos, sempre
 *     checados.
 *   - Nenhuma biblioteca externa. Só libc e libpam.
 *   - Nenhuma rede. O módulo fala com um socket Unix local; toda a criptografia
 *     e todo o TLS vivem no daemon, fora do processo privilegiado.
 *   - Exatamente um caminho que retorna PAM_SUCCESS, marcado abaixo. Todo o
 *     resto retorna PAM_AUTHINFO_UNAVAIL, que faz o PAM seguir para o próximo
 *     módulo da pilha.
 *
 * Instale SEMPRE como `sufficient`, jamais como `required`:
 *
 *     auth  sufficient  pam_phoneauth.so  timeout=30
 *
 * Build:
 *     clang -Wall -Wextra -O2 -bundle -o pam_phoneauth.so pam_phoneauth.c -lpam
 */


#include <security/pam_appl.h>
#include <security/pam_modules.h>


/*
 * Transporte, framing e JSON vivem no header compartilhado: o plugin de
 * autorização fala o mesmo protocolo pelo mesmo socket, e duas cópias do
 * framing seriam duas chances de divergir em silêncio.
 */
#include "../common/phoneauth_wire.h"

static int parse_timeout(int argc, const char **argv) {
    int timeout = PA_DEFAULT_TIMEOUT_S;
    for (int i = 0; i < argc; i++) {
        if (strncmp(argv[i], "timeout=", 8) != 0) continue;

        char *end = NULL;
        errno = 0;
        long v = strtol(argv[i] + 8, &end, 10);
        if (errno != 0 || end == argv[i] + 8 || *end != '\0') continue;

        if (v < PA_MIN_TIMEOUT_S) v = PA_MIN_TIMEOUT_S;
        if (v > PA_MAX_TIMEOUT_S) v = PA_MAX_TIMEOUT_S;
        timeout = (int)v;
    }
    return timeout;
}

static const char *pam_str(pam_handle_t *pamh, int item) {
    const void *p = NULL;
    if (pam_get_item(pamh, item, &p) != PAM_SUCCESS || p == NULL) return "";
    return (const char *)p;
}

/* ------------------------------------------------------------------ */
/* Entradas PAM                                                        */
/* ------------------------------------------------------------------ */

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags,
                                   int argc, const char **argv) {
    (void)flags;

    const int64_t deadline = now_ms() + (int64_t)parse_timeout(argc, argv) * 1000;

    const char *user = NULL;
    if (pam_get_user(pamh, &user, NULL) != PAM_SUCCESS || user == NULL || *user == '\0')
        return PAM_AUTHINFO_UNAVAIL;

    const char *service = pam_str(pamh, PAM_SERVICE);
    const char *tty     = pam_str(pamh, PAM_TTY);
    const char *ruser   = pam_str(pamh, PAM_RUSER);
    const char *rhost   = pam_str(pamh, PAM_RHOST);

    /*
     * Enviamos o pid e deixamos o daemon resolver a linha de comando via
     * sysctl. Isso mantém a leitura de memória de outro processo fora do
     * contexto setuid, e o daemon tem o contexto para formatar o motivo que o
     * usuário vai ler no celular.
     */
    char pid_buf[24];
    snprintf(pid_buf, sizeof(pid_buf), "%ld", (long)getpid());

    char req[PA_REQ_MAX];
    jw_t w;
    jw_init(&w, req, sizeof(req));
    jw_raw(&w, "{");
    jw_kv(&w, "type", "auth.begin");   jw_char(&w, ',');
    jw_kv(&w, "user", user);           jw_char(&w, ',');
    jw_kv(&w, "service", service);     jw_char(&w, ',');
    jw_kv(&w, "tty", tty);             jw_char(&w, ',');
    jw_kv(&w, "ruser", ruser);         jw_char(&w, ',');
    jw_kv(&w, "rhost", rhost);         jw_char(&w, ',');
    jw_str(&w, "pid"); jw_char(&w, ':'); jw_raw(&w, pid_buf);
    jw_raw(&w, "}");

    if (w.overflow) return PAM_AUTHINFO_UNAVAIL;

    int fd = connect_daemon(deadline);
    if (fd < 0) return PAM_AUTHINFO_UNAVAIL;   /* daemon fora do ar: cai para o próximo módulo */

    int result = PAM_AUTHINFO_UNAVAIL;

    if (frame_write(fd, req, w.len, deadline) == 0) {
        char resp[PA_RESP_MAX];
        ssize_t n = frame_read(fd, resp, sizeof(resp), deadline);

        /*
         * >>> O ÚNICO caminho de sucesso do módulo. <<<
         *
         * Exige um frame bem formado, do tamanho declarado, contendo `"ok":
         * true`. Qualquer outro desfecho — timeout, EOF, frame malformado,
         * `"ok": false`, ausência da chave — cai no PAM_AUTHINFO_UNAVAIL
         * inicializado acima.
         *
         * Um patch que acrescente outro `result = PAM_SUCCESS` neste arquivo
         * precisa de justificativa muito boa.
         */
        if (n > 0 && json_bool_is_true(resp, (size_t)n, "ok")) {
            result = PAM_SUCCESS;
        }

        /* A resposta pode conter contexto do pedido; não deixe rastro. */
        memset(resp, 0, sizeof(resp));
    }

    close(fd);
    return result;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags,
                              int argc, const char **argv) {
    (void)pamh; (void)flags; (void)argc; (void)argv;
    return PAM_SUCCESS;   /* nada de credencial para estabelecer */
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags,
                                int argc, const char **argv) {
    (void)pamh; (void)flags; (void)argc; (void)argv;
    return PAM_IGNORE;    /* gestão de conta não é nossa; deixe para a pilha */
}
