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

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include <security/pam_appl.h>
#include <security/pam_modules.h>

#define PA_SOCKET_PATH       "/var/run/phoneauthd.sock"
#define PA_DEFAULT_TIMEOUT_S 30
#define PA_MAX_TIMEOUT_S     120   /* teto rígido: um daemon com bug não trava seu terminal */
#define PA_MIN_TIMEOUT_S     5
#define PA_REQ_MAX           2048
#define PA_RESP_MAX          4096
#define PA_FRAME_MAX         65536

/* ------------------------------------------------------------------ */
/* Relógio                                                             */
/* ------------------------------------------------------------------ */

static int64_t now_ms(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return 0;
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* ------------------------------------------------------------------ */
/* Escrita JSON                                                        */
/*                                                                     */
/* Um escritor mínimo com truncamento explícito. Se qualquer append não */
/* couber, marca overflow e para de escrever; o chamador aborta. Nunca  */
/* emitimos JSON parcialmente formado.                                  */
/* ------------------------------------------------------------------ */

typedef struct {
    char  *buf;
    size_t cap;
    size_t len;
    int    overflow;
} jw_t;

static void jw_init(jw_t *w, char *buf, size_t cap) {
    w->buf = buf; w->cap = cap; w->len = 0; w->overflow = 0;
    if (cap > 0) buf[0] = '\0';
}

static void jw_raw(jw_t *w, const char *s) {
    if (w->overflow) return;
    size_t n = strlen(s);
    if (w->len + n + 1 > w->cap) { w->overflow = 1; return; }
    memcpy(w->buf + w->len, s, n);
    w->len += n;
    w->buf[w->len] = '\0';
}

static void jw_char(jw_t *w, char c) {
    if (w->overflow) return;
    if (w->len + 2 > w->cap) { w->overflow = 1; return; }
    w->buf[w->len++] = c;
    w->buf[w->len] = '\0';
}

/*
 * Escreve uma string JSON entre aspas, escapando o que precisa.
 *
 * Bytes de controle viram \u00XX. Bytes >= 0x80 são copiados como estão: o
 * daemon valida UTF-8 do lado dele, e reescrever aqui só criaria uma segunda
 * implementação de UTF-8 dentro de um processo setuid.
 *
 * NUL nunca aparece porque a entrada é sempre string C.
 */
static void jw_str(jw_t *w, const char *s) {
    static const char hex[] = "0123456789abcdef";
    jw_char(w, '"');
    if (s) {
        for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
            if (w->overflow) return;
            switch (*p) {
                case '"':  jw_raw(w, "\\\""); break;
                case '\\': jw_raw(w, "\\\\"); break;
                case '\n': jw_raw(w, "\\n");  break;
                case '\r': jw_raw(w, "\\r");  break;
                case '\t': jw_raw(w, "\\t");  break;
                default:
                    if (*p < 0x20) {
                        char esc[7] = { '\\', 'u', '0', '0', hex[*p >> 4], hex[*p & 0xF], '\0' };
                        jw_raw(w, esc);
                    } else {
                        jw_char(w, (char)*p);
                    }
            }
        }
    }
    jw_char(w, '"');
}

static void jw_kv(jw_t *w, const char *key, const char *val) {
    jw_str(w, key);
    jw_char(w, ':');
    jw_str(w, val);
}

/* ------------------------------------------------------------------ */
/* Leitura JSON                                                        */
/*                                                                     */
/* Não é um parser de JSON. É um scanner para uma resposta de formato   */
/* fixo e conhecido, deliberadamente ingênuo, porque um parser completo */
/* dentro de um processo setuid seria muito mais superfície de ataque   */
/* do que o problema justifica.                                        */
/*                                                                     */
/* Contrato: procura a chave no nível de texto e exige literalmente     */
/* `true` como valor. Qualquer outra coisa — inclusive a chave aparecer */
/* dentro de outra string — resulta em "não aprovado". O modo de falha  */
/* é sempre negar.                                                     */
/* ------------------------------------------------------------------ */

static int json_bool_is_true(const char *buf, size_t len, const char *key) {
    char pattern[32];
    int  pn = snprintf(pattern, sizeof(pattern), "\"%s\"", key);
    if (pn <= 0 || (size_t)pn >= sizeof(pattern)) return 0;
    size_t plen = (size_t)pn;

    for (size_t i = 0; i + plen <= len; i++) {
        if (memcmp(buf + i, pattern, plen) != 0) continue;

        size_t j = i + plen;
        while (j < len && (buf[j] == ' ' || buf[j] == '\t')) j++;
        if (j >= len || buf[j] != ':') continue;
        j++;
        while (j < len && (buf[j] == ' ' || buf[j] == '\t')) j++;

        if (j + 4 <= len && memcmp(buf + j, "true", 4) == 0) {
            /* Rejeita `truex` e afins: o token tem que terminar aqui. */
            if (j + 4 == len) return 1;
            char after = buf[j + 4];
            if (after == ',' || after == '}' || after == ' ' ||
                after == '\t' || after == '\n' || after == '\r') return 1;
        }
        return 0;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* E/S com prazo                                                       */
/* ------------------------------------------------------------------ */

static int wait_ready(int fd, short events, int64_t deadline) {
    for (;;) {
        int64_t remaining = deadline - now_ms();
        if (remaining <= 0) return -1;
        if (remaining > INT32_MAX) remaining = INT32_MAX;

        struct pollfd pfd = { .fd = fd, .events = events, .revents = 0 };
        int r = poll(&pfd, 1, (int)remaining);
        if (r > 0) {
            if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) return -1;
            return 0;
        }
        if (r == 0) return -1;
        if (errno != EINTR) return -1;
    }
}

static int write_all(int fd, const void *data, size_t len, int64_t deadline) {
    const unsigned char *p = data;
    size_t off = 0;
    while (off < len) {
        if (wait_ready(fd, POLLOUT, deadline) != 0) return -1;
        ssize_t n = write(fd, p + off, len - off);
        if (n > 0) { off += (size_t)n; continue; }
        if (n < 0 && (errno == EINTR || errno == EAGAIN)) continue;
        return -1;
    }
    return 0;
}

static int read_all(int fd, void *data, size_t len, int64_t deadline) {
    unsigned char *p = data;
    size_t off = 0;
    while (off < len) {
        if (wait_ready(fd, POLLIN, deadline) != 0) return -1;
        ssize_t n = read(fd, p + off, len - off);
        if (n > 0) { off += (size_t)n; continue; }
        if (n == 0) return -1;                                   /* EOF prematuro */
        if (n < 0 && (errno == EINTR || errno == EAGAIN)) continue;
        return -1;
    }
    return 0;
}

/* Enquadramento: 4 bytes de comprimento big-endian, depois o corpo JSON. */

static int frame_write(int fd, const char *json, size_t len, int64_t deadline) {
    unsigned char hdr[4];
    hdr[0] = (unsigned char)((len >> 24) & 0xFF);
    hdr[1] = (unsigned char)((len >> 16) & 0xFF);
    hdr[2] = (unsigned char)((len >> 8)  & 0xFF);
    hdr[3] = (unsigned char)( len        & 0xFF);
    if (write_all(fd, hdr, 4, deadline) != 0) return -1;
    return write_all(fd, json, len, deadline);
}

static ssize_t frame_read(int fd, char *out, size_t cap, int64_t deadline) {
    unsigned char hdr[4];
    if (read_all(fd, hdr, 4, deadline) != 0) return -1;

    uint32_t len = ((uint32_t)hdr[0] << 24) | ((uint32_t)hdr[1] << 16) |
                   ((uint32_t)hdr[2] << 8)  |  (uint32_t)hdr[3];

    if (len == 0 || len > PA_FRAME_MAX || len > cap) return -1;
    if (read_all(fd, out, len, deadline) != 0) return -1;
    return (ssize_t)len;
}

/* ------------------------------------------------------------------ */
/* Conexão                                                             */
/* ------------------------------------------------------------------ */

static int connect_daemon(int64_t deadline) {
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;

    /* Falha em tempo de compilação seria melhor, mas o caminho é uma constante
       curta e conhecida; a checagem aqui é barata e explícita. */
    if (strlen(PA_SOCKET_PATH) >= sizeof(addr.sun_path)) return -1;
    strncpy(addr.sun_path, PA_SOCKET_PATH, sizeof(addr.sun_path) - 1);

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        close(fd);
        return -1;
    }

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        if (errno != EINPROGRESS) { close(fd); return -1; }
        if (wait_ready(fd, POLLOUT, deadline) != 0) { close(fd); return -1; }

        int err = 0;
        socklen_t elen = sizeof(err);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &elen) != 0 || err != 0) {
            close(fd);
            return -1;
        }
    }
    return fd;
}

/* ------------------------------------------------------------------ */
/* Opções do módulo                                                    */
/* ------------------------------------------------------------------ */

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
