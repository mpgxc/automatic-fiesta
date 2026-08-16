/*
 * phoneauth_wire — transporte compartilhado com o daemon.
 *
 * O módulo PAM e o plugin de autorização falam o mesmo protocolo pelo mesmo
 * socket Unix. Antes isto vivia só dentro do pam_phoneauth.c; quando o plugin
 * do SecurityAgent apareceu, copiar seria a pior opção possível — o framing e o
 * scanner JSON são exatamente as peças em que uma divergência silenciosa entre
 * duas cópias vira falha de autenticação difícil de enxergar.
 *
 * É um header com implementações `static` de propósito: cada lado ganha a sua
 * cópia em tempo de compilação, sem biblioteca, sem link novo e sem mexer na
 * forma como os testes do PAM alcançam as funções static incluindo o .c direto.
 *
 * As restrições do pam_phoneauth.c valem aqui inteiras, porque este código roda
 * dentro dele: nenhuma alocação dinâmica, nenhuma biblioteca externa, nenhuma
 * rede — só um socket Unix local, com toda a criptografia do outro lado.
 */

#ifndef PHONEAUTH_WIRE_H
#define PHONEAUTH_WIRE_H

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

/*
 * Sobreponível por -D só para teste: o caminho real exige root para escutar, e
 * um teste que precisa de root é um teste que ninguém roda. Em produção vale
 * sempre o padrão abaixo.
 */
#ifndef PA_SOCKET_PATH
#define PA_SOCKET_PATH       "/var/run/phoneauthd.sock"
#endif
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
/*                                                                     */
/* Para o modo de falha ser mesmo sempre negar, TODAS as ocorrências da */
/* chave têm que valer `true`, não só a primeira. Parar na primeira     */
/* deixava passar `{"ok":true,"ok":false}` e                            */
/* `{"detalhe":{"ok":true},"ok":false}` — em ambos um parser de verdade */
/* diz "não aprovado" e o scanner dizia "aprovado".                     */
/*                                                                     */
/* Limitação que permanece, de propósito: o scanner não conta chaves,   */
/* então uma resposta que só tivesse `ok` aninhado                      */
/* (`{"detalhe":{"ok":true}}`, sem `ok` de topo) ainda seria aceita.    */
/* Rastrear profundidade exigiria acompanhar estado de string — isto é, */
/* justamente o parser que não queremos dentro do processo setuid. O    */
/* daemon responde um objeto plano de dois campos; a checagem de topo   */
/* fica com ele.                                                        */
/* ------------------------------------------------------------------ */

/* Espaço em branco de JSON (RFC 8259 §2). O conjunto anterior tinha só  */
/* espaço e tab, então `{"ok":\ntrue}` — JSON perfeitamente válido —     */
/* era lido como negação.                                               */
static int json_is_ws(char c) {
    return c == ' ' || c == '\t' || c == '\n' || c == '\r';
}

static int json_bool_is_true(const char *buf, size_t len, const char *key) {
    char pattern[32];
    int  pn = snprintf(pattern, sizeof(pattern), "\"%s\"", key);
    if (pn <= 0 || (size_t)pn >= sizeof(pattern)) return 0;
    size_t plen = (size_t)pn;

    int found = 0;

    for (size_t i = 0; i + plen <= len; i++) {
        if (memcmp(buf + i, pattern, plen) != 0) continue;

        size_t j = i + plen;
        while (j < len && json_is_ws(buf[j])) j++;
        /* Sem dois pontos não é uso como chave (ex.: a string "ok" como
           valor). Segue procurando; não é motivo para negar. */
        if (j >= len || buf[j] != ':') continue;
        j++;
        while (j < len && json_is_ws(buf[j])) j++;

        if (j + 4 > len || memcmp(buf + j, "true", 4) != 0) return 0;

        /* Rejeita `truex` e afins: o token tem que terminar aqui. */
        if (j + 4 < len) {
            char after = buf[j + 4];
            if (after != ',' && after != '}' && !json_is_ws(after)) return 0;
        }

        found = 1;
        i = j + 3;   /* o i++ do laço leva para depois do token */
    }
    return found;
}

/* ------------------------------------------------------------------ */
/* E/S com prazo                                                       */
/* ------------------------------------------------------------------ */

/*
 * Escrita que não pode levantar SIGPIPE.
 *
 * Este módulo vive dentro de sudo/login. SIGPIPE com disposição padrão MATA o
 * processo hospedeiro, e o daemon fecha a conexão em vários caminhos legítimos
 * (par sem credencial legível, frame recusado, daemon reiniciando). Sem esta
 * proteção, um daemon que fecha entre o nosso connect() e o nosso write()
 * derruba o sudo do usuário em vez de só falhar a autenticação.
 *
 * As duas plataformas expõem mecanismos diferentes, então usamos os dois:
 * SO_NOSIGPIPE no socket (macOS/BSD) e MSG_NOSIGNAL no envio (Linux).
 */
static void pa_set_nosigpipe(int fd) {
#ifdef SO_NOSIGPIPE
    int on = 1;
    (void)setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &on, (socklen_t)sizeof(on));
#else
    (void)fd;
#endif
}

static ssize_t pa_send(int fd, const void *buf, size_t len) {
#ifdef MSG_NOSIGNAL
    return send(fd, buf, len, MSG_NOSIGNAL);
#else
    return write(fd, buf, len);
#endif
}

static int wait_ready(int fd, short events, int64_t deadline) {
    for (;;) {
        int64_t remaining = deadline - now_ms();
        if (remaining <= 0) return -1;
        if (remaining > INT32_MAX) remaining = INT32_MAX;

        struct pollfd pfd = { .fd = fd, .events = events, .revents = 0 };
        int r = poll(&pfd, 1, (int)remaining);
        if (r > 0) {
            if (pfd.revents & (POLLERR | POLLNVAL)) return -1;
            /*
             * POLLHUP chega JUNTO com POLLIN quando o par mandou a resposta
             * inteira e fechou — que é exatamente o que o daemon faz
             * (writeFrame e, na linha seguinte, close(fd)). Tratar POLLHUP
             * como erro aqui jogava fora uma aprovação válida já entregue no
             * buffer do socket, e a autenticação falhava por conta disso.
             *
             * O evento pedido tem prioridade. Se ele não veio, aí sim POLLHUP
             * é fim de linha. E mesmo quando seguimos adiante, quem decide é o
             * read()/send(): read devolve 0 (EOF) e send devolve EPIPE, e os
             * dois já são tratados como falha pelos chamadores.
             */
            if (pfd.revents & events) return 0;
            if (pfd.revents & POLLHUP) return -1;
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
        ssize_t n = pa_send(fd, p + off, len - off);
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

    pa_set_nosigpipe(fd);

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

#endif /* PHONEAUTH_WIRE_H */
