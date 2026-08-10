/* Testa pam_phoneauth.c incluindo o .c diretamente.
 *
 * Duas camadas:
 *
 *   1. Funções puras (scanner JSON, escritor JSON, parse de opções). Rodam em
 *      qualquer lugar, inclusive fora do macOS com headers PAM de shim.
 *   2. E/S real sobre socketpair(2): enquadramento, prazo, EOF no meio do
 *      frame, e as duas armadilhas que só aparecem com um socket de verdade —
 *      POLLHUP junto com a resposta, e SIGPIPE ao escrever para um par que
 *      fechou. Nenhum dos dois é visível em teste de função pura, e os dois
 *      acontecem no caminho normal do daemon (ControlServer.handle escreve o
 *      frame e fecha o fd na linha seguinte).
 *
 * Compile com ASan+UBSan; vários casos usam buffers de tamanho exato no heap
 * justamente para o sanitizador pegar overread de um byte.
 */
#include <assert.h>
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include <security/pam_appl.h>
#include <security/pam_modules.h>

/* Stubs controláveis das funções PAM que o módulo referencia. Por padrão
   falham, que é o comportamento que os testes de função pura assumem. */
static int         stub_get_user_rc = PAM_AUTHINFO_UNAVAIL;
static const char *stub_user        = NULL;
static int         stub_get_item_rc = PAM_AUTHINFO_UNAVAIL;
static const char *stub_item        = NULL;

int pam_get_item(const pam_handle_t *p, int t, const void **i) {
    (void)p; (void)t;
    if (stub_get_item_rc != PAM_SUCCESS) return stub_get_item_rc;
    *i = stub_item;
    return PAM_SUCCESS;
}
int pam_get_user(pam_handle_t *p, const char **u, const char *pr) {
    (void)p; (void)pr;
    if (stub_get_user_rc != PAM_SUCCESS) return stub_get_user_rc;
    *u = stub_user;
    return PAM_SUCCESS;
}

#include "pam_phoneauth.c"

static int fails = 0;

static void fail(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    printf("  FALHOU ");
    vprintf(fmt, ap);
    printf("\n");
    va_end(ap);
    fails++;
}

/* ------------------------------------------------------------------ */
/* Camada 1 — funções puras                                            */
/* ------------------------------------------------------------------ */

static void ck_scan(const char *json, int expect, const char *why) {
    /* Buffer de tamanho EXATO no heap: sem NUL terminador, como sai de
       frame_read. Se o scanner ler um byte a mais, o ASan aponta. */
    size_t n = strlen(json);
    char *heap = malloc(n ? n : 1);
    memcpy(heap, json, n);
    int got = json_bool_is_true(heap, n, "ok");
    free(heap);
    if (got != expect) {
        printf("  FALHOU [%s]\n    entrada: %s\n    esperado %d, obteve %d\n", why, json, expect, got);
        fails++;
    }
}

static void ck_write(const char *in, const char *expect, const char *why) {
    char buf[256];
    jw_t w; jw_init(&w, buf, sizeof(buf));
    jw_str(&w, in);
    if (w.overflow || strcmp(buf, expect) != 0) {
        printf("  FALHOU [%s]\n    esperado %s\n    obteve   %s (overflow=%d)\n", why, expect, buf, w.overflow);
        fails++;
    }
}

/* ------------------------------------------------------------------ */
/* Camada 2 — apoio para E/S real                                      */
/* ------------------------------------------------------------------ */

/* Monta um socketpair, escreve do lado "daemon" um cabeçalho com `declared` e
   `blen` bytes de corpo, e opcionalmente fecha esse lado (o que o daemon de
   verdade faz logo depois de responder). Devolve os dois fds. */
static void fake_daemon(int *mod_fd, int *dmn_fd, uint32_t declared,
                        const void *body, size_t blen, int hangup) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) { perror("socketpair"); exit(2); }
    unsigned char hdr[4] = {
        (unsigned char)((declared >> 24) & 0xFF), (unsigned char)((declared >> 16) & 0xFF),
        (unsigned char)((declared >> 8)  & 0xFF), (unsigned char)( declared        & 0xFF),
    };
    if (write(sv[1], hdr, 4) != 4) { perror("write hdr"); exit(2); }
    if (blen > 0 && write(sv[1], body, blen) != (ssize_t)blen) { perror("write body"); exit(2); }
    if (hangup) { close(sv[1]); sv[1] = -1; }
    *mod_fd = sv[0];
    *dmn_fd = sv[1];
}

/* Igual, mas sem cabeçalho: escreve bytes crus. */
static void fake_daemon_raw(int *mod_fd, int *dmn_fd, const void *raw, size_t n, int hangup) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) { perror("socketpair"); exit(2); }
    if (n > 0 && write(sv[1], raw, n) != (ssize_t)n) { perror("write raw"); exit(2); }
    if (hangup) { close(sv[1]); sv[1] = -1; }
    *mod_fd = sv[0];
    *dmn_fd = sv[1];
}

static void shut(int a, int b) { if (a >= 0) close(a); if (b >= 0) close(b); }

static const char RESP_OK[]   = "{\"type\":\"auth.result\",\"ok\":true}";
static const char RESP_DENY[] = "{\"type\":\"auth.result\",\"ok\":false}";

static void test_frame_read(void) {
    printf("frame_read sobre socket real:\n");
    const size_t ok_len = sizeof(RESP_OK) - 1;
    int m, d;

    /* O caminho normal do daemon: responde e fecha na sequência. Antes da
       correção do POLLHUP isto perdia a aprovação e o sudo caía na senha. */
    {
        fake_daemon(&m, &d, (uint32_t)ok_len, RESP_OK, ok_len, 1);
        char *buf = malloc(PA_RESP_MAX);
        ssize_t n = frame_read(m, buf, PA_RESP_MAX, now_ms() + 2000);
        if (n != (ssize_t)ok_len)
            fail("[daemon responde e fecha] frame perdido: n=%zd, esperado %zu", n, ok_len);
        else if (!json_bool_is_true(buf, (size_t)n, "ok"))
            fail("[daemon responde e fecha] resposta lida mas não reconhecida como aprovação");
        free(buf); shut(m, d);
    }

    /* Mesmo frame, par ainda aberto: o caminho que já funcionava. */
    {
        fake_daemon(&m, &d, (uint32_t)ok_len, RESP_OK, ok_len, 0);
        char *buf = malloc(PA_RESP_MAX);
        ssize_t n = frame_read(m, buf, PA_RESP_MAX, now_ms() + 2000);
        if (n != (ssize_t)ok_len) fail("[par aberto] n=%zd", n);
        free(buf); shut(m, d);
    }

    /* Negação explícita continua sendo negação. */
    {
        const size_t dn = sizeof(RESP_DENY) - 1;
        fake_daemon(&m, &d, (uint32_t)dn, RESP_DENY, dn, 1);
        char *buf = malloc(PA_RESP_MAX);
        ssize_t n = frame_read(m, buf, PA_RESP_MAX, now_ms() + 2000);
        if (n <= 0 || json_bool_is_true(buf, (size_t)n, "ok"))
            fail("[ok:false] aprovou uma negação (n=%zd)", n);
        free(buf); shut(m, d);
    }

    /* Comprimento declarado zero. */
    {
        fake_daemon(&m, &d, 0, NULL, 0, 1);
        char *buf = malloc(PA_RESP_MAX);
        if (frame_read(m, buf, PA_RESP_MAX, now_ms() + 1000) != -1) fail("[len=0] deveria falhar");
        free(buf); shut(m, d);
    }

    /* Comprimento declarado maior que a capacidade: buffer de tamanho exato no
       heap para o ASan pegar qualquer escrita fora. */
    {
        const size_t cap = 32;
        fake_daemon(&m, &d, 5000, RESP_OK, ok_len, 1);
        char *tight = malloc(cap);
        if (frame_read(m, tight, cap, now_ms() + 1000) != -1) fail("[len>cap] deveria falhar");
        free(tight); shut(m, d);
    }

    /* Comprimento declarado acima do teto do protocolo. */
    {
        fake_daemon(&m, &d, PA_FRAME_MAX + 1, RESP_OK, ok_len, 1);
        char *buf = malloc(PA_RESP_MAX);
        if (frame_read(m, buf, PA_RESP_MAX, now_ms() + 1000) != -1) fail("[len>PA_FRAME_MAX] deveria falhar");
        free(buf); shut(m, d);
    }

    /* 0xFFFFFFFF: o valor que estoura se alguém trocar o tipo por int. */
    {
        fake_daemon(&m, &d, 0xFFFFFFFFu, RESP_OK, ok_len, 1);
        char *buf = malloc(PA_RESP_MAX);
        if (frame_read(m, buf, PA_RESP_MAX, now_ms() + 1000) != -1) fail("[len=0xFFFFFFFF] deveria falhar");
        free(buf); shut(m, d);
    }

    /* Comprimento declarado maior que o corpo entregue, e o par fecha. */
    {
        fake_daemon(&m, &d, (uint32_t)(ok_len + 50), RESP_OK, ok_len, 1);
        char *buf = malloc(PA_RESP_MAX);
        if (frame_read(m, buf, PA_RESP_MAX, now_ms() + 1000) != -1)
            fail("[corpo curto demais] deveria falhar");
        free(buf); shut(m, d);
    }

    /* Cabeçalho pela metade e EOF. */
    {
        fake_daemon_raw(&m, &d, "\0\0", 2, 1);
        char *buf = malloc(PA_RESP_MAX);
        if (frame_read(m, buf, PA_RESP_MAX, now_ms() + 1000) != -1) fail("[header parcial] deveria falhar");
        free(buf); shut(m, d);
    }

    /* Nada, só EOF. */
    {
        fake_daemon_raw(&m, &d, NULL, 0, 1);
        char *buf = malloc(PA_RESP_MAX);
        if (frame_read(m, buf, PA_RESP_MAX, now_ms() + 1000) != -1) fail("[EOF imediato] deveria falhar");
        free(buf); shut(m, d);
    }

    /* Corpo exatamente do tamanho da capacidade: fronteira do `len > cap`. */
    {
        const size_t cap = 64;
        char *body = malloc(cap);
        memset(body, 'x', cap);
        memcpy(body, "{\"ok\":true,\"pad\":\"", 18);
        body[cap - 2] = '"'; body[cap - 1] = '}';
        fake_daemon(&m, &d, (uint32_t)cap, body, cap, 1);
        char *tight = malloc(cap);
        ssize_t n = frame_read(m, tight, cap, now_ms() + 1000);
        if (n != (ssize_t)cap) fail("[len==cap] deveria aceitar, obteve %zd", n);
        else if (!json_bool_is_true(tight, (size_t)n, "ok")) fail("[len==cap] não reconheceu a aprovação");
        free(body); free(tight); shut(m, d);
    }

    /* Prazo já vencido: falha, e sem esperar. */
    {
        fake_daemon(&m, &d, (uint32_t)ok_len, RESP_OK, ok_len, 0);
        int64_t t0 = now_ms();
        char *buf = malloc(PA_RESP_MAX);
        if (frame_read(m, buf, PA_RESP_MAX, now_ms() - 1) != -1) fail("[prazo vencido] deveria falhar");
        if (now_ms() - t0 > 500) fail("[prazo vencido] demorou %lld ms", (long long)(now_ms() - t0));
        free(buf); shut(m, d);
    }

    /* Prazo curto sem nenhum dado: falha por timeout, não trava. */
    {
        int sv[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) { perror("socketpair"); exit(2); }
        int64_t t0 = now_ms();
        char *buf = malloc(PA_RESP_MAX);
        if (frame_read(sv[0], buf, PA_RESP_MAX, now_ms() + 120) != -1) fail("[timeout] deveria falhar");
        int64_t dt = now_ms() - t0;
        if (dt < 100 || dt > 2000) fail("[timeout] respeitou mal o prazo: %lld ms", (long long)dt);
        free(buf); shut(sv[0], sv[1]);
    }

    /* fd inválido (já fechado): POLLNVAL, falha imediata. */
    {
        int sv[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) { perror("socketpair"); exit(2); }
        int dead = sv[0];
        shut(sv[0], sv[1]);
        int64_t t0 = now_ms();
        char *buf = malloc(PA_RESP_MAX);
        if (frame_read(dead, buf, PA_RESP_MAX, now_ms() + 3000) != -1) fail("[fd fechado] deveria falhar");
        if (now_ms() - t0 > 500) fail("[fd fechado] esperou o prazo inteiro em vez de falhar na hora");
        free(buf);
    }

    /* Corpo com NUL no meio: frame_read não termina string, e o scanner
       trabalha por comprimento — o campo depois do NUL tem que ser visto. */
    {
        const char body[] = "{\"a\":\"\0\",\"ok\":true}";
        const size_t bl = sizeof(body) - 1;
        fake_daemon(&m, &d, (uint32_t)bl, body, bl, 1);
        char *buf = malloc(PA_RESP_MAX);
        ssize_t n = frame_read(m, buf, PA_RESP_MAX, now_ms() + 1000);
        if (n != (ssize_t)bl) fail("[NUL no corpo] n=%zd, esperado %zu", n, bl);
        else if (!json_bool_is_true(buf, (size_t)n, "ok")) fail("[NUL no corpo] chave depois do NUL foi ignorada");
        free(buf); shut(m, d);
    }
}

static void test_frame_write(void) {
    printf("frame_write / write_all:\n");
    int m, d;

    /* Ida e volta do cabeçalho big-endian. */
    {
        int sv[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) { perror("socketpair"); exit(2); }
        const char *json = "{\"type\":\"auth.begin\",\"user\":\"mpgxc\"}";
        size_t jl = strlen(json);
        if (frame_write(sv[0], json, jl, now_ms() + 1000) != 0) fail("[frame_write] falhou no caminho feliz");
        unsigned char hdr[4];
        if (read(sv[1], hdr, 4) != 4) fail("[frame_write] cabeçalho não chegou");
        uint32_t got = ((uint32_t)hdr[0] << 24) | ((uint32_t)hdr[1] << 16) |
                       ((uint32_t)hdr[2] << 8) | (uint32_t)hdr[3];
        if (got != jl) fail("[frame_write] comprimento %u != %zu", got, jl);
        char echo[128];
        if (read(sv[1], echo, jl) != (ssize_t)jl || memcmp(echo, json, jl) != 0)
            fail("[frame_write] corpo divergiu");
        shut(sv[0], sv[1]);
    }

    /* Prazo vencido: falha sem escrever. */
    {
        int sv[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) { perror("socketpair"); exit(2); }
        if (frame_write(sv[0], "{}", 2, now_ms() - 1) != -1) fail("[write prazo vencido] deveria falhar");
        shut(sv[0], sv[1]);
    }

    /* Escrever para um par que fechou tem que falhar LIMPO. Sem proteção de
       SIGPIPE isto mata o processo — que aqui seria o sudo do usuário. Roda em
       filho justamente porque, se a proteção sumir, o sinal é fatal. */
    {
        pid_t pid = fork();
        if (pid == 0) {
            int sv[2];
            if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) _exit(70);
            pa_set_nosigpipe(sv[0]);      /* o mesmo que connect_daemon faz */
            close(sv[1]);
            const char *json = "{\"type\":\"auth.begin\"}";
            int r = frame_write(sv[0], json, strlen(json), now_ms() + 1000);
            close(sv[0]);
            _exit(r == 0 ? 71 : 0);       /* esperado: falha limpa, sem sinal */
        }
        int st = 0;
        if (waitpid(pid, &st, 0) < 0) { perror("waitpid"); exit(2); }
        if (WIFSIGNALED(st))
            fail("[SIGPIPE] frame_write para par fechado matou o processo com sinal %d (%s) — "
                 "no sudo isso derruba a sessão do usuário", WTERMSIG(st), strsignal(WTERMSIG(st)));
        else if (WEXITSTATUS(st) == 70) fail("[SIGPIPE] socketpair falhou no filho");
        else if (WEXITSTATUS(st) == 71) fail("[SIGPIPE] frame_write disse que escreveu para um par fechado");
        else if (WEXITSTATUS(st) != 0) fail("[SIGPIPE] filho saiu com %d", WEXITSTATUS(st));
    }

    (void)m; (void)d;
}

/* ------------------------------------------------------------------ */
/* Camada 2 — decisão e entradas PAM                                   */
/* ------------------------------------------------------------------ */

/* A costura onde a decisão realmente nasce: frame_read seguido do scanner, na
   mesma forma que pam_sm_authenticate usa. Cada resposta abaixo passa por um
   socket de verdade. */
static void test_decision_seam(void) {
    printf("costura da decisão (frame real -> aprovação):\n");
    struct { const char *body; int approve; const char *why; } cases[] = {
        { "{\"type\":\"auth.result\",\"ok\":true}",   1, "resposta canônica do daemon" },
        { "{\"type\":\"auth.result\",\"ok\":false}",  0, "negação canônica" },
        { "{\"ok\":true}",                            1, "mínima" },
        { "{\"ok\":false}",                           0, "negação mínima" },
        { "{}",                                       0, "sem a chave" },
        { "{\"type\":\"error\",\"code\":\"badFrame\"}", 0, "frame de erro do daemon" },
        { "nao e json",                               0, "lixo" },
        { "{\"ok\":true,\"ok\":false}",               0, "chave duplicada, negação por último" },
        { "{\"detalhe\":{\"ok\":true},\"ok\":false}", 0, "aprovação aninhada, negação no topo" },
        { "{\"reason\":\"ok\",\"ok\":false}",         0, "string \"ok\" como valor antes da negação" },
        { "{\"ok\":truetrue}",                        0, "token colado" },
    };
    for (size_t i = 0; i < sizeof(cases)/sizeof(cases[0]); i++) {
        size_t bl = strlen(cases[i].body);
        int m, d;
        fake_daemon(&m, &d, (uint32_t)bl, cases[i].body, bl, 1);
        char *buf = malloc(PA_RESP_MAX);
        ssize_t n = frame_read(m, buf, PA_RESP_MAX, now_ms() + 1000);
        int approved = (n > 0 && json_bool_is_true(buf, (size_t)n, "ok"));
        if (approved != cases[i].approve)
            fail("[%s] esperado aprovar=%d, obteve %d (%s)", cases[i].why, cases[i].approve, approved, cases[i].body);
        free(buf); shut(m, d);
    }
}

static void test_pam_entry_points(void) {
    printf("entradas PAM:\n");

    /* Não há daemon em PA_SOCKET_PATH durante o teste. Toda chamada tem que
       cair em PAM_AUTHINFO_UNAVAIL — nunca em PAM_SUCCESS. */
    struct { int rc; const char *user; const char *why; } cases[] = {
        { PAM_AUTHINFO_UNAVAIL, NULL,        "pam_get_user falha" },
        { PAM_SUCCESS,          NULL,        "usuário NULL" },
        { PAM_SUCCESS,          "",          "usuário vazio" },
        { PAM_SUCCESS,          "mpgxc",     "usuário normal, daemon ausente" },
        { PAM_SUCCESS,          "a\"b\\c\n", "usuário com metacaracteres de JSON" },
    };
    for (size_t i = 0; i < sizeof(cases)/sizeof(cases[0]); i++) {
        stub_get_user_rc = cases[i].rc;
        stub_user        = cases[i].user;
        stub_get_item_rc = PAM_AUTHINFO_UNAVAIL;
        int r = pam_sm_authenticate(NULL, 0, 0, NULL);
        if (r == PAM_SUCCESS) fail("[%s] pam_sm_authenticate devolveu PAM_SUCCESS sem daemon!", cases[i].why);
        else if (r != PAM_AUTHINFO_UNAVAIL) fail("[%s] devolveu %d, esperado PAM_AUTHINFO_UNAVAIL", cases[i].why, r);
    }

    /* Usuário grande o bastante para estourar o buffer do pedido: tem que
       abortar antes de abrir socket, e sem escrever fora. */
    {
        char *huge = malloc(PA_REQ_MAX * 2 + 1);
        memset(huge, 'u', PA_REQ_MAX * 2);
        huge[PA_REQ_MAX * 2] = '\0';
        stub_get_user_rc = PAM_SUCCESS;
        stub_user = huge;
        stub_get_item_rc = PAM_AUTHINFO_UNAVAIL;
        if (pam_sm_authenticate(NULL, 0, 0, NULL) != PAM_AUTHINFO_UNAVAIL)
            fail("[usuário gigante] deveria dar PAM_AUTHINFO_UNAVAIL");
        free(huge);
    }

    /* Itens PAM controlados pelo atacante (rhost/tty vêm da rede em sshd).
       Continuam sem virar aprovação e sem estourar buffer. */
    {
        stub_get_user_rc = PAM_SUCCESS;
        stub_user = "mpgxc";
        stub_get_item_rc = PAM_SUCCESS;
        stub_item = "x\",\"ok\":true,\"z\":\"";
        if (pam_sm_authenticate(NULL, 0, 0, NULL) == PAM_SUCCESS)
            fail("[item PAM hostil] virou PAM_SUCCESS");
        stub_item = NULL;   /* pam_get_item devolve sucesso com ponteiro nulo */
        if (pam_sm_authenticate(NULL, 0, 0, NULL) == PAM_SUCCESS)
            fail("[item PAM nulo] virou PAM_SUCCESS");
    }

    /* Sem vazamento de descritor nos caminhos de erro: como fd é sempre o menor
       livre, um dup(0) antes e depois tem que dar o mesmo número. */
    {
        stub_get_user_rc = PAM_SUCCESS;
        stub_user = "mpgxc";
        stub_get_item_rc = PAM_AUTHINFO_UNAVAIL;
        int probe = dup(0);
        if (probe < 0) { perror("dup"); exit(2); }
        close(probe);
        for (int i = 0; i < 200; i++) (void)pam_sm_authenticate(NULL, 0, 0, NULL);
        int probe2 = dup(0);
        if (probe2 != probe) fail("[vazamento de fd] dup(0) foi de %d para %d após 200 chamadas", probe, probe2);
        if (probe2 >= 0) close(probe2);
    }

    /* As outras duas entradas. setcred devolve PAM_SUCCESS de propósito (não há
       credencial a estabelecer) e não autentica ninguém; acct_mgmt se abstém. */
    if (pam_sm_setcred(NULL, 0, 0, NULL) != PAM_SUCCESS) fail("pam_sm_setcred deveria devolver PAM_SUCCESS");
    if (pam_sm_acct_mgmt(NULL, 0, 0, NULL) != PAM_IGNORE) fail("pam_sm_acct_mgmt deveria devolver PAM_IGNORE");

    stub_get_user_rc = PAM_AUTHINFO_UNAVAIL;
    stub_get_item_rc = PAM_AUTHINFO_UNAVAIL;
    stub_user = NULL;
    stub_item = NULL;
}

/* ------------------------------------------------------------------ */

int main(void) {
    printf("scanner JSON — deve APROVAR:\n");
    ck_scan("{\"type\":\"auth.result\",\"ok\":true}", 1, "resposta canônica");
    ck_scan("{\"ok\":true}",                          1, "mínima");
    ck_scan("{\"ok\" : true}",                        1, "espaços ao redor dos dois pontos");
    ck_scan("{\"ok\":true,\"x\":1}",                  1, "seguido de vírgula");
    ck_scan("{\"ok\":true\n}",                        1, "seguido de newline");
    ck_scan("{\"ok\":true\t}",                        1, "seguido de tab");
    ck_scan("{\"a\":1,\"ok\":true}",                  1, "não é o primeiro campo");
    ck_scan("{\"x\":\"ok\",\"ok\":true}",             1, "string \"ok\" como valor antes da chave real");

    /* Espaço em branco de JSON inclui newline e retorno de carro (RFC 8259 §2).
       O daemon hoje escreve compacto, mas ligar `.prettyPrinted` num refactor
       não pode transformar toda aprovação em recusa silenciosa. */
    printf("scanner JSON — espaço em branco completo:\n");
    ck_scan("{\"ok\":\ntrue}",   1, "newline depois dos dois pontos");
    ck_scan("{\"ok\"\n:\ntrue}", 1, "newline dos dois lados dos dois pontos");
    ck_scan("{\"ok\":\r\ntrue}", 1, "CRLF depois dos dois pontos");
    ck_scan("{\n  \"ok\" : true\n}", 1, "objeto identado");

    printf("scanner JSON — deve NEGAR:\n");
    ck_scan("{\"ok\":false}",         0, "negação explícita");
    ck_scan("{\"ok\":null}",          0, "null");
    ck_scan("{\"ok\":\"true\"}",      0, "true como string, não booleano");
    ck_scan("{\"ok\":truex}",         0, "token com sufixo");
    ck_scan("{\"ok\":true1}",         0, "true seguido de dígito");
    ck_scan("{\"ok\":truthy}",        0, "prefixo parecido");
    ck_scan("{\"ok\":tru}",           0, "token truncado");
    ck_scan("{\"notok\":true}",       0, "chave é sufixo de outra");
    ck_scan("{\"okay\":true}",        0, "chave é prefixo de outra");
    ck_scan("{\"OK\":true}",          0, "capitalização diferente");
    ck_scan("{\"type\":\"auth.result\"}", 0, "chave ausente");
    ck_scan("{}",                     0, "objeto vazio");
    ck_scan("",                       0, "vazio");
    ck_scan("{\"ok\"true}",           0, "sem dois pontos");
    ck_scan("{\"ok\":}",              0, "sem valor");
    ck_scan("{\"ok\":",               0, "truncado logo após os dois pontos");
    ck_scan("{\"ok\":tru",            0, "truncado no meio do token");
    ck_scan("{\"ok\":truetrue}",      0, "dois tokens colados");
    ck_scan("{\"ok\":[true]}",        0, "true dentro de array");
    ck_scan("{\"ok\":{\"ok\":true}}", 0, "objeto no lugar do booleano");
    ck_scan("[\"ok\",true]",          0, "array no lugar do objeto");

    /* O modo de falha tem que ser SEMPRE negar. Em todos estes um parser de
       JSON de verdade responde "não aprovado", e o scanner precisa concordar.
       Parar na primeira ocorrência da chave deixava os três primeiros passarem
       como aprovação. */
    printf("scanner JSON — chave repetida e aninhada (fail-open):\n");
    ck_scan("{\"ok\":true,\"ok\":false}",                 0, "duplicada: aprovação primeiro, negação depois");
    ck_scan("{\"detalhe\":{\"ok\":true},\"ok\":false}",   0, "aprovação aninhada antes da negação de topo");
    ck_scan("{\"lista\":[{\"ok\":true}],\"ok\":false}",   0, "aprovação dentro de array antes da negação");
    ck_scan("{\"a\":{\"b\":{\"ok\":true}},\"ok\":null}",  0, "aninhada em dois níveis antes de null");
    ck_scan("{\"ok\":false,\"ok\":true}",                 0, "duplicada na ordem inversa");
    ck_scan("{\"ok\":true,\"x\":1,\"ok\":\"true\"}",      0, "segunda ocorrência vira string");
    ck_scan("{\"ok\":true,\"detalhe\":{\"ok\":false}}",   0, "negação aninhada depois da aprovação");
    ck_scan("{\"ok\":true,\"ok\":true}",                  1, "duplicada, ambas aprovando");

    /* O que acontece se um valor de string carregar a chave. Em JSON válido a
       aspa interna vem escapada, e o escape é o que nos salva. Este é o caso
       que motiva a invariante de o daemon nunca ecoar dado não confiável no
       frame de auth.result. */
    printf("scanner JSON — injeção via valor de string:\n");
    ck_scan("{\"reason\":\"sudo \\\"ok\\\":true\",\"ok\":false}", 0,
            "chave escapada dentro de string não engana");
    ck_scan("{\"reason\":\"x\",\"ok\":false}", 0, "campo anterior benigno");
    ck_scan("{\"reason\":\"sudo \\\"ok\\\":true\",\"ok\":true}", 1,
            "escape não impede a aprovação legítima");

    /* Um valor de string com aspa CRUA é JSON inválido e não pode ser
       produzido por um serializador correto; documentamos que aqui enganaria. */
    {
        const char raw[] = "{\"r\":\"\"ok\":true\",\"ok\":false}";
        int crua = json_bool_is_true(raw, sizeof(raw) - 1, "ok");
        printf("  (nota: JSON inválido com aspa crua retorna %d — por isso o daemon\n"
               "   nunca ecoa dado não confiável em auth.result)\n", crua);
    }

    printf("escritor JSON:\n");
    ck_write("simples",        "\"simples\"",           "sem escapes");
    ck_write("a\"b",           "\"a\\\"b\"",            "aspa");
    ck_write("a\\b",           "\"a\\\\b\"",            "barra invertida");
    ck_write("a\nb",           "\"a\\nb\"",             "newline");
    ck_write("a\rb",           "\"a\\rb\"",             "retorno de carro");
    ck_write("a\tb",           "\"a\\tb\"",             "tab");
    ck_write("a\x01" "b",      "\"a\\u0001b\"",         "byte de controle");
    ck_write("a\x1f" "b",      "\"a\\u001fb\"",         "controle 0x1f");
    ck_write("café",           "\"café\"",              "UTF-8 passa direto");
    ck_write("",               "\"\"",                  "string vazia");
    ck_write("\x7f",           "\"\x7f\"",              "DEL não é de controle em JSON");

    /* Escapar não pode virar vetor de injeção: newline no motivo. */
    ck_write("sudo x\n\"ok\":true", "\"sudo x\\n\\\"ok\\\":true\"",
             "tentativa de injeção é neutralizada");

    /* O que o escritor produz tem que sobreviver a uma volta pelo scanner:
       nenhuma entrada de campo pode fabricar uma aprovação. */
    printf("escritor -> scanner (ida e volta):\n");
    {
        const char *hostis[] = {
            "\",\"ok\":true", "x\",\"ok\": true,\"y\":\"", "\\\",\"ok\":true",
            "\n\"ok\":true", "\r\n\"ok\":true", "\t\"ok\":true", "}\"ok\":true{",
        };
        for (size_t i = 0; i < sizeof(hostis)/sizeof(hostis[0]); i++) {
            char buf[512];
            jw_t w; jw_init(&w, buf, sizeof(buf));
            jw_raw(&w, "{");
            jw_kv(&w, "user", hostis[i]); jw_char(&w, ',');
            jw_kv(&w, "ok", "false");
            jw_raw(&w, "}");
            if (w.overflow) { fail("[ida e volta %zu] overflow inesperado", i); continue; }
            if (json_bool_is_true(buf, w.len, "ok"))
                fail("[ida e volta %zu] campo hostil fabricou aprovação: %s", i, buf);
        }
    }

    printf("escritor JSON — overflow:\n");
    {
        char small[8];
        jw_t w; jw_init(&w, small, sizeof(small));
        jw_str(&w, "esta string é bem maior que o buffer");
        if (!w.overflow) { printf("  FALHOU: overflow não sinalizado\n"); fails++; }
        if (strlen(small) >= sizeof(small)) { printf("  FALHOU: estourou o buffer!\n"); fails++; }
    }
    {
        /* Após overflow, appends seguintes continuam sem escrever. */
        char small[4];
        jw_t w; jw_init(&w, small, sizeof(small));
        jw_raw(&w, "aaaaaaaaaa");
        size_t after = w.len;
        jw_raw(&w, "bbbb");
        if (w.len != after) { printf("  FALHOU: escreveu depois do overflow\n"); fails++; }
        if (strlen(small) >= sizeof(small)) { printf("  FALHOU: estourou o buffer!\n"); fails++; }
    }
    {
        /* Capacidade exata: a string cabe com o NUL e nada mais. Buffer no heap
           para o ASan pegar um byte a mais. */
        char *exact = malloc(3);          /* "x" entre aspas = 3 bytes + NUL... */
        jw_t w; jw_init(&w, exact, 3);
        jw_str(&w, "x");                  /* precisa de 4: '"','x','"','\0' */
        if (!w.overflow) fail("[cap exata] deveria estourar em cap=3 para \"x\"");
        free(exact);

        char *exact4 = malloc(4);
        jw_t w4; jw_init(&w4, exact4, 4);
        jw_str(&w4, "x");
        if (w4.overflow || strcmp(exact4, "\"x\"") != 0) fail("[cap exata] cap=4 deveria caber");
        free(exact4);
    }
    {
        /* cap == 0: não pode escrever byte nenhum. */
        char *zero = malloc(1);
        zero[0] = (char)0xAB;
        jw_t w; jw_init(&w, zero, 0);
        jw_str(&w, "qualquer");
        jw_raw(&w, "coisa");
        jw_char(&w, 'x');
        if (!w.overflow) fail("[cap=0] deveria marcar overflow");
        if ((unsigned char)zero[0] != 0xAB) fail("[cap=0] escreveu em buffer de capacidade zero");
        free(zero);
    }

    printf("parse de timeout (clamp):\n");
    {
        const char *a1[] = {"timeout=30"};   if (parse_timeout(1,a1) != 30)  { printf("  FALHOU normal\n"); fails++; }
        const char *a2[] = {"timeout=1"};    if (parse_timeout(1,a2) != 5)   { printf("  FALHOU piso\n"); fails++; }
        const char *a3[] = {"timeout=9999"}; if (parse_timeout(1,a3) != 120) { printf("  FALHOU teto\n"); fails++; }
        const char *a4[] = {"timeout=abc"};  if (parse_timeout(1,a4) != 30)  { printf("  FALHOU não numérico\n"); fails++; }
        const char *a5[] = {"timeout=30x"};  if (parse_timeout(1,a5) != 30)  { printf("  FALHOU lixo à direita\n"); fails++; }
        const char *a6[] = {"timeout=-5"};   if (parse_timeout(1,a6) != 5)   { printf("  FALHOU negativo\n"); fails++; }
        const char *a7[] = {"outra=coisa"};  if (parse_timeout(1,a7) != 30)  { printf("  FALHOU opção alheia\n"); fails++; }
        if (parse_timeout(0,NULL) != 30) { printf("  FALHOU sem args\n"); fails++; }

        const char *a8[] = {"timeout="};              if (parse_timeout(1,a8) != 30)  fail("timeout vazio");
        const char *a9[] = {"timeout=99999999999999999999"}; if (parse_timeout(1,a9) != 30) fail("overflow de strtol ignorado");
        const char *a10[] = {"timeout= 30"};          if (parse_timeout(1,a10) != 30) fail("espaço à esquerda vira 30 mesmo");
        const char *a11[] = {"timeout=0x40"};         if (parse_timeout(1,a11) != 30) fail("hexadecimal não deveria colar");
        const char *a12[] = {"timeout=10","timeout=60"}; if (parse_timeout(2,a12) != 60) fail("última opção vence");
        const char *a13[] = {"timeout=10","timeout=x"};  if (parse_timeout(2,a13) != 10) fail("opção inválida não apaga a válida");
    }

    test_frame_read();
    test_frame_write();
    test_decision_seam();
    test_pam_entry_points();

    printf(fails ? "\n%d FALHA(S)\n" : "\nTodos os testes passaram\n", fails);
    return fails ? 1 : 0;
}
