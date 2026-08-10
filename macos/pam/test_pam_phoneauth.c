/* Testa as funções puras de pam_phoneauth.c incluindo o .c diretamente. */
#include <assert.h>
#include <stdio.h>

/* Stubs das funções PAM que o módulo referencia. */
typedef struct pam_handle pam_handle_t;
int pam_get_item(const pam_handle_t *p, int t, const void **i) { (void)p;(void)t;(void)i; return 1; }
int pam_get_user(pam_handle_t *p, const char **u, const char *pr) { (void)p;(void)u;(void)pr; return 1; }

#include "pam_phoneauth.c"

static int fails = 0;

static void ck_scan(const char *json, int expect, const char *why) {
    int got = json_bool_is_true(json, strlen(json), "ok");
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

int main(void) {
    printf("scanner JSON — deve APROVAR:\n");
    ck_scan("{\"type\":\"auth.result\",\"ok\":true}", 1, "resposta canônica");
    ck_scan("{\"ok\":true}",                          1, "mínima");
    ck_scan("{\"ok\" : true}",                        1, "espaços ao redor dos dois pontos");
    ck_scan("{\"ok\":true,\"x\":1}",                  1, "seguido de vírgula");
    ck_scan("{\"ok\":true\n}",                        1, "seguido de newline");
    ck_scan("{\"ok\":true\t}",                        1, "seguido de tab");
    ck_scan("{\"a\":1,\"ok\":true}",                  1, "não é o primeiro campo");

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

    /* O que acontece se um valor de string carregar a chave. Em JSON válido a
       aspa interna vem escapada, e o escape é o que nos salva. Este é o caso
       que motiva a invariante de o daemon nunca ecoar dado não confiável no
       frame de auth.result. */
    printf("scanner JSON — injeção via valor de string:\n");
    ck_scan("{\"reason\":\"sudo \\\"ok\\\":true\",\"ok\":false}", 0,
            "chave escapada dentro de string não engana");
    ck_scan("{\"reason\":\"x\",\"ok\":false}", 0, "campo anterior benigno");

    /* Um valor de string com aspa CRUA é JSON inválido e não pode ser
       produzido por um serializador correto; documentamos que aqui enganaria. */
    int crua = json_bool_is_true("{\"r\":\"\"ok\":true\",\"ok\":false}",
                                 strlen("{\"r\":\"\"ok\":true\",\"ok\":false}"), "ok");
    printf("  (nota: JSON inválido com aspa crua retorna %d — por isso o daemon\n"
           "   nunca ecoa dado não confiável em auth.result)\n", crua);

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

    /* Escapar não pode virar vetor de injeção: newline no motivo. */
    ck_write("sudo x\n\"ok\":true", "\"sudo x\\n\\\"ok\\\":true\"",
             "tentativa de injeção é neutralizada");

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
    }

    printf(fails ? "\n%d FALHA(S)\n" : "\nTodos os testes passaram\n", fails);
    return fails ? 1 : 0;
}
