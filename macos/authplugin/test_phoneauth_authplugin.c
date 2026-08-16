/*
 * Testes do plugin de autorização.
 *
 * O que importa verificar aqui é diferente do módulo PAM, e mais severo: lá o
 * caminho de falha cai para a senha, aqui ele **nega**, e negar encerra a
 * avaliação do direito. Então o alvo destes testes é a assimetria — permitir
 * só acontece com uma resposta perfeita do daemon, e todo o resto nega.
 *
 * Compila incluindo o .c direto, como os testes do PAM, para alcançar as
 * funções static.
 */

#include "phoneauth_authplugin.c"

#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <sys/stat.h>

/* ------------------------------------------------------------------ */
/* Motor falso                                                         */
/* ------------------------------------------------------------------ */

static AuthorizationResult g_resultado;
static int                 g_set_result_chamado;
static int                 g_did_deactivate_chamado;

static const char *g_hint_username;
static const char *g_hint_prompt;
static size_t      g_hint_username_len;   /* permite hint sem terminador */

static OSStatus falso_set_result(AuthorizationEngineRef e, AuthorizationResult r) {
    (void)e;
    g_resultado = r;
    g_set_result_chamado++;
    return errAuthorizationSuccess;
}

static OSStatus falso_did_deactivate(AuthorizationEngineRef e) {
    (void)e;
    g_did_deactivate_chamado++;
    return errAuthorizationSuccess;
}

static OSStatus falso_get_hint(AuthorizationEngineRef e, AuthorizationString key,
                               const AuthorizationValue **out) {
    (void)e;
    static AuthorizationValue v;
    if (strcmp(key, "username") == 0 && g_hint_username != NULL) {
        v.data   = (void *)g_hint_username;
        v.length = (UInt32)g_hint_username_len;
        *out = &v;
        return errAuthorizationSuccess;
    }
    if (strcmp(key, "prompt") == 0 && g_hint_prompt != NULL) {
        v.data   = (void *)g_hint_prompt;
        v.length = (UInt32)strlen(g_hint_prompt);
        *out = &v;
        return errAuthorizationSuccess;
    }
    *out = NULL;
    return errAuthorizationInternal;
}

static AuthorizationCallbacks g_callbacks = {
    .version          = kAuthorizationCallbacksVersion,
    .SetResult        = falso_set_result,
    .DidDeactivate    = falso_did_deactivate,
    .GetHintValue     = falso_get_hint,
};

/* ------------------------------------------------------------------ */
/* Daemon falso sobre o socket real                                    */
/* ------------------------------------------------------------------ */

static char        g_resposta[512];
static size_t      g_resposta_len;
static int         g_responder;      /* 0 = aceita e fecha calado */
static int         g_ouvinte = -1;

static void *daemon_falso(void *arg) {
    (void)arg;
    int c = accept(g_ouvinte, NULL, NULL);
    if (c < 0) return NULL;

    char lixo[PA_REQ_MAX];
    uint8_t hdr[4];
    if (read(c, hdr, 4) == 4) {
        size_t n = ((size_t)hdr[0] << 24) | ((size_t)hdr[1] << 16) |
                   ((size_t)hdr[2] << 8) | (size_t)hdr[3];
        if (n > sizeof(lixo)) n = sizeof(lixo);
        ssize_t lido = read(c, lixo, n);
        (void)lido;
    }

    if (g_responder) {
        uint8_t out[4];
        out[0] = (uint8_t)(g_resposta_len >> 24); out[1] = (uint8_t)(g_resposta_len >> 16);
        out[2] = (uint8_t)(g_resposta_len >> 8);  out[3] = (uint8_t)(g_resposta_len);
        ssize_t e1 = write(c, out, 4);
        ssize_t e2 = write(c, g_resposta, g_resposta_len);
        (void)e1; (void)e2;
    }
    close(c);
    return NULL;
}

/* Do tamanho de sun_path: maior daria aviso de truncamento no bind. */
static char g_sock_path[108];

static void subir_daemon(const char *resposta, int responder) {
    g_responder = responder;
    if (resposta != NULL) {
        g_resposta_len = strlen(resposta);
        memcpy(g_resposta, resposta, g_resposta_len);
    }

    g_ouvinte = socket(AF_UNIX, SOCK_STREAM, 0);
    assert(g_ouvinte >= 0);

    struct sockaddr_un a;
    memset(&a, 0, sizeof(a));
    a.sun_family = AF_UNIX;
    unlink(g_sock_path);
    snprintf(a.sun_path, sizeof(a.sun_path), "%s", g_sock_path);
    assert(bind(g_ouvinte, (struct sockaddr *)&a, sizeof(a)) == 0);
    assert(listen(g_ouvinte, 1) == 0);
}

/* Invoca o mecanismo contra o daemon falso e devolve o resultado. */
static AuthorizationResult invocar(void) {
    pthread_t t;
    pthread_create(&t, NULL, daemon_falso, NULL);

    pa_plugin_t p = { .callbacks = &g_callbacks };
    pa_mechanism_t m = { .plugin = &p, .engine = NULL };

    g_set_result_chamado = 0;
    g_resultado = kAuthorizationResultUndefined;
    pa_mechanism_invoke((AuthorizationMechanismRef)&m);

    pthread_join(t, NULL);
    close(g_ouvinte);
    unlink(g_sock_path);
    return g_resultado;
}

/* ------------------------------------------------------------------ */

int main(void) {
    snprintf(g_sock_path, sizeof(g_sock_path), "/tmp/pa_authplugin_test.sock");

    /*
     * connect_daemon usa PA_SOCKET_PATH fixo. Para exercitar o caminho real de
     * ponta a ponta sem root, o teste redefine o alvo via este símbolo — ver o
     * -D no Makefile de teste.
     */
    printf("socket de teste: %s\n\n", PA_SOCKET_PATH);
    snprintf(g_sock_path, sizeof(g_sock_path), "%s", PA_SOCKET_PATH);

    g_hint_username     = "mpgxc";
    g_hint_username_len = strlen("mpgxc");
    g_hint_prompt       = "Os Ajustes do Sistema querem fazer alterações.";

    printf("permite só com ok:true bem formado:\n");
    subir_daemon("{\"type\":\"auth.result\",\"ok\":true}", 1);
    assert(invocar() == kAuthorizationResultAllow);
    assert(g_set_result_chamado == 1);

    printf("nega com ok:false:\n");
    subir_daemon("{\"type\":\"auth.result\",\"ok\":false}", 1);
    assert(invocar() == kAuthorizationResultDeny);

    printf("nega quando a chave ok não existe:\n");
    subir_daemon("{\"type\":\"auth.result\"}", 1);
    assert(invocar() == kAuthorizationResultDeny);

    printf("nega quando o daemon fecha sem responder:\n");
    subir_daemon(NULL, 0);
    assert(invocar() == kAuthorizationResultDeny);

    printf("nega quando o daemon nem existe:\n");
    unlink(PA_SOCKET_PATH);
    {
        pa_plugin_t p = { .callbacks = &g_callbacks };
        pa_mechanism_t m = { .plugin = &p, .engine = NULL };
        g_resultado = kAuthorizationResultUndefined;
        pa_mechanism_invoke((AuthorizationMechanismRef)&m);
        assert(g_resultado == kAuthorizationResultDeny);
    }

    printf("hint sem terminador NUL não vaza além do comprimento:\n");
    {
        /* "mpgxcLIXO" com length=5: só "mpgxc" pode entrar. */
        g_hint_username     = "mpgxcLIXO";
        g_hint_username_len = 5;
        char out[64];
        pa_plugin_t p = { .callbacks = &g_callbacks };
        pa_mechanism_t m = { .plugin = &p, .engine = NULL };
        pa_hint_str(&m, "username", out, sizeof(out));
        assert(strcmp(out, "mpgxc") == 0);
    }

    printf("hint maior que o buffer trunca sem estourar:\n");
    {
        static char grande[4096];
        memset(grande, 'A', sizeof(grande) - 1);
        g_hint_username     = grande;
        g_hint_username_len = sizeof(grande) - 1;
        char out[16];
        pa_plugin_t p = { .callbacks = &g_callbacks };
        pa_mechanism_t m = { .plugin = &p, .engine = NULL };
        pa_hint_str(&m, "username", out, sizeof(out));
        assert(strlen(out) == 15);
    }

    printf("hint ausente vira string vazia, não lixo:\n");
    {
        g_hint_username = NULL;
        char out[32];
        memset(out, 'Z', sizeof(out));
        pa_plugin_t p = { .callbacks = &g_callbacks };
        pa_mechanism_t m = { .plugin = &p, .engine = NULL };
        pa_hint_str(&m, "username", out, sizeof(out));
        assert(out[0] == '\0');
    }

    printf("deactivate avisa o motor:\n");
    {
        pa_plugin_t p = { .callbacks = &g_callbacks };
        pa_mechanism_t m = { .plugin = &p, .engine = NULL };
        g_did_deactivate_chamado = 0;
        pa_mechanism_deactivate((AuthorizationMechanismRef)&m);
        assert(g_did_deactivate_chamado == 1);
    }

    printf("create devolve a interface com a versão certa:\n");
    {
        AuthorizationPluginRef plugin = NULL;
        const AuthorizationPluginInterface *iface = NULL;
        assert(AuthorizationPluginCreate(&g_callbacks, &plugin, &iface) == errAuthorizationSuccess);
        assert(iface != NULL);
        assert(iface->version == kAuthorizationPluginInterfaceVersion);
        assert(iface->MechanismInvoke == pa_mechanism_invoke);
        assert(iface->MechanismCreate == pa_mechanism_create);
        assert(iface->MechanismDestroy == pa_mechanism_destroy);
        iface->PluginDestroy(plugin);
    }

    printf("\nTodos os testes passaram\n");
    return 0;
}
