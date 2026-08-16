/*
 * phoneauth_authplugin — aprova diálogos do SecurityAgent pela digital do
 * celular pareado.
 *
 * Complementa o pam_phoneauth.so. O módulo PAM cobre `sudo` e `su`; estes são
 * os pedidos que **não passam por PAM** — "Os Ajustes do Sistema querem fazer
 * alterações", destravar um painel de preferências, instalar um pacote. Eles
 * vão pelo SecurityAgent, que consulta o authorization database para saber
 * quais mecanismos rodar para cada direito nomeado.
 *
 * ────────────────────────────────────────────────────────────────────────────
 * A DIFERENÇA QUE GOVERNA TUDO AQUI: ISTO NÃO TEM `sufficient`.
 *
 * O módulo PAM pode falhar à vontade — daemon fora do ar, celular sem bateria,
 * você em outra rede — porque `sufficient` faz o PAM seguir para o próximo
 * módulo e pedir a senha. Um mecanismo de autorização não tem esse degrau: o
 * primeiro que diz "não" encerra a avaliação inteira, e não existe resultado
 * que signifique "não sei, pergunte a outro".
 *
 * Consequência prática, que precisa estar escrita onde alguém vá ler antes de
 * mexer: enquanto este mecanismo for o único de um direito, esse direito fica
 * indisponível quando o celular não responde. Não é bug, é a forma do
 * mecanismo.
 *
 * A saída de emergência é deliberadamente outra pilha: `sudo` continua sendo
 * PAM, com queda para senha, então
 *
 *     sudo phoneauthctl authplugin disable
 *
 * restaura a regra original em qualquer situação. É por isso que o `enable`
 * recusa mexer em direitos dos quais o próprio resgate depende.
 * ────────────────────────────────────────────────────────────────────────────
 *
 * Nenhuma senha passa por aqui. O mecanismo responde apenas "permitido" ou
 * "negado" — nunca injeta credencial no contexto, e portanto nunca exige que o
 * Mac guarde a senha de login em disco. Essa é a linha que separa este
 * subconjunto do que o docs/modelo-de-ameacas.md classifica como
 * "qualitativamente pior do que tudo na v1".
 *
 * Build:
 *     clang -bundle -o PhoneAuth phoneauth_authplugin.c -framework Security \
 *           -framework CoreFoundation
 */

#include <Security/AuthorizationPlugin.h>
#include <Security/AuthorizationTags.h>
#include <CoreFoundation/CoreFoundation.h>

/*
 * Mesmo transporte do módulo PAM: mesmo socket, mesmo framing, mesmo scanner
 * JSON. Duas cópias divergindo seria a pior falha possível justamente aqui.
 */
#include "../common/phoneauth_wire.h"

/* ------------------------------------------------------------------ */
/* Estado                                                              */
/* ------------------------------------------------------------------ */

typedef struct {
    const AuthorizationCallbacks *callbacks;
} pa_plugin_t;

typedef struct {
    pa_plugin_t            *plugin;
    AuthorizationEngineRef  engine;
} pa_mechanism_t;

/* ------------------------------------------------------------------ */
/* Leitura do contexto                                                 */
/* ------------------------------------------------------------------ */

/*
 * Copia um hint textual para `out`, sempre terminando em NUL.
 *
 * O SecurityAgent entrega `AuthorizationValue` com comprimento explícito e sem
 * garantia de terminador — tratar isso como string C direto seria leitura fora
 * dos limites com dado que vem de fora do processo.
 */
static void pa_hint_str(pa_mechanism_t *m, const char *key, char *out, size_t cap) {
    if (cap == 0) return;
    out[0] = '\0';

    const AuthorizationValue *value = NULL;
    if (m->plugin->callbacks->GetHintValue(m->engine, key, &value) != errAuthorizationSuccess)
        return;
    if (value == NULL || value->data == NULL || value->length == 0) return;

    size_t n = value->length;
    if (n >= cap) n = cap - 1;

    /* Um hint com NUL no meio truncaria o JSON silenciosamente; corta ali. */
    const char *src = (const char *)value->data;
    size_t i = 0;
    for (; i < n; i++) {
        if (src[i] == '\0') break;
        out[i] = src[i];
    }
    out[i] = '\0';
}

/* ------------------------------------------------------------------ */
/* Mecanismo                                                           */
/* ------------------------------------------------------------------ */

static OSStatus pa_mechanism_create(AuthorizationPluginRef inPlugin,
                                    AuthorizationEngineRef inEngine,
                                    AuthorizationMechanismId mechanismId,
                                    AuthorizationMechanismRef *outMechanism) {
    (void)mechanismId;

    pa_mechanism_t *m = (pa_mechanism_t *)calloc(1, sizeof(*m));
    if (m == NULL) return errAuthorizationInternal;

    m->plugin = (pa_plugin_t *)inPlugin;
    m->engine = inEngine;
    *outMechanism = (AuthorizationMechanismRef)m;
    return errAuthorizationSuccess;
}

static OSStatus pa_mechanism_invoke(AuthorizationMechanismRef inMechanism) {
    pa_mechanism_t *m = (pa_mechanism_t *)inMechanism;

    const int64_t deadline = now_ms() + (int64_t)PA_DEFAULT_TIMEOUT_S * 1000;

    char user[256];
    char prompt[512];
    pa_hint_str(m, kAuthorizationEnvironmentUsername, user, sizeof(user));
    pa_hint_str(m, kAuthorizationEnvironmentPrompt, prompt, sizeof(prompt));

    /*
     * `service` distingue, na tela do celular, um pedido gráfico de um `sudo`.
     * Quem aprova precisa saber o que está aprovando, e "sudo" seria mentira.
     */
    char pid_buf[24];
    snprintf(pid_buf, sizeof(pid_buf), "%ld", (long)getpid());

    char req[PA_REQ_MAX];
    jw_t w;
    jw_init(&w, req, sizeof(req));
    jw_raw(&w, "{");
    jw_kv(&w, "type", "auth.begin");             jw_char(&w, ',');
    jw_kv(&w, "user", user);                     jw_char(&w, ',');
    jw_kv(&w, "service", "authorization");       jw_char(&w, ',');
    jw_kv(&w, "tty", "");                        jw_char(&w, ',');
    jw_kv(&w, "ruser", "");                      jw_char(&w, ',');
    jw_kv(&w, "rhost", prompt);                  jw_char(&w, ',');
    jw_str(&w, "pid"); jw_char(&w, ':'); jw_raw(&w, pid_buf);
    jw_raw(&w, "}");

    /*
     * O único caminho que permite. Espelha a regra do pam_phoneauth.c: exige
     * frame bem formado, do tamanho declarado, com `"ok": true`. Qualquer outro
     * desfecho nega.
     *
     * Aqui negar tem peso maior que no PAM, porque não há próximo módulo — daí
     * o cuidado de manter este bloco tão pequeno quanto o de lá, e a regra de
     * que um segundo `permitido` neste arquivo exige justificativa muito boa.
     */
    AuthorizationResult result = kAuthorizationResultDeny;

    if (!w.overflow) {
        int fd = connect_daemon(deadline);
        if (fd >= 0) {
            if (frame_write(fd, req, w.len, deadline) == 0) {
                char resp[PA_RESP_MAX];
                ssize_t n = frame_read(fd, resp, sizeof(resp), deadline);
                if (n > 0 && json_bool_is_true(resp, (size_t)n, "ok")) {
                    result = kAuthorizationResultAllow;
                }
                memset(resp, 0, sizeof(resp));
            }
            close(fd);
        }
    }

    memset(req, 0, sizeof(req));

    OSStatus status = m->plugin->callbacks->SetResult(m->engine, result);
    return status;
}

static OSStatus pa_mechanism_deactivate(AuthorizationMechanismRef inMechanism) {
    pa_mechanism_t *m = (pa_mechanism_t *)inMechanism;
    return m->plugin->callbacks->DidDeactivate(m->engine);
}

static OSStatus pa_mechanism_destroy(AuthorizationMechanismRef inMechanism) {
    /*
     * Os refs da Apple são ponteiros para struct opaca `const`, mas a memória é
     * nossa — veio do calloc em MechanismCreate. O cast descarta um const que
     * descreve a visão de quem chama, não a propriedade do bloco.
     */
    free((void *)(uintptr_t)inMechanism);
    return errAuthorizationSuccess;
}

/* ------------------------------------------------------------------ */
/* Plugin                                                              */
/* ------------------------------------------------------------------ */

static OSStatus pa_plugin_destroy(AuthorizationPluginRef inPlugin) {
    /* Mesmo motivo do MechanismDestroy: o bloco é nosso, o const é da API. */
    free((void *)(uintptr_t)inPlugin);
    return errAuthorizationSuccess;
}

static const AuthorizationPluginInterface pa_interface = {
    kAuthorizationPluginInterfaceVersion,
    pa_plugin_destroy,
    pa_mechanism_create,
    pa_mechanism_invoke,
    pa_mechanism_deactivate,
    pa_mechanism_destroy,
};

OSStatus AuthorizationPluginCreate(const AuthorizationCallbacks *callbacks,
                                   AuthorizationPluginRef *outPlugin,
                                   const AuthorizationPluginInterface **outPluginInterface) {
    if (callbacks == NULL || callbacks->version < 1) return errAuthorizationInternal;

    pa_plugin_t *p = (pa_plugin_t *)calloc(1, sizeof(*p));
    if (p == NULL) return errAuthorizationInternal;

    p->callbacks       = callbacks;
    *outPlugin          = (AuthorizationPluginRef)p;
    *outPluginInterface = &pa_interface;
    return errAuthorizationSuccess;
}
