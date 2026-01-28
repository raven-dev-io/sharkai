
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>
#include <string.h>
#include <unistd.h>

#include <json-c/json.h>

#include "sharkai_config.h"

static sharkai_model_info_t *g_runtime_models = NULL;  // optional override
static size_t g_runtime_models_count = 0;
static int g_models_initialized = 0;


static const sharkai_model_info_t sharkai_models[] = {
    {
        .name = "mistral",
        .domain = "localhost",
        .requires_api_key = false,
        .api_endpoint = "/api/generate",
        .uses_https = false,
        .payload_type = SHARKAI_PAYLOAD_OLLAMA
    },
    {
        .name = "grok-code-fast-1",
        .domain = "api.x.ai",
        .requires_api_key = true,
        .api_endpoint = "/v1/chat/completions",
        .uses_https = true,
        .payload_type = SHARKAI_PAYLOAD_CHAT_COMPLETIONS
    },
    {
        .name = "gpt-5.2-pro",
        .domain = "api.openai.com",
        .requires_api_key = true,
        .api_endpoint = "/v1/responses",
        .uses_https = true,
        .payload_type = SHARKAI_PAYLOAD_OPENAI_RESPONSES
    },
    {
        .name = NULL
    }
};


static sharkai_config_t g_sharkai_config = {
    .host = "127.0.0.1",
    .port = 11434,
    .model = "mistral",
    .api_key = "",
    .api_endpoint = "/api/generate",
    .uses_https = false
};


static void sharkai_get_models_conf_path(char *dir, size_t dir_sz,
                                         char *file, size_t file_sz)
{
    const char *home = getenv("HOME");
    if (!home || !home[0]) {
        snprintf(dir,  dir_sz,  ".sharkai");
        snprintf(file, file_sz, ".sharkai/models.conf");
        return;
    }

    snprintf(dir,  dir_sz,  "%s/.config/wireshark/sharkai", home);
    snprintf(file, file_sz, "%s/.config/wireshark/sharkai/models.conf", home);
}


static void sharkai_mkdir_p(const char *path)
{
    if (!path || !path[0])
        return;

    char tmp[512];
    if (snprintf(tmp, sizeof(tmp), "%s", path) >= (int)sizeof(tmp))
        return;

    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            mkdir(tmp, 0700);
            *p = '/';
        }
    }
    mkdir(tmp, 0700);
}


static void sharkai_free_runtime_models(void)
{
    if (!g_runtime_models)
        return;

    for (size_t i = 0; i < g_runtime_models_count; i++) {
        free((void*)g_runtime_models[i].name);
        free((void*)g_runtime_models[i].domain);
        free((void*)g_runtime_models[i].api_endpoint);
    }
    free(g_runtime_models);

    g_runtime_models = NULL;
    g_runtime_models_count = 0;
}


static void sharkai_write_default_models_conf(const char *path)
{
    json_object *arr = json_object_new_array();
    if (!arr)
        return;

    for (int i = 0; sharkai_models[i].name; i++) {
        const sharkai_model_info_t *m = &sharkai_models[i];
        json_object *o = json_object_new_object();

        json_object_object_add(o, "name",
            json_object_new_string(m->name));
        json_object_object_add(o, "domain",
            json_object_new_string(m->domain ? m->domain : ""));
        json_object_object_add(o, "requires_api_key",
            json_object_new_boolean(m->requires_api_key));
        json_object_object_add(o, "api_endpoint",
            json_object_new_string(m->api_endpoint ? m->api_endpoint : ""));
        json_object_object_add(o, "uses_https",
            json_object_new_boolean(m->uses_https));
        json_object_object_add(o, "payload_type",
            json_object_new_int((int)m->payload_type));

        json_object_array_add(arr, o);
    }

    FILE *f = fopen(path, "w");
    if (f) {
        fprintf(f, "%s\n",
            json_object_to_json_string_ext(
                arr, JSON_C_TO_STRING_PRETTY |
                JSON_C_TO_STRING_NOSLASHESCAPE));
        fclose(f);
    }

    json_object_put(arr);
}


static void sharkai_load_models_from_json(json_object *arr)
{
    size_t count = json_object_array_length(arr);
    if (count == 0)
        return;

    /* Optional hard clamp for safety */
    if (count > SHARKAI_MAX_MODELS)
        count = SHARKAI_MAX_MODELS;

    sharkai_model_info_t *models =
        calloc(count + 1, sizeof(*models));
    if (!models)
        return;

    size_t valid = 0;

    for (size_t i = 0; i < count; i++) {
        json_object *o = json_object_array_get_idx(arr, (int)i);
        if (!o || !json_object_is_type(o, json_type_object))
            continue;

        json_object *jname;
        if (!json_object_object_get_ex(o, "name", &jname) ||
            !json_object_is_type(jname, json_type_string))
            continue;

        const char *name = json_object_get_string(jname);
        if (!name || !name[0])
            continue;

        /* --- Collect optional fields safely --- */

        const char *domain_s = "";
        const char *endpoint_s = "";
        bool requires_api_key = false;
        bool uses_https = false;
        sharkai_payload_type_t payload_type = SHARKAI_PAYLOAD_OLLAMA;

        json_object *v;

        if (json_object_object_get_ex(o, "domain", &v) &&
            json_object_is_type(v, json_type_string))
            domain_s = json_object_get_string(v);

        if (json_object_object_get_ex(o, "api_endpoint", &v) &&
            json_object_is_type(v, json_type_string))
            endpoint_s = json_object_get_string(v);

        if (json_object_object_get_ex(o, "requires_api_key", &v) &&
            json_object_is_type(v, json_type_boolean))
            requires_api_key = json_object_get_boolean(v);

        if (json_object_object_get_ex(o, "uses_https", &v) &&
            json_object_is_type(v, json_type_boolean))
            uses_https = json_object_get_boolean(v);

        if (json_object_object_get_ex(o, "payload_type", &v) &&
            json_object_is_type(v, json_type_int)) {
            int pt = json_object_get_int(v);
            if (pt >= SHARKAI_PAYLOAD_OLLAMA &&
                pt <= SHARKAI_PAYLOAD_OPENAI_RESPONSES)
                payload_type = (sharkai_payload_type_t)pt;
        }

        /* --- Allocate strings atomically --- */

        char *name_dup = strdup(name);
        char *domain_dup = strdup(domain_s ? domain_s : "");
        char *endpoint_dup = strdup(endpoint_s ? endpoint_s : "");

        if (!name_dup || !domain_dup || !endpoint_dup) {
            free(name_dup);
            free(domain_dup);
            free(endpoint_dup);
            continue;
        }

        /* --- Commit entry --- */

        sharkai_model_info_t *m = &models[valid];

        m->name = name_dup;
        m->domain = domain_dup;
        m->api_endpoint = endpoint_dup;
        m->requires_api_key = requires_api_key;
        m->uses_https = uses_https;
        m->payload_type = payload_type;

        valid++;
    }

    if (valid == 0) {
        free(models);
        return;
    }

    models[valid].name = NULL; /* sentinel */

    sharkai_free_runtime_models();
    g_runtime_models = models;
    g_runtime_models_count = valid;
}

static void sharkai_models_init_once(void)
{
    if (g_models_initialized)
        return;
    g_models_initialized = 1;

    char dir[512], file[512];
    sharkai_get_models_conf_path(dir, sizeof(dir), file, sizeof(file));

    /* Ensure config directory exists */
    sharkai_mkdir_p(dir);

    /* If file does not exist, create defaults and stop */
    if (access(file, F_OK) != 0) {
        sharkai_write_default_models_conf(file);
        return; /* built-in models remain active */
    }

    FILE *f = fopen(file, "r");
    if (!f)
        return;

    /* Determine file size safely */
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return;
    }

    long sz = ftell(f);
    if (sz < 0 || sz > (64 * 1024)) {  /* hard cap: 64 KB */
        fclose(f);
        return;
    }

    if (fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        return;
    }

    if (sz == 0) {
        fclose(f);
        return;
    }

    char *buf = malloc((size_t)sz + 1);
    if (!buf) {
        fclose(f);
        return;
    }

    size_t nread = fread(buf, 1, (size_t)sz, f);
    fclose(f);

    if (nread == 0) {
        free(buf);
        return;
    }

    buf[nread] = '\0';

    /* Parse JSON */
    json_object *root = json_tokener_parse(buf);
    free(buf);

    if (!root)
        return;

    json_object *arr = NULL;

    if (json_object_is_type(root, json_type_array)) {
        arr = root;
    }
    else if (json_object_is_type(root, json_type_object)) {
        json_object_object_get_ex(root, "models", &arr);
    }

    if (arr && json_object_is_type(arr, json_type_array)) {
        sharkai_load_models_from_json(arr);
    }

    json_object_put(root);
}


static const sharkai_model_info_t *sharkai_models_active(void)
{
    return g_runtime_models ? g_runtime_models : sharkai_models;
}


const sharkai_model_info_t *
sharkai_get_model_info(const char *model)
{
    sharkai_models_init_once();
    if (!model || !model[0])
        return NULL;

    const sharkai_model_info_t *models = sharkai_models_active();

    for (int i = 0; models[i].name; i++) {
        if (strcmp(models[i].name, model) == 0)
            return &models[i];
    }
    return NULL;
}


const sharkai_model_info_t *sharkai_get_models(void)
{
    sharkai_models_init_once();
    return sharkai_models_active();
}


const sharkai_config_t *sharkai_get_config(void)
{
    return &g_sharkai_config;
}


void sharkai_set_config(const char *host,
                        int port,
                        const char *model,
                        const char *api_key,
                        const char *api_endpoint,
                        bool https_override)
{
    if (host && host[0] != '\0') {
        strncpy(g_sharkai_config.host, host,
                sizeof(g_sharkai_config.host) - 1);
        g_sharkai_config.host[sizeof(g_sharkai_config.host) - 1] = '\0';
    }

    if (port > 0 && port < 65536) {
        g_sharkai_config.port = port;
    }

    if (port == 443 || https_override) {
        g_sharkai_config.uses_https = true;
    }

    if (model && model[0] != '\0') {
        const sharkai_model_info_t *info = sharkai_get_model_info(model);
        if (info) {
            strncpy(g_sharkai_config.model, model,
                    sizeof(g_sharkai_config.model) - 1);
            g_sharkai_config.model[sizeof(g_sharkai_config.model) - 1] = '\0';

            /* Clear API key automatically if model doesn't need it */
            if (!info->requires_api_key) {
                g_sharkai_config.api_key[0] = '\0';
            }
        }
    }

    if (api_endpoint && api_endpoint[0] != '\0') {
        strncpy(g_sharkai_config.api_endpoint, api_endpoint,
            sizeof(g_sharkai_config.api_endpoint) - 1);
        g_sharkai_config.api_endpoint[sizeof(g_sharkai_config.api_endpoint) - 1] = '\0';
    }

    /*
     * api_key semantics:
     *  - NULL => leave unchanged
     *  - ""   => explicitly clear
     */
    if (api_key) {
        strncpy(g_sharkai_config.api_key, api_key,
                sizeof(g_sharkai_config.api_key) - 1);
        g_sharkai_config.api_key[sizeof(g_sharkai_config.api_key) - 1] = '\0';
    }
}
