#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>

#define SHARKAI_MAX_MODELS 32

typedef enum {
    SHARKAI_PAYLOAD_OLLAMA,
    SHARKAI_PAYLOAD_CHAT_COMPLETIONS,
    SHARKAI_PAYLOAD_OPENAI_RESPONSES
} sharkai_payload_type_t;

typedef struct {
    char host[256];
    int  port;
    char model[256];
    char api_key[256];
    char api_endpoint[256];
    bool uses_https;
} sharkai_config_t;

typedef struct {
    const char *name;
    const char *domain;
    bool        requires_api_key;
    const char *api_endpoint;
    bool        uses_https;
    sharkai_payload_type_t payload_type;
} sharkai_model_info_t;

const sharkai_config_t *sharkai_get_config(void);
const sharkai_model_info_t *sharkai_get_models(void);
const sharkai_model_info_t *sharkai_get_model_info(const char *model);
void sharkai_set_config(const char *host,
                        int port,
                        const char *model,
                        const char *api_key,
                        const char *api_endpoint,
                        bool https_override);
void sharkai_models_init_once(void);

#ifdef __cplusplus
}
#endif