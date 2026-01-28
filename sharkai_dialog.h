#pragma once

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    SHARKAI_LLM_PAYLOAD_FILTER_STRING = 1,
    SHARKAI_LLM_PAYLOAD_PACKET_ANALYSIS = 2
} sharkai_llm_payload_type_t;

/* Prompt dialog (already correct) */
char *sharkai_filter_dialog_run(const char *title);

/* C-safe entry point (NO Qt types) */
void sharkai_config_dialog_run_c(void);

void sharkai_packet_analysis_dialog_run(struct json_object *packet_data);

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
/* C++-only API */
#include <QWidget>
void sharkai_config_dialog_run(QWidget *parent);
#endif
