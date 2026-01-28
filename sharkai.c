#include <stdio.h>
#include <stdlib.h>

#include <epan/plugin_if.h>
#include <epan/frame_data.h>
#include <epan/frame_data_sequence.h>
#include <epan/epan_dissect.h>
#include <epan/proto.h>

#include <wsutil/wslog.h>

#include <wiretap/wtap.h>

#include <json-c/json.h>

#include "sharkai.h"
#include "sharkai_dialog.h"
#include "sharkai_qt_bridge.h"

const int plugin_want_major = 4;
const int plugin_want_minor = 6;

const char plugin_name[] = "SharkAI";
const char plugin_description[] = "SharkAI Packet Copilot";
const char plugin_version[] = "0.1.0";
const char plugin_release[] = "SharkAI Packet Copilot (Phase 1)";


typedef struct {
    char *prompt_text;
    char *response_text;
} sharkai_filter_dialog_ctx_t;

typedef struct {
    uint32_t *frames;
    size_t frame_count;
    size_t max_frames;
    size_t dissected;
    json_object *packet_list; 
} sharkai_dissect_ctx_t;

typedef struct {
    int depth;
    int max_depth;
    const char *current_proto;  /* e.g. "eth", "ip", "tcp" */
    json_object *out;
    json_object *json_obj;
} sharkai_tree_walk_ctx_t;

static void
sharkai_walk_node(proto_node *node, gpointer user_data)
{
    sharkai_tree_walk_ctx_t *ctx = (sharkai_tree_walk_ctx_t *)user_data;
    proto_item *pi = (proto_item *)node;

    if (!pi || !pi->finfo || !pi->finfo->hfinfo)
        return;

    const char *abbrev = pi->finfo->hfinfo->abbrev;

    /* ===================== HARD SUPPRESSION ===================== */

    if (abbrev &&
        (
            strcmp(abbrev, "data") == 0 ||
            strcmp(abbrev, "frame") == 0 ||
            strcmp(abbrev, "http.file_data") == 0 ||
            strcmp(abbrev, "tcp.segment_data") == 0 ||
            strcmp(abbrev, "tcp.payload") == 0 ||
            strcmp(abbrev, "ip.addr") == 0 ||
            strcmp(abbrev, "ip.host") == 0 ||
            strcmp(abbrev, "udp.payload") == 0 ||
            strstr(abbrev, "tcp.reassembled") != NULL ||
            g_str_has_prefix(abbrev, "frame.") ||
            g_str_has_prefix(abbrev, "_ws.") ||
            g_str_has_prefix(abbrev, "ip.src.") ||
            g_str_has_prefix(abbrev, "ip.src_") ||
            g_str_has_prefix(abbrev, "ip.dst.") ||
            g_str_has_prefix(abbrev, "ip.dst_")
        ))
        return;

    if (abbrev &&
        (
            strcmp(abbrev, "radiotap.bytes") == 0 ||
            strcmp(abbrev, "wlan.addr") == 0 ||
            strcmp(abbrev, "wlan.oui") == 0 ||
            g_str_has_prefix(abbrev, "wlan.addr_") ||
            g_str_has_prefix(abbrev, "wlan.oui_") ||
            g_str_has_prefix(abbrev, "wlan.sa.") ||
            g_str_has_prefix(abbrev, "wlan.sa_") ||
            g_str_has_prefix(abbrev, "wlan.ta.") ||
            g_str_has_prefix(abbrev, "wlan.ta_") ||
            g_str_has_prefix(abbrev, "wlan.ra.") ||
            g_str_has_prefix(abbrev, "wlan.ra_") ||
            g_str_has_prefix(abbrev, "wlan.da.") ||
            g_str_has_prefix(abbrev, "wlan.da_") ||
            g_str_has_prefix(abbrev, "wlan.bssid.") ||
            g_str_has_prefix(abbrev, "wlan.bssid_")
        ))
        return;

    if (abbrev && strcmp(abbrev, "json") == 0)
        json_object_object_add(ctx->out, "json", ctx->json_obj);

    /* ================= json.member_with_value =================
    * Example label tail: "sdkver:339"
    * Store as: ctx->json_obj["sdkver"] = "339"
    */
    if (abbrev &&
        strcmp(abbrev, "json.member_with_value") == 0 &&
        ctx->json_obj)
    {
        char label[1024];
        size_t value_offset = 0;

        proto_item_fill_label(pi->finfo, label, &value_offset);

        if (value_offset < strlen(label)) {
            const char *s = label + value_offset;

            /* skip common separators/spaces */
            while (*s == ' ' || *s == ':' || *s == '\t')
                s++;

            if (*s) {
                /* find first ':' separating key and value */
                const char *colon = strchr(s, ':');
                if (colon && colon != s) {
                    size_t klen = (size_t)(colon - s);

                    /* copy key */
                    char *k = g_strndup(s, klen);

                    /* value starts after ':' */
                    const char *v = colon + 1;
                    while (*v == ' ' || *v == '\t')
                        v++;

                    if (k && *k) {
                        json_object_object_add(
                            ctx->json_obj,
                            k,
                            json_object_new_string(v)
                        );
                    }

                    g_free(k);
                }
            }
        }

        return; /* don't let json.* fall through */
    }

    if (pi->finfo->hfinfo->bitmask != 0)
        return;

    proto_tree *subtree = proto_item_get_subtree(pi);

    gboolean is_protocol =
        abbrev &&
        strchr(abbrev, '.') == NULL &&
        subtree != NULL;

    gboolean print_node = TRUE;

    if (ctx->current_proto &&
        strcmp(ctx->current_proto, "eth") == 0 &&
        strcmp(abbrev, "eth.src") != 0 &&
        strcmp(abbrev, "eth.dst") != 0)
        print_node = FALSE;

    if (print_node && ctx->out && abbrev &&
        !g_str_has_prefix(abbrev, "json.")) {
        char label[1024];
        size_t value_offset = 0;

        proto_item_fill_label(pi->finfo, label, &value_offset);

        if (value_offset < strlen(label)) {
            const char *val = label + value_offset;
            while (*val == ' ' || *val == ':')
                val++;

            if (*val) {
                json_object_object_add(
                    ctx->out,
                    abbrev,
                    json_object_new_string(val)
                );
            }
        }
    }

    /* ================= RECURSION ================= */

    if (!subtree || ctx->depth >= ctx->max_depth)
        return;

    sharkai_tree_walk_ctx_t child_ctx = *ctx;
    child_ctx.depth++;

    if (is_protocol)
        child_ctx.current_proto = abbrev;

    proto_tree_children_foreach(
        subtree,
        sharkai_walk_node,
        &child_ctx
    );
}


static json_object * sharkai_build_packet_json(proto_tree *tree, int max_depth)
{
    if (!tree) return NULL;

    json_object *packet_json = json_object_new_object();
    json_object *json_obj = json_object_new_object(); 

    sharkai_tree_walk_ctx_t w = { 
        .depth = 0, 
        .max_depth = max_depth, 
        .current_proto = NULL,
        .out = packet_json,
        .json_obj = json_obj
    };
    proto_tree_children_foreach(tree, sharkai_walk_node, &w);

    /* DEBUG */
    // const char *json_str =
    //    json_object_to_json_string_ext(packet_json, JSON_C_TO_STRING_PRETTY);
    // g_message("SharkAI packet JSON:\n%s", json_str);

    return packet_json; /* caller owns */
}


static json_object *sharkai_build_ollama_payload(
    const char *model,
    const char *prompt)
{
    json_object *root = json_object_new_object();

    json_object_object_add(root, "model",
                           json_object_new_string(model));

    json_object_object_add(root, "prompt",
                           json_object_new_string(prompt));

    json_object_object_add(root, "stream",
                           json_object_new_boolean(FALSE));

    return root; /* caller owns */
}


static void sharkai_submit_prompt(
    sharkai_filter_dialog_ctx_t *ctx)
{
    if (!ctx || !ctx->prompt_text || ctx->prompt_text[0] == '\0') {
        g_warning("SharkAI: empty prompt");
        return;
    }

    /* Hardcode model for now */
    const char *model = "llama3.2";

    json_object *payload =
        sharkai_build_ollama_payload(model, ctx->prompt_text);

    const char *json_str =
        json_object_to_json_string_ext(
            payload, JSON_C_TO_STRING_PRETTY);

    g_message("SharkAI Ollama payload:\n%s", json_str);

    /* Echo payload to response pane (Phase 1 UX) */
    g_clear_pointer(&ctx->response_text, g_free);
    ctx->response_text = g_strdup(json_str);

    json_object_put(payload);
}


static void sharkai_filter_from_prompt_cb(
    ext_menubar_gui_type gui_type _U_,
    void *gui_object _U_,
    void *user_data _U_)
{
    char *prompt = sharkai_filter_dialog_run("SharkAI - Create Filter From Prompt");
    if (prompt) {
        g_free(prompt);
    }
}


static void sharkai_configure_cb(
    ext_menubar_gui_type gui_type _U_,
    void *gui_object _U_,
    void *user_data _U_)
{
    sharkai_config_dialog_run_c();
}


/* ----------------------------- */
/* Packet extraction context     */
/* ----------------------------- */
static void *
sharkai_capture_file_cb(capture_file *cf, void *user_data)
{
    sharkai_dissect_ctx_t *ctx = (sharkai_dissect_ctx_t *)user_data;

    //g_message("SharkAI: capture_file_cb enter");
    //g_message("SharkAI: cf=%p ctx=%p", (void *)cf, (void *)ctx);

    if (!cf || !ctx || !cf->provider.wth) {
        g_warning("SharkAI: invalid inputs");
        return NULL;
    }

    if (!cf->provider.frames) {
        g_warning("SharkAI: no frame_data_sequence available");
        return NULL;
    }

    wtap *wth = cf->provider.wth;
    int file_type_subtype = wtap_file_type_subtype(wth);

    if (!ctx->frames || ctx->frame_count == 0) {
        g_warning("SharkAI: no selected frames");
        return NULL;
    }

    //g_message("SharkAI: processing %zu selected frames", ctx->frame_count);

    for (size_t i = 0; i < ctx->frame_count; i++) {
        uint32_t frame_num = ctx->frames[i];
        //g_message("SharkAI: processing frame %u", frame_num);

        frame_data *fd =
            frame_data_sequence_find(cf->provider.frames, frame_num);

        if (!fd) {
            g_warning("SharkAI: frame_data not found for frame %u", frame_num);
            continue;
        }


        // g_message("SharkAI: frame_data OK num=%u cap_len=%u pkt_len=%u file_off=%" G_GINT64_FORMAT,
        //           fd->num, fd->cap_len, fd->pkt_len, fd->file_off);

        if (!fd->pfd) {
            g_warning("SharkAI: frame %u has no proto data", frame_num);
            continue;
        }

        wtap_rec rec;
        char *err_info = NULL;
        int err = 0;

        wtap_rec_init(&rec, 0);

        /* Seek to this packet */
        if (!wtap_seek_read(
                wth,
                fd->file_off,
                &rec,
                &err,
                &err_info))
        {
            g_warning("SharkAI: wtap_seek_read failed for frame %u: %s",
                    fd->num, err_info ? err_info : "(unknown)");
            g_free(err_info);
            wtap_rec_cleanup(&rec);
            continue;
        }

        epan_dissect_t *edt = epan_dissect_new(cf->epan, TRUE, TRUE);

        epan_dissect_run(
            edt,
            file_type_subtype,
            &rec,        /* from wtap_seek_read */
            fd,
            NULL
        );

        proto_tree *tree = edt->tree;

        /* walk tree here and build packet json */
        json_object *packet_json =
            sharkai_build_packet_json(tree, 10);

        if (packet_json) {
            json_object_array_add(ctx->packet_list, packet_json);
            ctx->dissected++;
        }

        epan_dissect_free(edt);
        wtap_rec_cleanup(&rec);
        g_clear_pointer(&err_info, g_free);

    }

    return NULL;
}


/* ----------------------------- */
/* Menu callbacks                */
/* ----------------------------- */

static void sharkai_summarize_cb(
    ext_menubar_gui_type gui_type _U_,
    void *gui_object _U_,
    void *user_data _U_)
{
    size_t count = 0;
    uint32_t *frames = sharkai_qt_get_selected_frames(&count);

    if (!frames || count == 0) {
        g_warning("SharkAI: no selected frames found");
        return;
    }

    const size_t MAX_FRAMES = 50;
    if (count > MAX_FRAMES) {
        g_warning("SharkAI: too many frames selected (%zu)", count);
        g_free(frames);
        return;
    }

    sharkai_dissect_ctx_t ctx = {
        .frames = frames,
        .frame_count = count,
        .max_frames = MAX_FRAMES,
        .dissected = 0,
        .packet_list = json_object_new_array()
    };

    plugin_if_get_capture_file(sharkai_capture_file_cb, &ctx);

    //g_message("SharkAI: dissected %zu packets", ctx.dissected);

    const char *json_str =
        json_object_to_json_string_ext(
            ctx.packet_list,
            JSON_C_TO_STRING_PRETTY
        );

    //g_message("SharkAI packet list:\n%s", json_str);

    sharkai_packet_analysis_dialog_run(ctx.packet_list);

    json_object_put(ctx.packet_list);

    /* DO NOT free epan_dissect_t yet — next step */
    g_free(frames);
}


/* ----------------------------- */
/* Plugin registration           */
/* ----------------------------- */

WS_DLL_PUBLIC void plugin_register(void)
{
    //g_message("SharkAI: plugin_register() called");

    ext_menu_t *menu = ext_menubar_register_menu(
        0,
        "SharkAI",
        true
    );

    if (!menu) {
        g_warning("SharkAI: ext_menubar_register_menu returned NULL");
        return;
    }

    /* Attach under an existing menu by NAME */
    ext_menubar_set_parentmenu(menu, "Tools");

    ext_menubar_add_entry(
        menu,
        "Create filter from prompt",
        "Create a filter string from a plain-language prompt",
        sharkai_filter_from_prompt_cb,
        NULL
    );

    ext_menubar_add_entry(
        menu,
        "Summarize selected packets",
        "Send selected packets to SharkAI for analysis",
        sharkai_summarize_cb,
        NULL
    );

    ext_menubar_add_entry(
        menu,
        "Configure SharkAI…",
        "Configure LLM options",
        sharkai_configure_cb,
        NULL
    );
}

WS_DLL_PUBLIC void plugin_reg_handoff(void)
{
    /* Intentionally empty for UI-only plugin */
}
