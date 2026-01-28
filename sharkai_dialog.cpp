#include "sharkai_dialog.h"

#include <glib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include <json-c/json.h>

#include <QtWidgets/QDialog>
#include <QtWidgets/QPlainTextEdit>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QVBoxLayout>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QLabel>
#include <QtCore/QString>
#include <QtCore/QThread>
#include <QtCore/QMetaObject>
#include <QApplication>
#include <QMainWindow>
#include <QObject>
#include <QComboBox>
#include <QCheckBox>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QSpinBox>
#include <QNetworkAccessManager>
#include <QNetworkRequest>
#include <QNetworkReply>
#include <QEventLoop>
#include <QUrl>

extern "C" {
#include "sharkai_config.h"
}

static char *sharkai_build_instruction_prompt(const char *user_prompt, int payload_type)
{
    const char *safe = user_prompt ? user_prompt : "";
    
    if (payload_type == SHARKAI_LLM_PAYLOAD_FILTER_STRING) {
        return g_strdup_printf(
            "You are a network analyst. Convert the following request into a valid "
            "Wireshark/tshark display filter.\n"
            "Return ONLY the filter expression.\n"
            "Do NOT include explanations.\n"
            "Do NOT include markdown or code blocks.\n"
            "Do NOT include multiple tshark filters.\n"
            "Return exactly ONE valid tshark display filter string.\n\n"
            "User request a tshark filter be made for this prompt: %s",
            safe
        );
    } else if (payload_type == SHARKAI_LLM_PAYLOAD_PACKET_ANALYSIS) {
        return g_strdup_printf(
            "You are a cybersecurity analyst. The following JSON contains filtered packet capture data.\n"
            "Please summarize key observations — including communication patterns, anomalies, possible server roles, and any security concerns.\n"
            "Be concise but informative.\n\n"
            "User requests that you analyze the following packet data: %s",
            safe
        );
    }
    return NULL;
}

static json_object *
sharkai_build_llm_payload(const char *model,
                          const char *user_prompt,
                          int payload_type)
{
    const sharkai_model_info_t *info =
        sharkai_get_model_info(model);

    if (!info)
        return NULL;

    json_object *root = json_object_new_object();
    char *instruction =
        sharkai_build_instruction_prompt(user_prompt, payload_type);

    switch (info->payload_type) {

    case SHARKAI_PAYLOAD_OLLAMA:
        /*
         * Ollama /api/generate
         * {
         *   "model": "...",
         *   "prompt": "...",
         *   "stream": false
         * }
         */
        json_object_object_add(
            root, "model",
            json_object_new_string(info->name)
        );

        json_object_object_add(
            root, "prompt",
            json_object_new_string(instruction)
        );

        json_object_object_add(
            root, "stream",
            json_object_new_boolean(FALSE)
        );
        break;

    case SHARKAI_PAYLOAD_CHAT_COMPLETIONS:
        /*
         * OpenAI / Grok / Chat Completions
         * {
         *   "model": "...",
         *   "messages": [
         *     { "role": "user", "content": "..." }
         *   ],
         *   "temperature": 0
         * }
         */
        json_object_object_add(
            root, "model",
            json_object_new_string(info->name)
        );

        {
            json_object *messages = json_object_new_array();
            json_object *msg = json_object_new_object();

            json_object_object_add(
                msg, "role",
                json_object_new_string("user")
            );

            json_object_object_add(
                msg, "content",
                json_object_new_string(instruction)
            );

            json_object_array_add(messages, msg);

            json_object_object_add(
                root, "messages",
                messages
            );
        }

        json_object_object_add(
            root, "temperature",
            json_object_new_double(0.0)
        );
        break;

    case SHARKAI_PAYLOAD_OPENAI_RESPONSES:
        /*
         * OpenAI /v1/responses
         * {
         *   "model": "...",
         *   "input": [
         *     {
         *       "role": "user",
         *       "content": "..."
         *     }
         *   ]
         * }
         */
        json_object_object_add(
            root, "model",
            json_object_new_string(info->name)
        );

        {
            json_object *input = json_object_new_array();
            json_object *item  = json_object_new_object();

            json_object_object_add(
                item, "role",
                json_object_new_string("user")
            );

            json_object_object_add(
                item, "content",
                json_object_new_string(instruction)
            );

            json_object_array_add(input, item);

            json_object_object_add(
                root, "input",
                input
            );
        }
        break;
    }

    g_free(instruction);
    return root;  /* caller owns */
}


static QString sharkai_query_llm_https(const char *json_payload, QLabel *statusLabel)
{
    const sharkai_config_t *cfg = sharkai_get_config();
    const sharkai_model_info_t *info =
        sharkai_get_model_info(cfg->model);

    if (!info)
        return "[!] unknown model";

    QUrl url;
    url.setScheme("https");
    url.setHost(cfg->host);
    url.setPort(cfg->port);
    url.setPath(info->api_endpoint);

    QNetworkRequest req(url);
    req.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
    req.setRawHeader("Accept", "application/json");
    req.setRawHeader("User-Agent", "SharkAI/1.0");

    if (cfg->api_key[0]) {
        QByteArray auth = "Bearer ";
        auth.append(cfg->api_key);
        req.setRawHeader("Authorization", auth);
    }

    QNetworkAccessManager mgr;
    QEventLoop loop;

    bool first_chunk_fired = false;

    QNetworkReply *reply = mgr.post(req, QByteArray(json_payload));

    QObject::connect(reply, &QNetworkReply::readyRead, [&]() {
        if (!first_chunk_fired) {
            first_chunk_fired = true;

            if (statusLabel) {
                QMetaObject::invokeMethod(
                    statusLabel,
                    [statusLabel]() {
                        statusLabel->setText("● Responding");
                        statusLabel->setStyleSheet(
                            "color: green; font-weight: bold;"
                        );
                    },
                    Qt::QueuedConnection
                );
            }
        }
    });

    QObject::connect(reply, &QNetworkReply::finished,
                     &loop, &QEventLoop::quit);

    loop.exec();

    if (reply->error() != QNetworkReply::NoError) {
        QString err = reply->errorString();
        QByteArray body = reply->readAll();
        reply->deleteLater();

        return QString("[!] HTTPS request failed: %1\n%2")
            .arg(err)
            .arg(QString::fromUtf8(body));
    }

    QByteArray body = reply->readAll();
    reply->deleteLater();

    json_object *root = json_tokener_parse(body.constData());
    if (!root)
        return "[!] failed to parse JSON response";

    /* ================= OpenAI Responses API ================= */
    if (info->payload_type == SHARKAI_PAYLOAD_OPENAI_RESPONSES &&
        strcmp(info->api_endpoint, "/v1/responses") == 0) {
        
        json_object *output = nullptr;
        if (!json_object_object_get_ex(root, "output", &output) ||
            !json_object_is_type(output, json_type_array)) {
            json_object_put(root);
            return "[!] no output[] in Responses API reply";
        }

        for (int i = 0; i < json_object_array_length(output); i++) {
            json_object *item = json_object_array_get_idx(output, i);
            json_object *type = nullptr;

            if (!json_object_object_get_ex(item, "type", &type))
                continue;

            if (strcmp(json_object_get_string(type), "message") != 0)
                continue;

            json_object *content = nullptr;
            if (!json_object_object_get_ex(item, "content", &content) ||
                !json_object_is_type(content, json_type_array))
                continue;

            for (int j = 0; j < json_object_array_length(content); j++) {
                json_object *part = json_object_array_get_idx(content, j);
                json_object *ptype = nullptr;
                json_object *text  = nullptr;

                if (!json_object_object_get_ex(part, "type", &ptype))
                    continue;

                if (strcmp(json_object_get_string(ptype), "output_text") != 0)
                    continue;

                if (!json_object_object_get_ex(part, "text", &text))
                    continue;

                QString result =
                    QString::fromUtf8(json_object_get_string(text));

                json_object_put(root);
                return result.trimmed();
            }
        }

        json_object_put(root);
        return "[!] no output_text found in Responses API reply";
    }

    // NOTE: chat-completions do NOT return "response"
    json_object *choices = nullptr;
    if (!json_object_object_get_ex(root, "choices", &choices) ||
        !json_object_is_type(choices, json_type_array) ||
        json_object_array_length(choices) == 0) {
        /* DEBUG */
        //g_print(json_object_to_json_string(root));
        json_object_put(root);
        return "[!] no choices[] in reply";
    }

    json_object *choice0 = json_object_array_get_idx(choices, 0);
    json_object *message = nullptr;
    json_object *content = nullptr;

    if (!json_object_object_get_ex(choice0, "message", &message) ||
        !json_object_object_get_ex(message, "content", &content)) {
        json_object_put(root);
        return "[!] malformed chat response";
    }

    QString result =
        QString::fromUtf8(json_object_get_string(content));

    json_object_put(root);
    return result.trimmed();
}


static QString sharkai_query_llm_plain_http(
    const char *json_payload,
    void (*on_first_chunk)(void *),
    void *userdata)
{
    const sharkai_config_t *cfg = sharkai_get_config();
    const char *host = cfg->host;
    const int port = cfg->port;
    const char *path = cfg->api_endpoint;

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        return "[!] socket() failed";
    }

    struct addrinfo hints{};
    struct addrinfo *res = nullptr;

    hints.ai_family   = AF_UNSPEC;    // IPv4 or IPv6
    hints.ai_socktype = SOCK_STREAM;

    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", port);

    int rc = getaddrinfo(host, port_str, &hints, &res);
    if (rc != 0) {
        close(sock);
        return QString("[!] DNS resolution failed: %1")
            .arg(gai_strerror(rc));
    }

    int connected = -1;
    for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
        connected = connect(sock, ai->ai_addr, ai->ai_addrlen);
        if (connected == 0)
            break;
    }

    freeaddrinfo(res);

    if (connected != 0) {
        close(sock);
        return QString("[!] connect() failed: %1")
            .arg(strerror(errno));
    }

    /* Build HTTP request */
    QByteArray request;
    request.append("POST ");
    request.append(path);
    request.append(" HTTP/1.1\r\n");

    request.append("Host: ");
    request.append(host);
    request.append(":");
    request.append(QByteArray::number(port));
    request.append("\r\n");

    request.append("Content-Type: application/json\r\n");
    request.append("Content-Length: ");
    request.append(QByteArray::number(strlen(json_payload)));
    request.append("\r\n");
    request.append("Accept: application/json\r\n");
    request.append("User-Agent: SharkAI/1.0\r\n");
    request.append("Connection: close\r\n\r\n");
    request.append(json_payload);

    if (send(sock, request.constData(), request.size(), 0) < 0) {
        close(sock);
        return "[!] send() failed";
    }

    /* ---- STREAMING RESPONSE HANDLER (Ollama/Mistral) ---- */

    QByteArray buffer;
    QString final_response;
    char buf[4096];
    ssize_t n;

    /* First: skip HTTP headers */
    bool headers_done = false;
    bool saw_any_json = false;

    while ((n = recv(sock, buf, sizeof(buf), 0)) > 0) {
        buffer.append(buf, n);

        while (true) {

            /* Strip headers first */
            if (!headers_done) {
                int hdr_end = buffer.indexOf("\r\n\r\n");
                if (hdr_end < 0)
                    break;

                buffer.remove(0, hdr_end + 4);
                headers_done = true;
            }

            /* Ollama sends newline-delimited JSON */
            int nl = buffer.indexOf('\n');
            if (nl < 0)
                break;

            QByteArray line = buffer.left(nl).trimmed();
            buffer.remove(0, nl + 1);

            if (line.isEmpty())
                continue;

            json_object *obj = json_tokener_parse(line.constData());
            if (!obj)
                continue;

            saw_any_json = true;

            json_object *resp = nullptr;
            json_object *done = nullptr;

            if (json_object_object_get_ex(obj, "response", &resp)) {

                // ---- FIRST REAL RESPONSE CHUNK ----
                if (on_first_chunk) {
                    on_first_chunk(userdata);
                    on_first_chunk = nullptr;   // fire once
                }

                final_response +=
                    QString::fromUtf8(json_object_get_string(resp));
            }

            if (json_object_object_get_ex(obj, "done", &done) &&
                json_object_get_boolean(done)) {
                json_object_put(obj);
                close(sock);
                return final_response.trimmed();
            }

            json_object_put(obj);
        }
    }

    /* Socket closed unexpectedly */
    close(sock);

    /* ===================== FALLBACK ===================== */
    /* Single JSON response (non-streaming Ollama behavior) */

    if (!saw_any_json && !buffer.isEmpty()) {

        json_object *obj = json_tokener_parse(buffer.constData());
        if (obj) {

            json_object *resp = nullptr;
            if (json_object_object_get_ex(obj, "response", &resp)) {

                if (on_first_chunk) {
                    on_first_chunk(userdata);
                }

                QString result =
                    QString::fromUtf8(json_object_get_string(resp));

                json_object_put(obj);
                return result.trimmed();
            }

            json_object_put(obj);
        }
    }

    if (final_response.isEmpty()) {
        return "[!] no response received from LLM";
    }

    return final_response.trimmed();

}


static QString sharkai_query_llm_http(
    const char *json_payload,
    void (*on_first_chunk)(void *),
    void *userdata)
{
    const sharkai_config_t *cfg = sharkai_get_config();

    bool uses_https = cfg->uses_https || (cfg->port == 443);

    if (uses_https) {
        // HTTPS path (no streaming callback used yet)
        return sharkai_query_llm_https(json_payload, static_cast<QLabel *>(userdata));
    } else {
        // Plain HTTP streaming path
        return sharkai_query_llm_plain_http(json_payload, on_first_chunk, userdata);
    }
}


static void sharkai_run_query_async(
    QPlainTextEdit *outputEdit,
    QLabel *statusLabel,
    QString payload)
{
    // Disable UI feedback immediately
    outputEdit->setPlainText("[*] Querying LLM…");

    QPointer<QPlainTextEdit> safeEdit(outputEdit);
    QPointer<QLabel> safeLabel(statusLabel);

    QThread *worker = QThread::create([safeEdit, safeLabel, payload]() {

        auto on_first_chunk = [](void *ud) {
            QLabel *label = static_cast<QLabel *>(ud);
            if (!label) return;

            QMetaObject::invokeMethod(
                label,
                [label]() {
                    label->setText("● Responding");
                    label->setStyleSheet("color: green; font-weight: bold;");
                },
                Qt::QueuedConnection
            );
        };

        QString response = sharkai_query_llm_http(
            payload.toUtf8().constData(),
            on_first_chunk,
            safeLabel
        );

        // Marshal final response back to UI thread
        QMetaObject::invokeMethod(
            safeEdit,
            [safeEdit, response]() {
                if (safeEdit)
                    safeEdit->setPlainText(response);
            },
            Qt::QueuedConnection
        );
    });

    QObject::connect(worker, &QThread::finished,
                     worker, &QObject::deleteLater);

    worker->start();
}


static bool sharkai_apply_display_filter(const QString &filter)
{
    if (filter.trimmed().isEmpty()) {
        g_message("Failed to trim");
        return false;
    }

    QMainWindow *mw = nullptr;

    for (QWidget *w : QApplication::topLevelWidgets()) {
        mw = qobject_cast<QMainWindow *>(w);
        if (mw) {
            break;
        }
    }

    if (!mw) {
        g_message("Failed to locate Wireshark main window");
        return false;
    }
    QObject *df = nullptr;

    for (QObject *obj : mw->findChildren<QObject *>()) {
        const char *cls = obj->metaObject()->className();
        if (g_strcmp0(cls, "DisplayFilterEdit") == 0) {
            df = obj;
            break;
        }
    }

    if (!df) {
        g_message("Failed to locate DisplayFilterEdit widget");
        return false;
    }
    // Set text and trigger apply
    QMetaObject::invokeMethod(
        df,
        "setText",
        Q_ARG(QString, filter)
    );

    QMetaObject::invokeMethod(
        df,
        "applyDisplayFilter"
    );

    return true;
}


char *sharkai_filter_dialog_run(const char *title)
{
    const sharkai_config_t *cfg = sharkai_get_config();
    
    const char *model = cfg->model;

    QDialog dlg;
    dlg.setWindowTitle(title ? title : "SharkAI");
    dlg.resize(1000, 600);

    auto *layout = new QVBoxLayout(&dlg);

    auto *statusLabel = new QLabel("● Idle...", &dlg);
    statusLabel->setStyleSheet("color: #000000; font-weight: bold;");
    layout->addWidget(statusLabel);

    layout->addWidget(new QLabel("Prompt", &dlg));
    auto *promptEdit = new QPlainTextEdit(&dlg);
    promptEdit->setPlaceholderText("e.g. show me all dns queries from 192.168.1.10 to any address");
    layout->addWidget(promptEdit);

    layout->addWidget(new QLabel("Response / Output", &dlg));
    auto *outputEdit = new QPlainTextEdit(&dlg);
    outputEdit->setReadOnly(true);
    layout->addWidget(outputEdit);

    auto *btnRow = new QHBoxLayout();
    auto *cancelBtn = new QPushButton("Cancel", &dlg);
    auto *submitBtn = new QPushButton("Submit Input", &dlg);
    auto *applyBtn  = new QPushButton("Apply Filter", &dlg);

    btnRow->addWidget(cancelBtn);
    btnRow->addStretch(1);
    btnRow->addWidget(submitBtn);
    btnRow->addWidget(applyBtn);
    layout->addLayout(btnRow);

    // Return value
    char *result_prompt = NULL;

    QObject::connect(cancelBtn, &QPushButton::clicked, [&]() {
        result_prompt = NULL;
        dlg.reject();
    });

    QObject::connect(submitBtn, &QPushButton::clicked, [&]() {
        const QString prompt_qs = promptEdit->toPlainText();
        const QByteArray prompt_bytes = prompt_qs.toUtf8();

        const char *prompt_c = prompt_bytes.constData();
        if (!prompt_c || prompt_c[0] == '\0') {
            outputEdit->setPlainText("[-] Prompt is empty.");
            return;
        }

        statusLabel->setStyleSheet("color: #ffaa00; font-weight: bold;");
        statusLabel->setText("● Thinking...");

        json_object *payload = sharkai_build_llm_payload(model, prompt_c, SHARKAI_LLM_PAYLOAD_FILTER_STRING);
        const char *json_str = json_object_to_json_string_ext(payload, JSON_C_TO_STRING_PRETTY);

        // Echo to lower pane (no status label in this dialog)
        sharkai_run_query_async(
            outputEdit,
            statusLabel,
            QString::fromUtf8(json_str)
        );

        json_object_put(payload);
    });

    QObject::connect(applyBtn, &QPushButton::clicked, [&]() {
        QString filter = outputEdit->toPlainText().trimmed();

        if (filter.isEmpty()) {
            outputEdit->appendPlainText("\n[!] No filter to apply.");
            return;
        }

        if (!sharkai_apply_display_filter(filter)) {
            outputEdit->appendPlainText("\n[!] Failed to apply display filter.");
            return;
        }

        // Success → close dialog
        dlg.accept();
    });

    dlg.exec();

    // Return whatever is currently in prompt (or NULL if canceled)
    if (dlg.result() == QDialog::Rejected) {
        return NULL;
    }

    const QByteArray final_prompt = promptEdit->toPlainText().toUtf8();
    if (final_prompt.isEmpty()) return NULL;

    return g_strdup(final_prompt.constData());
}

void sharkai_packet_analysis_dialog_run(json_object *packet_data)
{
    if (!packet_data) {
        return;
    }

    const sharkai_config_t *cfg = sharkai_get_config();
    const char *model = cfg->model;

    // ----- Dialog -----
    QDialog dlg;
    dlg.setWindowTitle("SharkAI - Packet Analysis");
    dlg.resize(1000, 600);

    auto *layout = new QVBoxLayout(&dlg);

    auto *statusLabel = new QLabel("● Thinking...", &dlg);
    statusLabel->setStyleSheet("color: #ffaa00; font-weight: bold;");
    layout->addWidget(statusLabel);

    // Label
    layout->addWidget(new QLabel("Response / Output", &dlg));

    // Output pane (copyable, read-only)
    auto *outputEdit = new QPlainTextEdit(&dlg);
    outputEdit->setReadOnly(true);
    outputEdit->setLineWrapMode(QPlainTextEdit::WidgetWidth);
    layout->addWidget(outputEdit);

    // Button row
    auto *btnRow = new QHBoxLayout();
    auto *closeBtn = new QPushButton("Close", &dlg);

    btnRow->addStretch(1);
    btnRow->addWidget(closeBtn);
    layout->addLayout(btnRow);

    QObject::connect(closeBtn, &QPushButton::clicked, [&]() {
        dlg.accept();
    });

    // ----- Build LLM payload from packet JSON -----
    const char *packet_json_str =
        json_object_to_json_string_ext(
            packet_data,
            JSON_C_TO_STRING_PRETTY
        );

    if (!packet_json_str || packet_json_str[0] == '\0') {
        outputEdit->setPlainText("[-] No packet data provided.");
        dlg.exec();
        return;
    }

    json_object *payload =
        sharkai_build_llm_payload(model, packet_json_str, SHARKAI_LLM_PAYLOAD_PACKET_ANALYSIS);

    const char *payload_str =
        json_object_to_json_string_ext(
            payload,
            JSON_C_TO_STRING_PRETTY
        );

    // ----- Send to LLM (async, streaming-safe) -----
    sharkai_run_query_async(
        outputEdit,
        statusLabel,
        QString::fromUtf8(payload_str)
    );

    json_object_put(payload);

    // Modal dialog
    dlg.exec();
}


void sharkai_config_dialog_run(QWidget *parent)
{
    const sharkai_config_t *cfg = sharkai_get_config();

    QDialog dlg(parent);
    dlg.setWindowTitle("SharkAI Configuration");
    dlg.resize(400, 150);

    auto *layout = new QVBoxLayout(&dlg);

    /* Host */
    auto *hostLabel = new QLabel("LLM Host:");
    auto *hostEdit  = new QLineEdit(cfg->host);

    /* Port */
    auto *portLabel = new QLabel("LLM Port:");
    auto *portEdit  = new QSpinBox();
    portEdit->setRange(1, 65535);
    portEdit->setValue(cfg->port);

    /* HTTPS Override */
    auto *httpsCheck = new QCheckBox("Use HTTPS (override model default)");
    httpsCheck->setChecked(false);

    layout->addWidget(hostLabel);
    layout->addWidget(hostEdit);
    layout->addWidget(portLabel);
    layout->addWidget(portEdit);

    /* Model */
    auto *modelLabel = new QLabel("Model:");
    auto *modelCombo = new QComboBox();

    /* Endpoint */
    auto *endpointLabel = new QLabel("API Endpoint:");
    auto *endpointEdit  = new QLineEdit();

    /* API Key */
    auto *apiKeyLabel = new QLabel("API Key:");
    auto *apiKeyEdit  = new QLineEdit();
    apiKeyEdit->setEchoMode(QLineEdit::Password);

    const sharkai_model_info_t *selectedModel = nullptr;

    const sharkai_model_info_t *sharkai_models =
        sharkai_get_models();

    for (int i = 0; sharkai_models[i].name; i++) {
        modelCombo->addItem(sharkai_models[i].name);

        if (strcmp(sharkai_models[i].name, cfg->model) == 0) {
            modelCombo->setCurrentIndex(modelCombo->count() - 1);
            selectedModel = &sharkai_models[i];
        }
    }

    if (selectedModel) {
        endpointEdit->setText(selectedModel->api_endpoint);
        apiKeyLabel->setVisible(selectedModel->requires_api_key);
        apiKeyEdit->setVisible(selectedModel->requires_api_key);
    } else {
        endpointEdit->setText("");
        apiKeyLabel->setVisible(false);
        apiKeyEdit->setVisible(false);
    }

    /* Populate host from model domain if present */
    if (selectedModel && selectedModel->domain && selectedModel->domain[0] != '\0') {
        hostEdit->setText(selectedModel->domain);
    }

    apiKeyEdit->setText(cfg->api_key);

    layout->addWidget(modelLabel);
    layout->addWidget(modelCombo);
    layout->addWidget(endpointLabel);
    layout->addWidget(endpointEdit);
    layout->addWidget(apiKeyLabel);
    layout->addWidget(apiKeyEdit);
    layout->addWidget(httpsCheck);

    QObject::connect(modelCombo, &QComboBox::currentTextChanged,
                     [&](const QString &text) {
        const sharkai_model_info_t *info =
            sharkai_get_model_info(text.toUtf8().constData());

        if (!info)
            return;

        /* Update host from model domain */
        if (info->domain && info->domain[0] != '\0') {
            hostEdit->setText(info->domain);
        }

        endpointEdit->setText(info->api_endpoint);
        apiKeyLabel->setVisible(info->requires_api_key);
        apiKeyEdit->setVisible(info->requires_api_key);

        if (!info->requires_api_key) {
            apiKeyEdit->clear();
        }
    });

    /* Buttons */
    auto *btnRow = new QHBoxLayout();
    auto *cancelBtn = new QPushButton("Cancel");
    auto *saveBtn   = new QPushButton("Save");

    btnRow->addStretch(1);
    btnRow->addWidget(cancelBtn);
    btnRow->addWidget(saveBtn);
    layout->addLayout(btnRow);

    QObject::connect(cancelBtn, &QPushButton::clicked,
                     &dlg, &QDialog::reject);

    QObject::connect(saveBtn, &QPushButton::clicked, [&]() {
        sharkai_set_config(
            hostEdit->text().toUtf8().constData(),
            portEdit->value(),
            modelCombo->currentText().toUtf8().constData(),
            apiKeyEdit->text().toUtf8().constData(),
            endpointEdit->text().toUtf8().constData(),
            httpsCheck->isChecked()
        );
        dlg.accept();
    });

    /* Force Qt to compute final size */
    dlg.adjustSize();

    /* Determine centering target */
    QRect target;

    if (parent) {
        target = parent->frameGeometry();
    } else {
        target = QGuiApplication::primaryScreen()->availableGeometry();
    }

    /* Center dialog */
    dlg.move(
        target.center() - dlg.frameGeometry().center()
    );

    dlg.exec();
}


static QWidget *sharkai_find_ws_main_window()
{
    // Best: whatever window is currently active (usually Wireshark main)
    if (QWidget *aw = QApplication::activeWindow())
        return aw->window();

    // Fallback: find a QMainWindow among top-levels
    for (QWidget *w : QApplication::topLevelWidgets()) {
        if (auto *mw = qobject_cast<QMainWindow *>(w))
            return mw;
    }

    // Last resort: first top-level window
    const auto tops = QApplication::topLevelWidgets();
    if (!tops.isEmpty())
        return tops.first();

    return nullptr;
}


extern "C" void sharkai_config_dialog_run_c(void)
{
    QWidget *parent = sharkai_find_ws_main_window();

    sharkai_config_dialog_run(parent);
}