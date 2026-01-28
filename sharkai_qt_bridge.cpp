#include <QApplication>
#include <QAbstractItemView>
#include <QHeaderView>
#include <QItemSelectionModel>
#include <QModelIndexList>
#include <QVariant>
#include <QString>

#include <glib.h>   // g_malloc / g_free
#include <stdint.h>
#include <stddef.h>

static bool modelLooksLikePacketList(QAbstractItemModel *m)
{
    if (!m) return false;
    if (m->columnCount() < 1) return false;

    // Heuristic: column 0 header is typically "No." in Wireshark
    QVariant hdr = m->headerData(0, Qt::Horizontal, Qt::DisplayRole);
    if (!hdr.isValid()) return false;

    const QString h = hdr.toString().trimmed();
    if (h != "No." && h != "No") return false;

    // Another cheap heuristic: must have some rows when capture loaded
    // (If empty capture, selection will be empty anyway.)
    return true;
}

static QAbstractItemView *findPacketListView(QWidget *root)
{
    if (!root) return nullptr;

    // Search common view base class; PacketList is a view subclass internally.
    const auto views = root->findChildren<QAbstractItemView *>();
    for (QAbstractItemView *v : views) {
        if (!v) continue;
        QAbstractItemModel *m = v->model();
        if (!modelLooksLikePacketList(m)) continue;

        // Must have selection model
        if (!v->selectionModel()) continue;

        return v;
    }
    return nullptr;
}

extern "C" uint32_t *
sharkai_qt_get_selected_frames(size_t *count)
{
    if (!count) return nullptr;
    *count = 0;

    QWidget *w = QApplication::activeWindow();
    if (!w) return nullptr;

    QAbstractItemView *view = findPacketListView(w);
    if (!view) return nullptr;

    QItemSelectionModel *sel = view->selectionModel();
    if (!sel) return nullptr;

    // Selected rows in *this view's model coordinates*
    const QModelIndexList rows = sel->selectedRows(0); // column 0 = "No."
    if (rows.isEmpty()) return nullptr;

    uint32_t *frames = (uint32_t *)g_malloc(sizeof(uint32_t) * rows.size());
    size_t out = 0;

    QAbstractItemModel *m = view->model();
    for (const QModelIndex &idx : rows) {
        if (!idx.isValid()) continue;

        QVariant v = m->data(idx, Qt::DisplayRole);
        if (!v.isValid()) continue;

        bool ok = false;
        uint32_t n = v.toString().trimmed().toUInt(&ok, 10);
        if (!ok || n == 0) continue;

        frames[out++] = n;
    }

    if (out == 0) {
        g_free(frames);
        return nullptr;
    }

    *count = out;
    return frames;
}
