/*
 * bb-shared / ui / SharedClipboard.cpp - see SharedClipboard.hpp.
 */
#include "SharedClipboard.hpp"

#include <bb/system/Clipboard>

#include <QDebug>

namespace bbshared {

SharedClipboard::SharedClipboard(QObject* parent) :
        QObject(parent)
{
}

bool SharedClipboard::copy(const QString& text)
{
    bb::system::Clipboard clipboard;
    clipboard.clear();
    const bool ok = clipboard.insert(QString::fromLatin1("text/plain"), text.toUtf8());
    if (!ok) {
        qWarning() << "[bb-shared] clipboard: copy failed";
    }
    return ok;
}

} // namespace bbshared
