#include "Importer.hpp"
#include "AmneziaKey.hpp"

#include <bb/device/HardwareInfo>
#include <bb/system/Clipboard>

#include <QFile>
#include <QFileInfo>
#include <QStringList>
#include <QUrl>
#include <QDebug>

namespace tunnel {

namespace {

// The daemon's limit for a .conf (bt_store.h, BT_CONF_MAX).
const qint64 kConfMax = 192 * 1024;
// And for a profile's name (BT_NAME_MAX): bytes of UTF-8.
const int kNameMax = 64;

// At most kNameMax bytes of UTF-8, never cutting a character in two.
QString fitName(const QString& name)
{
    QString out = name.trimmed();
    while (out.toUtf8().size() > kNameMax) {
        out.chop(1);
    }
    return out;
}

} // namespace

Importer::Importer(QObject* parent) :
        QObject(parent),
        m_qrTotal(0)
{
}

void Importer::setError(const QString& error)
{
    if (error != m_lastError) {
        m_lastError = error;
        emit lastErrorChanged();
    }
}

QString Importer::localPath(const QString& pathOrUri)
{
    if (pathOrUri.startsWith(QLatin1String("file://"))) {
        // Encoded as the invocation framework sends it: parse it as such, or %20 is decoded twice
        // (KB: Qt 4 QUrl double encoding).
        return QUrl::fromEncoded(pathOrUri.toUtf8()).toLocalFile();
    }
    return pathOrUri;
}

QString Importer::readFile(const QString& pathOrUri)
{
    const QString path = localPath(pathOrUri);
    QFile file(path);
    if (!file.exists()) {
        setError(QString::fromLatin1("missing"));
        return QString();
    }
    if (file.size() > kConfMax) {
        setError(QString::fromLatin1("large"));
        return QString();
    }
    if (!file.open(QIODevice::ReadOnly)) {
        qWarning() << "[import] cannot open" << path << file.errorString();
        setError(QString::fromLatin1("unreadable"));
        return QString();
    }
    const QByteArray data = file.readAll();
    file.close();
    if (data.contains('\0')) {
        setError(QString::fromLatin1("binary"));
        return QString();
    }
    setError(QString());
    return QString::fromUtf8(data.constData(), data.size());
}

QString Importer::clipboardText() const
{
    bb::system::Clipboard clipboard;
    const QByteArray data = clipboard.value(QString::fromLatin1("text/plain"));
    return QString::fromUtf8(data.constData(), data.size());
}

QString Importer::fileName(const QString& pathOrUri) const
{
    return QFileInfo(localPath(pathOrUri)).fileName();
}

QString Importer::nameFromFile(const QString& pathOrUri) const
{
    return fitName(QFileInfo(localPath(pathOrUri)).completeBaseName());
}

QString Importer::nameFromConf(const QString& text) const
{
    const QStringList lines = text.split(QLatin1Char('\n'));
    for (int i = 0; i < lines.size(); ++i) {
        const QString line = lines.at(i).trimmed();
        if (!line.startsWith(QLatin1String("Endpoint"), Qt::CaseInsensitive)) {
            continue;
        }
        const int eq = line.indexOf(QLatin1Char('='));
        if (eq < 0 || line.left(eq).trimmed().compare(QLatin1String("Endpoint"), Qt::CaseInsensitive) != 0) {
            continue;
        }
        QString host = line.mid(eq + 1).trimmed();
        if (host.startsWith(QLatin1Char('['))) {
            host = host.mid(1, host.indexOf(QLatin1Char(']')) - 1);         // [2001:db8::1]:51820
        } else if (host.contains(QLatin1Char(':'))) {
            host = host.left(host.lastIndexOf(QLatin1Char(':')));         // host:51820
        }
        return fitName(host);
    }
    return QString();
}

int Importer::lineCount(const QString& text) const
{
    return text.trimmed().isEmpty() ? 0 : text.trimmed().count(QLatin1Char('\n')) + 1;
}

QString Importer::kind(const QString& text) const
{
    const QString t = text.trimmed();
    if (t.startsWith(QLatin1String("vpn://"), Qt::CaseInsensitive)) {
        return QString::fromLatin1("amnezia-key");
    }
    if (t.contains(QLatin1String("[Interface]"), Qt::CaseInsensitive)) {
        return QString::fromLatin1("conf");
    }
    // One word of the admin console's: no spaces, no lines.
    if (t.startsWith(QLatin1String("tskey-")) && !t.contains(QLatin1Char(' ')) && !t.contains(QLatin1Char('\n'))) {
        return QString::fromLatin1("tailscale-key");
    }
    return QString::fromLatin1("other");
}

QString Importer::deviceHostname() const
{
    bb::device::HardwareInfo hw;
    const QString model = hw.modelName().toLower().trimmed();
    QString out;
    bool dash = false;

    // "BlackBerry Passport" -> "passport": the brand says nothing in a tailnet of BlackBerries.
    QString m = model;
    if (m.startsWith(QLatin1String("blackberry"))) {
        m = m.mid(10).trimmed();
    }
    for (int i = 0; i < m.size() && out.size() < 63; ++i) {
        const QChar c = m.at(i);
        if ((c >= QLatin1Char('a') && c <= QLatin1Char('z')) || (c >= QLatin1Char('0') && c <= QLatin1Char('9'))) {
            out.append(c);
            dash = false;
        } else if (!out.isEmpty() && !dash) {
            out.append(QLatin1Char('-'));
            dash = true;
        }
    }
    while (out.endsWith(QLatin1Char('-'))) {
        out.chop(1);
    }
    return out.isEmpty() ? QString::fromLatin1("blackberry") : out;
}

QVariantMap Importer::fromAmneziaKey(const QString& text) const
{
    const AmneziaKey::Result r = AmneziaKey::fromText(text);
    QVariantMap out;
    out.insert(QString::fromLatin1("ok"), r.ok);
    out.insert(QString::fromLatin1("conf"), r.conf);
    out.insert(QString::fromLatin1("name"), r.name);
    out.insert(QString::fromLatin1("error"), r.error);
    out.insert(QString::fromLatin1("detail"), r.detail);
    return out;
}

void Importer::qrReset()
{
    m_qrParts.clear();
    m_qrTotal = 0;
}

QVariantMap Importer::qrFeed(const QString& code)
{
    QVariantMap out;
    AmneziaKey::Part part;
    if (!AmneziaKey::parsePart(code, &part)) {
        out.insert(QString::fromLatin1("state"), QString::fromLatin1("text"));
        out.insert(QString::fromLatin1("text"), code);
        return out;
    }
    // The camera sees the same part over and over, and another series may come into view: a
    // different count starts afresh.
    if (part.total != m_qrTotal) {
        m_qrParts.clear();
        m_qrTotal = part.total;
    }
    m_qrParts.insert(part.index, part.data);
    if (m_qrParts.size() < m_qrTotal) {
        out.insert(QString::fromLatin1("state"), QString::fromLatin1("part"));
        out.insert(QString::fromLatin1("received"), m_qrParts.size());
        out.insert(QString::fromLatin1("total"), m_qrTotal);
        return out;
    }
    QByteArray all;
    for (int i = 0; i < m_qrTotal; ++i) {
        all += m_qrParts.value(i);
    }
    qrReset();
    out.insert(QString::fromLatin1("state"), QString::fromLatin1("text"));
    out.insert(QString::fromLatin1("text"), AmneziaKey::keyText(all));
    return out;
}

} // namespace tunnel
