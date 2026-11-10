#include "Changelog.hpp"
#include "TunnelSettings.hpp"

#include "L10n.hpp"

#include <bb/data/JsonDataAccess>

#include <QDebug>
#include <QStringList>

namespace tunnel {

Changelog::Changelog(QObject* parent) :
        QObject(parent)
{
    // A language switch in Settings re-reads the notes, so the next "What's new" is in the new
    // language without a restart.
    connect(TunnelSettings::instance(), SIGNAL(languageChanged(QString)), this, SLOT(reload()));
    load();
}

void Changelog::load()
{
    m_entries.clear();
    // A SUPPORTED code via the shared registry ("system" -> the device's, unsupported -> "en").
    const QString code = bbshared::L10n::resolve(TunnelSettings::instance()->language());

    // The language's own file first (changelog_ru.json, ...). A missing one only means "no
    // translation for this language" - English then.
    if (code != QLatin1String("en")) {
        bb::data::JsonDataAccess json;
        const QVariant root = json.load(QString::fromLatin1("app/native/assets/changelog_%1.json").arg(code));
        if (!json.hasError()) {
            m_entries = root.toList();
            qDebug() << "[changelog] loaded" << m_entries.size() << "entries (changelog_" << code << ".json)";
            return;
        }
    }

    bb::data::JsonDataAccess json;
    const QVariant root = json.load(QString::fromLatin1("app/native/assets/changelog.json"));
    if (json.hasError()) {
        qWarning() << "[changelog] load failed:" << json.error().errorMessage();
        return;
    }
    m_entries = root.toList();
    qDebug() << "[changelog] loaded" << m_entries.size() << "entries (changelog.json)";
}

void Changelog::reload()
{
    load();
}

QVariantList Changelog::all() const
{
    return m_entries;
}

QVariantList Changelog::since(const QString& fromVersion) const
{
    if (fromVersion.isEmpty()) {
        return QVariantList();
    }
    QVariantList out;
    for (int i = 0; i < m_entries.size(); ++i) {
        const QVariantMap entry = m_entries.at(i).toMap();
        if (compareVersions(entry.value("version").toString(), fromVersion) > 0) {
            out.append(entry);
        }
    }
    return out;
}

int Changelog::compareVersions(const QString& a, const QString& b)
{
    const QStringList pa = a.split(QLatin1Char('.'));
    const QStringList pb = b.split(QLatin1Char('.'));
    const int n = qMax(pa.size(), pb.size());
    for (int i = 0; i < n; ++i) {
        const int va = i < pa.size() ? pa.at(i).toInt() : 0;
        const int vb = i < pb.size() ? pb.at(i).toInt() : 0;
        if (va != vb) {
            return va < vb ? -1 : 1;
        }
    }
    return 0;
}

} // namespace tunnel
