#include "TunnelSettings.hpp"

#include "L10n.hpp"

#include <QCoreApplication>
#include <QSettings>

namespace tunnel {

namespace {

const char* const kLanguage = "settings/language";
const char* const kNotifyLost = "settings/notifyLost";
const char* const kNotifyDaemon = "settings/notifyDaemon";
const char* const kNotifyConnected = "settings/notifyConnected";
const char* const kDemoMode = "settings/demoMode";
const char* const kLastSeenVersion = "settings/lastSeenVersion";
const char* const kOnboardingDone = "settings/onboardingDone";

} // namespace

TunnelSettings* TunnelSettings::instance()
{
    static TunnelSettings* one = 0;
    if (one == 0) {
        one = new TunnelSettings();
        one->setParent(QCoreApplication::instance());
    }
    return one;
}

TunnelSettings::TunnelSettings() :
        QObject(0)
{
    const Saved s = saved();
    m_language = s.language;
    m_notifyLost = s.notifyLost;
    m_notifyDaemon = s.notifyDaemon;
    m_notifyConnected = s.notifyConnected;
    m_demoMode = s.demoMode;
    QSettings settings;
    m_lastSeenVersion = settings.value(QString::fromLatin1(kLastSeenVersion)).toString();
    m_onboardingDone = settings.value(QString::fromLatin1(kOnboardingDone), false).toBool();
}

TunnelSettings::Saved TunnelSettings::saved()
{
    QSettings settings;
    // What the other process wrote since this one last looked.
    settings.sync();
    Saved s;
    s.language = settings.value(QString::fromLatin1(kLanguage), QString::fromLatin1("system")).toString();
    s.notifyLost = settings.value(QString::fromLatin1(kNotifyLost), true).toBool();
    s.notifyDaemon = settings.value(QString::fromLatin1(kNotifyDaemon), true).toBool();
    s.notifyConnected = settings.value(QString::fromLatin1(kNotifyConnected), false).toBool();
    s.demoMode = settings.value(QString::fromLatin1(kDemoMode), false).toBool();
    return s;
}

void TunnelSettings::save(const char* key, const QVariant& value)
{
    QSettings settings;
    settings.setValue(QString::fromLatin1(key), value);
    // On disk now: the service reads the file, not this process's cache.
    settings.sync();
}

void TunnelSettings::setLanguage(const QString& language)
{
    if (language == m_language) {
        return;
    }
    m_language = language;
    save(kLanguage, language);
    emit languageChanged(language);
}

void TunnelSettings::setNotifyLost(bool on)
{
    if (on == m_notifyLost) {
        return;
    }
    m_notifyLost = on;
    save(kNotifyLost, on);
    emit notificationsChanged();
}

void TunnelSettings::setNotifyDaemon(bool on)
{
    if (on == m_notifyDaemon) {
        return;
    }
    m_notifyDaemon = on;
    save(kNotifyDaemon, on);
    emit notificationsChanged();
}

void TunnelSettings::setNotifyConnected(bool on)
{
    if (on == m_notifyConnected) {
        return;
    }
    m_notifyConnected = on;
    save(kNotifyConnected, on);
    emit notificationsChanged();
}

void TunnelSettings::setDemoMode(bool on)
{
    if (on == m_demoMode) {
        return;
    }
    m_demoMode = on;
    save(kDemoMode, on);
    emit demoModeChanged();
}

void TunnelSettings::setLastSeenVersion(const QString& version)
{
    if (version == m_lastSeenVersion) {
        return;
    }
    m_lastSeenVersion = version;
    save(kLastSeenVersion, version);
    emit lastSeenVersionChanged();
}

void TunnelSettings::setOnboardingDone(bool done)
{
    if (done == m_onboardingDone) {
        return;
    }
    m_onboardingDone = done;
    save(kOnboardingDone, done);
    emit onboardingDoneChanged();
}

QVariantList TunnelSettings::supportedLanguages() const
{
    return bbshared::L10n::languages();
}

QString TunnelSettings::languageName(const QString& code) const
{
    return bbshared::L10n::nativeNameFor(code);
}

} // namespace tunnel
