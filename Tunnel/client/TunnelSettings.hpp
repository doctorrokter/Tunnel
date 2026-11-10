/*
 * TunnelSettings - what the app keeps for itself and shares with the service (the context property
 * "settings"; docs/APP.md, sections 6 and 11). QSettings group "settings", in the one file both
 * processes open (main.cpp gives them the same names - KB 7.2).
 *
 *   language          "system" | "en" | "ru" | ... - a code bb-shared L10n ships a catalog for; the
 *                     same API as BBHealth's and Syno's, so their LanguageSettingsPage is used as is
 *   notifyLost        the service tells "connection lost" (on)
 *   notifyDaemon      ... "the tunnel service does not answer" (on)
 *   notifyConnected   ... keeps "connected" in the Hub while a tunnel is up (off)
 *   demoMode          the demo daemon instead of the real one (development builds; on the simulator
 *                     always). The service reads it too: in demo it expects no daemon
 *   lastSeenVersion   the app version "What's new" was last shown for
 *   onboardingDone    the setup guide was gone through or skipped: no more at the start
 *
 * The profiles and always-on are not here: the daemon keeps them (APP.md, section 2).
 *
 * The service reads saved() - afresh from the file on every decision: QSettings caches its file per
 * process, and the app may have written since.
 */

#ifndef TUNNEL_TUNNELSETTINGS_HPP_
#define TUNNEL_TUNNELSETTINGS_HPP_

#include <QObject>
#include <QString>
#include <QVariantList>

namespace tunnel {

class TunnelSettings: public QObject
{
    Q_OBJECT
    Q_PROPERTY(QString language READ language WRITE setLanguage NOTIFY languageChanged)
    Q_PROPERTY(bool notifyLost READ notifyLost WRITE setNotifyLost NOTIFY notificationsChanged)
    Q_PROPERTY(bool notifyDaemon READ notifyDaemon WRITE setNotifyDaemon NOTIFY notificationsChanged)
    Q_PROPERTY(bool notifyConnected READ notifyConnected WRITE setNotifyConnected NOTIFY notificationsChanged)
    Q_PROPERTY(bool demoMode READ demoMode WRITE setDemoMode NOTIFY demoModeChanged)
    Q_PROPERTY(QString lastSeenVersion READ lastSeenVersion WRITE setLastSeenVersion NOTIFY lastSeenVersionChanged)
    Q_PROPERTY(bool onboardingDone READ onboardingDone WRITE setOnboardingDone NOTIFY onboardingDoneChanged)
public:
    // The saved settings as they are in the file right now (the service's view).
    struct Saved {
        Saved() : notifyLost(true), notifyDaemon(true), notifyConnected(false), demoMode(false) {}
        QString language;
        bool notifyLost;
        bool notifyDaemon;
        bool notifyConnected;
        bool demoMode;
    };

    // The process's one instance, created on first use (parented to qApp).
    static TunnelSettings* instance();
    static Saved saved();

    QString language() const { return m_language; }
    void setLanguage(const QString& language);
    bool notifyLost() const { return m_notifyLost; }
    void setNotifyLost(bool on);
    bool notifyDaemon() const { return m_notifyDaemon; }
    void setNotifyDaemon(bool on);
    bool notifyConnected() const { return m_notifyConnected; }
    void setNotifyConnected(bool on);
    bool demoMode() const { return m_demoMode; }
    void setDemoMode(bool on);
    QString lastSeenVersion() const { return m_lastSeenVersion; }
    void setLastSeenVersion(const QString& version);
    bool onboardingDone() const { return m_onboardingDone; }
    void setOnboardingDone(bool done);

    // [{ code, name }] - the languages the app ships a catalog for (bb-shared L10n).
    Q_INVOKABLE QVariantList supportedLanguages() const;
    // A language in its own name ("Русский").
    Q_INVOKABLE QString languageName(const QString& code) const;

Q_SIGNALS:
    void languageChanged(const QString& language);
    void notificationsChanged();
    void demoModeChanged();
    void lastSeenVersionChanged();
    void onboardingDoneChanged();

private:
    TunnelSettings();
    void save(const char* key, const QVariant& value);

    QString m_language;
    bool m_notifyLost;
    bool m_notifyDaemon;
    bool m_notifyConnected;
    bool m_demoMode;
    QString m_lastSeenVersion;
    bool m_onboardingDone;
};

} // namespace tunnel

#endif /* TUNNEL_TUNNELSETTINGS_HPP_ */
