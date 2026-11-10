/*
 * Notifier - the service's Hub notifications (docs/APP.md, section 11), from what the daemon says:
 *   - "Connection lost: Home" - reconnecting, an error, or a connection that does not come (a reason
 *     while connecting) for longer than 30 s; a switch of networks is shorter and never shown. When
 *     the tunnel is back, "Connected: Home" in its place; either goes when the tunnel is turned off
 *     or its profile deleted. notifyLost, on by default.
 *   - "The tunnel service does not answer" - the daemon's socket gone and not back within 60 s, or
 *     not there 2 min after the service started. notifyDaemon, on. Not in the demo mode: there is no
 *     daemon to miss then.
 *   - "Tunnel on" - one silent entry while any tunnel is up (BB10 shows no VPN mark for a tunnel of
 *     ours), gone when none is - or the daemon is. notifyConnected, off.
 * One key per profile: a new state replaces the old entry, the Hub does not fill up. A tap opens the
 * app on that profile. The texts are in the app's language (Settings > Language), read at the
 * moment of saying, as the settings are: the app writes them, this process only reads.
 */

#ifndef TUNNEL_NOTIFIER_HPP_
#define TUNNEL_NOTIFIER_HPP_

#include <QHash>
#include <QObject>
#include <QSet>
#include <QString>

class QFileSystemWatcher;
class QTimer;
class QTranslator;

namespace tunnel {

class DaemonClient;
class Profile;
class ProfileList;

class Notifier: public QObject
{
    Q_OBJECT
public:
    Notifier(DaemonClient* client, ProfileList* profiles, QObject* parent = 0);

    // The clock for "does not answer" starts now (the service has just started).
    void start();

private Q_SLOTS:
    void evaluate();
    void onConnectedChanged();
    void checkDaemon();
    void onSettingsTouched();

private:
    void post(const QString& key, const QString& title, const QString& body, const QString& profileId,
            bool quiet);
    void drop(const QString& key);
    void updateIndicator();
    void useAppLanguage();
    QString reasonText(const QString& reason) const;
    static QString keyFor(const QString& profileId);

    DaemonClient* m_client;
    ProfileList* m_profiles;
    QTimer* m_lostTimer;
    QTimer* m_daemonTimer;
    QFileSystemWatcher* m_watcher;
    QTranslator* m_translator;
    // Profiles in trouble since (ms); "lost" is in the Hub for these; a notice of theirs is (lost, or
    // "connected" in its place); these were up in this run.
    QHash<QString, qint64> m_troubleSince;
    QSet<QString> m_lostShown;
    QSet<QString> m_shown;
    QSet<QString> m_wasUp;
    bool m_daemonShown;
    QString m_indicator;
};

} // namespace tunnel

#endif /* TUNNEL_NOTIFIER_HPP_ */
