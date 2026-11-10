#include "Notifier.hpp"
#include "DaemonClient.hpp"
#include "Profiles.hpp"
#include "RootAutostart.hpp"
#include "TunnelSettings.hpp"

#include "L10n.hpp"

#include <bb/platform/Notification>
#include <bb/platform/NotificationDefaultApplicationSettings>
#include <bb/platform/NotificationError>
#include <bb/platform/NotificationPolicy>
#include <bb/platform/NotificationPriorityPolicy>
#include <bb/platform/NotificationType>
#include <bb/system/InvokeRequest>

#include <QDateTime>
#include <QDir>
#include <QFileInfo>
#include <QFileSystemWatcher>
#include <QSettings>
#include <QStringList>
#include <QTimer>
#include <QTranslator>
#include <QDebug>

namespace tunnel {

namespace {

// Trouble shorter than this is a switch of networks: not worth a word.
const qint64 kLostAfterMs = 30 * 1000;
// The daemon gone this long, or not there this long after the service started.
const int kDaemonGoneMs = 60 * 1000;
const int kDaemonAtStartMs = 120 * 1000;
// From the boot hook the daemon starts when root comes up: up to about 15 minutes after a boot.
const int kDaemonAtStartFromHookMs = 16 * 60 * 1000;

const char* const kDaemonKey = "tunnel_daemon";
const char* const kIndicatorKey = "tunnel_on";

qint64 nowMs()
{
    return QDateTime::currentMSecsSinceEpoch();
}

} // namespace

Notifier::Notifier(DaemonClient* client, ProfileList* profiles, QObject* parent) :
        QObject(parent),
        m_client(client),
        m_profiles(profiles),
        m_lostTimer(new QTimer(this)),
        m_daemonTimer(new QTimer(this)),
        m_watcher(new QFileSystemWatcher(this)),
        m_translator(new QTranslator(this)),
        m_daemonShown(false)
{
    m_lostTimer->setSingleShot(true);
    connect(m_lostTimer, SIGNAL(timeout()), this, SLOT(evaluate()));
    m_daemonTimer->setSingleShot(true);
    connect(m_daemonTimer, SIGNAL(timeout()), this, SLOT(checkDaemon()));

    connect(client, SIGNAL(connectedChanged()), this, SLOT(onConnectedChanged()));
    connect(profiles, SIGNAL(stateChanged(QObject*, const QString&)), this, SLOT(evaluate()));
    // A reason alone moves no state: "connecting" that never comes gains "handshake" and stays.
    connect(profiles, SIGNAL(profileChanged(QObject*)), this, SLOT(evaluate()));
    connect(profiles, SIGNAL(listChanged()), this, SLOT(evaluate()));
    connect(profiles, SIGNAL(loadedChanged()), this, SLOT(evaluate()));

    // The app changed a setting (a switch in Settings > Notifications): acted on now, not at the next
    // event. QSettings replaces its file on a write, so the folder is watched, not the file - made
    // first: after an install the service may start before the app ever wrote a setting, and a
    // folder that is not there cannot be watched.
    const QString dir = QFileInfo(QSettings().fileName()).absolutePath();
    if (!dir.isEmpty() && QDir().mkpath(dir)) {
        m_watcher->addPath(dir);
        connect(m_watcher, SIGNAL(directoryChanged(const QString&)), this, SLOT(onSettingsTouched()));
    }

    // Seen, and shown for a moment on top - as the other apps of ours set it.
    bb::platform::NotificationDefaultApplicationSettings defaults;
    defaults.setLed(bb::platform::NotificationPolicy::Allow);
    defaults.setPreview(bb::platform::NotificationPriorityPolicy::Allow);
    defaults.apply();
}

void Notifier::start()
{
    if (RootAutostart::hookInstalled()) {
        m_daemonTimer->start(kDaemonAtStartFromHookMs);
    } else {
        m_daemonTimer->start(kDaemonAtStartMs);
    }
}

QString Notifier::keyFor(const QString& profileId)
{
    return QString::fromLatin1("tunnel_") + profileId;
}

void Notifier::useAppLanguage()
{
    bbshared::L10n::installTranslator(m_translator, TunnelSettings::saved().language);
}

void Notifier::onSettingsTouched()
{
    evaluate();
    if (!m_client->connected()) {
        checkDaemon();
    }
}

void Notifier::onConnectedChanged()
{
    if (m_client->connected()) {
        m_daemonTimer->stop();
        if (m_daemonShown) {
            drop(QString::fromLatin1(kDaemonKey));
            m_daemonShown = false;
        }
        return;
    }
    // Gone: what the tunnels do is unknown until it is back - their own words wait. But no tunnel
    // runs without it: "Tunnel on" goes now (a crash says nothing of its tunnels first).
    m_lostTimer->stop();
    m_troubleSince.clear();
    m_daemonTimer->start(kDaemonGoneMs);
    updateIndicator();
}

void Notifier::checkDaemon()
{
    if (m_client->connected() || m_daemonShown) {
        return;
    }
    const TunnelSettings::Saved s = TunnelSettings::saved();
    if (s.demoMode || !s.notifyDaemon) {
        return;
    }
    if (m_daemonTimer->isActive()) {
        return;                 // not yet: the minute (or two) is not over
    }
    useAppLanguage();
    post(QString::fromLatin1(kDaemonKey), tr("The tunnel service does not answer"),
            tr("No tunnel works until it runs again. It starts as root when the phone boots."),
            QString(), false);
    m_daemonShown = true;
}

QString Notifier::reasonText(const QString& reason) const
{
    if (reason == QLatin1String("no_network")) {
        return tr("No network.");
    }
    if (reason == QLatin1String("resolve")) {
        return tr("The server's name is not found.");
    }
    if (reason == QLatin1String("handshake")) {
        return tr("The server does not answer.");
    }
    if (reason == QLatin1String("tun") || reason == QLatin1String("route") || reason == QLatin1String("conf")) {
        return tr("The tunnel could not be set up.");
    }
    // Tailscale.
    if (reason == QLatin1String("control")) {
        return tr("Tailscale's server cannot be reached.");
    }
    if (reason == QLatin1String("relay")) {
        return tr("Tailscale's relay does not answer.");
    }
    if (reason == QLatin1String("approval")) {
        return tr("An admin must approve the device in the Tailscale admin console.");
    }
    if (reason == QLatin1String("login")) {
        return tr("The login was not accepted. Log in again.");
    }
    if (reason == QLatin1String("expired")) {
        return tr("The login expired. Log in again.");
    }
    if (reason == QLatin1String("removed")) {
        return tr("The device was removed from the tailnet. Log in again.");
    }
    if (reason == QLatin1String("browser")) {
        return tr("The login link and its QR code are on the profile's page in Tunnel.");
    }
    return tr("Reconnecting.");
}

void Notifier::evaluate()
{
    if (!m_client->connected() || !m_profiles->loaded()) {
        return;
    }
    const TunnelSettings::Saved s = TunnelSettings::saved();
    const qint64 now = nowMs();
    const QList<Profile*> list = m_profiles->profiles();
    QSet<QString> present;
    bool translated = false;

    for (int i = 0; i < list.size(); ++i) {
        Profile* p = list.at(i);
        const QString id = p->id();
        const QString state = p->state();
        present.insert(id);
        // In trouble: reconnecting, an error, or a connection that does not come. A refused second
        // "all traffic" profile is the user's own doing, and the app says it.
        const bool trouble = (state == QLatin1String("reconnecting") || state == QLatin1String("error")
                || (state == QLatin1String("connecting") && !p->reason().isEmpty()))
                && p->reason() != QLatin1String("conflict");
        if (trouble) {
            if (!m_troubleSince.contains(id)) {
                m_troubleSince.insert(id, now);
            } else if (now - m_troubleSince.value(id) >= kLostAfterMs && !m_lostShown.contains(id)
                    && s.notifyLost) {
                if (!translated) {
                    useAppLanguage();
                    translated = true;
                }
                // A login link waiting is no failure: the user has something to do.
                const QString title = p->reason() == QLatin1String("browser")
                        ? tr("Log in: %1").arg(p->name())
                        : (m_wasUp.contains(id)
                                ? tr("Connection lost: %1").arg(p->name())
                                : tr("Cannot connect: %1").arg(p->name()));
                post(keyFor(id), title, reasonText(p->reason()), id, false);
                m_lostShown.insert(id);
                m_shown.insert(id);
            }
            continue;
        }
        m_troubleSince.remove(id);
        if (state == QLatin1String("up")) {
            m_wasUp.insert(id);
            if (m_lostShown.contains(id)) {
                if (!translated) {
                    useAppLanguage();
                    translated = true;
                }
                // Good news in the bad news' place - quietly.
                post(keyFor(id), tr("Connected: %1").arg(p->name()), tr("The tunnel works again."), id, true);
                m_lostShown.remove(id);
            }
        } else if (state == QLatin1String("down")) {
            // Turned off: whatever was said about it is over - the bad news or the good.
            m_wasUp.remove(id);
            if (m_shown.contains(id)) {
                drop(keyFor(id));
                m_shown.remove(id);
                m_lostShown.remove(id);
            }
        }
    }

    // Profiles deleted meanwhile.
    const QList<QString> shown = m_shown.toList();
    for (int i = 0; i < shown.size(); ++i) {
        if (!present.contains(shown.at(i))) {
            drop(keyFor(shown.at(i)));
            m_shown.remove(shown.at(i));
            m_lostShown.remove(shown.at(i));
            m_troubleSince.remove(shown.at(i));
        }
    }

    // Woken when the next trouble's 30 s are over, to say it then - not at the next tick of a coarse
    // periodic timer, which may come a little early and leave it for one more round.
    qint64 due = -1;
    QHash<QString, qint64>::const_iterator it = m_troubleSince.constBegin();
    for (; it != m_troubleSince.constEnd(); ++it) {
        if (m_lostShown.contains(it.key())) {
            continue;
        }
        const qint64 at = it.value() + kLostAfterMs;
        // Past due and still not said: "Connection lost" is off - the settings' watcher wakes us.
        if (at <= now) {
            continue;
        }
        if (due < 0 || at < due) {
            due = at;
        }
    }
    if (due < 0) {
        m_lostTimer->stop();
    } else {
        m_lostTimer->start((int)qMax((qint64)0, due - now) + 50);
    }
    updateIndicator();
}

void Notifier::updateIndicator()
{
    const TunnelSettings::Saved s = TunnelSettings::saved();
    QStringList names;
    const QList<Profile*> list = m_profiles->profiles();
    for (int i = 0; i < list.size(); ++i) {
        if (list.at(i)->state() == QLatin1String("up")) {
            names.append(list.at(i)->name());
        }
    }
    const QString text = (s.notifyConnected && m_client->connected()) ? names.join(QString::fromLatin1(", ")) : QString();
    if (text == m_indicator) {
        return;
    }
    m_indicator = text;
    if (text.isEmpty()) {
        drop(QString::fromLatin1(kIndicatorKey));
        return;
    }
    useAppLanguage();
    post(QString::fromLatin1(kIndicatorKey), tr("Tunnel on"), text, QString(), true);
}

void Notifier::post(const QString& key, const QString& title, const QString& body, const QString& profileId,
        bool quiet)
{
    bb::platform::Notification notice(key);
    notice.setTitle(title);
    notice.setBody(body);
    if (quiet) {
        notice.setType(bb::platform::NotificationType::AllAlertsOff);
    }
    // A tap opens the app - on the profile, when there is one (ApplicationUI::onInvoked).
    bb::system::InvokeRequest open;
    open.setTarget(QString::fromLatin1("doctorrokter.BBTunnel"));
    if (!profileId.isEmpty()) {
        open.setAction(QString::fromLatin1("doctorrokter.BBTunnel.OPENPROFILE"));
        open.setMimeType(QString::fromLatin1("text/plain"));
        open.setData(profileId.toUtf8());
    }
    notice.setInvokeRequest(open);
    const bb::platform::NotificationError::Type error = notice.notify();
    if (error != bb::platform::NotificationError::None) {
        qWarning() << "[notify]" << key << "did not reach the Hub:" << error;
    } else {
        qDebug() << "[notify]" << key << title;
    }
}

void Notifier::drop(const QString& key)
{
    bb::platform::Notification::deleteFromInbox(key);
    qDebug() << "[notify]" << key << "gone";
}

} // namespace tunnel
