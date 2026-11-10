/*
 * Copyright (c) 2013-2015 BlackBerry Limited.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "applicationui.hpp"
#include "BbSharedDimens.hpp"
#include "BbSharedUi.hpp"
#include "L10n.hpp"
#include "DaemonClient.hpp"
#include "Profiles.hpp"
#include "TunnelSettings.hpp"
#include "gui/Changelog.hpp"
#include "gui/Importer.hpp"

#include <bb/cascades/Application>
#include <bb/cascades/QmlDocument>
#include <bb/cascades/AbstractPane>
#include <bb/cascades/LocaleHandler>
#include <bb/system/InvokeManager>
#include <bb/system/InvokeRequest>

#include <QDeclarativeContext>
#include <QDeclarativeEngine>
#include <QDir>
#include <QFile>
#include <QTranslator>
#include <QUrl>
#include <QDebug>

// Only the cascades namespace is opened: L10n.hpp brings in bb::system::LocaleHandler, so with
// bb::system open as well a bare LocaleHandler would be ambiguous.
using namespace bb::cascades;

ApplicationUI::ApplicationUI() :
        QObject(),
        m_translator(new QTranslator(this)),
        m_localeHandler(new LocaleHandler(this)),
        m_invokeManager(new bb::system::InvokeManager(this)),
        m_client(0),
        m_profiles(0),
        m_visible(true),
        m_statsWanted(false)
{
    // A .conf opened "in Tunnel", a tap on a notification: listened for BEFORE the scene exists, or
    // the startup invocation of a cold start is missed.
    QObject::connect(m_invokeManager, SIGNAL(invoked(const bb::system::InvokeRequest&)),
            this, SLOT(onInvoked(const bb::system::InvokeRequest&)));

    // Language layer first: the shared L10n module builds its language map from the shipped
    // BBTunnel_<code>.qm files (English is the source language and ships none).
    bbshared::L10n::init(QString::fromLatin1("BBTunnel"));

    tunnel::TunnelSettings* settings = tunnel::TunnelSettings::instance();

    // The language follows the setting (Settings > Language), and with "system" the device, live.
    bool ok = QObject::connect(m_localeHandler, SIGNAL(systemLanguageChanged()),
            this, SLOT(onSystemLanguageChanged()));
    Q_ASSERT(ok);
    ok = QObject::connect(settings, SIGNAL(languageChanged(QString)), this, SLOT(onSystemLanguageChanged()));
    Q_ASSERT(ok);
    Q_UNUSED(ok);

    // initial load
    onSystemLanguageChanged();

    // The daemon, or the demo in its place (docs/APP.md, section 12): on the simulator always - it
    // has no daemon; on a phone when Settings > Diagnostics says so. A development build only.
    bool demo = false;
#ifdef TUNNEL_DEMO
#if defined(__X86__) || defined(__i386__)
    // The service reads it too: in demo it expects no daemon.
    settings->setDemoMode(true);
#endif
    demo = settings->demoMode();
#else
    if (settings->demoMode()) {
        settings->setDemoMode(false);           // a production build has no demo
    }
#endif
    m_client = new tunnel::DaemonClient(demo, this);
    m_profiles = new tunnel::ProfileList(m_client, this);

    // Statistics only while a profile page is open and the app is on screen (APP.md, section 8).
    QObject::connect(Application::instance(), SIGNAL(fullscreen()), this, SLOT(onFullscreen()));
    QObject::connect(Application::instance(), SIGNAL(thumbnail()), this, SLOT(onBackground()));
    QObject::connect(Application::instance(), SIGNAL(invisible()), this, SLOT(onBackground()));

    // bb-shared's QML types (import bb.shared 1.0): the Repeater of the connections list, the Help
    // sheet coffee card's SharedClipboard.
    bbshared::registerUiTypes();

    // On the engine's ROOT context, not the document's: only those stay live inside list rows,
    // sheets, pushed pages and the Active Frame (KB 1.14).
    QDeclarativeContext* context = QmlDocument::defaultDeclarativeEngine()->rootContext();
    context->setContextProperty("app", this);
    // The spacing of every app's service pages (2 du, 3 du on a Passport).
    bbshared::installDimensContext(context);
    // The daemon's link: connected, its version, send() for the pages that talk to it directly
    // (Diagnostics' log, the service restart).
    context->setContextProperty("daemon", m_client);
    // The profiles and their tunnels (client/Profiles.hpp).
    context->setContextProperty("profiles", m_profiles);
    // Language, notifications, demo, "What's new" (client/TunnelSettings.hpp).
    context->setContextProperty("settings", settings);
    // Text for the import sheet: files, the clipboard.
    context->setContextProperty("importer", new tunnel::Importer(this));
    // The release notes behind "What's new".
    context->setContextProperty("changelog", new tunnel::Changelog(this));
    // The developer tools (Settings > Diagnostics: the demo switch) - not in a production build.
#ifdef TUNNEL_PRODUCTION
    context->setContextProperty("devMode", QVariant(false));
#else
    context->setContextProperty("devMode", QVariant(true));
#endif

    QmlDocument* qml = QmlDocument::create("asset:///main.qml").parent(this);
    AbstractPane* root = qml->createRootObject<AbstractPane>();
    Application::instance()->setScene(root);

    m_client->start();
    startService();
}

void ApplicationUI::onSystemLanguageChanged()
{
    const QString lang = bbshared::L10n::installTranslator(m_translator,
            tunnel::TunnelSettings::instance()->language());
    qDebug() << "[tunnel] translator loaded for" << lang;
}

void ApplicationUI::onInvoked(const bb::system::InvokeRequest& request)
{
    const QString action = request.action();
    qDebug() << "[tunnel] invoked:" << action << request.uri();

    if (action == QLatin1String("doctorrokter.BBTunnel.OPENPROFILE")) {
        const QString id = QString::fromUtf8(request.data().constData(), request.data().size()).trimmed();
        if (!id.isEmpty()) {
            m_pendingProfile = id;
            emit openProfileRequested(id);
        }
        return;
    }
    // "Open in Tunnel": a .conf from the file manager, a mail, a messenger.
    if (action == QLatin1String("bb.action.OPEN") || action == QLatin1String("bb.action.VIEW")) {
        const QString path = request.uri().toLocalFile();
        if (!path.isEmpty()) {
            m_pendingImport = path;
            emit importFileRequested(path);
        }
    }
}

QString ApplicationUI::takePendingImport()
{
    const QString path = m_pendingImport;
    m_pendingImport.clear();
    return path;
}

QString ApplicationUI::takePendingProfile()
{
    const QString id = m_pendingProfile;
    m_pendingProfile.clear();
    return id;
}

QString ApplicationUI::bundledDaemonVersion() const
{
    return tunnel::DaemonClient::bundledVersion();
}

QString ApplicationUI::logForSharing() const
{
    // Oldest first: each log's older half, then its current one. First the boot loop's
    // (daemon/boot/bbtunneld-boot.sh, in the shared misc folder: did the daemon start, and why
    // not), then the daemon's - its files belong to the app's uid (bbtunneld --owner) - then the
    // service's and the app's own. A current log that is not there, or any that cannot be opened, gets a
    // line saying so instead of its text: a part left out silently looks like a log that was
    // never written.
    struct Part {
        const char* path;
        bool current;   // not there - said too; a missing older half is normal
    };
    static const Part kParts[] = {
        { "/accounts/1000/shared/misc/bbtunneld-boot.old.txt", false },
        { "/accounts/1000/shared/misc/bbtunneld-boot.txt", true },
        { "data/logs/daemon.1.txt", false },
        { "data/logs/daemon.txt", true },
        { "data/logs/service.1.txt", false },
        { "data/logs/service.txt", true },
        { "data/logs/gui.1.txt", false },
        { "data/logs/gui.txt", true }
    };
    QByteArray all;
    bool anyRead = false;
    for (unsigned i = 0; i < sizeof(kParts) / sizeof(kParts[0]); ++i) {
        const QByteArray path(kParts[i].path);
        QFile part(QString::fromLatin1(kParts[i].path));
        if (!part.exists()) {
            if (kParts[i].current) {
                all += "==== " + path + ": not there ====\n\n";
            }
            continue;
        }
        if (!part.open(QIODevice::ReadOnly)) {
            all += "==== " + path + ": cannot be opened (" + part.errorString().toUtf8() + ") ====\n\n";
            continue;
        }
        all += "==== " + path + " ====\n";
        all += part.readAll();
        all += "\n";
        anyRead = true;
    }
    if (!anyRead) {
        return QString();
    }
    // A share target cannot read our sandbox: the shared area, as BBTelega's QR card. .txt - the
    // phone's viewer opens nothing else.
    const QString dir = QString::fromLatin1("/accounts/1000/shared/misc");
    QDir().mkpath(dir);
    QFile out(dir + QString::fromLatin1("/tunnel-log.txt"));
    if (!out.open(QIODevice::WriteOnly | QIODevice::Truncate) || out.write(all) != all.size()) {
        qWarning() << "[tunnel] the log for sharing could not be written:" << out.errorString();
        return QString();
    }
    out.close();
    return QUrl::fromLocalFile(out.fileName()).toString();
}

void ApplicationUI::setStatsWanted(bool wanted)
{
    if (wanted == m_statsWanted) {
        return;
    }
    m_statsWanted = wanted;
    updateStats();
    emit statsWantedChanged();
}

void ApplicationUI::onFullscreen()
{
    m_visible = true;
    updateStats();
}

void ApplicationUI::onBackground()
{
    m_visible = false;
    updateStats();
}

void ApplicationUI::updateStats()
{
    // Once a second the daemon wakes the phone for them: only while someone looks (DAEMON section 3).
    m_client->setStats(m_statsWanted && m_visible);
}

void ApplicationUI::startService()
{
    // The headless service starts on boot, but not right after an install or under the debugger,
    // so nudge it on every launch. Harmless when it is already running.
    bb::system::InvokeRequest request;
    request.setTarget("doctorrokter.BBTunnelService");
    request.setAction("doctorrokter.BBTunnelService.START");
    m_invokeManager->invoke(request);
}
