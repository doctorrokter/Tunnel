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

#ifndef ApplicationUI_HPP_
#define ApplicationUI_HPP_

#include <QObject>
#include <QString>

namespace bb {
    namespace cascades {
        class LocaleHandler;
    }
    namespace system {
        class InvokeManager;
        class InvokeRequest;
    }
}

namespace tunnel {
    class DaemonClient;
    class ProfileList;
}

class QTranslator;

// The app (docs/APP.md): the scene, what QML reaches (the context properties - see the ctor), the
// language, and what comes from outside - a .conf opened "in Tunnel" from another app, a tap on the
// service's notification.
class ApplicationUI: public QObject
{
    Q_OBJECT
    // A profile page is open: statistics are wanted - they flow while the app is on screen too.
    Q_PROPERTY(bool statsWanted READ statsWanted WRITE setStatsWanted NOTIFY statsWantedChanged)
    // The daemon this package ships (daemon/src/bt_version.h) - the running one may be older (APP.md 9).
    Q_PROPERTY(QString bundledDaemonVersion READ bundledDaemonVersion CONSTANT)
public:
    ApplicationUI();
    virtual ~ApplicationUI() {}

    bool statsWanted() const { return m_statsWanted; }
    void setStatsWanted(bool wanted);
    QString bundledDaemonVersion() const;

    // What came from outside before QML was ready for it (a cold start by the invocation):
    // taken once - "" when there is nothing.
    Q_INVOKABLE QString takePendingImport();
    Q_INVOKABLE QString takePendingProfile();

    // The boot loop's, the daemon's and the service's logs in one file a share target can read (the
    // shared area: shared/misc/tunnel-log.txt, overwritten each time): its file:// URI, "" when no
    // log could be read at all.
    // The share itself is QML's (KB: an outbound share only from QML).
    Q_INVOKABLE QString logForSharing() const;

Q_SIGNALS:
    void statsWantedChanged();
    // A .conf opened "in Tunnel" (a local path): the import sheet takes it.
    void importFileRequested(const QString& path);
    // A tap on the service's notification: that profile's page.
    void openProfileRequested(const QString& id);

private slots:
    void onSystemLanguageChanged();
    void onInvoked(const bb::system::InvokeRequest& request);
    void onFullscreen();
    void onBackground();

private:
    void startService();
    void updateStats();

    QTranslator* m_translator;
    bb::cascades::LocaleHandler* m_localeHandler;
    bb::system::InvokeManager* m_invokeManager;
    tunnel::DaemonClient* m_client;
    tunnel::ProfileList* m_profiles;
    bool m_visible;
    bool m_statsWanted;
    QString m_pendingImport;
    QString m_pendingProfile;
};

#endif /* ApplicationUI_HPP_ */
