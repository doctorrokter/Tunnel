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

#ifndef SERVICE_H_
#define SERVICE_H_

#include <QObject>

namespace bb {
    namespace system {
        class InvokeManager;
        class InvokeRequest;
    }
}

namespace tunnel {
    class DaemonClient;
    class Notifier;
    class ProfileList;
    class RootAutostart;
}

// The headless half of BBTunnel (docs/APP.md, section 11): starts on boot, follows the daemon's
// events (watch, no statistics) and says in the Hub what the user should know - a lost connection,
// a daemon that does not answer, and on request that a tunnel is on. It is a client of the daemon
// like the app: it keeps no profiles, cannot restart the daemon (it is not root), and always-on is
// the daemon's own business.
class Service: public QObject
{
    Q_OBJECT
public:
    Service();
    virtual ~Service() {}

private slots:
    void handleInvoke(const bb::system::InvokeRequest& request);
    void onRestartTimerReply();
    void onRestartTimerTimeout();

private:
    void scheduleRestart(int seconds);

    bb::system::InvokeManager* m_invokeManager;
    tunnel::DaemonClient* m_client;
    tunnel::ProfileList* m_profiles;
    tunnel::Notifier* m_notifier;
    tunnel::RootAutostart* m_rootAutostart;
    qint64 m_startedAt;         // tells a fresh install from an update (see UPDATED)
    bool m_restartBooked;
};

#endif /* SERVICE_H_ */
