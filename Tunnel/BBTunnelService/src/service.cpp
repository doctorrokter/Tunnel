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

#include "service.hpp"

#include "DaemonClient.hpp"
#include "Profiles.hpp"
#include "service/Notifier.hpp"
#include "service/RootAutostart.hpp"

#include <bb/system/InvokeDateTime>
#include <bb/system/InvokeManager>
#include <bb/system/InvokeReply>
#include <bb/system/InvokeReplyError>
#include <bb/system/InvokeRequest>
#include <bb/system/InvokeTimerRequest>

#include <QCoreApplication>
#include <QDateTime>
#include <QTimer>
#include <QDebug>

using namespace bb::system;

namespace {

// After an update: exit and have the framework start the new binary this much later (Syno's way:
// nothing else brings a nostop service back with the new binary - KB 7.2).
const int kRestartDelaySec = 60;
const char* const kRestartTimerId = "bbtunnel_restart";

qint64 nowSec()
{
    return QDateTime::currentMSecsSinceEpoch() / 1000;
}

} // namespace

Service::Service() :
        QObject(),
        m_invokeManager(new InvokeManager(this)),
        m_client(0),
        m_profiles(0),
        m_notifier(0),
        m_rootAutostart(0),
        m_startedAt(nowSec()),
        m_restartBooked(false)
{
    bool ok = QObject::connect(m_invokeManager, SIGNAL(invoked(const bb::system::InvokeRequest&)),
            this, SLOT(handleInvoke(const bb::system::InvokeRequest&)));
    Q_ASSERT(ok);
    Q_UNUSED(ok);

    // Always the real daemon: in the app's demo mode the notifier only keeps quiet about a daemon
    // that is not there.
    m_client = new tunnel::DaemonClient(false, this);
    m_profiles = new tunnel::ProfileList(m_client, this);
    m_notifier = new tunnel::Notifier(m_client, m_profiles, this);
    m_notifier->start();
    m_client->start();
    m_rootAutostart = new tunnel::RootAutostart(this);
    m_rootAutostart->start();
    qDebug() << "[svc] started";
}

void Service::handleInvoke(const bb::system::InvokeRequest& request)
{
    const QString action = request.action();
    qDebug() << "[svc] invoked:" << action;

    // The package was replaced. Under _sys_headless_nostop THIS process would keep running the old
    // binary until a reboot, and nothing brings a headless service back by itself: book our own
    // return, then exit (KB 7.2). But a service that has only just come up IS the new binary,
    // started to receive this very event - it stays.
    if (action == QLatin1String("bb.action.system.UPDATED")) {
        if (nowSec() - m_startedAt < 30) {
            qWarning() << "[svc] installed and started by this very event - staying";
            return;
        }
        qWarning() << "[svc] package updated - booking a restart, then exiting";
        scheduleRestart(kRestartDelaySec);
        return;
    }

    // START (every app launch), STARTED (boot), TIMER_FIRED (our own restart): the process only
    // needs to run - which it now does. The daemon's link keeps itself up.
}

void Service::scheduleRestart(int seconds)
{
    // A single-shot timer invoke (10.3.0+): the framework launches this target at that time - the
    // NEW binary - and the timer expires on completion, so nothing is left registered.
    const QDateTime when = QDateTime::currentDateTime().addSecs(seconds);
    InvokeDateTime at(when.date(), when.time());
    InvokeTimerRequest request;
    request.set(QString::fromLatin1(kRestartTimerId), at, QString::fromLatin1("doctorrokter.BBTunnelService"));
    InvokeReply* reply = m_invokeManager->registerTimer(request);
    if (reply == 0) {
        qWarning() << "[svc] restart timer could not be sent - staying alive";
        return;     // a service on the old binary still beats no service at all
    }
    connect(reply, SIGNAL(finished()), this, SLOT(onRestartTimerReply()));
    // ...and if the reply never arrives, stay rather than exit into nothing.
    QTimer::singleShot(10 * 1000, this, SLOT(onRestartTimerTimeout()));
}

void Service::onRestartTimerReply()
{
    InvokeReply* reply = qobject_cast<InvokeReply*>(sender());
    if (reply == 0) {
        return;
    }
    const bool booked = reply->error() == InvokeReplyError::None;
    reply->deleteLater();
    if (!booked) {
        qWarning() << "[svc] restart timer refused - staying alive with the old binary";
        return;
    }
    m_restartBooked = true;
    qWarning() << "[svc] restart booked - exiting so the new binary loads";
    QCoreApplication::quit();
}

void Service::onRestartTimerTimeout()
{
    if (!m_restartBooked) {
        qWarning() << "[svc] no answer to the restart timer - staying alive";
    }
}
