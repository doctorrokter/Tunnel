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

#include "FileLog.hpp"
#include "L10n.hpp"

#include <bb/Application>

using namespace bb;

int main(int argc, char **argv)
{
    Application app(argc, argv);

    // The same organisation/application names as the GUI: both entry points share one sandbox,
    // so with the same names QSettings points both processes at the same file (KB 7.2).
    QCoreApplication::setOrganizationName("BBTunnel");
    QCoreApplication::setApplicationName("BBTunnel");

    // data/logs/service.txt - also the file the boot loop takes the app's uid from.
    tunnel::FileLog::install("service");

    // The service's own catalogs (BBTunnelService_<lang>.qm): the few lines it says in the Hub, in
    // the language the app is set to (Notifier reads it at the moment of saying).
    bbshared::L10n::init(QString::fromLatin1("BBTunnelService"));

    Service srv;

    // Enter the service's main event loop.
    return Application::exec();
}
