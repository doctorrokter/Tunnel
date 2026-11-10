/*
 * FileLog - the app's and the service's qDebug/qWarning into data/logs/<name>.txt, shared from
 * Settings > Diagnostics in one file with the daemon's and the boot loop's logs. .txt: the phone's
 * viewer opens nothing else. Two files of 256 KB at most, as the daemon keeps its own: the size is
 * looked at on every line, not only at the start - the processes run for days.
 */

#ifndef TUNNEL_FILELOG_HPP
#define TUNNEL_FILELOG_HPP

namespace tunnel {
namespace FileLog {

// Opens data/logs/<name>.txt (<name>.1.txt is the older half) and takes over Qt's messages. The
// current folder must be the sandbox, as it is when the system starts us.
void install(const char* name);

} // namespace FileLog
} // namespace tunnel

#endif
