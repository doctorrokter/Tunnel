/*
 * RootAutostart - the service puts the daemon's boot start in place by itself on a root firmware
 * with a root wrapper and a boot-hook folder (root v4; docs/DAEMON.md section 12, docs/APP.md
 * section 11). No button: it runs at every start of the service, so an update of the app updates
 * the hook too, and the script rewrites nothing that is the same already.
 *
 * The wrapper takes a command on stdin, and that command feeds the package's bbtunneld-boot.sh to a
 * shell in its install mode; the last line of the output is the verdict: result=<word>. Root comes
 * up to about 15 minutes after a boot, so a failed try is repeated once a minute for that long. A
 * phone with no wrapper the app can see (root v2) keeps its hand-made boot start: nothing is done.
 *
 * Everything it learns goes to the service's log (data/logs/service.txt) and is not repeated when
 * it stays the same.
 */

#ifndef TUNNEL_ROOTAUTOSTART_HPP
#define TUNNEL_ROOTAUTOSTART_HPP

#include <QObject>
#include <QProcess>
#include <QString>

class QTimer;

namespace tunnel {

class RootAutostart: public QObject
{
    Q_OBJECT
public:
    explicit RootAutostart(QObject* parent = 0);

    // The first try, from the event loop.
    void start();

    // The hook has been in place at least once on this phone: the daemon starts when root comes
    // up, up to about 15 minutes after a boot, and not at the boot itself.
    static bool hookInstalled();

private slots:
    void tryInstall();
    void onProcessError(QProcess::ProcessError error);
    void onProcessFinished();
    void onTimeout();

private:
    static QString findWrapper();
    static QString scriptPath();

    void finishTry(const QString& outcome, bool installed);
    void logOnce(const QString& line);

    QProcess* m_process;
    QTimer* m_timeout;
    QString m_wrapper;
    QString m_lastLine;     // what was logged last: the same outcome once a minute is one line
    int m_tries;
    bool m_timedOut;
};

} // namespace tunnel

#endif
