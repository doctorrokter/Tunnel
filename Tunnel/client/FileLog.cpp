#include "FileLog.hpp"

#include <QByteArray>
#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QMutex>
#include <QMutexLocker>
#include <QString>
#include <QtGlobal>

#include <stdio.h>
#include <stdlib.h>

namespace tunnel {
namespace FileLog {

namespace {

const qint64 kLogMax = 256 * 1024;

QByteArray g_path;
QByteArray g_oldPath;
FILE* g_log = 0;
qint64 g_logSize = 0;
// The GUI logs from more than one thread.
QMutex g_lock;

// The log over kLogMax - to its .1.txt (the one before goes), a new one.
void rotateIfFull()
{
    if (g_logSize <= kLogMax) {
        return;
    }
    if (g_log != 0) {
        fclose(g_log);
    }
    remove(g_oldPath.constData());
    rename(g_path.constData(), g_oldPath.constData());
    g_log = fopen(g_path.constData(), "a");
    g_logSize = 0;
}

void writeLine(QtMsgType type, const char* message)
{
    char level = 'E';
    if (type == QtDebugMsg) {
        level = 'D';
    } else if (type == QtWarningMsg) {
        level = 'W';
    }
    fprintf(stderr, "%s\n", message);
    {
        QMutexLocker locker(&g_lock);
        if (g_log != 0) {
            const QByteArray when = QDateTime::currentDateTime().toString(QString::fromLatin1("yyyy-MM-dd hh:mm:ss.zzz")).toLatin1();
            const int written = fprintf(g_log, "%s %c %s\n", when.constData(), level, message);
            fflush(g_log);
            if (written > 0) {
                g_logSize += written;
            }
            rotateIfFull();
        }
    }
    if (type == QtFatalMsg) {
        abort();
    }
}

} // namespace

void install(const char* name)
{
    const QByteArray base = QByteArray("data/logs/") + name;
    g_path = base + ".txt";
    g_oldPath = base + ".1.txt";

    // The daemon writes its log here too (--log), but does not make the folder: we do, as the
    // app's uid - the daemon, as root, can write into it anyway.
    QDir().mkpath(QString::fromLatin1("data/logs"));
    g_logSize = QFile(QString::fromLatin1(g_path)).size();
    rotateIfFull();
    if (g_log == 0) {
        g_log = fopen(g_path.constData(), "a");
    }
    qInstallMsgHandler(writeLine);
}

} // namespace FileLog
} // namespace tunnel
