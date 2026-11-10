#include "RootAutostart.hpp"

#include <QCoreApplication>
#include <QFile>
#include <QFileInfo>
#include <QSettings>
#include <QStringList>
#include <QTimer>
#include <QDebug>

namespace tunnel {

namespace {

const int kTryTimeoutMs = 60 * 1000;    // the script copies the daemon: more than GPS Boost's work
const int kRetryAfterMs = 60 * 1000;
const int kMaxTries = 16;               // root comes up to about 15 minutes after a boot

const char* const kHookKey = "rootAutostart/installed";

// The verdict is the last line of the output: result=<word>. None - an empty string.
QString verdictOf(const QString& output)
{
    const QStringList lines = output.split(QLatin1Char('\n'), QString::SkipEmptyParts);
    if (lines.isEmpty()) {
        return QString();
    }
    const QString last = lines.last().trimmed();
    if (!last.startsWith(QLatin1String("result="))) {
        return QString();
    }
    return last.mid(7);
}

} // namespace

RootAutostart::RootAutostart(QObject* parent) :
        QObject(parent),
        m_process(0),
        m_timeout(new QTimer(this)),
        m_tries(0),
        m_timedOut(false)
{
    m_timeout->setSingleShot(true);
    connect(m_timeout, SIGNAL(timeout()), this, SLOT(onTimeout()));
}

void RootAutostart::start()
{
    QTimer::singleShot(0, this, SLOT(tryInstall()));
}

bool RootAutostart::hookInstalled()
{
    return QSettings().value(QString::fromLatin1(kHookKey), false).toBool();
}

QString RootAutostart::findWrapper()
{
    const char* const wrappers[] = { "/base/bin/__root", "/bin/__root" };
    for (unsigned i = 0; i < sizeof(wrappers) / sizeof(wrappers[0]); ++i) {
        const QString path = QString::fromLatin1(wrappers[i]);
        if (QFile::exists(path)) {
            return path;
        }
    }
    return QString();
}

// The real path of the script in the package: the shell runs outside our sandbox.
QString RootAutostart::scriptPath()
{
    return QFileInfo(QCoreApplication::applicationDirPath() + QString::fromLatin1("/bbtunneld-boot.sh")).canonicalFilePath();
}

void RootAutostart::tryInstall()
{
    if (m_process != 0) {
        return;
    }
    m_wrapper = findWrapper();
    if (m_wrapper.isEmpty()) {
        qWarning() << "[autostart] no root wrapper the app can see: the boot start is set up by hand on this phone";
        return;
    }
    const QString script = scriptPath();
    if (script.isEmpty() || script.contains(QLatin1Char('\''))) {
        qWarning() << "[autostart] the start script is not in the package, or its path cannot be quoted:" << script;
        return;
    }

    m_tries += 1;
    m_timedOut = false;
    m_process = new QProcess(this);
    m_process->setProcessChannelMode(QProcess::MergedChannels);
    connect(m_process, SIGNAL(error(QProcess::ProcessError)), this, SLOT(onProcessError(QProcess::ProcessError)));
    connect(m_process, SIGNAL(finished(int, QProcess::ExitStatus)), this, SLOT(onProcessFinished()));
    m_timeout->start(kTryTimeoutMs);

    const QString command = QString::fromLatin1("/bin/ksh -s install '%1' < '%1'\n").arg(script);
    m_process->start(m_wrapper, QStringList(), QIODevice::ReadWrite);
    m_process->write(command.toLocal8Bit());
    m_process->closeWriteChannel();
}

void RootAutostart::onProcessError(QProcess::ProcessError error)
{
    // Only a process that never started: every other error ends in finished() too.
    if (error != QProcess::FailedToStart || m_process == 0) {
        return;
    }
    finishTry(QString::fromLatin1("%1 did not start: %2").arg(m_wrapper, m_process->errorString()), false);
}

void RootAutostart::onTimeout()
{
    if (m_process == 0) {
        return;
    }
    m_timedOut = true;
    m_process->kill();      // finished() follows
}

void RootAutostart::onProcessFinished()
{
    if (m_process == 0) {
        return;
    }
    const QString output = QString::fromLocal8Bit(m_process->readAll());
    if (m_timedOut) {
        finishTry(QString::fromLatin1("%1 timed out; said: %2").arg(m_wrapper, output.simplified()), false);
        return;
    }
    const QString verdict = verdictOf(output);
    const bool installed = verdict == QLatin1String("ok") || verdict == QLatin1String("same");
    finishTry(QString::fromLatin1("%1: %2").arg(m_wrapper, output.simplified()), installed);
}

void RootAutostart::finishTry(const QString& outcome, bool installed)
{
    m_timeout->stop();
    m_process->deleteLater();
    m_process = 0;

    logOnce(outcome);
    if (installed) {
        QSettings settings;
        if (!settings.value(QString::fromLatin1(kHookKey), false).toBool()) {
            settings.setValue(QString::fromLatin1(kHookKey), true);
        }
        return;
    }
    if (m_tries >= kMaxTries) {
        qWarning() << "[autostart] gave up after" << m_tries << "tries; the next start of the service tries again";
        return;
    }
    QTimer::singleShot(kRetryAfterMs, this, SLOT(tryInstall()));
}

void RootAutostart::logOnce(const QString& line)
{
    if (line == m_lastLine) {
        return;
    }
    m_lastLine = line;
    qWarning() << "[autostart]" << line;
}

} // namespace tunnel
