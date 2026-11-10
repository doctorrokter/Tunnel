/*
 * bbstub.h - just enough of BB10's platform classes for client/ to build and run on Linux (Qt 5) in
 * client_test: the Hub, an invocation, the device's language and model. Each <bb/...> header under
 * stubs/ is one line that includes this file. Nothing reaches a real Hub: a notification lands in bbstub::hub(), keyed
 * as the real one is, for the checks to read.
 */

#ifndef BBSTUB_H_
#define BBSTUB_H_

#include <QByteArray>
#include <QFile>
#include <QJsonDocument>
#include <QJsonParseError>
#include <QLocale>
#include <QMap>
#include <QString>
#include <QVariant>

namespace bbstub {

// A notification as the Hub would hold it now.
struct Posted {
    QString title;
    QString body;
    // NotificationType::AllAlertsOff - no sound, no LED, no flash.
    bool quiet;
    // Where a tap goes: the invocation's action and data (the profile's id).
    QString action;
    QByteArray data;
};

// key -> the notification: notify() puts, deleteFromInbox() takes.
inline QMap<QString, Posted>& hub()
{
    static QMap<QString, Posted> h;
    return h;
}

// Every notify(), for "nothing was said meanwhile".
inline int& posts()
{
    static int n = 0;
    return n;
}

} // namespace bbstub

namespace bb {
namespace system {

class InvokeRequest
{
public:
    void setTarget(const QString& target) { m_target = target; }
    void setAction(const QString& action) { m_action = action; }
    void setMimeType(const QString& mime) { m_mime = mime; }
    void setData(const QByteArray& data) { m_data = data; }
    QString target() const { return m_target; }
    QString action() const { return m_action; }
    QByteArray data() const { return m_data; }

private:
    QString m_target;
    QString m_action;
    QString m_mime;
    QByteArray m_data;
};

struct LocaleType {
    enum Type {
        Messages,
        Region
    };
};

// The device's language: the process's own locale.
class LocaleHandler
{
public:
    explicit LocaleHandler(LocaleType::Type) {}
    QLocale locale() const { return QLocale(); }
};

// What bbstub::clipboard() holds.
class Clipboard
{
public:
    QByteArray value(const QString&) const { return clipboardText(); }
    static QByteArray& clipboardText()
    {
        static QByteArray text;
        return text;
    }
};

} // namespace system

// bb::data::JsonDataAccess over Qt 5's parser: an object comes back as a QVariantMap, as on the phone
// (numbers are doubles here, integers there - the client reads values as text either way).
namespace data {

class DataAccessError
{
public:
    QString errorMessage() const { return m_message; }
    QString m_message;
};

class JsonDataAccess
{
public:
    JsonDataAccess() : m_failed(false) {}

    QVariant loadFromBuffer(const QByteArray& buffer)
    {
        QJsonParseError e;
        const QJsonDocument doc = QJsonDocument::fromJson(buffer, &e);
        m_failed = e.error != QJsonParseError::NoError;
        m_error.m_message = e.errorString();
        return doc.toVariant();
    }
    QVariant loadFromBuffer(const QString& buffer) { return loadFromBuffer(buffer.toUtf8()); }
    QVariant load(const QString& path)
    {
        QFile f(path);
        if (!f.open(QIODevice::ReadOnly)) {
            m_failed = true;
            return QVariant();
        }
        return loadFromBuffer(f.readAll());
    }
    bool hasError() const { return m_failed; }
    DataAccessError error() const { return m_error; }

private:
    bool m_failed;
    DataAccessError m_error;
};

} // namespace data

namespace platform {

struct NotificationError {
    enum Type {
        None = 0,
        Unknown
    };
};

struct NotificationType {
    enum Type {
        Default,
        AllAlertsOff
    };
};

struct NotificationPolicy {
    enum Type {
        Default,
        Allow,
        Deny
    };
};

struct NotificationPriorityPolicy {
    enum Type {
        Default,
        Allow,
        Deny
    };
};

class NotificationDefaultApplicationSettings
{
public:
    void setLed(NotificationPolicy::Type) {}
    void setPreview(NotificationPriorityPolicy::Type) {}
    NotificationError::Type apply() { return NotificationError::None; }
};

class Notification
{
public:
    explicit Notification(const QString& key = QString()) : m_key(key), m_quiet(false) {}
    void setTitle(const QString& title) { m_title = title; }
    void setBody(const QString& body) { m_body = body; }
    void setType(NotificationType::Type type) { m_quiet = type == NotificationType::AllAlertsOff; }
    void setInvokeRequest(const bb::system::InvokeRequest& request) { m_invoke = request; }

    NotificationError::Type notify() const
    {
        bbstub::Posted p;
        p.title = m_title;
        p.body = m_body;
        p.quiet = m_quiet;
        p.action = m_invoke.action();
        p.data = m_invoke.data();
        bbstub::hub().insert(m_key, p);
        ++bbstub::posts();
        return NotificationError::None;
    }

    static NotificationError::Type deleteFromInbox(const QString& key)
    {
        bbstub::hub().remove(key);
        return NotificationError::None;
    }

private:
    QString m_key;
    QString m_title;
    QString m_body;
    bool m_quiet;
    bb::system::InvokeRequest m_invoke;
};

} // namespace platform

// bb::device::HardwareInfo: the model a test sets (a Passport unless it says otherwise).
namespace device {

class HardwareInfo
{
public:
    QString modelName() const { return model(); }
    static QString& model()
    {
        static QString name = QString::fromLatin1("Passport");
        return name;
    }
};

} // namespace device
} // namespace bb

#endif /* BBSTUB_H_ */
