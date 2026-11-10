#include "DaemonClient.hpp"

#ifdef TUNNEL_DEMO
#include "DemoDaemon.hpp"
#endif

#include <QDir>
#include <QStringList>
#include <QTimer>
#include <QDebug>

namespace tunnel {

namespace {

// A whole block of the largest size the protocol allows, and its ending (bt_proto.h).
const int kBufSize = BT_BLOCK_MAX + 4;

// Seconds between tries while there is no daemon: soon at first, then every 30 s.
const int kRetrySeconds[] = { 1, 2, 5, 10, 30 };
const int kRetrySteps = sizeof(kRetrySeconds) / sizeof(kRetrySeconds[0]);

// A parsed block as a map: a value is a string, a key that repeats a list of them.
QVariantMap toMap(const bt_block* b)
{
    QVariantMap m;
    for (size_t i = 0; i < b->n; ++i) {
        const QString key = QString::fromLatin1(b->kv[i].key);
        const QString value = QString::fromUtf8(b->kv[i].val, (int)b->kv[i].val_len);
        QVariantMap::iterator it = m.find(key);
        if (it == m.end()) {
            m.insert(key, value);
        } else if (it.value().type() == QVariant::StringList) {
            QStringList list = it.value().toStringList();
            list.append(value);
            it.value() = list;
        } else {
            it.value() = QStringList() << it.value().toString() << value;
        }
    }
    return m;
}

} // namespace

DaemonClient::DaemonClient(bool demo, QObject* parent) :
        QObject(parent),
        m_socket(new QLocalSocket(this)),
        m_retry(new QTimer(this)),
        m_attempt(0),
        m_buf(new char[kBufSize]),
        m_block(new bt_block),
        m_nextId(0),
        m_helloId(0),
        m_connected(false),
        m_protoVersion(0),
        m_stats(false),
        m_demo(0)
{
    bt_reader_init(&m_reader, m_buf, (size_t)kBufSize);
    m_retry->setSingleShot(true);
    connect(m_retry, SIGNAL(timeout()), this, SLOT(tryConnect()));
    connect(m_socket, SIGNAL(connected()), this, SLOT(onConnected()));
    connect(m_socket, SIGNAL(disconnected()), this, SLOT(onDisconnected()));
    connect(m_socket, SIGNAL(error(QLocalSocket::LocalSocketError)),
            this, SLOT(onSocketError(QLocalSocket::LocalSocketError)));
    connect(m_socket, SIGNAL(readyRead()), this, SLOT(onReadyRead()));
#ifdef TUNNEL_DEMO
    if (demo) {
        m_demo = new DemoDaemon(this);
    }
#else
    Q_UNUSED(demo);
#endif
}

DaemonClient::~DaemonClient()
{
    delete[] m_buf;
    delete m_block;
}

QString DaemonClient::socketPath()
{
    return QDir::currentPath() + QString::fromLatin1("/data/daemon.sock");
}

void DaemonClient::start()
{
#ifdef TUNNEL_DEMO
    if (m_demo) {
        m_demo->start();
        return;
    }
#endif
    tryConnect();
}

void DaemonClient::retryNow()
{
    if (m_connected || m_demo) {
        return;
    }
    m_retry->stop();
    m_attempt = 0;
    tryConnect();
}

void DaemonClient::tryConnect()
{
    if (m_socket->state() != QLocalSocket::UnconnectedState) {
        return;
    }
    m_socket->connectToServer(socketPath());
}

void DaemonClient::onConnected()
{
    // A new stream: nothing of the last one may be taken for the start of a block.
    bt_reader_init(&m_reader, m_buf, (size_t)kBufSize);
    m_items.clear();
    m_helloId = sendRaw(QString::fromLatin1("hello"), QVariantMap());
}

void DaemonClient::demoConnected()
{
    m_helloId = sendRaw(QString::fromLatin1("hello"), QVariantMap());
}

void DaemonClient::onDisconnected()
{
    lost();
}

void DaemonClient::onSocketError(QLocalSocket::LocalSocketError error)
{
    // No socket file (ServerNotFound) or nobody behind it (ConnectionRefused): the daemon is not
    // running. Qt says error() BEFORE the socket turns unconnected (qlocalsocket_unix.cpp, 4.8 and 5
    // alike), so its state is no answer here - a failed try looked "connecting", and no new try was
    // ever made. Once Qt is done with the socket: let go of it and try again later (lost()).
    if (m_attempt == 0 || m_connected) {
        qDebug() << "[client] socket:" << error << m_socket->errorString();
    }
    QTimer::singleShot(0, this, SLOT(onDisconnected()));
}

void DaemonClient::lost()
{
    const bool was = m_connected;
    m_connected = false;
    m_helloId = 0;
    m_items.clear();
    if (m_socket->state() != QLocalSocket::UnconnectedState) {
        m_socket->abort();
    }
    scheduleRetry();
    if (was) {
        qWarning() << "[client] the daemon is gone";
        emit connectedChanged();
    }
}

void DaemonClient::scheduleRetry()
{
    if (m_retry->isActive()) {
        return;
    }
    const int seconds = kRetrySeconds[qMin(m_attempt, kRetrySteps - 1)];
    ++m_attempt;
    m_retry->start(seconds * 1000);
}

void DaemonClient::onReadyRead()
{
    char err[96];

    while (m_socket->state() == QLocalSocket::ConnectedState) {
        size_t room = 0;
        char* space = bt_reader_space(&m_reader, &room);
        qint64 got = 0;
        if (room > 0) {
            got = m_socket->read(space, (qint64)room);
            if (got < 0) {
                lost();
                return;
            }
            bt_reader_commit(&m_reader, (size_t)got);
        }
        // Every whole block, before reading more: one read may bring several.
        int r;
        while ((r = bt_reader_next(&m_reader, m_block, err, sizeof(err))) == 1) {
            if (m_block->n == 0) {
                continue;
            }
            const QString kind = QString::fromLatin1(m_block->kv[0].key);
            const QString what = QString::fromUtf8(m_block->kv[0].val, (int)m_block->kv[0].val_len);
            // The block lives in the reader's buffer until the next call: taken out first.
            receive(kind, what, toMap(m_block));
            if (m_socket->state() != QLocalSocket::ConnectedState) {
                return;
            }
        }
        if (r < 0) {
            qWarning() << "[client] the daemon's stream is broken:" << err;
            lost();
            return;
        }
        if (got <= 0 && m_socket->bytesAvailable() <= 0) {
            break;
        }
    }
}

void DaemonClient::receive(const QString& kind, const QString& what, const QVariantMap& block)
{
    if (kind == QLatin1String("event")) {
        emit event(what, block);
        return;
    }
    const int id = block.value(QString::fromLatin1("id")).toInt();
    if (kind == QLatin1String("item")) {
        if (id > 0) {
            m_items[id].append(block);
        }
        return;
    }
    if (kind != QLatin1String("reply")) {
        return;
    }
    const QVariantList items = m_items.take(id);
    if (id > 0 && id == m_helloId) {
        m_helloId = 0;
        if (block.value(QString::fromLatin1("errno")).toString() != QLatin1String("0")) {
            qWarning() << "[client] hello refused:" << block.value(QString::fromLatin1("error")).toString();
            lost();
            return;
        }
        m_daemonVersion = block.value(QString::fromLatin1("daemon")).toString();
        m_protoVersion = block.value(QString::fromLatin1("proto")).toInt();
        m_connected = true;
        m_attempt = 0;
        qDebug() << "[client] connected: daemon" << m_daemonVersion << "proto" << m_protoVersion;
        sendWatch();
        emit connectedChanged();
        return;
    }
    emit replied(id, what, block, items);
}

int DaemonClient::send(const QString& cmd, const QVariantMap& args)
{
    if (!m_connected) {
        return 0;
    }
    return sendRaw(cmd, args);
}

int DaemonClient::sendRaw(const QString& cmd, const QVariantMap& args)
{
    if (m_nextId >= 0x7fffffff) {
        m_nextId = 0;
    }
    const int id = ++m_nextId;
#ifdef TUNNEL_DEMO
    if (m_demo) {
        m_demo->request(id, cmd, args);
        return id;
    }
#endif
    QByteArray buf;
    buf.resize(BT_BLOCK_MAX);
    bt_writer w;
    bt_writer_init(&w, buf.data(), (size_t)buf.size());
    const QByteArray c = cmd.toUtf8();
    bt_put_n(&w, "cmd", c.constData(), (size_t)c.size());
    bt_put_u64(&w, "id", (uint64_t)id);
    for (QVariantMap::const_iterator it = args.constBegin(); it != args.constEnd(); ++it) {
        const QByteArray key = it.key().toLatin1();
        const QVariant& v = it.value();
        const QStringList values = (v.type() == QVariant::StringList || v.type() == QVariant::List)
                ? v.toStringList()
                : QStringList(v.toString());
        for (int i = 0; i < values.size(); ++i) {
            const QByteArray value = values.at(i).toUtf8();
            bt_put_n(&w, key.constData(), value.constData(), (size_t)value.size());
        }
    }
    if (!bt_end(&w) || w.failed) {
        qWarning() << "[client] a" << cmd << "block would not fit";
        return 0;
    }
    buf.resize((int)w.len);
    m_socket->write(buf);
    return id;
}

void DaemonClient::setStats(bool on)
{
    if (m_stats == on) {
        return;
    }
    m_stats = on;
    if (m_connected) {
        sendWatch();
    }
}

void DaemonClient::sendWatch()
{
    QVariantMap args;
    args.insert(QString::fromLatin1("stats"), QString::fromLatin1(m_stats ? "1" : "0"));
    sendRaw(QString::fromLatin1("watch"), args);
}

} // namespace tunnel
