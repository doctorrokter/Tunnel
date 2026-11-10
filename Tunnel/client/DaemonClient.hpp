/*
 * DaemonClient - the link to bbtunneld (docs/APP.md, section 2; the protocol - docs/DAEMON.md,
 * section 3). The daemon's unix socket is data/daemon.sock in the package's sandbox - the app's and
 * the service's working directory - and belongs to the app's uid (bbtunneld --owner).
 *
 * The protocol is the daemon's own code: daemon/src/bt_proto.c frames the stream, parses a block and
 * builds one. On top of it:
 *   - connecting: no socket, or it refuses (the daemon is not running) - again in 1, 2, 5, 10, then
 *     every 30 s. Connected once `hello` is answered; daemonVersion / protoVersion then say which
 *     daemon it is (the app compares them, APP.md section 9);
 *   - send(): a command with id=; its reply comes with the item= blocks that came before it under the
 *     same id (profile.list, status). A value is a string; a key that repeats becomes a list;
 *   - watch: always; stats=1 only while someone asks (setStats) - kept across a reconnect;
 *   - events arrive as event(kind, data).
 *
 * Demo (TUNNEL_DEMO builds - development only): no socket, DemoDaemon answers (APP.md section 12).
 */

#ifndef TUNNEL_DAEMONCLIENT_HPP_
#define TUNNEL_DAEMONCLIENT_HPP_

#include <QByteArray>
#include <QHash>
#include <QLocalSocket>
#include <QObject>
#include <QString>
#include <QVariantList>
#include <QVariantMap>

extern "C" {
#include "bt_proto.h"
}
#include "bt_version.h"

class QTimer;

namespace tunnel {

class DemoDaemon;

class DaemonClient: public QObject
{
    Q_OBJECT
    // hello answered: commands go through.
    Q_PROPERTY(bool connected READ connected NOTIFY connectedChanged)
    // What hello said: the daemon's version ("0.1.0") and its protocol's.
    Q_PROPERTY(QString daemonVersion READ daemonVersion NOTIFY connectedChanged)
    Q_PROPERTY(int protoVersion READ protoVersion NOTIFY connectedChanged)
    // No daemon: the demo answers.
    Q_PROPERTY(bool demo READ demo CONSTANT)
public:
    // `demo` counts only in a TUNNEL_DEMO build.
    explicit DaemonClient(bool demo, QObject* parent = 0);
    virtual ~DaemonClient();

    // data/daemon.sock under the working directory (the sandbox).
    static QString socketPath();

    bool connected() const { return m_connected; }
    QString daemonVersion() const { return m_daemonVersion; }
    int protoVersion() const { return m_protoVersion; }
    bool demo() const { return m_demo != 0; }

    // Connects now, and keeps reconnecting.
    void start();
    // "Retry" on the screen: a try now, and the next ones from 1 s again.
    Q_INVOKABLE void retryNow();

    // A command. A value is a QString (or what toString() reads), a list for a repeated key. The id
    // its reply comes with (> 0); 0 when not connected, or the block would be too big.
    Q_INVOKABLE int send(const QString& cmd, const QVariantMap& args = QVariantMap());

    // Statistics once a second (watch stats=1) while on.
    void setStats(bool on);

    // The protocol version this client speaks.
    static int clientProto() { return BT_PROTO_VERSION; }
    // The version of the daemon this package ships (daemon/src/bt_version.h): a running daemon with
    // another one is the old binary after a reinstall (docs/APP.md, section 9).
    static QString bundledVersion() { return QString::fromLatin1(BT_VERSION); }

Q_SIGNALS:
    void connectedChanged();
    // The reply to send()'s id: errno 0 (reply["errno"] == "0") = done; else error=, and line= for
    // a .conf. `items`: the item= blocks that came before it.
    void replied(int id, const QString& cmd, const QVariantMap& reply, const QVariantList& items);
    void event(const QString& kind, const QVariantMap& data);

private Q_SLOTS:
    void onConnected();
    void onDisconnected();
    void onSocketError(QLocalSocket::LocalSocketError error);
    void onReadyRead();
    void tryConnect();

private:
    friend class DemoDaemon;

    // A block, parsed - from the socket or from the demo. `kind`: its first key (reply / item /
    // event), `what`: that key's value.
    void receive(const QString& kind, const QString& what, const QVariantMap& block);
    // A command without the connected check: hello goes out before there is a connection to speak of.
    int sendRaw(const QString& cmd, const QVariantMap& args);
    // Demo: hello over the demo's "connection".
    void demoConnected();
    void sendWatch();
    void lost();
    void scheduleRetry();

    QLocalSocket* m_socket;
    QTimer* m_retry;
    int m_attempt;
    char* m_buf;
    bt_reader m_reader;
    bt_block* m_block;
    int m_nextId;
    int m_helloId;
    bool m_connected;
    QString m_daemonVersion;
    int m_protoVersion;
    bool m_stats;
    QHash<int, QVariantList> m_items;
    DemoDaemon* m_demo;
};

} // namespace tunnel

#endif /* TUNNEL_DAEMONCLIENT_HPP_ */
