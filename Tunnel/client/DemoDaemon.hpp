/*
 * DemoDaemon - profiles and tunnels without a daemon: to lay the screens out on the simulator, and on
 * a phone whose daemon does not run yet (docs/APP.md, section 12). Development builds only
 * (TUNNEL_DEMO). It answers DaemonClient's commands as bbtunneld does - the same keys, the same
 * events, the same errno - with four made-up profiles:
 *   Home     - AmneziaWG, all traffic: up in 1.5 s
 *   Work     - WireGuard, 10.20.0.0/16: up in 1 s
 *   NAS      - WireGuard at a server that never answers: "handshake" after 15 s, as the daemon says it
 *   Tailnet  - Tailscale: control at 1 s, then the relay, up at 2 s; four nodes, two of them online
 * An import takes any text with [Interface] and a PrivateKey line; anything else gets a line error,
 * like the daemon's; a Tailscale import, any key that starts "tskey-". Nothing is kept: every start
 * begins with the four again.
 */

#ifndef TUNNEL_DEMODAEMON_HPP_
#define TUNNEL_DEMODAEMON_HPP_

#include <QList>
#include <QObject>
#include <QString>
#include <QStringList>
#include <QVariantMap>

class QTimer;

namespace tunnel {

class DaemonClient;

class DemoDaemon: public QObject
{
    Q_OBJECT
public:
    explicit DemoDaemon(DaemonClient* client);

    // The "connection": hello goes out a moment later.
    void start();
    // A command from the client; the answer comes after a turn of the event loop, as over a socket.
    void request(int id, const QString& cmd, const QVariantMap& args);

private Q_SLOTS:
    void connectNow();
    void flush();
    void tick();

private:
    struct Tunnel {
        Tunnel() : order(0), since(0), rx(0), tx(0), handshake(0), silent(false), relayUp(false), link(false) {}
        QString id;
        QString name;
        QString type;
        int order;
        QStringList address;
        QStringList dns;
        QStringList allowed;
        QString endpoint;
        QString publicKey;
        QString state;
        QString reason;
        QString detail;
        qint64 since;           // ms: when it started coming up
        double rx;
        double tx;
        qint64 handshake;       // wall seconds
        bool silent;            // its server never answers
        bool relayUp;           // Tailscale: its home relay is up (it comes after control)
        bool link;              // Tailscale: logs in by a link - the next start waits at one a while
    };

    // A block for the client: kind (reply / item / event) and the value of that first key.
    void push(const QString& kind, const QString& what, const QVariantMap& block);
    void reply(int id, const QString& cmd, QVariantMap block, int code = 0, const QString& error = QString());
    void tunnelEvent(const Tunnel& t);
    void profileEvent(const QString& id, const QString& action);
    QVariantMap summary(const Tunnel& t) const;
    QVariantMap describe(const Tunnel& t) const;
    void nodes(int id, const Tunnel& t);
    Tunnel* find(const QString& id);
    bool full(const Tunnel& t) const;

    struct Out {
        QString kind;
        QString what;
        QVariantMap block;
    };

    DaemonClient* m_client;
    QTimer* m_flush;
    QTimer* m_tick;
    QList<Out> m_out;
    QList<Tunnel> m_tunnels;
    QString m_alwaysOn;
    QString m_alwaysOnTailscale;
    bool m_stats;
    int m_ticks;
    int m_nextId;
    qint64 m_debugUntil;    // log.debug on until then (ms); 0 - off
};

} // namespace tunnel

#endif /* TUNNEL_DEMODAEMON_HPP_ */
