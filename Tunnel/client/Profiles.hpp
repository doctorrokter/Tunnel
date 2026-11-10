/*
 * Profiles - the daemon's profiles and tunnels as objects the screens bind to (docs/APP.md, sections
 * 2-4) and the service watches (section 11). The daemon is the only source: nothing here is kept on
 * the phone, it is rebuilt on every connection (profile.list, settings.get, status) and kept current
 * by the events (tunnel, profile, stats).
 *
 * Profile - one profile: what profile.list says (name, type, order, always-on), its tunnel as the
 * daemon has it (state, reason, detail; a Tailscale tunnel's tailnet too), statistics while they are
 * asked for (watch stats=1), the details of profile.get once loadDetails() asked for them, and a
 * Tailscale profile's nodes once loadNodes() did. A Profile object lives as long as the
 * list: bindings stay across a reconnect, a row's switch is not rebuilt on every event, and a page
 * that shows a profile deleted meanwhile never holds a dangling pointer (it is only set "down").
 *
 * ProfileList - the list, in the daemon's order, and the commands on it. A command's failure comes
 * back as failed(); an import (or a new .conf) as importDone(); a second "all traffic" profile as
 * conflict().
 */

#ifndef TUNNEL_PROFILES_HPP_
#define TUNNEL_PROFILES_HPP_

#include <QHash>
#include <QList>
#include <QObject>
#include <QSet>
#include <QString>
#include <QStringList>
#include <QVariantList>
#include <QVariantMap>

namespace tunnel {

class DaemonClient;

class Profile: public QObject
{
    Q_OBJECT
    Q_PROPERTY(QString id READ id CONSTANT)
    Q_PROPERTY(QString name READ name NOTIFY changed)
    // "wireguard" | "amneziawg" | "tailscale"
    Q_PROPERTY(QString type READ type NOTIFY changed)
    Q_PROPERTY(bool amnezia READ amnezia NOTIFY changed)
    Q_PROPERTY(bool tailscale READ tailscale NOTIFY changed)
    Q_PROPERTY(int order READ order NOTIFY changed)
    Q_PROPERTY(bool alwaysOn READ alwaysOn NOTIFY changed)
    // down | connecting | up | reconnecting | error - bt_tunnel.h
    Q_PROPERTY(QString state READ state NOTIFY changed)
    // "" or conf, conflict, tun, route, no_network, resolve, handshake; Tailscale: control, relay,
    // approval, login, expired, removed, browser (a login link to open - tailnet.authUrl)
    Q_PROPERTY(QString reason READ reason NOTIFY changed)
    Q_PROPERTY(QString detail READ detail NOTIFY changed)
    // The daemon holds the tunnel (not down): what a row's switch shows.
    Q_PROPERTY(bool active READ active NOTIFY changed)
    // Its DNS is the system's now.
    Q_PROPERTY(bool holdsDns READ holdsDns NOTIFY changed)
    // Statistics (watch stats=1). QML has no 64-bit integer: doubles.
    Q_PROPERTY(double rxBytes READ rxBytes NOTIFY statsChanged)
    Q_PROPERTY(double txBytes READ txBytes NOTIFY statsChanged)
    // The wall clock second of the last handshake, 0 = none yet.
    Q_PROPERTY(double handshakeSec READ handshakeSec NOTIFY statsChanged)
    // Where the peer answered from last - after DNS and roaming.
    Q_PROPERTY(QString endpointNow READ endpointNow NOTIFY statsChanged)
    // profile.get: public_key, address[], dns[], dns_search, mtu, listen_port, peers, endpoint[],
    // allowed_count, allowed[] (the first 64), and "full" - true when AllowedIPs hold a /0.
    // A Tailscale profile's: control, login (ok; pending - with its auth key at the next start; link - by
    // a link then), hostname, node_key, tailnet, node_name, address[] - the last netmap's, kept by the
    // daemon.
    Q_PROPERTY(QVariantMap details READ details NOTIFY detailsChanged)
    Q_PROPERTY(bool detailsLoaded READ detailsLoaded NOTIFY detailsChanged)
    // A Tailscale tunnel that is up, as the daemon describes it: tailnet, addresses (ours, 100.x...),
    // name, relay (the home region's code), relayUp, nodes, nodesActive, and authUrl - the login link
    // to open while the reason is browser ("" otherwise). Empty while it is down.
    Q_PROPERTY(QVariantMap tailnet READ tailnet NOTIFY tailnetChanged)
    // tailscale.nodes (loadNodes): { name, addresses, online ("1", "0", "" unknown), expired, relay
    // (its home DERP region's number, 0 unknown), active, rx, tx } each, in the netmap's order.
    Q_PROPERTY(QVariantList nodes READ nodes NOTIFY nodesChanged)
public:
    explicit Profile(const QString& id, QObject* parent = 0);

    QString id() const { return m_id; }
    QString name() const { return m_name; }
    QString type() const { return m_type; }
    bool amnezia() const { return m_type == QLatin1String("amneziawg"); }
    bool tailscale() const { return m_type == QLatin1String("tailscale"); }
    int order() const { return m_order; }
    bool alwaysOn() const { return m_alwaysOn; }
    QString state() const { return m_state; }
    QString reason() const { return m_reason; }
    QString detail() const { return m_detail; }
    bool active() const { return m_state != QLatin1String("down"); }
    bool holdsDns() const { return m_holdsDns; }
    double rxBytes() const { return m_rx; }
    double txBytes() const { return m_tx; }
    double handshakeSec() const { return m_handshake; }
    QString endpointNow() const { return m_endpointNow; }
    QVariantMap details() const { return m_details; }
    bool detailsLoaded() const { return m_detailsLoaded; }
    QVariantMap tailnet() const { return m_tailnet; }
    QVariantList nodes() const { return m_nodes; }

    // From a profile.list item. true when anything changed.
    bool setSummary(const QVariantMap& item);
    void setAlwaysOn(bool on);
    // From an event=tunnel, a status item or a tunnel.up reply.
    void setTunnel(const QVariantMap& data);
    // Its tunnel is not in the daemon's table.
    void setDown();
    void setStats(const QVariantMap& data);
    void setDetails(const QVariantMap& reply);
    void setNodes(const QVariantList& items);

Q_SIGNALS:
    void changed();
    void statsChanged();
    void detailsChanged();
    void tailnetChanged();
    void nodesChanged();
    // For the service: the state moved from `was`.
    void stateMoved(const QString& was);

private:
    QString m_id;
    QString m_name;
    QString m_type;
    int m_order;
    bool m_alwaysOn;
    QString m_state;
    QString m_reason;
    QString m_detail;
    bool m_holdsDns;
    double m_rx;
    double m_tx;
    double m_handshake;
    QString m_endpointNow;
    QVariantMap m_details;
    bool m_detailsLoaded;
    QVariantMap m_tailnet;
    QVariantList m_nodes;
};

class ProfileList: public QObject
{
    Q_OBJECT
    // Profile objects in the daemon's order.
    Q_PROPERTY(QVariantList all READ all NOTIFY listChanged)
    Q_PROPERTY(int count READ count NOTIFY listChanged)
    // profile.list has been answered (once; it stays through a reconnect - the list is kept).
    Q_PROPERTY(bool loaded READ loaded NOTIFY loadedChanged)
    // Since this connection both the list and the tunnels (status) are in: what is up is known.
    Q_PROPERTY(bool ready READ ready NOTIFY readyChanged)
    // The always-on profiles' ids, "" for none: one WireGuard or AmneziaWG profile, one Tailscale profile.
    Q_PROPERTY(QString alwaysOn READ alwaysOn NOTIFY alwaysOnChanged)
    Q_PROPERTY(QString alwaysOnTailscale READ alwaysOnTailscale NOTIFY alwaysOnChanged)
    // The profiles whose tunnel the daemon holds - the Active Frame's rows.
    Q_PROPERTY(QVariantList active READ active NOTIFY activeChanged)
public:
    explicit ProfileList(DaemonClient* client, QObject* parent = 0);

    QVariantList all() const;
    int count() const { return m_list.size(); }
    bool loaded() const { return m_loaded; }
    bool ready() const { return m_listSeen && m_statusSeen; }
    QString alwaysOn() const { return m_alwaysOn; }
    QString alwaysOnTailscale() const { return m_alwaysOnTailscale; }
    QVariantList active() const;
    QList<Profile*> profiles() const { return m_list; }

    Q_INVOKABLE QObject* find(const QString& id) const;
    Q_INVOKABLE void up(const QString& id);
    Q_INVOKABLE void down(const QString& id);
    // The answer to conflict(): `from` down, then `id` up (its error entry is reused).
    Q_INVOKABLE void switchTo(const QString& id, const QString& from);
    Q_INVOKABLE void rename(const QString& id, const QString& name);
    Q_INVOKABLE void remove(const QString& id);
    // on: the profile is always on, in the place of the one of its kind. Off: it is not any more.
    Q_INVOKABLE void setAlwaysOn(const QString& id, bool on);
    // A new profile / a new .conf for one: the request's id, 0 when it could not be sent; the answer
    // comes as importDone(request, ...).
    Q_INVOKABLE int importProfile(const QString& name, const QString& conf);
    Q_INVOKABLE int replaceConf(const QString& id, const QString& conf);
    // A Tailscale profile from an auth key (profile.import type=tailscale; `hostname` - the name the
    // phone asks for in the tailnet), and logging in again with a new key (profile.update authkey=):
    // the request's id, 0 when it could not be sent; the answer comes as importDone().
    Q_INVOKABLE int importTailscale(const QString& name, const QString& authKey, const QString& hostname);
    Q_INVOKABLE int relogin(const QString& id, const QString& authKey);
    // The same by a link (login=link, TAILSCALE.md section 11b): no key - at its next start the tunnel
    // gets a login link from control and waits there (reason browser, tailnet.authUrl) until somebody
    // logs in at it on another device.
    Q_INVOKABLE int importTailscaleLink(const QString& name, const QString& hostname);
    Q_INVOKABLE int reloginLink(const QString& id);
    // tailscale.nodes into the profile's nodes: a page asks while it is open (the daemon answers
    // only while the tunnel is up - else the list empties).
    Q_INVOKABLE void loadNodes(const QString& id);
    // profile.get into the profile's details; kept current (a profile event loads them again) while
    // wanted - a profile page is open.
    Q_INVOKABLE void loadDetails(const QString& id);
    Q_INVOKABLE void releaseDetails(const QString& id);
    // Everything again: the list, always-on, the tunnels.
    Q_INVOKABLE void refresh();

Q_SIGNALS:
    void listChanged();
    void loadedChanged();
    void readyChanged();
    void alwaysOnChanged();
    void activeChanged();
    // A command failed: the daemon's errno (DAEMON: 1 request, 2 command, 3 profile, 4 conf,
    // 5 busy, 6 system) and its text.
    void failed(const QString& cmd, int code, const QString& error);
    // An import or a replaced .conf: done, or the daemon's error with its line (0 = none). `note` -
    // what the daemon adds (the new .conf takes effect from the next start).
    void importDone(int request, bool ok, const QString& id, const QString& error, int line, const QString& note);
    // tunnel.up of `id` met `holder` holding the default route.
    void conflict(const QString& id, const QString& holder);
    // For the service: a profile's state moved from `was`.
    void stateChanged(QObject* profile, const QString& was);
    // For the service: anything of a profile changed - its name, or its tunnel's reason alone (a
    // connection that does not come stays "connecting" and only gains a reason).
    void profileChanged(QObject* profile);

private Q_SLOTS:
    void onConnectedChanged();
    void onReplied(int id, const QString& cmd, const QVariantMap& reply, const QVariantList& items);
    void onEvent(const QString& kind, const QVariantMap& data);
    void onProfileStateMoved(const QString& was);
    void onProfileChanged();

private:
    void mergeList(const QVariantList& items);
    void setAlwaysOnId(const QString& id, const QString& tailscaleId);
    void applyStatus(const QVariantList& items);
    void updateActive();
    void sendDetails(const QString& id);
    Profile* profile(const QString& id) const;

    void setSeen(bool* flag);

    DaemonClient* m_client;
    QList<Profile*> m_list;
    QHash<QString, Profile*> m_byId;
    bool m_loaded;
    bool m_listSeen;
    bool m_statusSeen;
    QString m_alwaysOn;
    QString m_alwaysOnTailscale;
    QStringList m_activeIds;
    // Requests whose answer someone waits for: import / replace (-> importDone), details (-> the id).
    QSet<int> m_imports;
    QHash<int, QString> m_detailRequests;
    QHash<int, QString> m_nodeRequests;
    QHash<QString, int> m_detailsWanted;
    // A tunnel event for a profile the list does not have yet: a refresh is on its way.
    bool m_refreshing;
};

} // namespace tunnel

#endif /* TUNNEL_PROFILES_HPP_ */
