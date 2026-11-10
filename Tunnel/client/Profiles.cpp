#include "Profiles.hpp"
#include "DaemonClient.hpp"

#include <QRegExp>
#include <QtAlgorithms>
#include <QDebug>

namespace tunnel {

namespace {

// A single value. A key can come twice with the same value - a status item is the tunnel's
// description and its statistics, each with profile= - and then it is a list: its first.
QString str(const QVariantMap& m, const char* key)
{
    const QVariant v = m.value(QString::fromLatin1(key));
    if (v.type() == QVariant::StringList) {
        const QStringList l = v.toStringList();
        return l.isEmpty() ? QString() : l.first();
    }
    return v.toString();
}

// A key that may come once or repeated (address=, allowed=) as a list either way.
QStringList list(const QVariantMap& m, const char* key)
{
    const QVariant v = m.value(QString::fromLatin1(key));
    if (!v.isValid()) {
        return QStringList();
    }
    if (v.type() == QVariant::StringList) {
        return v.toStringList();
    }
    return QStringList(v.toString());
}

bool byOrder(const Profile* a, const Profile* b)
{
    return a->order() < b->order();
}

} // namespace

// --------------------------------------------------------------------- Profile

Profile::Profile(const QString& id, QObject* parent) :
        QObject(parent),
        m_id(id),
        m_order(0),
        m_alwaysOn(false),
        m_state(QString::fromLatin1("down")),
        m_holdsDns(false),
        m_rx(0),
        m_tx(0),
        m_handshake(0),
        m_detailsLoaded(false)
{
}

bool Profile::setSummary(const QVariantMap& item)
{
    const QString name = str(item, "name");
    const QString type = str(item, "type");
    const int order = str(item, "order").toInt();
    const bool alwaysOn = str(item, "always_on") == QLatin1String("1");
    const QString state = str(item, "state");
    bool any = false;

    if (name != m_name || type != m_type || order != m_order || alwaysOn != m_alwaysOn) {
        m_name = name;
        m_type = type;
        m_order = order;
        m_alwaysOn = alwaysOn;
        any = true;
    }
    // The list says only whether there is a tunnel; the reason and statistics come with the
    // tunnel's own blocks. It settles "down" - a tunnel the daemon no longer holds.
    if (!state.isEmpty() && state != m_state && state == QLatin1String("down")) {
        setDown();
        return true;
    }
    if (any) {
        emit changed();
    }
    return any;
}

void Profile::setAlwaysOn(bool on)
{
    if (on == m_alwaysOn) {
        return;
    }
    m_alwaysOn = on;
    emit changed();
}

void Profile::setTunnel(const QVariantMap& data)
{
    const QString state = str(data, "state");
    if (state.isEmpty()) {
        return;
    }
    // A Tailscale tunnel's own lines come in the same block; a change of them alone is news too
    // (the relay came up, a node joined).
    if (tailscale() && state != QLatin1String("down") && data.contains(QString::fromLatin1("relay_up"))) {
        QVariantMap t;
        t.insert(QString::fromLatin1("tailnet"), str(data, "tailnet"));
        t.insert(QString::fromLatin1("addresses"), list(data, "ts_address"));
        t.insert(QString::fromLatin1("name"), str(data, "ts_name"));
        t.insert(QString::fromLatin1("relay"), str(data, "relay"));
        t.insert(QString::fromLatin1("relayUp"), str(data, "relay_up") == QLatin1String("1"));
        t.insert(QString::fromLatin1("nodes"), str(data, "nodes").toInt());
        t.insert(QString::fromLatin1("nodesActive"), str(data, "nodes_active").toInt());
        t.insert(QString::fromLatin1("authUrl"), str(data, "auth_url"));
        if (t != m_tailnet) {
            m_tailnet = t;
            emit tailnetChanged();
        }
    }
    const QString was = m_state;
    const QString reason = str(data, "reason");
    const QString detail = str(data, "detail");
    const bool dns = str(data, "dns") == QLatin1String("1");
    if (state == m_state && reason == m_reason && detail == m_detail && dns == m_holdsDns) {
        return;
    }
    m_state = state;
    m_reason = reason;
    m_detail = detail;
    m_holdsDns = dns;
    if (state == QLatin1String("down") && (!m_tailnet.isEmpty() || !m_nodes.isEmpty())) {
        m_tailnet.clear();
        m_nodes.clear();
        emit tailnetChanged();
        emit nodesChanged();
    }
    if (state == QLatin1String("down") && (m_rx != 0 || m_tx != 0 || m_handshake != 0 || !m_endpointNow.isEmpty())) {
        m_rx = 0;
        m_tx = 0;
        m_handshake = 0;
        m_endpointNow.clear();
        emit statsChanged();
    }
    emit changed();
    if (was != state) {
        emit stateMoved(was);
    }
}

void Profile::setDown()
{
    QVariantMap down;
    down.insert(QString::fromLatin1("state"), QString::fromLatin1("down"));
    setTunnel(down);
}

void Profile::setStats(const QVariantMap& data)
{
    m_rx = str(data, "rx_bytes").toDouble();
    m_tx = str(data, "tx_bytes").toDouble();
    m_handshake = str(data, "last_handshake_time_sec").toDouble();
    m_endpointNow = str(data, "endpoint");
    // Every time, changed or not: statistics come once a second while a page shows them, and its
    // "handshake 38 s ago" moves with them.
    emit statsChanged();
}

void Profile::setDetails(const QVariantMap& reply)
{
    QVariantMap d;
    d.insert(QString::fromLatin1("public_key"), str(reply, "public_key"));
    d.insert(QString::fromLatin1("address"), list(reply, "address"));
    d.insert(QString::fromLatin1("dns"), list(reply, "dns"));
    d.insert(QString::fromLatin1("dns_search"), str(reply, "dns_search"));
    d.insert(QString::fromLatin1("mtu"), str(reply, "mtu"));
    d.insert(QString::fromLatin1("listen_port"), str(reply, "listen_port"));
    d.insert(QString::fromLatin1("peers"), str(reply, "peers").toInt());
    d.insert(QString::fromLatin1("endpoint"), list(reply, "endpoint"));
    d.insert(QString::fromLatin1("allowed_count"), str(reply, "allowed_count").toInt());
    const QStringList allowed = list(reply, "allowed");
    d.insert(QString::fromLatin1("allowed"), allowed);
    d.insert(QString::fromLatin1("full"),
            allowed.contains(QString::fromLatin1("0.0.0.0/0")) || allowed.contains(QString::fromLatin1("::/0")));
    // A Tailscale profile's (the daemon's cache of the last netmap among them).
    d.insert(QString::fromLatin1("control"), str(reply, "control"));
    d.insert(QString::fromLatin1("login"), str(reply, "login"));
    d.insert(QString::fromLatin1("hostname"), str(reply, "hostname"));
    d.insert(QString::fromLatin1("node_key"), str(reply, "node_key"));
    d.insert(QString::fromLatin1("tailnet"), str(reply, "tailnet"));
    d.insert(QString::fromLatin1("node_name"), str(reply, "node_name"));
    m_details = d;
    m_detailsLoaded = true;
    emit detailsChanged();
}

void Profile::setNodes(const QVariantList& items)
{
    QVariantList out;
    for (int i = 0; i < items.size(); ++i) {
        const QVariantMap item = items.at(i).toMap();
        QVariantMap n;
        n.insert(QString::fromLatin1("name"), str(item, "name"));
        n.insert(QString::fromLatin1("addresses"), list(item, "address"));
        n.insert(QString::fromLatin1("online"), str(item, "online"));
        n.insert(QString::fromLatin1("expired"), str(item, "expired") == QLatin1String("1"));
        n.insert(QString::fromLatin1("relay"), str(item, "relay").toInt());
        n.insert(QString::fromLatin1("active"), str(item, "active") == QLatin1String("1"));
        n.insert(QString::fromLatin1("rx"), str(item, "rx_bytes").toDouble());
        n.insert(QString::fromLatin1("tx"), str(item, "tx_bytes").toDouble());
        out.append(n);
    }
    if (out != m_nodes) {
        m_nodes = out;
        emit nodesChanged();
    }
}

// --------------------------------------------------------------------- ProfileList

ProfileList::ProfileList(DaemonClient* client, QObject* parent) :
        QObject(parent),
        m_client(client),
        m_loaded(false),
        m_listSeen(false),
        m_statusSeen(false),
        m_refreshing(false)
{
    connect(client, SIGNAL(connectedChanged()), this, SLOT(onConnectedChanged()));
    connect(client, SIGNAL(replied(int, const QString&, const QVariantMap&, const QVariantList&)),
            this, SLOT(onReplied(int, const QString&, const QVariantMap&, const QVariantList&)));
    connect(client, SIGNAL(event(const QString&, const QVariantMap&)),
            this, SLOT(onEvent(const QString&, const QVariantMap&)));
}

QVariantList ProfileList::all() const
{
    QVariantList out;
    for (int i = 0; i < m_list.size(); ++i) {
        out.append(QVariant::fromValue(static_cast<QObject*>(m_list.at(i))));
    }
    return out;
}

QVariantList ProfileList::active() const
{
    QVariantList out;
    for (int i = 0; i < m_list.size(); ++i) {
        if (m_list.at(i)->active()) {
            out.append(QVariant::fromValue(static_cast<QObject*>(m_list.at(i))));
        }
    }
    return out;
}

Profile* ProfileList::profile(const QString& id) const
{
    return m_byId.value(id, 0);
}

QObject* ProfileList::find(const QString& id) const
{
    return profile(id);
}

void ProfileList::onConnectedChanged()
{
    if (m_client->connected()) {
        refresh();
    }
}

void ProfileList::refresh()
{
    if (!m_client->connected()) {
        return;
    }
    const bool wasReady = ready();
    m_listSeen = false;
    m_statusSeen = false;
    if (wasReady) {
        emit readyChanged();
    }
    m_refreshing = true;
    m_client->send(QString::fromLatin1("profile.list"));
    m_client->send(QString::fromLatin1("settings.get"));
    m_client->send(QString::fromLatin1("status"));
    QHash<QString, int>::const_iterator it = m_detailsWanted.constBegin();
    for (; it != m_detailsWanted.constEnd(); ++it) {
        sendDetails(it.key());
    }
}

void ProfileList::onReplied(int id, const QString& cmd, const QVariantMap& reply, const QVariantList& items)
{
    const int code = str(reply, "errno").toInt();
    const QString error = str(reply, "error");

    if (m_imports.remove(id)) {
        emit importDone(id, code == 0, str(reply, "profile"), error, str(reply, "line").toInt(), str(reply, "note"));
        return;
    }
    if (m_detailRequests.contains(id)) {
        const QString profileId = m_detailRequests.take(id);
        Profile* p = profile(profileId);
        if (code == 0 && p) {
            p->setDetails(reply);
        }
        return;
    }
    if (m_nodeRequests.contains(id)) {
        Profile* p = profile(m_nodeRequests.take(id));
        if (p) {
            // The tunnel is not up (errno 5): no netmap, no nodes.
            p->setNodes(code == 0 ? items : QVariantList());
        }
        return;
    }

    if (cmd == QLatin1String("profile.list")) {
        m_refreshing = false;
        if (code != 0) {
            emit failed(cmd, code, error);
            return;
        }
        mergeList(items);
        if (!m_loaded) {
            m_loaded = true;
            emit loadedChanged();
        }
        setSeen(&m_listSeen);
    } else if (cmd == QLatin1String("settings.get") || cmd == QLatin1String("settings.set")) {
        if (code != 0) {
            emit failed(cmd, code, error);
            return;
        }
        setAlwaysOnId(str(reply, "always_on"), str(reply, "always_on_tailscale"));
    } else if (cmd == QLatin1String("status")) {
        if (code == 0) {
            applyStatus(items);
        }
        setSeen(&m_statusSeen);
    } else if (cmd == QLatin1String("tunnel.up")) {
        if (code == 0) {
            return;
        }
        if (str(reply, "reason") == QLatin1String("conflict")) {
            // "profile 3fa81c02 already holds the default route"
            QRegExp holder(QString::fromLatin1("\\b([0-9a-f]{8})\\b"));
            const QString detail = str(reply, "detail");
            emit conflict(str(reply, "profile"), holder.indexIn(detail) >= 0 ? holder.cap(1) : QString());
            return;
        }
        emit failed(cmd, code, error);
    } else if (cmd == QLatin1String("tunnel.down") || cmd == QLatin1String("profile.update")
            || cmd == QLatin1String("profile.delete")) {
        if (code != 0) {
            emit failed(cmd, code, error);
        }
    }
}

void ProfileList::onEvent(const QString& kind, const QVariantMap& data)
{
    if (kind == QLatin1String("tunnel")) {
        Profile* p = profile(str(data, "profile"));
        if (p == 0) {
            // A profile this list does not have yet: it comes with the next list.
            if (!m_refreshing) {
                refresh();
            }
            return;
        }
        p->setTunnel(data);
    } else if (kind == QLatin1String("stats")) {
        Profile* p = profile(str(data, "profile"));
        if (p) {
            p->setStats(data);
        }
    } else if (kind == QLatin1String("profile")) {
        // Added, renamed, a new .conf, deleted - by this app, the other process or btctl.
        m_client->send(QString::fromLatin1("profile.list"));
        const QString id = str(data, "profile");
        if (str(data, "action") == QLatin1String("deleted")) {
            // The daemon clears always-on together with its profile and says nothing else of it.
            m_client->send(QString::fromLatin1("settings.get"));
        } else if (m_detailsWanted.contains(id)) {
            sendDetails(id);
        }
    }
}

void ProfileList::mergeList(const QVariantList& items)
{
    QList<Profile*> next;
    QSet<QString> seen;
    bool membership = false;

    for (int i = 0; i < items.size(); ++i) {
        const QVariantMap item = items.at(i).toMap();
        const QString id = str(item, "profile");
        if (id.isEmpty() || seen.contains(id)) {
            continue;
        }
        Profile* p = profile(id);
        if (p == 0) {
            p = new Profile(id, this);
            connect(p, SIGNAL(stateMoved(const QString&)), this, SLOT(onProfileStateMoved(const QString&)));
            connect(p, SIGNAL(changed()), this, SLOT(onProfileChanged()));
            m_byId.insert(id, p);
            membership = true;
        }
        p->setSummary(item);
        next.append(p);
        seen.insert(id);
    }
    for (int i = 0; i < m_list.size(); ++i) {
        Profile* p = m_list.at(i);
        if (!seen.contains(p->id())) {
            m_byId.remove(p->id());
            m_detailsWanted.remove(p->id());
            // Never deleted while the app runs: a page still shows it until it closes (listChanged),
            // and QML holds it in an unguarded variant - a deleted one would be a dangling pointer
            // there. It stays a child of the list, "down", and goes with it at exit: a few bytes.
            p->setDown();
            membership = true;
        }
    }
    qStableSort(next.begin(), next.end(), byOrder);
    if (membership || next != m_list) {
        m_list = next;
        emit listChanged();
    }
    updateActive();
}

void ProfileList::setSeen(bool* flag)
{
    if (*flag) {
        return;
    }
    *flag = true;
    if (ready()) {
        emit readyChanged();
    }
}

void ProfileList::setAlwaysOnId(const QString& id, const QString& tailscaleId)
{
    for (int i = 0; i < m_list.size(); ++i) {
        const QString profileId = m_list.at(i)->id();
        m_list.at(i)->setAlwaysOn(profileId == id || profileId == tailscaleId);
    }
    if (id != m_alwaysOn || tailscaleId != m_alwaysOnTailscale) {
        m_alwaysOn = id;
        m_alwaysOnTailscale = tailscaleId;
        emit alwaysOnChanged();
    }
}

void ProfileList::applyStatus(const QVariantList& items)
{
    QSet<QString> held;
    for (int i = 0; i < items.size(); ++i) {
        const QVariantMap item = items.at(i).toMap();
        Profile* p = profile(str(item, "profile"));
        if (p == 0) {
            continue;
        }
        held.insert(p->id());
        p->setTunnel(item);
        p->setStats(item);
    }
    for (int i = 0; i < m_list.size(); ++i) {
        if (!held.contains(m_list.at(i)->id())) {
            m_list.at(i)->setDown();
        }
    }
    updateActive();
}

void ProfileList::onProfileStateMoved(const QString& was)
{
    Profile* p = qobject_cast<Profile*>(sender());
    if (p) {
        emit stateChanged(p, was);
    }
    updateActive();
}

void ProfileList::onProfileChanged()
{
    updateActive();
    Profile* p = qobject_cast<Profile*>(sender());
    if (p) {
        emit profileChanged(p);
    }
}

void ProfileList::updateActive()
{
    QStringList ids;
    for (int i = 0; i < m_list.size(); ++i) {
        if (m_list.at(i)->active()) {
            ids.append(m_list.at(i)->id());
        }
    }
    if (ids != m_activeIds) {
        m_activeIds = ids;
        emit activeChanged();
    }
}

void ProfileList::up(const QString& id)
{
    QVariantMap args;
    args.insert(QString::fromLatin1("profile"), id);
    m_client->send(QString::fromLatin1("tunnel.up"), args);
}

void ProfileList::down(const QString& id)
{
    QVariantMap args;
    args.insert(QString::fromLatin1("profile"), id);
    m_client->send(QString::fromLatin1("tunnel.down"), args);
}

void ProfileList::switchTo(const QString& id, const QString& from)
{
    // In this order over the one connection: the daemon takes them one after the other.
    if (!from.isEmpty()) {
        down(from);
    }
    up(id);
}

void ProfileList::rename(const QString& id, const QString& name)
{
    QVariantMap args;
    args.insert(QString::fromLatin1("profile"), id);
    args.insert(QString::fromLatin1("name"), name);
    m_client->send(QString::fromLatin1("profile.update"), args);
}

void ProfileList::remove(const QString& id)
{
    QVariantMap args;
    args.insert(QString::fromLatin1("profile"), id);
    m_client->send(QString::fromLatin1("profile.delete"), args);
}

void ProfileList::setAlwaysOn(const QString& id, bool on)
{
    QVariantMap args;
    if (on) {
        args.insert(QString::fromLatin1("always_on"), id);
    } else {
        args.insert(QString::fromLatin1("always_off"), id);
    }
    m_client->send(QString::fromLatin1("settings.set"), args);
}

int ProfileList::importProfile(const QString& name, const QString& conf)
{
    QVariantMap args;
    args.insert(QString::fromLatin1("name"), name);
    args.insert(QString::fromLatin1("conf"), conf);
    const int id = m_client->send(QString::fromLatin1("profile.import"), args);
    if (id > 0) {
        m_imports.insert(id);
    }
    return id;
}

int ProfileList::replaceConf(const QString& id, const QString& conf)
{
    QVariantMap args;
    args.insert(QString::fromLatin1("profile"), id);
    args.insert(QString::fromLatin1("conf"), conf);
    const int request = m_client->send(QString::fromLatin1("profile.update"), args);
    if (request > 0) {
        m_imports.insert(request);
    }
    return request;
}

int ProfileList::importTailscale(const QString& name, const QString& authKey, const QString& hostname)
{
    QVariantMap args;
    args.insert(QString::fromLatin1("type"), QString::fromLatin1("tailscale"));
    args.insert(QString::fromLatin1("name"), name);
    args.insert(QString::fromLatin1("authkey"), authKey.trimmed());
    if (!hostname.isEmpty()) {
        args.insert(QString::fromLatin1("hostname"), hostname);
    }
    const int id = m_client->send(QString::fromLatin1("profile.import"), args);
    if (id > 0) {
        m_imports.insert(id);
    }
    return id;
}

int ProfileList::relogin(const QString& id, const QString& authKey)
{
    QVariantMap args;
    args.insert(QString::fromLatin1("profile"), id);
    args.insert(QString::fromLatin1("authkey"), authKey.trimmed());
    const int request = m_client->send(QString::fromLatin1("profile.update"), args);
    if (request > 0) {
        m_imports.insert(request);
    }
    return request;
}

int ProfileList::importTailscaleLink(const QString& name, const QString& hostname)
{
    QVariantMap args;
    args.insert(QString::fromLatin1("type"), QString::fromLatin1("tailscale"));
    args.insert(QString::fromLatin1("name"), name);
    args.insert(QString::fromLatin1("login"), QString::fromLatin1("link"));
    if (!hostname.isEmpty()) {
        args.insert(QString::fromLatin1("hostname"), hostname);
    }
    const int id = m_client->send(QString::fromLatin1("profile.import"), args);
    if (id > 0) {
        m_imports.insert(id);
    }
    return id;
}

int ProfileList::reloginLink(const QString& id)
{
    QVariantMap args;
    args.insert(QString::fromLatin1("profile"), id);
    args.insert(QString::fromLatin1("login"), QString::fromLatin1("link"));
    const int request = m_client->send(QString::fromLatin1("profile.update"), args);
    if (request > 0) {
        m_imports.insert(request);
    }
    return request;
}

void ProfileList::loadNodes(const QString& id)
{
    QVariantMap args;
    args.insert(QString::fromLatin1("profile"), id);
    const int request = m_client->send(QString::fromLatin1("tailscale.nodes"), args);
    if (request > 0) {
        m_nodeRequests.insert(request, id);
    }
}

void ProfileList::loadDetails(const QString& id)
{
    m_detailsWanted[id] += 1;
    sendDetails(id);
}

void ProfileList::releaseDetails(const QString& id)
{
    QHash<QString, int>::iterator it = m_detailsWanted.find(id);
    if (it == m_detailsWanted.end()) {
        return;
    }
    if (--it.value() <= 0) {
        m_detailsWanted.erase(it);
    }
}

void ProfileList::sendDetails(const QString& id)
{
    QVariantMap args;
    args.insert(QString::fromLatin1("profile"), id);
    const int request = m_client->send(QString::fromLatin1("profile.get"), args);
    if (request > 0) {
        m_detailRequests.insert(request, id);
    }
}

} // namespace tunnel
