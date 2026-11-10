#include "DemoDaemon.hpp"
#include "DaemonClient.hpp"

#include <QDateTime>
#include <QTimer>
#include <QDebug>

namespace tunnel {

namespace {

QString s(const char* text)
{
    return QString::fromLatin1(text);
}

qint64 nowMs()
{
    return QDateTime::currentMSecsSinceEpoch();
}

} // namespace

DemoDaemon::DemoDaemon(DaemonClient* client) :
        QObject(client),
        m_client(client),
        m_flush(new QTimer(this)),
        m_tick(new QTimer(this)),
        m_stats(false),
        m_ticks(0),
        m_nextId(0),
        m_debugUntil(0)
{
    m_flush->setSingleShot(true);
    m_flush->setInterval(0);
    connect(m_flush, SIGNAL(timeout()), this, SLOT(flush()));
    m_tick->setInterval(500);
    connect(m_tick, SIGNAL(timeout()), this, SLOT(tick()));

    Tunnel home;
    home.id = s("0a1b2c3d");
    home.name = QString::fromUtf8("Home");
    home.type = s("amneziawg");
    home.order = 0;
    home.address << s("10.8.0.2/32") << s("fd00:8::2/128");
    home.dns << s("10.8.0.1");
    home.allowed << s("0.0.0.0/0") << s("::/0");
    home.endpoint = s("vpn.example.com:51820");
    home.publicKey = s("3gFzYq0dPqzJ4q1mH8tWk9Xc2vR7uLs5oNbE6yAiT0Q=");
    home.state = s("down");
    m_tunnels.append(home);

    Tunnel work;
    work.id = s("4e5f6a7b");
    work.name = s("Work");
    work.type = s("wireguard");
    work.order = 1;
    work.address << s("10.20.5.14/32");
    work.allowed << s("10.20.0.0/16");
    work.endpoint = s("203.0.113.40:51820");
    work.publicKey = s("kQ8bV2cX5zN1mL4pR7tY0wE3uI6oA9sD2fG5hJ8kL1M=");
    work.state = s("down");
    m_tunnels.append(work);

    Tunnel nas;
    nas.id = s("8c9d0e1f");
    nas.name = s("NAS");
    nas.type = s("wireguard");
    nas.order = 2;
    nas.address << s("192.168.77.3/32");
    nas.allowed << s("192.168.77.0/24");
    nas.endpoint = s("nas.example.org:51820");
    nas.publicKey = s("Z1xC4vB7nM0qW3eR6tY9uI2oP5aS8dF1gH4jK7lZ0XA=");
    nas.state = s("down");
    nas.silent = true;
    m_tunnels.append(nas);

    Tunnel tailnet;
    tailnet.id = s("2b3c4d5e");
    tailnet.name = s("Tailnet");
    tailnet.type = s("tailscale");
    tailnet.order = 3;
    tailnet.address << s("100.101.102.7/32") << s("fd7a:115c:a1e0::7/128");
    tailnet.publicKey = s("nodekey:5d9c7e1f0a3b2c4d6e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d");
    tailnet.state = s("down");
    m_tunnels.append(tailnet);
}

void DemoDaemon::start()
{
    QTimer::singleShot(300, this, SLOT(connectNow()));
    m_tick->start();
}

void DemoDaemon::connectNow()
{
    m_client->demoConnected();
}

void DemoDaemon::push(const QString& kind, const QString& what, const QVariantMap& block)
{
    Out out;
    out.kind = kind;
    out.what = what;
    out.block = block;
    out.block.insert(kind, what);
    m_out.append(out);
    m_flush->start();
}

void DemoDaemon::flush()
{
    // Taken out first: a receiver may send another command at once.
    const QList<Out> out = m_out;
    m_out.clear();
    for (int i = 0; i < out.size(); ++i) {
        m_client->receive(out.at(i).kind, out.at(i).what, out.at(i).block);
    }
}

void DemoDaemon::reply(int id, const QString& cmd, QVariantMap block, int code, const QString& error)
{
    block.insert(s("id"), QString::number(id));
    block.insert(s("errno"), QString::number(code));
    if (code != 0) {
        block.insert(s("error"), error);
    }
    push(s("reply"), cmd, block);
}

DemoDaemon::Tunnel* DemoDaemon::find(const QString& id)
{
    for (int i = 0; i < m_tunnels.size(); ++i) {
        if (m_tunnels.at(i).id == id) {
            return &m_tunnels[i];
        }
    }
    return 0;
}

bool DemoDaemon::full(const Tunnel& t) const
{
    return t.allowed.contains(s("0.0.0.0/0")) || t.allowed.contains(s("::/0"));
}

QVariantMap DemoDaemon::summary(const Tunnel& t) const
{
    QVariantMap m;
    m.insert(s("profile"), t.id);
    m.insert(s("name"), t.name);
    m.insert(s("type"), t.type);
    m.insert(s("created"), s("1790000000"));
    m.insert(s("order"), QString::number(t.order));
    m.insert(s("state"), t.state);
    m.insert(s("always_on"), s(t.id == m_alwaysOn || t.id == m_alwaysOnTailscale ? "1" : "0"));
    return m;
}

QVariantMap DemoDaemon::describe(const Tunnel& t) const
{
    QVariantMap m;
    m.insert(s("profile"), t.id);
    m.insert(s("state"), t.state);
    m.insert(s("reason"), t.reason);
    if (!t.detail.isEmpty()) {
        m.insert(s("detail"), t.detail);
    }
    if (t.state != QLatin1String("down")) {
        m.insert(s("ifname"), s("tun0"));
        if (!t.dns.isEmpty()) {
            m.insert(s("dns"), s("1"));
        }
    }
    if (t.type == QLatin1String("tailscale") && t.state != QLatin1String("down")) {
        m.insert(s("tailnet"), s("example.github"));
        m.insert(s("ts_address"), QStringList() << s("100.101.102.7") << s("fd7a:115c:a1e0::7"));
        m.insert(s("ts_name"), s("passport.tail4ab2c.ts.net."));
        m.insert(s("relay"), s("fra"));
        m.insert(s("relay_up"), s(t.relayUp ? "1" : "0"));
        m.insert(s("nodes"), s("4"));
        m.insert(s("nodes_active"), s(t.state == QLatin1String("up") ? "1" : "0"));
        if (t.reason == QLatin1String("browser")) {
            m.insert(s("auth_url"), s("https://login.tailscale.com/a/1f2e3d4c5b6a7980"));
        }
    }
    return m;
}

// The made-up tailnet: a NAS that is talked to, a laptop online, a phone and a Raspberry Pi off.
void DemoDaemon::nodes(int id, const Tunnel& t)
{
    static const char* const names[] = { "nas", "laptop", "pixel", "raspberrypi" };
    static const char* const v4[] = { "100.101.102.2", "100.101.102.3", "100.101.102.4", "100.101.102.5" };
    static const char* const online[] = { "1", "1", "0", "0" };
    // Home DERP regions as Tailscale numbers them: Frankfurt (4), Amsterdam (14); the Pi's never known.
    static const char* const relay[] = { "4", "4", "14", "" };
    const bool up = t.state == QLatin1String("up");
    for (int i = 0; i < 4; ++i) {
        QVariantMap item;
        item.insert(s("id"), QString::number(id));
        item.insert(s("name"), s(names[i]));
        item.insert(s("address"), QStringList() << s(v4[i]) << QString::fromLatin1("fd7a:115c:a1e0::%1").arg(i + 2));
        item.insert(s("online"), s(online[i]));
        if (relay[i][0]) {
            item.insert(s("relay"), s(relay[i]));
        }
        item.insert(s("active"), s(i == 0 && up ? "1" : "0"));
        if (i == 0 && up) {
            item.insert(s("rx_bytes"), QString::number((qint64)t.rx));
            item.insert(s("tx_bytes"), QString::number((qint64)t.tx));
        }
        push(s("item"), s("node"), item);
    }
    QVariantMap m;
    m.insert(s("count"), s("4"));
    reply(id, s("tailscale.nodes"), m);
}

void DemoDaemon::tunnelEvent(const Tunnel& t)
{
    push(s("event"), s("tunnel"), describe(t));
}

void DemoDaemon::profileEvent(const QString& id, const QString& action)
{
    QVariantMap m;
    m.insert(s("profile"), id);
    m.insert(s("action"), action);
    push(s("event"), s("profile"), m);
}

void DemoDaemon::request(int id, const QString& cmd, const QVariantMap& args)
{
    const QString profile = args.value(s("profile")).toString();

    if (cmd == QLatin1String("hello")) {
        QVariantMap m;
        m.insert(s("daemon"), s("demo"));
        m.insert(s("proto"), QString::number(DaemonClient::clientProto()));
        reply(id, cmd, m);
    } else if (cmd == QLatin1String("watch")) {
        m_stats = args.value(s("stats")).toString() == QLatin1String("1");
        reply(id, cmd, QVariantMap());
    } else if (cmd == QLatin1String("profile.list")) {
        for (int i = 0; i < m_tunnels.size(); ++i) {
            QVariantMap item = summary(m_tunnels.at(i));
            item.insert(s("id"), QString::number(id));
            push(s("item"), s("profile"), item);
        }
        QVariantMap m;
        m.insert(s("count"), QString::number(m_tunnels.size()));
        reply(id, cmd, m);
    } else if (cmd == QLatin1String("settings.get") || cmd == QLatin1String("settings.set")) {
        if (args.contains(s("always_on"))) {
            const QString ao = args.value(s("always_on")).toString();
            if (ao.isEmpty()) {
                m_alwaysOn.clear();
                m_alwaysOnTailscale.clear();
            } else {
                const Tunnel* t = find(ao);
                if (t == 0) {
                    reply(id, cmd, QVariantMap(), 3, s("always_on= names no profile"));
                    return;
                }
                if (t->type == QLatin1String("tailscale")) {
                    m_alwaysOnTailscale = ao;
                } else {
                    m_alwaysOn = ao;
                }
            }
        }
        if (args.contains(s("always_off"))) {
            const QString off = args.value(s("always_off")).toString();
            if (m_alwaysOn == off) {
                m_alwaysOn.clear();
            }
            if (m_alwaysOnTailscale == off) {
                m_alwaysOnTailscale.clear();
            }
        }
        QVariantMap m;
        m.insert(s("always_on"), m_alwaysOn);
        m.insert(s("always_on_tailscale"), m_alwaysOnTailscale);
        m.insert(s("kill_switch"), s("0"));
        reply(id, cmd, m);
    } else if (cmd == QLatin1String("status")) {
        int n = 0;
        for (int i = 0; i < m_tunnels.size(); ++i) {
            const Tunnel& t = m_tunnels.at(i);
            if (t.state == QLatin1String("down")) {
                continue;
            }
            QVariantMap item = describe(t);
            item.insert(s("id"), QString::number(id));
            item.insert(s("rx_bytes"), QString::number((qint64)t.rx));
            item.insert(s("tx_bytes"), QString::number((qint64)t.tx));
            item.insert(s("last_handshake_time_sec"), QString::number(t.handshake));
            push(s("item"), s("tunnel"), item);
            ++n;
        }
        QVariantMap m;
        m.insert(s("count"), QString::number(n));
        reply(id, cmd, m);
    } else if (cmd == QLatin1String("profile.get")) {
        Tunnel* t = find(profile);
        if (t == 0) {
            reply(id, cmd, QVariantMap(), 3, s("no such profile"));
            return;
        }
        QVariantMap m = summary(*t);
        if (t->type == QLatin1String("tailscale")) {
            m.insert(s("control"), s("https://controlplane.tailscale.com"));
            m.insert(s("login"), s(t->link ? "link" : "ok"));
            m.insert(s("hostname"), s("passport"));
            m.insert(s("node_key"), t->publicKey);
            m.insert(s("tailnet"), s("example.github"));
            m.insert(s("node_name"), s("passport.tail4ab2c.ts.net."));
            m.insert(s("address"), t->address);
            reply(id, cmd, m);
            return;
        }
        m.insert(s("public_key"), t->publicKey);
        m.insert(s("address"), t->address);
        m.insert(s("dns"), t->dns);
        m.insert(s("peers"), s("1"));
        m.insert(s("endpoint"), t->endpoint);
        m.insert(s("allowed_count"), QString::number(t->allowed.size()));
        m.insert(s("allowed"), t->allowed);
        if (t->type == QLatin1String("amneziawg")) {
            m.insert(s("mtu"), s("1380"));
        }
        reply(id, cmd, m);
    } else if (cmd == QLatin1String("tailscale.nodes")) {
        Tunnel* t = find(profile);
        if (t == 0) {
            reply(id, cmd, QVariantMap(), 3, s("no such profile"));
            return;
        }
        if (t->type != QLatin1String("tailscale")) {
            reply(id, cmd, QVariantMap(), 1, s("not a Tailscale profile"));
            return;
        }
        if (t->state == QLatin1String("down") || t->state == QLatin1String("error")) {
            reply(id, cmd, QVariantMap(), 5, s("the tunnel is not up: no netmap"));
            return;
        }
        nodes(id, *t);
    } else if ((cmd == QLatin1String("profile.import") && args.value(s("type")).toString() == QLatin1String("tailscale"))
            || (cmd == QLatin1String("profile.update") && (args.contains(s("authkey")) || args.contains(s("login"))))) {
        // Tailscale: any key of the admin console's form, or login=link; the login itself would happen
        // at tunnel.up - by a link it waits there a while, as if somebody logged in on another device.
        const QString key = args.value(s("authkey")).toString();
        const bool link = args.value(s("login")).toString() == QLatin1String("link");
        if (!link && (!key.startsWith(QLatin1String("tskey-")) || key.contains(QLatin1Char(' ')))) {
            reply(id, cmd, QVariantMap(), 1, s("authkey= missing or not an auth key (or login=link)"));
            return;
        }
        if (cmd == QLatin1String("profile.update")) {
            Tunnel* t = find(profile);
            if (t == 0) {
                reply(id, cmd, QVariantMap(), 3, s("no such profile"));
                return;
            }
            t->link = link;
            QVariantMap m;
            m.insert(s("profile"), t->id);
            if (t->state != QLatin1String("down")) {
                m.insert(s("note"), s(link ? "the tunnel asks for a login link from its next start"
                                           : "the tunnel logs in with it from its next start"));
            }
            reply(id, cmd, m);
            profileEvent(t->id, s("updated"));
            return;
        }
        Tunnel t;
        t.id = QString::fromLatin1("d%1").arg(++m_nextId, 7, 10, QLatin1Char('0'));
        t.name = args.value(s("name")).toString();
        t.type = s("tailscale");
        t.order = m_tunnels.size();
        t.address << s("100.101.102.9/32");
        t.publicKey = s("nodekey:0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0");
        t.state = s("down");
        t.link = link;
        m_tunnels.append(t);
        QVariantMap m;
        m.insert(s("profile"), t.id);
        reply(id, cmd, m);
        profileEvent(t.id, s("added"));
    } else if (cmd == QLatin1String("profile.import") || (cmd == QLatin1String("profile.update")
            && args.contains(s("conf")))) {
        const QString conf = args.value(s("conf")).toString();
        const QStringList lines = conf.split(QLatin1Char('\n'));
        int line = 0;
        bool iface = false;
        bool key = false;
        for (int i = 0; i < lines.size(); ++i) {
            const QString l = lines.at(i).trimmed();
            if (l == QLatin1String("[Interface]")) {
                iface = true;
            } else if (l.startsWith(QLatin1String("PrivateKey"))) {
                key = true;
                if (l.section(QLatin1Char('='), 1).trimmed().length() < 43) {
                    line = i + 1;
                    break;
                }
            }
        }
        if (line > 0) {
            QVariantMap m;
            m.insert(s("line"), QString::number(line));
            reply(id, cmd, m, 4, s("PrivateKey is not a key (44 characters of base64)"));
            return;
        }
        if (!iface || !key) {
            QVariantMap m;
            m.insert(s("line"), s("1"));
            reply(id, cmd, m, 4, s("no [Interface] with a PrivateKey"));
            return;
        }
        const bool awg = conf.contains(s("Jc")) || conf.contains(s("H1")) || conf.contains(s("S1"));
        if (cmd == QLatin1String("profile.update")) {
            Tunnel* t = find(profile);
            if (t == 0) {
                reply(id, cmd, QVariantMap(), 3, s("no such profile"));
                return;
            }
            t->type = s(awg ? "amneziawg" : "wireguard");
            QVariantMap m;
            m.insert(s("profile"), t->id);
            if (t->state != QLatin1String("down")) {
                m.insert(s("note"), s("the tunnel uses the new .conf from its next start"));
            }
            reply(id, cmd, m);
            profileEvent(t->id, s("updated"));
            return;
        }
        Tunnel t;
        t.id = QString::fromLatin1("d%1").arg(++m_nextId, 7, 10, QLatin1Char('0'));
        t.name = args.value(s("name")).toString();
        t.type = s(awg ? "amneziawg" : "wireguard");
        t.order = m_tunnels.size();
        t.address << s("10.99.0.2/32");
        t.allowed << s("0.0.0.0/0");
        t.endpoint = s("198.51.100.9:51820");
        t.publicKey = s("hN4mW7qE0rT3yU6iO9pA2sD5fG8hJ1kL4zX7cV0bN3Q=");
        t.state = s("down");
        m_tunnels.append(t);
        QVariantMap m;
        m.insert(s("profile"), t.id);
        reply(id, cmd, m);
        profileEvent(t.id, s("added"));
    } else if (cmd == QLatin1String("profile.update")) {
        Tunnel* t = find(profile);
        if (t == 0) {
            reply(id, cmd, QVariantMap(), 3, s("no such profile"));
            return;
        }
        if (args.contains(s("name"))) {
            t->name = args.value(s("name")).toString();
        }
        QVariantMap m;
        m.insert(s("profile"), t->id);
        reply(id, cmd, m);
        profileEvent(t->id, s("updated"));
    } else if (cmd == QLatin1String("profile.delete")) {
        for (int i = 0; i < m_tunnels.size(); ++i) {
            if (m_tunnels.at(i).id == profile) {
                m_tunnels.removeAt(i);
                if (m_alwaysOn == profile) {
                    m_alwaysOn.clear();
                }
                if (m_alwaysOnTailscale == profile) {
                    m_alwaysOnTailscale.clear();
                }
                QVariantMap m;
                m.insert(s("profile"), profile);
                reply(id, cmd, m);
                profileEvent(profile, s("deleted"));
                return;
            }
        }
        reply(id, cmd, QVariantMap(), 3, s("no such profile"));
    } else if (cmd == QLatin1String("tunnel.up")) {
        Tunnel* t = find(profile);
        if (t == 0) {
            reply(id, cmd, QVariantMap(), 3, s("no such profile"));
            return;
        }
        if (t->state != QLatin1String("down") && t->state != QLatin1String("error")) {
            reply(id, cmd, describe(*t));
            return;
        }
        if (full(*t)) {
            for (int i = 0; i < m_tunnels.size(); ++i) {
                const Tunnel& o = m_tunnels.at(i);
                if (o.id != t->id && o.state != QLatin1String("down") && o.state != QLatin1String("error") && full(o)) {
                    t->state = s("error");
                    t->reason = s("conflict");
                    t->detail = QString::fromLatin1("profile %1 already holds the default route").arg(o.id);
                    tunnelEvent(*t);
                    reply(id, cmd, describe(*t), 6, s("the tunnel did not come up: see reason and detail"));
                    return;
                }
            }
        }
        t->state = s("connecting");
        t->reason.clear();
        t->detail.clear();
        t->since = nowMs();
        tunnelEvent(*t);
        reply(id, cmd, describe(*t));
    } else if (cmd == QLatin1String("tunnel.down")) {
        Tunnel* t = find(profile);
        const bool was = t != 0 && t->state != QLatin1String("down");
        if (was) {
            t->state = s("down");
            t->reason.clear();
            t->detail.clear();
            t->relayUp = false;
            t->rx = 0;
            t->tx = 0;
            t->handshake = 0;
            tunnelEvent(*t);
        }
        QVariantMap m;
        m.insert(s("profile"), profile);
        m.insert(s("was_up"), s(was ? "1" : "0"));
        reply(id, cmd, m);
    } else if (cmd == QLatin1String("log.tail")) {
        QVariantMap m;
        m.insert(s("text"), s("2026-09-30 12:00:00.000 I bbtunneld demo starting\n"
                              "2026-09-30 12:00:00.100 I demo: no daemon, made-up profiles\n"));
        reply(id, cmd, m);
    } else if (cmd == QLatin1String("log.debug")) {
        // As the daemon: on=1 for 30 minutes, on=0 off, without on= the state.
        const QString on = args.value(s("on")).toString();
        if (on == QLatin1String("1")) {
            m_debugUntil = nowMs() + 30 * 60 * 1000;
        } else if (on == QLatin1String("0")) {
            m_debugUntil = 0;
        }
        const qint64 left = m_debugUntil > nowMs() ? (m_debugUntil - nowMs() + 999) / 1000 : 0;
        QVariantMap m;
        m.insert(s("debug"), s(left > 0 ? "1" : "0"));
        m.insert(s("left"), QString::number(left));
        reply(id, cmd, m);
    } else if (cmd == QLatin1String("daemon.restart")) {
        reply(id, cmd, QVariantMap());
    } else {
        reply(id, cmd, QVariantMap(), 2, s("no such command"));
    }
}

void DemoDaemon::tick()
{
    const qint64 now = nowMs();
    ++m_ticks;
    for (int i = 0; i < m_tunnels.size(); ++i) {
        Tunnel& t = m_tunnels[i];
        if (t.state == QLatin1String("connecting") || t.state == QLatin1String("reconnecting")) {
            if (t.silent) {
                if (t.reason.isEmpty() && now - t.since > 15000) {
                    t.reason = s("handshake");
                    t.detail = s("no answer from the server: its key, the protocol (AmneziaWG?) or a block");
                    tunnelEvent(t);
                }
                continue;
            }
            if (t.type == QLatin1String("tailscale")) {
                // By a link: control's link at 1 s, somebody logs in there at 25 s - then as with a key.
                if (t.link) {
                    if (now - t.since > 25000) {
                        t.link = false;
                        t.since = now;
                        t.reason.clear();
                        t.detail.clear();
                        tunnelEvent(t);
                    } else if (now - t.since > 1000 && t.reason.isEmpty()) {
                        t.reason = s("browser");
                        t.detail = s("waiting for a login at the link");
                        tunnelEvent(t);
                    }
                    continue;
                }
                // Control answers at 1 s - then the relay is what it waits for - and the relay at 2 s.
                if (now - t.since > 2000) {
                    t.state = s("up");
                    t.reason.clear();
                    t.relayUp = true;
                    t.handshake = QDateTime::currentDateTime().toTime_t();
                    tunnelEvent(t);
                } else if (now - t.since > 1000 && t.reason.isEmpty()) {
                    t.reason = s("relay");
                    tunnelEvent(t);
                }
                continue;
            }
            if (now - t.since > (t.type == QLatin1String("amneziawg") ? 1500 : 1000)) {
                t.state = s("up");
                t.handshake = QDateTime::currentDateTime().toTime_t();
                tunnelEvent(t);
            }
        } else if (t.state == QLatin1String("up")) {
            t.rx += 3000 + (m_ticks % 7) * 1500;
            t.tx += 700 + (m_ticks % 5) * 300;
            // A new handshake every two minutes, as WireGuard rekeys.
            if (QDateTime::currentDateTime().toTime_t() - t.handshake >= 120) {
                t.handshake = QDateTime::currentDateTime().toTime_t();
            }
        }
    }
    if (m_stats && m_ticks % 2 == 0) {
        for (int i = 0; i < m_tunnels.size(); ++i) {
            const Tunnel& t = m_tunnels.at(i);
            if (t.state == QLatin1String("down")) {
                continue;
            }
            QVariantMap m;
            m.insert(s("profile"), t.id);
            m.insert(s("rx_bytes"), QString::number((qint64)t.rx));
            m.insert(s("tx_bytes"), QString::number((qint64)t.tx));
            m.insert(s("last_handshake_time_sec"), QString::number(t.handshake));
            if (t.state == QLatin1String("up")) {
                m.insert(s("endpoint"), t.endpoint.startsWith(QLatin1String("vpn."))
                        ? s("203.0.113.7:51820") : t.endpoint);
            }
            push(s("event"), s("stats"), m);
        }
    }
}

} // namespace tunnel
