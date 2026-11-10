/*
 * client_test - the app's and the service's own C++ (client/) against a real bbtunneld: what the screens
 * would show and what the Hub would get, step by step, while the daemon answers, restarts and dies. The
 * protocol, the model and the service's decisions are the code the phone runs; only BB10's platform
 * classes are stubs (stubs/bbstub.h: a notification lands in a map instead of the Hub).
 *
 *   client_test --app DIR --work DIR   the real daemon. Run by daemon/test/e2e/run.sh client, inside the
 *                                      phone's namespace, the daemon under a restart loop like the
 *                                      phone's launcher. DIR is the "sandbox" (data/daemon.sock,
 *                                      data/Settings); WORK holds the e2e world's files (phone.conf,
 *                                      split.conf, full2.conf, bad.conf, silent.conf, phone.pub) and
 *                                      the loop's daemon.pid and "pause" switch.
 *   client_test --tailscale --app DIR --work DIR
 *                                      a Tailscale profile against the real daemon on the Tailscale stand:
 *                                      run by daemon/test/ts/e2e.sh client; WORK holds the stand's auth
 *                                      keys, control URL, the NAS's address and two hooks (runTailscale).
 *   client_test --demo                 the same client against the demo daemon (client/DemoDaemon): no
 *                                      daemon, no root. The demo must speak as the daemon does, or the
 *                                      screens checked in demo mode prove little.
 *   client_test --keys                 AmneziaVPN keys (client/gui/AmneziaKey), made here as its app
 *                                      makes them: the text, the QR series, what is no connection.
 *
 * Build: client/test/build.sh (WSL, Qt 5 - the phone has 4.8, the client code builds for both).
 */

#include "DaemonClient.hpp"
#include "Profiles.hpp"
#include "TunnelSettings.hpp"
#include "gui/AmneziaKey.hpp"
#include "gui/Importer.hpp"
#include "service/Notifier.hpp"

#include <bb/device/HardwareInfo>
#include <bb/platform/Notification>

#include <QCoreApplication>
#include <QDataStream>
#include <QDateTime>
#include <QDir>
#include <QElapsedTimer>
#include <QEventLoop>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QPair>
#include <QProcess>
#include <QRegExp>
#include <QSettings>
#include <QStringList>
#include <QTimer>

#include <cstdio>
#include <functional>

using namespace tunnel;

namespace {

int g_failed = 0;

QString u(const char* text)
{
    return QString::fromUtf8(text);
}

void section(const char* name)
{
    printf("== %s\n", name);
    fflush(stdout);
}

void step(const QString& name, bool ok)
{
    printf("   %s  %s\n", ok ? "ok  " : "FAIL", name.toUtf8().constData());
    fflush(stdout);
    if (!ok) {
        g_failed = 1;
    }
}

// The event loop runs until cond() holds or `ms` pass.
bool within(int ms, const std::function<bool()>& cond)
{
    QElapsedTimer t;
    t.start();
    while (!cond()) {
        if (t.elapsed() >= ms) {
            return false;
        }
        QEventLoop loop;
        QTimer::singleShot(20, &loop, SLOT(quit()));
        loop.exec();
    }
    return true;
}

// The event loop runs for `ms`, whatever happens.
void idle(int ms)
{
    within(ms, [] { return false; });
}

int sh(const QString& command)
{
    return QProcess::execute(u("/bin/sh"), QStringList() << u("-c") << command);
}

QString readFile(const QString& path)
{
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly)) {
        return QString();
    }
    return QString::fromUtf8(f.readAll());
}

Profile* prof(const ProfileList& list, const QString& id)
{
    return static_cast<Profile*>(list.find(id));
}

Profile* byName(const ProfileList& list, const QString& name)
{
    const QList<Profile*> all = list.profiles();
    for (int i = 0; i < all.size(); ++i) {
        if (all.at(i)->name() == name) {
            return all.at(i);
        }
    }
    return 0;
}

QStringList names(const ProfileList& list)
{
    QStringList out;
    const QList<Profile*> all = list.profiles();
    for (int i = 0; i < all.size(); ++i) {
        out << all.at(i)->name();
    }
    return out;
}

bool inHub(const QString& key)
{
    return bbstub::hub().contains(key);
}

bbstub::Posted posted(const QString& key)
{
    return bbstub::hub().value(key);
}

QString keyOf(const QString& profileId)
{
    return u("tunnel_") + profileId;
}

// What a list says, for the checks: imports answered, failures, conflicts, state moves.
struct Recorder {
    struct Import {
        Import() : done(false), ok(false), line(0) {}
        bool done;
        bool ok;
        QString id;
        QString error;
        int line;
        QString note;
    };

    QMap<int, Import> imports;
    QList<QPair<QString, int> > failures;
    QList<QPair<QString, QString> > conflicts;
    QStringList moves;

    explicit Recorder(ProfileList* list)
    {
        QObject::connect(list, &ProfileList::importDone,
                [this](int request, bool ok, const QString& id, const QString& error, int line, const QString& note) {
                    Import& i = imports[request];
                    i.done = true;
                    i.ok = ok;
                    i.id = id;
                    i.error = error;
                    i.line = line;
                    i.note = note;
                });
        QObject::connect(list, &ProfileList::failed, [this](const QString& cmd, int code, const QString&) {
            failures.append(qMakePair(cmd, code));
        });
        QObject::connect(list, &ProfileList::conflict, [this](const QString& id, const QString& holder) {
            conflicts.append(qMakePair(id, holder));
        });
        QObject::connect(list, &ProfileList::stateChanged, [this](QObject* p, const QString& was) {
            Profile* profile = static_cast<Profile*>(p);
            moves << profile->id() + u(":") + was + u(">") + profile->state();
        });
    }

    bool failed(const char* cmd, int code) const
    {
        return failures.contains(qMakePair(u(cmd), code));
    }

    bool failedAny(const char* cmd) const
    {
        for (int i = 0; i < failures.size(); ++i) {
            if (failures.at(i).first == u(cmd)) {
                return true;
            }
        }
        return false;
    }

    // Waits for an import's answer; its id when it went through, "" when not.
    QString answer(int request, int ms = 5000)
    {
        if (request <= 0 || !within(ms, [&] { return imports.value(request).done; })) {
            return QString();
        }
        return imports.value(request).ok ? imports.value(request).id : QString();
    }
};

// The world around the phone: the e2e's files, the daemon's restart loop, the other namespace.
struct World {
    QString work;

    QString conf(const char* name) const { return readFile(work + u("/") + u(name)); }
    void pause() const { QFile f(work + u("/pause")); f.open(QIODevice::WriteOnly); }
    void resume() const { QFile::remove(work + u("/pause")); }
    int kill(const char* sig) const { return sh(QString(u("kill -%1 \"$(cat '%2/daemon.pid')\"")).arg(u(sig), work)); }
    int inet(const QString& command) const { return sh(u("ip netns exec bt-inet ") + command); }
    // The network manager: what it writes when the phone changes networks (e2e run.sh, $RESOLV).
    int resolv(const char* server) const
    {
        return sh(QString(u("printf 'nameserver %1\\n' > /etc/netns/bt-phone/resolv.conf")).arg(u(server)));
    }
};

// ----------------------------------------------------------------------- AmneziaVPN keys, made as its app makes them

// exportController.cpp: qCompress(JSON, 8), base64url without padding, "vpn://".
QString vpnKey(const QJsonObject& root, bool prefix = true)
{
    const QByteArray packed = qCompress(QJsonDocument(root).toJson(), 8);
    const QString b64 = QString::fromLatin1(packed.toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals));
    return prefix ? u("vpn://") + b64 : b64;
}

// qrCodeUtils.cpp: the compressed JSON in parts of 850 bytes, each a QDataStream of magic, count,
// index and the part, as base64url.
QStringList qrSeries(const QJsonObject& root)
{
    const QByteArray data = qCompress(QJsonDocument(root).toJson(), 8);
    const int k = 850;
    const quint8 count = (quint8)((data.size() + k - 1) / k);
    QStringList out;
    for (int i = 0; i < data.size(); i += k) {
        QByteArray chunk;
        QDataStream s(&chunk, QIODevice::WriteOnly);
        s << (qint16)1984 << count << (quint8)(i / k) << data.mid(i, k);
        out << QString::fromLatin1(chunk.toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals));
    }
    return out;
}

// A connection key: one container, its client's last_config holding the .conf (awgProtocolConfig.cpp,
// selfHostedAdminServerConfig.cpp - the fields a shared connection carries).
QJsonObject connectionKey(const char* container, const char* proto, const QString& conf, const QJsonObject& root)
{
    QJsonObject client;
    if (!conf.isEmpty()) {
        client[u("config")] = conf;
    }
    client[u("hostName")] = root.value(u("hostName")).toString();
    client[u("mtu")] = u("1376");
    QJsonObject protocol;
    protocol[u("port")] = u("51820");
    protocol[u("transport_proto")] = u("udp");
    protocol[u("last_config")] = QString::fromUtf8(QJsonDocument(client).toJson(QJsonDocument::Compact));
    QJsonObject c;
    c[u("container")] = u(container);
    c[proto] = protocol;
    QJsonObject key = root;
    key[u("format_version")] = 1;
    key[u("containers")] = QJsonArray() << c;
    key[u("defaultContainer")] = u(container);
    return key;
}

bool has(const QString& conf, const char* line)
{
    return conf.split(QLatin1Char('\n')).contains(u(line));
}

int runKeys()
{
    Importer importer;
    const QString awgText = u(
            "[Interface]\nAddress = 10.8.1.5/32\nDNS = $PRIMARY_DNS, $SECONDARY_DNS\n"
            "PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=\nJc = 4\nJmin = 10\nJmax = 50\n"
            "S1 = 24\nS2 = 32\nS3 = 16\nS4 = 20\nH1 = 100000-100999\nH2 = 200000-200999\nH3 = 300000-300999\n"
            "H4 = 400000-499999\nI1 = <r 2><b 0x858000010001000000000669636c6f756403636f6d0000010001>\nI2 = \n"
            "I3 = \nI4 = \nI5 = \n\n[Peer]\nPublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\n"
            "PresharedKey = FpCyhws9cxwWoV4xELtfJvjJN+zQVRPISllRWgeopVE=\nAllowedIPs = 0.0.0.0/0, ::/0\n"
            "Endpoint = 203.0.113.9:51820\nPersistentKeepalive = 25-35\n");
    QJsonObject root;
    root[u("description")] = u("Мой сервер");
    root[u("hostName")] = u("203.0.113.9");
    root[u("dns1")] = u("172.29.172.254");

    section("keys 1. a connection key");
    const QJsonObject awgKey = connectionKey("amnezia-awg2", "awg", awgText, root);
    AmneziaKey::Result r = AmneziaKey::fromText(vpnKey(awgKey));
    step(u("vpn://: read, named as in AmneziaVPN (") + r.name + u(")"), r.ok && r.name == u("Мой сервер"));
    step(u("its .conf: the keys, the obfuscation, the server"), has(r.conf, "PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=")
            && has(r.conf, "H4 = 400000-499999") && has(r.conf, "S3 = 16") && has(r.conf, "PersistentKeepalive = 25-35")
            && has(r.conf, "Endpoint = 203.0.113.9:51820") && has(r.conf, "PresharedKey = FpCyhws9cxwWoV4xELtfJvjJN+zQVRPISllRWgeopVE="));
    step(u("DNS: the key's dns1 (AmneziaDNS), the default for the missing dns2"), has(r.conf, "DNS = 172.29.172.254, 1.0.0.1"));
    step(u("lines left without a value dropped (I2-I5)"), !r.conf.contains(u("I2")) && !r.conf.contains(u("I5")));
    step(u("the phone's MTU added, once, in [Interface]"), r.conf.count(u("MTU")) == 1
            && r.conf.indexOf(u("MTU = 1280")) < r.conf.indexOf(u("[Peer]")));
    step(u("without the prefix: the same"), AmneziaKey::fromText(vpnKey(awgKey, false)).conf == r.conf);
    step(u("the JSON itself: the same"), AmneziaKey::fromText(QString::fromUtf8(QJsonDocument(awgKey).toJson())).conf == r.conf);
    step(u("wrapped by a mail (spaces, line breaks): the same"),
            AmneziaKey::fromText(vpnKey(awgKey).insert(40, u("\n  ")).insert(90, u(" "))).conf == r.conf);
    const QVariantMap viaImporter = importer.fromAmneziaKey(vpnKey(awgKey));
    step(u("through the importer, as QML gets it"), viaImporter.value(u("ok")).toBool()
            && viaImporter.value(u("conf")).toString() == r.conf && importer.kind(vpnKey(awgKey)) == u("amnezia-key"));

    QJsonObject noDns = root;
    noDns.remove(u("dns1"));
    noDns[u("dns2")] = u("not-an-address");
    r = AmneziaKey::fromText(vpnKey(connectionKey("amnezia-wireguard", "wireguard", awgText, noDns)));
    step(u("no usable DNS in the key: 1.1.1.1, 1.0.0.1"), r.ok && has(r.conf, "DNS = 1.1.1.1, 1.0.0.1"));

    // An older or third-party share: fields, no text.
    QJsonObject fields;
    fields[u("hostName")] = u("vpn.example.com");
    fields[u("port")] = 51820;
    fields[u("client_ip")] = u("10.8.1.7");
    fields[u("client_priv_key")] = u("yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=");
    fields[u("server_pub_key")] = u("xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=");
    fields[u("allowed_ips")] = QJsonArray() << u("0.0.0.0/0") << u("::/0");
    fields[u("Jc")] = u("3");
    fields[u("H1")] = u("1234");
    QJsonObject protocol;
    protocol[u("last_config")] = QString::fromUtf8(QJsonDocument(fields).toJson(QJsonDocument::Compact));
    QJsonObject c;
    c[u("container")] = u("amnezia-awg");
    c[u("awg")] = protocol;
    QJsonObject fieldsKey;
    fieldsKey[u("containers")] = QJsonArray() << c;
    fieldsKey[u("hostName")] = u("vpn.example.com");
    r = AmneziaKey::fromText(vpnKey(fieldsKey));
    step(u("fields only: the .conf built from them"), r.ok && has(r.conf, "Address = 10.8.1.7/32")
            && has(r.conf, "Endpoint = vpn.example.com:51820") && has(r.conf, "Jc = 3") && has(r.conf, "H1 = 1234")
            && has(r.conf, "AllowedIPs = 0.0.0.0/0, ::/0") && has(r.conf, "DNS = 1.1.1.1, 1.0.0.1"));
    step(u("... named by its host"), r.name == u("vpn.example.com"));

    section("keys 2. the QR series");
    // A big one: a description that does not compress, as a long split-tunnel config would not.
    QByteArray noise;
    for (int i = 0; i < 1500; ++i) {
        noise.append((char)(qrand() & 0xff));
    }
    QJsonObject bigRoot = root;
    bigRoot[u("description")] = QString::fromLatin1(noise.toHex());
    const QJsonObject bigKey = connectionKey("amnezia-awg2", "awg", awgText, bigRoot);
    const QStringList parts = qrSeries(bigKey);
    step(u("two parts or more (") + QString::number(parts.size()) + u(")"), parts.size() >= 2);
    importer.qrReset();
    QVariantMap fed = importer.qrFeed(parts.at(1));
    step(u("a part: 1 of ") + QString::number(parts.size()), fed.value(u("state")).toString() == u("part")
            && fed.value(u("received")).toInt() == 1 && fed.value(u("total")).toInt() == parts.size());
    fed = importer.qrFeed(parts.at(1));
    step(u("the same part again: still 1"), fed.value(u("received")).toInt() == 1);
    for (int i = 0; i < parts.size(); ++i) {
        if (i != 1) {
            fed = importer.qrFeed(parts.at(i));
        }
    }
    step(u("all parts: the whole key"), fed.value(u("state")).toString() == u("text")
            && fed.value(u("text")).toString().startsWith(u("vpn://")));
    r = AmneziaKey::fromText(fed.value(u("text")).toString());
    step(u("... made the same .conf as the key's text"), r.ok && r.conf == AmneziaKey::fromText(vpnKey(bigKey)).conf);
    importer.qrReset();
    fed = importer.qrFeed(qrSeries(awgKey).at(0));
    step(u("a key in one part: at once"), fed.value(u("state")).toString() == u("text")
            && AmneziaKey::fromText(fed.value(u("text")).toString()).conf == AmneziaKey::fromText(vpnKey(awgKey)).conf);
    fed = importer.qrFeed(awgText);
    step(u("a QR code with a .conf: its text as it is"), fed.value(u("state")).toString() == u("text")
            && fed.value(u("text")).toString() == awgText);
    fed = importer.qrFeed(vpnKey(awgKey));
    step(u("a QR code with a key's text: as it is"), fed.value(u("text")).toString() == vpnKey(awgKey));

    section("keys 3. what is not a connection");
    QJsonObject sub;
    sub[u("name")] = u("Amnezia Premium");
    sub[u("config_version")] = 2;
    sub[u("api_config")] = QJsonObject();
    QJsonObject auth;
    auth[u("api_key")] = u("secret");
    sub[u("auth_data")] = auth;
    // apiUtils.cpp: the signature 000000ff in the size's place, then the raw zlib stream.
    const QByteArray signedData = QByteArray::fromHex("000000ff") + qCompress(QJsonDocument(sub).toJson(), 6).mid(4);
    r = AmneziaKey::fromText(u("vpn://") + QString::fromLatin1(signedData.toBase64(QByteArray::Base64UrlEncoding)));
    step(u("a subscription key (signed, 000000ff): said so"), !r.ok && r.error == u("subscription"));
    QJsonObject full = connectionKey("amnezia-awg2", "awg", QString(), root);
    full[u("userName")] = u("root");
    full[u("password")] = u("secret");
    r = AmneziaKey::fromText(vpnKey(full));
    step(u("a full-access key (the server's SSH login): said so"), !r.ok && r.error == u("full-access"));
    QJsonObject ovpn;
    ovpn[u("container")] = u("amnezia-openvpn");
    ovpn[u("openvpn")] = QJsonObject();
    QJsonObject dns;
    dns[u("container")] = u("amnezia-dns");
    QJsonObject other;
    other[u("containers")] = QJsonArray() << ovpn << dns;
    r = AmneziaKey::fromText(vpnKey(other));
    step(u("OpenVPN only: the protocols named (") + r.detail + u(")"), !r.ok && r.error == u("other-protocols")
            && r.detail == u("OpenVPN"));
    r = AmneziaKey::fromText(vpnKey(connectionKey("amnezia-awg2", "awg", QString(), root)));
    step(u("AmneziaWG without a connection in it: said so"), !r.ok && r.error == u("no-connection"));
    const QString whole = vpnKey(awgKey);
    r = AmneziaKey::fromText(whole.left(whole.size() / 2));
    step(u("cut short: damaged"), !r.ok && r.error == u("damaged"));
    r = AmneziaKey::fromText(u("vpn://not a key at all!"));
    step(u("not base64: damaged"), !r.ok && r.error == u("damaged"));
    // 64 KB of zeros compress to almost nothing; a size far past the bound is refused, not inflated.
    QByteArray bomb = qCompress(QByteArray(2 * 1024 * 1024, 'x'), 9);
    r = AmneziaKey::fromText(u("vpn://") + QString::fromLatin1(bomb.toBase64(QByteArray::Base64UrlEncoding)));
    step(u("2 MB inside a small key: refused, not inflated whole"), !r.ok && r.error == u("damaged"));

    section("keys 4. Tailscale");
    step(u("an auth key is told apart"), importer.kind(u("  tskey-auth-kAbc1CNTRL-0123\n")) == u("tailscale-key")
            && importer.kind(u("tskey-auth with words")) == u("other") && importer.kind(u("tskeyless")) == u("other"));
    bb::device::HardwareInfo::model() = u("Passport");
    step(u("the phone's name in a tailnet: passport"), importer.deviceHostname() == u("passport"));
    bb::device::HardwareInfo::model() = u("BlackBerry Classic");
    step(u("... the brand dropped: classic"), importer.deviceHostname() == u("classic"));
    bb::device::HardwareInfo::model() = u("Q10 (SQN100-3)");
    step(u("... one DNS label: q10-sqn100-3"), importer.deviceHostname() == u("q10-sqn100-3"));
    bb::device::HardwareInfo::model() = u("??");
    step(u("... nothing usable: blackberry"), importer.deviceHostname() == u("blackberry"));
    bb::device::HardwareInfo::model() = u("Passport");

    return g_failed;
}

// A silent profile of its own: its own networks, a server that never answers.
QString deadConf(const World& w, int n)
{
    QString c = w.conf("silent.conf");
    c.replace(QRegExp(u("Address = [^\n]*")), QString(u("Address = 10.95.%1.2/32")).arg(n));
    c.replace(QRegExp(u("AllowedIPs = [^\n]*")), QString(u("AllowedIPs = 10.95.%1.0/24")).arg(n));
    return c;
}

// ----------------------------------------------------------------------- the real daemon

int runReal(const World& w)
{
    // The phone after a boot: the app (or the service) may start before the daemon does.
    section("client 0. before the daemon");
    const QString sock = DaemonClient::socketPath();
    w.pause();
    w.kill("TERM");
    within(5000, [&] { return !QFileInfo(sock).exists(); });
    DaemonClient early(false);
    DaemonClient waiting(false);
    early.start();
    waiting.start();
    // The tries at 1, 3 and 8 s fail; the next is 10 s away.
    idle(9000);
    step(u("no daemon yet: not connected, still trying"), !early.connected() && !waiting.connected());
    w.resume();
    step(u("the daemon comes"), within(5000, [&] { return QFileInfo(sock).exists(); }));
    idle(300);
    early.retryNow();
    step(u("'Retry': connected at once"), within(1000, [&] { return early.connected(); }));
    step(u("without it: connected by the next try"), within(15000, [&] { return waiting.connected(); }));

    DaemonClient app(false);
    ProfileList list(&app);
    Recorder rec(&list);

    section("client 1. connect");
    app.start();
    step(u("connected"), within(5000, [&] { return app.connected(); }));
    step(u("the daemon is this build's (") + app.daemonVersion() + u(") - no restart asked (APP section 9)"),
            app.daemonVersion() == DaemonClient::bundledVersion());
    step(u("... its protocol ours"), app.protoVersion() == DaemonClient::clientProto());
    step(u("the list is ready: profiles and tunnels in"), within(5000, [&] { return list.ready(); }));
    step(u("... loaded, empty"), list.loaded() && list.count() == 0);

    section("client 2. import, details");
    int r = list.importProfile(u("Bad"), w.conf("bad.conf"));
    rec.answer(r);
    step(u("a broken .conf: refused with its line (") + rec.imports.value(r).error + u(")"),
            rec.imports.value(r).done && !rec.imports.value(r).ok && rec.imports.value(r).line == 2);
    const QString home = rec.answer(list.importProfile(u("Home"), w.conf("phone.conf")));
    step(u("import: an id (") + home + u(")"), QRegExp(u("[0-9a-f]{8}")).exactMatch(home));
    step(u("the list has it"), within(3000, [&] { return list.count() == 1 && prof(list, home) != 0; }));
    Profile* h = prof(list, home);
    if (h == 0) {
        step(u("no profile to go on with"), false);
        return 1;
    }
    step(u("... Home, WireGuard, down, switch off"),
            h->name() == u("Home") && h->type() == u("wireguard") && !h->amnezia() && h->state() == u("down")
            && !h->active());
    list.loadDetails(home);
    step(u("details: loaded"), within(3000, [&] { return h->detailsLoaded(); }));
    const QVariantMap d = h->details();
    step(u("details: our public key"), d.value(u("public_key")).toString() == w.conf("phone.pub").trimmed());
    step(u("details: both addresses"),
            d.value(u("address")).toStringList() == (QStringList() << u("10.99.0.2/32") << u("fd99::2/128")));
    step(u("details: DNS and its search domain"),
            d.value(u("dns")).toStringList() == QStringList(u("10.99.0.1"))
            && d.value(u("dns_search")).toString() == u("test.lan"));
    step(u("details: MTU, one server as the .conf names it"),
            d.value(u("mtu")).toString() == u("1380") && d.value(u("peers")).toInt() == 1
            && d.value(u("endpoint")).toStringList() == QStringList(u("vpn.test:51820")));
    step(u("details: all traffic"), d.value(u("full")).toBool() && d.value(u("allowed_count")).toInt() == 2);
    step(u("a .conf bigger than a block: not sent (0)"),
            list.importProfile(u("Big"), QString(300 * 1024, QLatin1Char('x'))) == 0);

    section("client 3. up, statistics");
    rec.moves.clear();
    list.up(home);
    step(u("up within 15 s"), within(15000, [&] { return h->state() == u("up"); }));
    step(u("... through connecting: ") + rec.moves.join(u(", ")),
            rec.moves == (QStringList() << home + u(":down>connecting") << home + u(":connecting>up")));
    step(u("the switch on, the Active Frame lists it"), h->active() && list.active().size() == 1);
    step(u("its DNS is the system's now"), h->holdsDns());
    int statsSeen = 0;
    QMetaObject::Connection counting = QObject::connect(h, &Profile::statsChanged, [&] { ++statsSeen; });
    app.setStats(true);
    sh(u("ping -c 2 -W 2 198.18.0.1 > /dev/null 2>&1"));
    step(u("statistics: bytes in, a handshake, where the server answered from"), within(5000, [&] {
        return h->rxBytes() > 0 && h->handshakeSec() > 0 && h->endpointNow() == u("203.0.113.1:51820");
    }));
    const double nowSec = QDateTime::currentMSecsSinceEpoch() / 1000.0;
    step(u("... the handshake on the wall clock"), qAbs(nowSec - h->handshakeSec()) < 60);
    statsSeen = 0;
    step(u("statistics every second while asked"), within(3500, [&] { return statsSeen >= 2; }));
    app.setStats(false);
    idle(500);
    statsSeen = 0;
    idle(2500);
    step(u("... and none after"), statsSeen == 0);
    QObject::disconnect(counting);

    section("client 4. names, always-on");
    list.rename(home, u("Дом"));
    step(u("rename: the new name, in UTF-8"), within(3000, [&] { return h->name() == u("Дом"); }));
    list.setAlwaysOn(home, true);
    step(u("always-on: this profile"), within(3000, [&] { return list.alwaysOn() == home && h->alwaysOn(); }));
    list.setAlwaysOn(home, false);
    step(u("always-on: none"), within(3000, [&] { return list.alwaysOn().isEmpty() && !h->alwaysOn(); }));
    list.setAlwaysOn(u("00000000"), true);
    step(u("always-on: a profile that is not there - refused (3)"),
            within(3000, [&] { return rec.failed("settings.set", 3); }));
    list.setAlwaysOn(home, true);
    within(3000, [&] { return list.alwaysOn() == home; });

    section("client 5. two tunnels, the second 'all traffic'");
    const QString split = rec.answer(list.importProfile(u("Split"), w.conf("split.conf")));
    const QString full2 = rec.answer(list.importProfile(u("Full2"), w.conf("full2.conf")));
    step(u("three profiles, in the order they came"), within(3000, [&] {
        return names(list) == (QStringList() << u("Дом") << u("Split") << u("Full2"));
    }));
    Profile* s = prof(list, split);
    Profile* f2 = prof(list, full2);
    if (s == 0 || f2 == 0) {
        step(u("no profiles to go on with"), false);
        return 1;
    }
    list.up(split);
    step(u("a split tunnel beside it: up"), within(15000, [&] { return s->state() == u("up"); }));
    step(u("... two switches on"), list.active().size() == 2);
    list.up(full2);
    step(u("a second 'all traffic': the conflict, naming the holder"),
            within(3000, [&] { return rec.conflicts.contains(qMakePair(full2, home)); }));
    step(u("... its row: error, conflict"),
            within(3000, [&] { return f2->state() == u("error") && f2->reason() == u("conflict"); }));
    step(u("... not a failure the app would show"), !rec.failedAny("tunnel.up"));
    list.down(full2);
    step(u("'No': its entry goes, the switch off"), within(3000, [&] { return f2->state() == u("down"); }));
    step(u("... the holder still up"), h->state() == u("up"));
    list.up(full2);
    within(3000, [&] { return rec.conflicts.size() >= 2; });
    list.switchTo(full2, home);
    step(u("'Switch': the holder goes down"), within(5000, [&] { return h->state() == u("down"); }));
    const bool switched = within(5000, [&] {
        return (f2->state() == u("connecting") || f2->state() == u("up")) && f2->reason() != u("conflict");
    });
    step(u("... the new one comes up (") + f2->state() + u(")"), switched);
    list.down(full2);
    list.up(home);
    step(u("back: Home up again"), within(15000, [&] { return h->state() == u("up"); }));

    section("client 6. a new .conf");
    list.loadDetails(split);
    within(3000, [&] { return s->detailsLoaded(); });
    QString withMtu = w.conf("split.conf");
    withMtu.replace(u("Address = 10.97.0.2/32"), u("Address = 10.97.0.2/32\nMTU = 1300"));
    r = list.replaceConf(split, withMtu);
    rec.answer(r);
    step(u("taken while up, with the note: ") + rec.imports.value(r).note,
            rec.imports.value(r).ok && !rec.imports.value(r).note.isEmpty());
    step(u("... the open page's details follow"),
            within(3000, [&] { return s->details().value(u("mtu")).toString() == u("1300"); }));
    r = list.replaceConf(split, w.conf("bad.conf"));
    rec.answer(r);
    step(u("a broken one: refused with its line"),
            rec.imports.value(r).done && !rec.imports.value(r).ok && rec.imports.value(r).line == 2);
    list.releaseDetails(split);

    section("client 7. refusals");
    list.up(u("00000000"));
    step(u("up of a profile that is not there: refused (3)"),
            within(3000, [&] { return rec.failed("tunnel.up", 3); }));
    const QString dead1 = rec.answer(list.importProfile(u("Dead1"), deadConf(w, 1)));
    const QString dead2 = rec.answer(list.importProfile(u("Dead2"), deadConf(w, 2)));
    const QString dead3 = rec.answer(list.importProfile(u("Dead3"), deadConf(w, 3)));
    within(3000, [&] { return prof(list, dead3) != 0; });
    list.up(dead1);
    list.up(dead2);
    step(u("four tunnels"), within(5000, [&] { return list.active().size() == 4; }));
    list.up(dead3);
    step(u("a fifth: refused (5, busy) - the phone has four"), within(3000, [&] { return rec.failed("tunnel.up", 5); }));
    step(u("... its switch off"), prof(list, dead3) != 0 && prof(list, dead3)->state() == u("down"));
    list.down(dead2);
    list.remove(dead2);
    list.remove(dead3);
    within(3000, [&] { return list.count() == 4; });

    section("client 8. the service beside the app");
    // Its own connection, list and notifier, as the other process has them; the settings file is shared.
    DaemonClient svc(false);
    ProfileList svcList(&svc);
    Notifier notifier(&svc, &svcList);
    svc.start();
    notifier.start();
    step(u("the service connects beside the app"), within(5000, [&] { return svc.connected() && svcList.ready(); }));
    step(u("... the same profiles"), names(svcList) == names(list));
    list.rename(split, u("Split 2"));
    step(u("a rename in the app reaches the service"), within(3000, [&] {
        return prof(svcList, split) != 0 && prof(svcList, split)->name() == u("Split 2");
    }));
    step(u("'While connected' off by default: no 'Tunnel on'"), !inHub(u("tunnel_on")));
    TunnelSettings::instance()->setNotifyConnected(true);
    step(u("switched on in the app: the service puts it up at once"), within(3000, [&] { return inHub(u("tunnel_on")); }));
    step(u("... quiet, naming the tunnels up: ") + posted(u("tunnel_on")).body,
            posted(u("tunnel_on")).quiet && posted(u("tunnel_on")).title == u("Tunnel on")
            && posted(u("tunnel_on")).body == u("Дом, Split 2"));

    // Dead1 has been trying since section 7: its state stays "connecting", only a reason comes - and
    // nothing else is in trouble meanwhile to wake the service up.
    step(u("'Cannot connect: Dead1', with nothing else going on"), within(50000, [&] { return inHub(keyOf(dead1)); })
            && posted(keyOf(dead1)).title == u("Cannot connect: Dead1")
            && posted(keyOf(dead1)).body == u("The server does not answer."));
    list.down(dead1);
    step(u("Dead1 turned off: its notice goes"), within(5000, [&] { return !inHub(keyOf(dead1)); }));

    // The phone moves to LTE while Home's server is silent: Home reconnects for longer than 30 s.
    w.inet(u("nft add table inet silence"));
    w.inet(u("nft 'add chain inet silence input { type filter hook input priority -1; policy accept; }'"));
    w.inet(u("nft add rule inet silence input udp dport 51820 drop"));
    sh(u("ip link set wifi0 down && ip route replace default via 10.64.0.1 dev lte0"));
    w.resolv("10.64.0.1");
    step(u("LTE: Home reconnects"), within(10000, [&] { return h->state() == u("reconnecting"); }));
    step(u("... Split is back up within seconds"), within(20000, [&] { return s->state() == u("up"); }));
    step(u("'Connection lost: Дом' after 30 s"), within(50000, [&] { return inHub(keyOf(home)); }));
    const bbstub::Posted lost = posted(keyOf(home));
    step(u("... why (") + lost.body + u("), not quiet, a tap opens the profile"),
            lost.title == u("Connection lost: Дом")
            && (lost.body == u("Reconnecting.") || lost.body == u("The server does not answer."))
            && !lost.quiet && lost.action == u("doctorrokter.BBTunnel.OPENPROFILE") && lost.data == home.toUtf8());
    step(u("a switch of networks is shorter: nothing about Split"), !inHub(keyOf(split)));
    w.inet(u("nft delete table inet silence"));
    sh(u("ip link set wifi0 up && ip route replace default via 192.168.1.1 dev wifi0"));
    w.resolv("192.168.1.1");
    step(u("the server answers again: Home up"), within(40000, [&] { return h->state() == u("up"); }));
    step(u("'Connected: Дом' in its place, quietly"), within(10000, [&] {
        return posted(keyOf(home)).title == u("Connected: Дом");
    }) && posted(keyOf(home)).quiet && posted(keyOf(home)).body == u("The tunnel works again."));

    section("client 9. the daemon gone, and back");
    w.pause();
    w.kill("TERM");
    QElapsedTimer gone;
    gone.start();
    step(u("both connections see it gone"), within(5000, [&] { return !app.connected() && !svc.connected(); }));
    step(u("'Tunnel on' leaves the Hub with it"), within(3000, [&] { return !inHub(u("tunnel_on")); }));
    step(u("... no word of it in the first 55 s"), !within(55000 - (int)gone.elapsed(), [&] { return inHub(u("tunnel_daemon")); }));
    step(u("'The tunnel service does not answer' after a minute"), within(20000, [&] { return inHub(u("tunnel_daemon")); }));
    w.resume();
    // A minute and more without it: the tries are 30 s apart by now (DaemonClient, kRetrySeconds).
    step(u("the loop starts it again: both back by the next try"),
            within(35000, [&] { return app.connected() && svc.connected(); }));
    step(u("... the notice goes"), within(3000, [&] { return !inHub(u("tunnel_daemon")); }));
    step(u("the same objects: an open page is not stale"), prof(list, home) == h && prof(list, split) == s);
    step(u("always-on: Home up again"), within(15000, [&] { return h->state() == u("up"); }));
    step(u("'Tunnel on' back"), within(5000, [&] { return inHub(u("tunnel_on")); }));

    section("client 10. daemon.restart, kill -9");
    app.setStats(true);
    app.send(u("daemon.restart"));
    step(u("daemon.restart: gone"), within(3000, [&] { return !app.connected(); }));
    step(u("... back within 10 s, ready"), within(10000, [&] { return app.connected() && list.ready(); }));
    step(u("... Home up again (always-on)"), within(15000, [&] { return h->state() == u("up"); }));
    statsSeen = 0;
    counting = QObject::connect(h, &Profile::statsChanged, [&] { ++statsSeen; });
    step(u("statistics resume by themselves"), within(4000, [&] { return statsSeen >= 2; }));
    QObject::disconnect(counting);
    app.setStats(false);
    step(u("'Tunnel on' in the Hub"), within(5000, [&] { return inHub(u("tunnel_on")); }));
    // Held off for a moment: a crash says nothing of its tunnels, and the service must see that
    // none runs without the daemon.
    w.pause();
    w.kill("KILL");
    step(u("kill -9: gone"), within(3000, [&] { return !app.connected() && !svc.connected(); }));
    step(u("... 'Tunnel on' leaves the Hub with it"), within(3000, [&] { return !inHub(u("tunnel_on")); }));
    w.resume();
    step(u("... back within 15 s"), within(15000, [&] { return app.connected() && list.ready(); }));
    step(u("... Home up again (the journal, always-on)"), within(15000, [&] { return h->state() == u("up"); }));

    section("client 11. delete");
    list.up(split);
    within(15000, [&] { return s->state() == u("up"); });
    list.remove(split);
    step(u("a tunnel that is up: deleted, gone from the list"), within(3000, [&] { return prof(list, split) == 0; }));
    step(u("... the object an open page holds lives on, down"), s->state() == u("down"));
    list.remove(home);
    step(u("the always-on profile: deleted"), within(3000, [&] { return prof(list, home) == 0; }));
    step(u("... always-on reads none"), within(3000, [&] { return list.alwaysOn().isEmpty(); }));
    step(u("the service's list follows"), within(3000, [&] { return names(svcList) == names(list); }));
    step(u("nothing left in the Hub about them"), within(3000, [&] {
        return !inHub(keyOf(home)) && !inHub(keyOf(split)) && !inHub(u("tunnel_on"));
    }));

    section("client 12. an AmneziaVPN key, all the way");
    // Home's connection as AmneziaVPN would share it: its .conf with the DNS left to the app and no
    // MTU, the key's own DNS the server's inner one.
    QString shared = w.conf("phone.conf");
    shared.replace(QRegExp(u("DNS = [^\n]*")), u("DNS = $PRIMARY_DNS, $SECONDARY_DNS"));
    shared.replace(QRegExp(u("MTU = [^\n]*\n")), QString());
    QJsonObject keyRoot;
    keyRoot[u("description")] = u("Сервер из AmneziaVPN");
    keyRoot[u("hostName")] = u("vpn.test");
    keyRoot[u("dns1")] = u("10.99.0.1");
    Importer importer;
    const QVariantMap made = importer.fromAmneziaKey(vpnKey(connectionKey("amnezia-wireguard", "wireguard", shared, keyRoot)));
    step(u("the key read: ") + made.value(u("name")).toString(), made.value(u("ok")).toBool());
    const QString fromKey = rec.answer(list.importProfile(made.value(u("name")).toString(), made.value(u("conf")).toString()));
    step(u("the daemon takes its .conf"), !fromKey.isEmpty() && within(3000, [&] { return prof(list, fromKey) != 0; }));
    Profile* k = prof(list, fromKey);
    if (k == 0) {
        return 1;
    }
    list.loadDetails(fromKey);
    step(u("details: the key's DNS, the phone's MTU"), within(3000, [&] { return k->detailsLoaded(); })
            && k->details().value(u("dns")).toStringList() == (QStringList() << u("10.99.0.1") << u("1.0.0.1"))
            && k->details().value(u("mtu")).toString() == u("1280"));
    list.up(fromKey);
    step(u("up against the real server"), within(15000, [&] { return k->state() == u("up"); }));
    step(u("... traffic through it"), sh(u("ping -c 1 -W 3 198.18.0.1 > /dev/null 2>&1")) == 0);
    list.down(fromKey);
    list.remove(fromKey);
    within(3000, [&] { return prof(list, fromKey) == 0; });

    return g_failed;
}

// ----------------------------------------------------------------------- the demo

int runDemo()
{
    DaemonClient app(true);
    ProfileList list(&app);
    Recorder rec(&list);

    section("demo 1. connect");
    app.start();
    step(u("connected"), within(3000, [&] { return app.connected(); }));
    step(u("the demo says so (daemon ") + app.daemonVersion() + u("), our protocol"),
            app.daemonVersion() == u("demo") && app.protoVersion() == DaemonClient::clientProto());
    step(u("ready: Home, Work, NAS, Tailnet"), within(3000, [&] { return list.ready(); })
            && names(list) == (QStringList() << u("Home") << u("Work") << u("NAS") << u("Tailnet")));
    Profile* home = byName(list, u("Home"));
    Profile* work = byName(list, u("Work"));
    Profile* nas = byName(list, u("NAS"));
    if (home == 0 || work == 0 || nas == 0) {
        step(u("no profiles to go on with"), false);
        return 1;
    }
    step(u("Home is AmneziaWG"), home->amnezia() && home->type() == u("amneziawg"));
    list.loadDetails(home->id());
    step(u("details as profile.get gives them"), within(2000, [&] { return home->detailsLoaded(); })
            && !home->details().value(u("public_key")).toString().isEmpty()
            && !home->details().value(u("address")).toStringList().isEmpty()
            && home->details().value(u("peers")).toInt() == 1
            && home->details().value(u("full")).toBool());

    section("demo 2. up, statistics, the conflict");
    rec.moves.clear();
    list.up(home->id());
    const bool up = within(6000, [&] { return home->state() == u("up"); });
    step(u("up through connecting: ") + rec.moves.join(u(", ")),
            up && rec.moves == (QStringList() << home->id() + u(":down>connecting") << home->id() + u(":connecting>up")));
    step(u("its DNS is the system's"), home->holdsDns());
    int statsSeen = 0;
    QObject::connect(home, &Profile::statsChanged, [&] { ++statsSeen; });
    app.setStats(true);
    step(u("statistics while asked"), within(3000, [&] { return statsSeen >= 2 && home->rxBytes() > 0; })
            && !home->endpointNow().isEmpty());
    app.setStats(false);
    list.up(work->id());
    step(u("a split tunnel beside it"), within(6000, [&] { return work->state() == u("up"); }));
    QString full = u("[Interface]\nPrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=\nAddress = 10.1.0.2/32\n\n"
            "[Peer]\nPublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\nAllowedIPs = 0.0.0.0/0\n"
            "Endpoint = 198.51.100.1:51820\n");
    const QString added = rec.answer(list.importProfile(u("Added"), full));
    step(u("import: an id, the list grows"), !added.isEmpty() && within(2000, [&] { return list.count() == 5; }));
    list.up(added);
    step(u("a second 'all traffic': the conflict, naming the holder"),
            within(2000, [&] { return rec.conflicts.contains(qMakePair(added, home->id())); }));
    list.down(added);
    step(u("'No': off"), within(2000, [&] { return prof(list, added)->state() == u("down"); }));
    int r = list.importProfile(u("Short"), u("[Interface]\nAddress = 10.1.0.2/32\nPrivateKey = short\n"));
    rec.answer(r);
    step(u("a broken key: refused with its line"), !rec.imports.value(r).ok && rec.imports.value(r).line == 3);
    r = list.importProfile(u("None"), u("[Peer]\nPublicKey = x\n"));
    rec.answer(r);
    step(u("no [Interface]: refused"), !rec.imports.value(r).ok && rec.imports.value(r).line > 0);

    section("demo 3. names, always-on, refusals, delete");
    list.rename(work->id(), u("Работа"));
    step(u("rename"), within(2000, [&] { return work->name() == u("Работа"); }));
    list.up(u("00000000"));
    step(u("up of a profile that is not there: refused (3)"), within(2000, [&] { return rec.failed("tunnel.up", 3); }));
    list.setAlwaysOn(home->id(), true);
    step(u("always-on"), within(2000, [&] { return list.alwaysOn() == home->id() && home->alwaysOn(); }));
    list.remove(home->id());
    step(u("delete the always-on profile: gone"), within(2000, [&] { return prof(list, home->id()) == 0; }));
    step(u("... always-on reads none"), within(2000, [&] { return list.alwaysOn().isEmpty(); }));
    list.up(nas->id());
    step(u("NAS: its server never answers - the reason after 15 s"),
            within(20000, [&] { return nas->reason() == u("handshake"); }) && nas->state() == u("connecting"));

    section("demo 4. Tailscale");
    Profile* ts = byName(list, u("Tailnet"));
    if (ts == 0) {
        step(u("no Tailnet profile"), false);
        return 1;
    }
    step(u("Tailnet is Tailscale"), ts->tailscale() && !ts->amnezia());
    list.setAlwaysOn(work->id(), true);
    list.setAlwaysOn(ts->id(), true);
    step(u("always-on: a WireGuard profile and a Tailscale one together"), within(2000, [&] {
        return list.alwaysOn() == work->id() && list.alwaysOnTailscale() == ts->id() && work->alwaysOn() && ts->alwaysOn();
    }));
    list.setAlwaysOn(nas->id(), true);
    step(u("always-on: another WireGuard profile takes only its own kind's place"), within(2000, [&] {
        return list.alwaysOn() == nas->id() && !work->alwaysOn() && list.alwaysOnTailscale() == ts->id() && ts->alwaysOn();
    }));
    list.setAlwaysOn(ts->id(), false);
    step(u("always-on off for one: the other stays"), within(2000, [&] {
        return list.alwaysOnTailscale().isEmpty() && !ts->alwaysOn() && list.alwaysOn() == nas->id() && nas->alwaysOn();
    }));
    list.setAlwaysOn(nas->id(), false);
    within(2000, [&] { return list.alwaysOn().isEmpty(); });
    rec.moves.clear();
    list.up(ts->id());
    step(u("waits for the relay, then up"), within(2000, [&] { return ts->reason() == u("relay"); })
            && within(4000, [&] { return ts->state() == u("up"); }));
    step(u("the tailnet from the tunnel's own lines: relay up, our 100.x address"),
            ts->tailnet().value(u("relayUp")).toBool() && ts->tailnet().value(u("relay")).toString() == u("fra")
            && ts->tailnet().value(u("addresses")).toStringList().value(0) == u("100.101.102.7"));
    list.loadNodes(ts->id());
    step(u("the nodes: four, the NAS in use, at home in Frankfurt"), within(2000, [&] { return ts->nodes().size() == 4; })
            && ts->nodes().at(0).toMap().value(u("active")).toBool()
            && ts->nodes().at(0).toMap().value(u("online")).toString() == u("1")
            && ts->nodes().at(0).toMap().value(u("relay")).toInt() == 4
            && ts->nodes().at(2).toMap().value(u("online")).toString() == u("0")
            && ts->nodes().at(3).toMap().value(u("relay")).toInt() == 0);
    list.loadDetails(ts->id());
    step(u("details: the official server, logged in"), within(2000, [&] {
                return ts->details().value(u("login")).toString() == u("ok");
            }) && ts->details().value(u("control")).toString() == u("https://controlplane.tailscale.com"));
    r = list.relogin(ts->id(), u("tskey-auth-kNew1CNTRL-abcdef"));
    rec.answer(r);
    step(u("a new auth key: taken, with a note while up"), rec.imports.value(r).ok && !rec.imports.value(r).note.isEmpty());
    list.loadNodes(work->id());
    step(u("nodes of a WireGuard profile: none"), within(2000, [&] { return work->nodes().isEmpty(); }));
    list.down(ts->id());
    step(u("down: the tailnet and the nodes forgotten"), within(2000, [&] {
                return ts->state() == u("down") && ts->tailnet().isEmpty() && ts->nodes().isEmpty();
            }));
    r = list.importTailscale(u("Mine"), u("tskey-auth-kAbc1CNTRL-xyz"), u("passport"));
    const QString mine = rec.answer(r);
    step(u("import with an auth key: a Tailscale profile"), !mine.isEmpty()
            && within(2000, [&] { return prof(list, mine) != 0 && prof(list, mine)->tailscale(); }));
    r = list.importTailscale(u("Bad"), u("not a key"), QString());
    rec.answer(r);
    step(u("a text that is no auth key: refused"), !rec.imports.value(r).ok);
    // By a link (TAILSCALE.md section 11b): no key; at its start the tunnel waits at a link.
    r = list.importTailscaleLink(u("Linked"), u("passport"));
    const QString linked = rec.answer(r);
    step(u("import by a link: a Tailscale profile"), !linked.isEmpty()
            && within(2000, [&] { return prof(list, linked) != 0 && prof(list, linked)->tailscale(); }));
    Profile* lp = prof(list, linked);
    if (lp != 0) {
        list.loadDetails(linked);
        step(u("... login=link until it logs in"), within(2000, [&] {
            return lp->details().value(u("login")).toString() == u("link");
        }));
        list.up(linked);
        step(u("... up: waiting at a link, the link among the tunnel's lines"),
                within(3000, [&] { return lp->reason() == u("browser"); })
                && lp->tailnet().value(u("authUrl")).toString().startsWith(u("https://login.tailscale.com/a/")));
        r = list.reloginLink(linked);
        rec.answer(r);
        step(u("log in again by a link: taken, with a note while up"), rec.imports.value(r).ok
                && rec.imports.value(r).note.contains(u("link")));
        list.down(linked);
        step(u("... down: the link forgotten"), within(2000, [&] {
            return lp->state() == u("down") && lp->tailnet().isEmpty();
        }));
    }
    return g_failed;
}

// ----------------------------------------------------------------------- Tailscale on the stand

// A node of a Tailscale profile by its name, as the app's list has it; empty when not there.
QVariantMap nodeNamed(const Profile* p, const QString& name)
{
    const QVariantList all = p->nodes();
    for (int i = 0; i < all.size(); ++i) {
        const QVariantMap n = all.at(i).toMap();
        if (n.value(u("name")).toString() == name) {
            return n;
        }
    }
    return QVariantMap();
}

// The app and the service against bbtunneld on the Tailscale stand (daemon/test/ts/e2e.sh client).
// WORK holds the stand's two auth keys, its control URL and the NAS's address, and what the phone
// cannot do itself: an admin expiring our node ("expire"), the NAS taking a new map after our new
// login ("nas-refresh" - the stand's quirk, e2e.sh section 6).
int runTailscale(const World& w)
{
    const QString key = w.conf("authkey").trimmed();
    const QString control = w.conf("control").trimmed();
    const QString nasIp = w.conf("nas.ip").trimmed();
    const QString pingNas = u("ping -c 1 -W 2 ") + nasIp + u(" > /dev/null 2>&1");
    DaemonClient app(false);
    ProfileList list(&app);
    Recorder rec(&list);

    section("tailscale 1. import");
    app.start();
    step(u("connected, the list ready and empty"), within(5000, [&] { return app.connected() && list.ready(); })
            && list.count() == 0);
    int r = list.importTailscale(u("Bad"), u("not a key"), QString());
    rec.answer(r);
    step(u("a text that is no auth key: refused (") + rec.imports.value(r).error + u(")"),
            rec.imports.value(r).done && !rec.imports.value(r).ok);
    // The sheet has no server field: the official one. Looked at here, never brought up - the stand
    // has no way out.
    const QString official = rec.answer(list.importTailscale(u("Official"), key, u("passport")));
    step(u("the sheet's import: a Tailscale profile (") + official + u(")"), !official.isEmpty()
            && within(3000, [&] { return prof(list, official) != 0 && prof(list, official)->tailscale(); }));
    Profile* o = prof(list, official);
    if (o != 0) {
        list.loadDetails(official);
        step(u("... the official server, not logged in yet, the phone's name"),
                within(3000, [&] { return o->detailsLoaded(); })
                && o->details().value(u("control")).toString() == u("https://controlplane.tailscale.com")
                && o->details().value(u("login")).toString() == u("pending")
                && o->details().value(u("hostname")).toString() == u("passport"));
        list.remove(official);
        step(u("... deleted"), within(3000, [&] { return prof(list, official) == 0; }));
    }
    // The stand's profile: its server given as btctl gives it (profile.import control=).
    QVariantMap args;
    args.insert(u("type"), u("tailscale"));
    args.insert(u("name"), u("Tailnet"));
    args.insert(u("authkey"), key);
    args.insert(u("control"), control);
    args.insert(u("hostname"), u("phone"));
    app.send(u("profile.import"), args);
    step(u("the stand's profile in the list"), within(5000, [&] { return byName(list, u("Tailnet")) != 0; }));
    Profile* t = byName(list, u("Tailnet"));
    if (t == 0) {
        step(u("no profile to go on with"), false);
        return 1;
    }
    const QString id = t->id();
    step(u("... Tailscale, down, no tailnet yet"),
            t->tailscale() && t->state() == u("down") && t->tailnet().isEmpty());

    section("tailscale 2. up");
    rec.moves.clear();
    list.up(id);
    step(u("up within 30 s"), within(30000, [&] { return t->state() == u("up"); }));
    step(u("... through connecting: ") + rec.moves.join(u(", ")), !rec.moves.isEmpty()
            && rec.moves.first() == id + u(":down>connecting") && rec.moves.last() == id + u(":connecting>up"));
    const bool relayUp = within(3000, [&] { return t->tailnet().value(u("relayUp")).toBool(); });
    // Our name as control has it: "phone", or "phone.<base domain>." when the stand's tailnet has MagicDNS.
    const QString ourName = t->tailnet().value(u("name")).toString();
    step(u("the tailnet from the tunnel's lines: the relay up, our 100.x address, our name"),
            relayUp && t->tailnet().value(u("addresses")).toStringList().value(0).startsWith(u("100.64."))
            && (ourName == u("phone") || ourName.startsWith(u("phone."))));
    list.loadDetails(id);
    step(u("details: logged in to the stand, a node key"), within(3000, [&] {
        return t->details().value(u("login")).toString() == u("ok");
    }) && t->details().value(u("control")).toString() == control
            && t->details().value(u("node_key")).toString().startsWith(u("nodekey:")));

    section("tailscale 3. the devices");
    step(u("the phone reaches the NAS"), within(15000, [&] { return sh(pingNas) == 0; }));
    // The page asks every 5 s; here once a second until it holds.
    auto nodesSay = [&](const std::function<bool()>& cond, int ms) {
        QElapsedTimer since;
        since.start();
        while (since.elapsed() < ms) {
            list.loadNodes(id);
            if (within(1000, cond)) {
                return true;
            }
        }
        return false;
    };
    step(u("the devices: the NAS online, in use, its address, its home region"), nodesSay([&] {
        const QVariantMap n = nodeNamed(t, u("nas"));
        return n.value(u("online")).toString() == u("1") && n.value(u("active")).toBool()
                && n.value(u("addresses")).toStringList().contains(nasIp) && n.value(u("relay")).toInt() > 0;
    }, 10000));
    step(u("... what went to it counted"), nodeNamed(t, u("nas")).value(u("tx")).toDouble() > 0);

    section("tailscale 4. the login expires");
    // The service beside the app, as the other process: its own connection, list and notifier.
    DaemonClient svc(false);
    ProfileList svcList(&svc);
    Notifier notifier(&svc, &svcList);
    svc.start();
    notifier.start();
    step(u("the service connects beside the app"), within(5000, [&] { return svc.connected() && svcList.ready(); }));
    sh(w.work + u("/expire"));
    step(u("error (expired)"), within(30000, [&] { return t->state() == u("error") && t->reason() == u("expired"); }));
    list.loadNodes(id);
    step(u("the devices: none without a netmap"), within(3000, [&] { return t->nodes().isEmpty(); }));
    step(u("'Connection lost: Tailnet' after 30 s, saying why"), within(50000, [&] { return inHub(keyOf(id)); })
            && posted(keyOf(id)).title == u("Connection lost: Tailnet")
            && posted(keyOf(id)).body == u("The login expired. Log in again.")
            && !posted(keyOf(id)).quiet);

    section("tailscale 5. log in again");
    r = list.relogin(id, w.conf("authkey2").trimmed());
    rec.answer(r);
    step(u("a new auth key: taken (") + rec.imports.value(r).note + u(")"), rec.imports.value(r).ok);
    // main.qml (tailscaleDone): a new login of a tunnel that is on reconnects it at once.
    if (t->active()) {
        list.down(id);
        list.up(id);
    }
    step(u("the restart takes the notice away"), within(5000, [&] { return !inHub(keyOf(id)); }));
    step(u("up with the new key"), within(30000, [&] { return t->state() == u("up"); }));
    sh(w.work + u("/nas-refresh"));
    step(u("the NAS again"), within(20000, [&] { return sh(pingNas) == 0; }));
    step(u("... and no notice back"), !inHub(keyOf(id)));

    section("tailscale 6. down, delete");
    list.down(id);
    step(u("down: the tailnet and the devices forgotten"), within(5000, [&] {
        return t->state() == u("down") && t->tailnet().isEmpty() && t->nodes().isEmpty();
    }));
    list.remove(id);
    step(u("deleted: the list empty"), within(5000, [&] { return list.count() == 0; }));

    // By a link (TAILSCALE.md section 11b): the app's own calls, Headscale's `auth register` as the
    // login somebody makes at the link on another device (the stand's script).
    section("tailscale 7. log in by a link");
    QVariantMap la;
    la.insert(u("type"), u("tailscale"));
    la.insert(u("name"), u("Linked"));
    la.insert(u("login"), u("link"));
    la.insert(u("control"), control);
    la.insert(u("hostname"), u("linkapp"));
    app.send(u("profile.import"), la);
    step(u("the profile in the list"), within(5000, [&] { return byName(list, u("Linked")) != 0; }));
    Profile* lk = byName(list, u("Linked"));
    if (lk == 0) {
        return 1;
    }
    const QString lid = lk->id();
    list.up(lid);
    step(u("waiting at a link: reason browser, the link among the tunnel's lines"),
            within(30000, [&] { return lk->reason() == u("browser") && !lk->tailnet().value(u("authUrl")).toString().isEmpty(); })
            && lk->tailnet().value(u("authUrl")).toString().startsWith(control + u("/register/")));
    const QString link = lk->tailnet().value(u("authUrl")).toString();
    step(u("Headscale: a login at the link"), sh(w.work + u("/register ") + link.section(QLatin1Char('/'), -1)) == 0);
    step(u("up, the link gone"), within(30000, [&] { return lk->state() == u("up"); })
            && within(3000, [&] { return lk->tailnet().value(u("authUrl")).toString().isEmpty(); }));
    list.loadDetails(lid);
    step(u("details: logged in"), within(3000, [&] { return lk->details().value(u("login")).toString() == u("ok"); }));
    step(u("the phone reaches the NAS"), within(20000, [&] { return sh(pingNas) == 0; }));
    list.remove(lid);
    step(u("deleted"), within(5000, [&] { return list.count() == 0; }));
    return g_failed;
}

} // namespace

int main(int argc, char** argv)
{
    QCoreApplication qapp(argc, argv);
    // One settings file for "the app" and "the service", as the two processes share it (KB 7.2).
    QCoreApplication::setOrganizationName(u("BBTunnel"));
    QCoreApplication::setApplicationName(u("BBTunnel"));

    const QStringList args = QCoreApplication::arguments();
    if (args.contains(u("--keys"))) {
        const int rc = runKeys();
        printf("\n%s\n", rc == 0 ? "client keys: all passed" : "client keys: FAILURES");
        return rc;
    }
    if (args.contains(u("--demo"))) {
        const QString dir = QDir::tempPath() + u("/bt_client_demo");
        QSettings::setPath(QSettings::NativeFormat, QSettings::UserScope, dir);
        const int rc = runDemo();
        printf("\n%s\n", rc == 0 ? "client demo: all passed" : "client demo: FAILURES");
        return rc;
    }
    const int a = args.indexOf(u("--app"));
    const int wk = args.indexOf(u("--work"));
    if (a < 0 || wk < 0 || a + 1 >= args.size() || wk + 1 >= args.size()) {
        fprintf(stderr, "usage: client_test --keys | --demo | [--tailscale] --app DIR --work DIR\n");
        return 2;
    }
    // DaemonClient::socketPath() is data/daemon.sock under the working directory - the sandbox.
    QDir::setCurrent(args.at(a + 1));
    QSettings::setPath(QSettings::NativeFormat, QSettings::UserScope, args.at(a + 1) + u("/data/Settings"));
    World w;
    w.work = args.at(wk + 1);
    if (args.contains(u("--tailscale"))) {
        const int rc = runTailscale(w);
        printf("\n%s\n", rc == 0 ? "client tailscale: all passed" : "client tailscale: FAILURES");
        return rc;
    }
    const int rc = runReal(w);
    printf("\n%s\n", rc == 0 ? "client: all passed" : "client: FAILURES");
    return rc;
}
