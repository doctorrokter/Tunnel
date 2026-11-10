#include "AmneziaKey.hpp"

#include <bb/data/JsonDataAccess>

#include <QRegExp>
#include <QStringList>
#include <QVariantList>
#include <QVariantMap>

#include <zlib.h>

namespace tunnel {

namespace {

// A key's JSON is a few KB. More than this out of zlib is no key - and a bomb is not inflated whole.
const int kInflateMax = 1024 * 1024;
// AmneziaVPN's QR series (qrCodeUtils.h, qrMagicCode).
const int kQrMagic = 1984;
// Its defaults when the key names no DNS (SecureAppSettingsRepository), and a phone's MTU
// (protocolConstants.h, awg / wireguard defaultMtu on Android and iOS).
const char* const kDns1 = "1.1.1.1";
const char* const kDns2 = "1.0.0.1";
const char* const kMtu = "1280";
// The daemon's limit for a profile's name (BT_NAME_MAX): bytes of UTF-8.
const int kNameMax = 64;

QString s(const char* text)
{
    return QString::fromLatin1(text);
}

// base64url without padding, as AmneziaVPN writes it; the plain alphabet too. Qt 4.8's fromBase64
// knows only the plain one. Whitespace a mail or a messenger put in is dropped; any other stray
// character makes it no key.
bool fromBase64Url(const QString& text, QByteArray* out)
{
    QByteArray b;
    b.reserve(text.size() + 3);
    for (int i = 0; i < text.size(); ++i) {
        const ushort c = text.at(i).unicode();
        if (c == ' ' || c == '\n' || c == '\r' || c == '\t') {
            continue;
        }
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '/') {
            b.append((char)c);
        } else if (c == '-') {
            b.append('+');
        } else if (c == '_') {
            b.append('/');
        } else if (c == '=') {
            continue;
        } else {
            return false;
        }
    }
    if (b.isEmpty() || b.size() % 4 == 1) {
        return false;
    }
    while (b.size() % 4 != 0) {
        b.append('=');
    }
    *out = QByteArray::fromBase64(b);
    return !out->isEmpty();
}

QString toBase64Url(const QByteArray& data)
{
    QByteArray b = data.toBase64();
    for (int i = 0; i < b.size(); ++i) {
        if (b.at(i) == '+') {
            b[i] = '-';
        } else if (b.at(i) == '/') {
            b[i] = '_';
        }
    }
    while (b.endsWith('=')) {
        b.chop(1);
    }
    return QString::fromLatin1(b.constData(), b.size());
}

// qCompress's format: a 4-byte big-endian size - which the subscription keys fill with their
// signature - then a zlib stream. Bounded, unlike qUncompress, which doubles its buffer for ever.
QByteArray inflate(const QByteArray& data)
{
    if (data.size() <= 4) {
        return QByteArray();
    }
    QByteArray out;
    out.resize(kInflateMax);
    uLongf len = (uLongf)out.size();
    const int r = uncompress(reinterpret_cast<Bytef*>(out.data()), &len,
            reinterpret_cast<const Bytef*>(data.constData()) + 4, (uLong)(data.size() - 4));
    if (r != Z_OK) {
        return QByteArray();
    }
    out.resize((int)len);
    return out;
}

QVariantMap parseJson(const QByteArray& text)
{
    if (text.isEmpty()) {
        return QVariantMap();
    }
    bb::data::JsonDataAccess json;
    const QVariant v = json.loadFromBuffer(text);
    if (json.hasError()) {
        return QVariantMap();
    }
    return v.toMap();
}

QString text(const QVariantMap& m, const char* key)
{
    return m.value(s(key)).toString().trimmed();
}

bool isIpv4(const QString& a)
{
    QRegExp re(s("(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})"));
    if (!re.exactMatch(a)) {
        return false;
    }
    for (int i = 1; i <= 4; ++i) {
        if (re.cap(i).toInt() > 255) {
            return false;
        }
    }
    return true;
}

QString fitName(const QString& name)
{
    QString out = name.trimmed();
    while (out.toUtf8().size() > kNameMax) {
        out.chop(1);
    }
    return out;
}

// The protocols of AmneziaVPN's other containers, as its app names them (containerUtils.cpp).
// Services that are no connection (its DNS, SFTP, a Tor site) are left out.
QString protocolName(const QString& container)
{
    static const char* const kNames[][2] = {
        { "amnezia-openvpn", "OpenVPN" },
        { "amnezia-openvpn-cloak", "OpenVPN over Cloak" },
        { "amnezia-shadowsocks", "OpenVPN over ShadowSocks" },
        { "amnezia-ipsec", "IKEv2" },
        { "amnezia-xray", "XRay" },
        { "amnezia-ssxray", "Shadowsocks" },
        { "amnezia-socks5proxy", "SOCKS5" },
        { "amnezia-mtproxy", "MTProxy" },
        { "amnezia-telemt", "MTProxy" },
        { "amnezia-dns", "" },
        { "amnezia-sftp", "" },
        { "amnezia-tor", "" }
    };
    for (unsigned i = 0; i < sizeof(kNames) / sizeof(kNames[0]); ++i) {
        if (container == QLatin1String(kNames[i][0])) {
            return s(kNames[i][1]);
        }
    }
    QString name = container;
    if (name.startsWith(QLatin1String("amnezia-"))) {
        name = name.mid(8);
    }
    return name;
}

// A connection's .conf from its fields, for a key whose last_config has no "config" text.
QString buildConf(const QVariantMap& client, const QVariantMap& server, const QVariantMap& root, bool awg)
{
    const QString privateKey = text(client, "client_priv_key");
    const QString serverKey = text(client, "server_pub_key");
    QString host = text(client, "hostName");
    if (host.isEmpty()) {
        host = text(root, "hostName");
    }
    QString port = text(client, "port");
    if (port.isEmpty() || port == QLatin1String("0")) {
        port = text(server, "port");
    }
    QString address = text(client, "client_ip");
    if (privateKey.isEmpty() || serverKey.isEmpty() || host.isEmpty() || port.isEmpty() || address.isEmpty()) {
        return QString();
    }
    if (!address.contains(QLatin1Char('/'))) {
        address += s("/32");
    }
    QStringList c;
    c << s("[Interface]");
    c << s("Address = ") + address;
    c << s("DNS = $PRIMARY_DNS, $SECONDARY_DNS");
    c << s("PrivateKey = ") + privateKey;
    if (awg) {
        static const char* const kAwgKeys[] = {
            "Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4", "I1", "I2", "I3", "I4", "I5",
            "HeaderProtectionKey", "ContentPaddingAddition", "RekeyAfterTime", "RekeyTimeout", "RejectAfterTime",
            "KeepaliveTimeout", "MaxHandshakeAttempts", "RandomTrailers", "DisableCookies"
        };
        for (unsigned i = 0; i < sizeof(kAwgKeys) / sizeof(kAwgKeys[0]); ++i) {
            QString v = text(client, kAwgKeys[i]);
            if (v.isEmpty()) {
                v = text(server, kAwgKeys[i]);
            }
            if (!v.isEmpty()) {
                c << s(kAwgKeys[i]) + s(" = ") + v;
            }
        }
    }
    c << QString();
    c << s("[Peer]");
    c << s("PublicKey = ") + serverKey;
    if (!text(client, "psk_key").isEmpty()) {
        c << s("PresharedKey = ") + text(client, "psk_key");
    }
    QStringList allowed = client.value(s("allowed_ips")).toStringList();
    c << s("AllowedIPs = ") + (allowed.isEmpty() ? s("0.0.0.0/0, ::/0") : allowed.join(s(", ")));
    c << s("Endpoint = ") + (host.contains(QLatin1Char(':')) ? s("[") + host + s("]") : host) + s(":") + port;
    const QString keepalive = text(client, "persistent_keep_alive");
    c << s("PersistentKeepalive = ") + (keepalive.isEmpty() ? s("25") : keepalive);
    return c.join(s("\n")) + s("\n");
}

// What the app does to the .conf before it connects (configuratorBase.cpp, awgConfigurator.cpp):
// the DNS filled in, the lines left without a value dropped - and the phone's MTU when it names none.
QString finish(const QString& conf, const QVariantMap& root)
{
    QString dns1 = text(root, "dns1");
    QString dns2 = text(root, "dns2");
    if (!isIpv4(dns1)) {
        dns1 = s(kDns1);
    }
    if (!isIpv4(dns2)) {
        dns2 = s(kDns2);
    }
    QString c = conf;
    c.replace(s("\r\n"), s("\n"));
    c.replace(QLatin1Char('\r'), QLatin1Char('\n'));
    c.replace(s("$PRIMARY_DNS"), dns1);
    c.replace(s("$SECONDARY_DNS"), dns2);

    const QStringList lines = c.split(QLatin1Char('\n'));
    QRegExp emptyValue(s("\\s*[^\\s=]+\\s*=\\s*"));
    QRegExp mtu(s("\\s*MTU\\s*=.*"), Qt::CaseInsensitive);
    bool hasMtu = false;
    QStringList kept;
    for (int i = 0; i < lines.size(); ++i) {
        if (emptyValue.exactMatch(lines.at(i))) {
            continue;
        }
        if (mtu.exactMatch(lines.at(i))) {
            hasMtu = true;
        }
        kept << lines.at(i);
    }
    if (!hasMtu) {
        for (int i = 0; i < kept.size(); ++i) {
            if (kept.at(i).trimmed().compare(s("[Interface]"), Qt::CaseInsensitive) == 0) {
                kept.insert(i + 1, s("MTU = ") + s(kMtu));
                break;
            }
        }
    }
    while (!kept.isEmpty() && kept.last().trimmed().isEmpty()) {
        kept.removeLast();
    }
    return kept.join(s("\n")) + s("\n");
}

AmneziaKey::Result fromJson(const QVariantMap& root)
{
    AmneziaKey::Result r;
    if (root.isEmpty()) {
        r.error = s("damaged");
        return r;
    }
    // Its subscriptions: the connection comes from Amnezia's servers (api_config, auth_data;
    // config_version 1 - Telegram, 2 - the gateway).
    if (root.contains(s("auth_data")) || root.contains(s("api_key")) || root.contains(s("api_config"))
            || root.contains(s("config_version"))) {
        r.error = s("subscription");
        return r;
    }
    // Full access: the server's SSH login, for managing it; no connection of its own.
    if (!text(root, "userName").isEmpty() && !text(root, "password").isEmpty()) {
        r.error = s("full-access");
        return r;
    }

    const QVariantList containers = root.value(s("containers")).toList();
    const QString preferred = text(root, "defaultContainer");
    QVariantMap chosen;
    QString chosenName;
    bool ours = false;
    QStringList others;
    for (int pass = 0; pass < 2 && chosenName.isEmpty(); ++pass) {
        for (int i = 0; i < containers.size(); ++i) {
            const QVariantMap c = containers.at(i).toMap();
            const QString name = text(c, "container");
            const bool isAwg = name == QLatin1String("amnezia-awg2") || name == QLatin1String("amnezia-awg");
            const bool isWg = name == QLatin1String("amnezia-wireguard");
            if (!isAwg && !isWg) {
                const QString other = protocolName(name);
                if (pass == 0 && !other.isEmpty() && !others.contains(other)) {
                    others << other;
                }
                continue;
            }
            ours = true;
            // The default container first, then any of ours.
            if (pass == 0 && name != preferred) {
                continue;
            }
            const QVariantMap proto = c.value(s(isAwg ? "awg" : "wireguard")).toMap();
            if (text(proto, "last_config").isEmpty()) {
                continue;
            }
            chosen = c;
            chosenName = name;
            break;
        }
    }
    if (chosenName.isEmpty()) {
        if (!ours && !others.isEmpty()) {
            r.error = s("other-protocols");
            r.detail = others.join(s(", "));
        } else {
            r.error = s("no-connection");
        }
        return r;
    }

    const bool awg = chosenName != QLatin1String("amnezia-wireguard");
    const QVariantMap server = chosen.value(s(awg ? "awg" : "wireguard")).toMap();
    const QVariantMap client = parseJson(text(server, "last_config").toUtf8());
    QString conf = client.value(s("config")).toString();
    if (!conf.contains(QLatin1String("[Interface]"), Qt::CaseInsensitive)) {
        conf = buildConf(client, server, root, awg);
    }
    if (conf.isEmpty()) {
        r.error = s("no-connection");
        return r;
    }
    r.conf = finish(conf, root);
    r.name = fitName(text(root, "description"));
    if (r.name.isEmpty()) {
        r.name = fitName(text(root, "name"));
    }
    if (r.name.isEmpty()) {
        r.name = fitName(text(root, "hostName"));
    }
    r.ok = true;
    return r;
}

} // namespace

AmneziaKey::Result AmneziaKey::fromText(const QString& input)
{
    QString t = input.trimmed();
    if (t.startsWith(QLatin1String("vpn://"), Qt::CaseInsensitive)) {
        t = t.mid(6);
    }
    if (t.startsWith(QLatin1Char('{'))) {
        return fromJson(parseJson(t.toUtf8()));
    }
    QByteArray raw;
    if (!fromBase64Url(t, &raw)) {
        Result r;
        r.error = s("damaged");
        return r;
    }
    return fromData(raw);
}

AmneziaKey::Result AmneziaKey::fromData(const QByteArray& data)
{
    QByteArray json = inflate(data);
    if (json.isEmpty()) {
        // AmneziaVPN takes an uncompressed one too.
        json = data;
    }
    return fromJson(parseJson(json));
}

bool AmneziaKey::parsePart(const QString& code, Part* part)
{
    const QString t = code.trimmed();
    if (t.isEmpty() || t.contains(QLatin1Char('[')) || t.startsWith(QLatin1String("vpn://"), Qt::CaseInsensitive)) {
        return false;
    }
    QByteArray b;
    if (!fromBase64Url(t, &b) || b.size() < 8) {
        return false;
    }
    const uchar* p = reinterpret_cast<const uchar*>(b.constData());
    const int magic = (p[0] << 8) | p[1];
    const int total = p[2];
    const int index = p[3];
    const quint32 len = ((quint32)p[4] << 24) | ((quint32)p[5] << 16) | ((quint32)p[6] << 8) | (quint32)p[7];
    if (magic != kQrMagic || total < 1 || index >= total || len == 0xffffffffu || len > (quint32)(b.size() - 8)) {
        return false;
    }
    part->total = total;
    part->index = index;
    part->data = b.mid(8, (int)len);
    return true;
}

QString AmneziaKey::keyText(const QByteArray& data)
{
    return s("vpn://") + toBase64Url(data);
}

} // namespace tunnel
