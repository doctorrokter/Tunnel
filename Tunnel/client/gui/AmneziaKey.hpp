/*
 * AmneziaKey - an AmneziaVPN key turned into the .conf the daemon takes (docs/APP.md, section 5): the
 * text "vpn://...", a .vpn file, or the QR codes AmneziaVPN shows for one. The format is read from
 * AmneziaVPN's own client (refs/amnezia-client, GPL - read, nothing taken; see APP.md for the places):
 *
 *   - the key is AmneziaVPN's description of a server: JSON, qCompress-ed (a 4-byte big-endian size,
 *     then zlib), base64url without padding, after "vpn://". Its subscription keys put the bytes
 *     000000ff where the size goes - zlib reads them the same;
 *   - its QR codes carry the compressed JSON in parts of 850 bytes, each as base64url of a QDataStream:
 *     qint16 1984, quint8 the number of parts, quint8 this part's index, QByteArray the part;
 *   - a WireGuard or AmneziaWG connection is a .conf already: containers[] -> {"container":
 *     "amnezia-awg2" | "amnezia-awg" | "amnezia-wireguard", "awg" | "wireguard": {"last_config":
 *     a JSON string -> "config"}}. Its DNS is left as $PRIMARY_DNS and $SECONDARY_DNS for the app:
 *     the key's dns1 / dns2 when they are IPv4 addresses, else 1.1.1.1 / 1.0.0.1 - as AmneziaVPN does.
 *     No MTU in it: AmneziaVPN on a phone uses 1280, and so does the .conf made here.
 *
 * Not a connection, said so: a subscription key (AmneziaFree, Premium - the connection comes from
 * Amnezia's servers at every start), a full-access key (the server's SSH login, for managing it), a key
 * of other protocols (OpenVPN, XRay...). Nothing here is logged or kept: the key holds a private key.
 */

#ifndef TUNNEL_AMNEZIAKEY_HPP_
#define TUNNEL_AMNEZIAKEY_HPP_

#include <QByteArray>
#include <QString>

namespace tunnel {

class AmneziaKey
{
public:
    struct Result {
        Result() : ok(false) {}
        bool ok;
        // The .conf.
        QString conf;
        // The server's name in the key ("description"), else its host; "" when it has none.
        QString name;
        // When not ok: "damaged" | "subscription" | "full-access" | "no-connection" | "other-protocols".
        QString error;
        // For "other-protocols": what the key holds instead ("OpenVPN, XRay").
        QString detail;
    };

    // One part of an AmneziaVPN QR series.
    struct Part {
        Part() : index(0), total(0) {}
        int index;
        int total;
        QByteArray data;
    };

    // "vpn://..." - or the same without the prefix, or the JSON itself.
    static Result fromText(const QString& text);
    // The parts of a QR series put together: the compressed JSON.
    static Result fromData(const QByteArray& data);
    // A QR code's text as a part of a series; false when it is none (a .conf, a key as text...).
    static bool parsePart(const QString& code, Part* part);
    // The parts put together as a key's text, "vpn://..." - for the same way in as a pasted one.
    static QString keyText(const QByteArray& data);
};

} // namespace tunnel

#endif /* TUNNEL_AMNEZIAKEY_HPP_ */
