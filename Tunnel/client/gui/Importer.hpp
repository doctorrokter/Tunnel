/*
 * Importer - text for the import sheet (docs/APP.md, section 5): a picked or invoked file, the
 * clipboard; the name to offer for it; what kind of text it is; an AmneziaVPN key made a .conf
 * (AmneziaKey), from its text or from the series of QR codes AmneziaVPN shows for one. The context
 * property "importer". It only reads: the text goes to the daemon (profile.import), which checks it
 * and says the line of a mistake. Nothing of it is written anywhere by the app.
 */

#ifndef TUNNEL_IMPORTER_HPP_
#define TUNNEL_IMPORTER_HPP_

#include <QByteArray>
#include <QMap>
#include <QObject>
#include <QString>
#include <QVariantMap>

namespace tunnel {

class Importer: public QObject
{
    Q_OBJECT
    // Why the last readFile() gave nothing: "missing", "large", "binary" or "unreadable".
    Q_PROPERTY(QString lastError READ lastError NOTIFY lastErrorChanged)
public:
    explicit Importer(QObject* parent = 0);

    QString lastError() const { return m_lastError; }

    // A file's text - a path, or a file:// URI as an invocation hands it over. "" when it cannot
    // be read or is bigger than a profile may be (lastError says which).
    Q_INVOKABLE QString readFile(const QString& pathOrUri);
    // What the clipboard holds as text, "" for nothing.
    Q_INVOKABLE QString clipboardText() const;
    // "home.conf" of ".../home.conf".
    Q_INVOKABLE QString fileName(const QString& pathOrUri) const;
    // "home" of ".../home.conf" - the name a file's profile is offered.
    Q_INVOKABLE QString nameFromFile(const QString& pathOrUri) const;
    // The host of the first Endpoint ("vpn.example.com"), "" when there is none - the name a QR
    // code's or a pasted profile is offered.
    Q_INVOKABLE QString nameFromConf(const QString& text) const;
    Q_INVOKABLE int lineCount(const QString& text) const;
    // "conf" - a .conf ([Interface]); "amnezia-key" - an AmneziaVPN key (vpn://); "tailscale-key" -
    // a Tailscale auth key (tskey-...); "other".
    Q_INVOKABLE QString kind(const QString& text) const;
    // The name this phone asks for in a tailnet: its model as one DNS label ("passport", "classic"),
    // "blackberry" when the model says nothing usable.
    Q_INVOKABLE QString deviceHostname() const;
    // An AmneziaVPN key's connection: { ok, conf, name } or { ok: false, error, detail } - the codes
    // of AmneziaKey::Result, for the sheet to say.
    Q_INVOKABLE QVariantMap fromAmneziaKey(const QString& text) const;

    // A scan starts: no parts of a QR series yet.
    Q_INVOKABLE void qrReset();
    // One QR code read. A part of AmneziaVPN's series: { state: "part", received, total } while
    // parts are missing. Anything else, or the last part: { state: "text", text } - what to import
    // (a .conf, or the whole key as "vpn://...").
    Q_INVOKABLE QVariantMap qrFeed(const QString& code);

Q_SIGNALS:
    void lastErrorChanged();

private:
    static QString localPath(const QString& pathOrUri);
    void setError(const QString& error);

    QString m_lastError;
    // The QR series being read: index -> part.
    QMap<int, QByteArray> m_qrParts;
    int m_qrTotal;
};

} // namespace tunnel

#endif /* TUNNEL_IMPORTER_HPP_ */
