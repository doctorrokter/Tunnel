/*
 * bb-shared / ui / QRView.hpp - a QR code as a Container, drawn in C++ off the UI thread. `import bb.shared
 * 1.0` (CONFIG += bb_shared_ui bb_shared_qr, registerUiTypes), then:
 *
 *     QRView {
 *         text: "https://login.tailscale.com/a/..."
 *         preferredWidth: ui.du(60)
 *         preferredHeight: ui.du(60)
 *     }
 *
 * and as fancy as wanted:
 *
 *     QRView {
 *         text: link
 *         color: Color.create("#2b8ad9")          // the modules; gradientColor + gradientAngle for two
 *         backgroundColor: Color.White            // the plate; Color.Transparent - none
 *         moduleRadius: 0.28                      // 0 square .. 0.5 round
 *         joinModules: false                      // each module rounded on its own
 *         eyeFrameRadius: 0.2                     // the three finder "eyes", apart from the modules
 *         eyeBallColor: Color.create("#e91e63")
 *         cornerRadius: ui.du(4)                  // the plate's corners, px
 *         iconSource: "asset:///images/logo.png"  // in the middle, its place cleared
 *         iconRadius: 0.5                         // round
 *         badgeSource: "file://" + avatarPath     // a round picture on the plate's top edge
 *         badgeRing: ui.du(0.6)
 *         preferredWidth: ui.du(92)
 *         preferredHeight: ui.du(110)
 *     }
 *
 * What it is: the Container's background is one picture of the container's size - the plate (the quiet zone
 * included) as big as fits with whole px a module, centred, transparent around it - so every straight edge
 * is sharp; the curved ones are anti-aliased. The encoder is Nayuki's qrcodegen (MIT, ui/qr), the drawing
 * ui/qr/QrDraw (plain C++, tested on a PC: ui/qr/test/run.sh). The text is encoded and the picture drawn
 * on a pool thread, the icon and the badge read from their files there too; the UI thread only shows it.
 * Pictures are kept in one cache shared by every instance (by everything that makes them, a file's time
 * and size included), so a page opened again shows its code at once.
 *
 * The size: the laid-out frame; until there is one, preferredWidth / preferredHeight when both are set
 * (the picture from the first frame). Give it the room it should take - a square for a plain code, taller
 * for a badge (its upper half sits above the plate, the plate grows by its lower half). The whole contract
 * of Container stays: children (on top of the code), layout, margins, alignment.
 *
 * saveImage() writes the same picture as a PNG - for sharing: the page's colour baked in under the
 * transparent parts, a world-readable path of the app's choosing. Text is never drawn into the picture
 * (Qt's text drawing crashes in a Cascades app, KB 51): a label under the code is the page's own Label.
 */
#ifndef BBSHARED_QRVIEW_HPP
#define BBSHARED_QRVIEW_HPP

#include <bb/cascades/Container>

#include <QFutureWatcher>
#include <QRectF>
#include <QSizeF>
#include <QString>
#include <QVariant>

namespace bb { namespace cascades { class LayoutUpdateHandler; } }

namespace bbshared {

namespace qrview { struct Job; struct Drawn; struct Picture; }

class QRView: public bb::cascades::Container
{
    Q_OBJECT
    Q_ENUMS(ErrorCorrection)
    // What the code says: a link, any text (UTF-8). Empty - no code, nothing drawn.
    Q_PROPERTY(QString text READ text WRITE setText NOTIFY textChanged)
    // How much of the code may be lost and it still reads. Auto: Medium; High with an icon (the icon hides
    // data). A higher level makes a denser code of the same text.
    Q_PROPERTY(ErrorCorrection errorCorrection READ errorCorrection WRITE setErrorCorrection NOTIFY errorCorrectionChanged)

    // --- Colours (Color). Unset where it says so: the property's own value, not Color.Transparent.
    // The dark modules. Black until set.
    Q_PROPERTY(QVariant color READ color WRITE setColor NOTIFY colorChanged)
    // Set: the modules run from `color` to this across the code, at gradientAngle.
    Q_PROPERTY(QVariant gradientColor READ gradientColor WRITE setGradientColor NOTIFY gradientColorChanged)
    // Degrees: 0 - left to right, 90 - top to bottom, 45 - corner to corner.
    Q_PROPERTY(float gradientAngle READ gradientAngle WRITE setGradientAngle NOTIFY gradientAngleChanged)
    // The plate: the light modules, the quiet zone, the icon's place, the badge's ring. White until set;
    // Color.Transparent - no plate (keep the page light behind it: a code reads dark on light).
    Q_PROPERTY(QVariant backgroundColor READ backgroundColor WRITE setBackgroundColor NOTIFY backgroundColorChanged)
    // The finders' frames and balls; unset - the modules' colours.
    Q_PROPERTY(QVariant eyeFrameColor READ eyeFrameColor WRITE setEyeFrameColor NOTIFY eyeFrameColorChanged)
    Q_PROPERTY(QVariant eyeBallColor READ eyeBallColor WRITE setEyeBallColor NOTIFY eyeBallColorChanged)

    // --- Shapes. Shares are clamped to their ranges.
    // The light margin around the code, in modules. The standard asks for 4; on a light page 2 reads too.
    Q_PROPERTY(int quietZone READ quietZone WRITE setQuietZone NOTIFY quietZoneChanged)
    // A module's corners, a share of its side: 0 square .. 0.5 round.
    Q_PROPERTY(float moduleRadius READ moduleRadius WRITE setModuleRadius NOTIFY moduleRadiusChanged)
    // A module's side, a share of its cell: 0.5 .. 1. Below 1 the modules stand apart (dots).
    Q_PROPERTY(float moduleScale READ moduleScale WRITE setModuleScale NOTIFY moduleScaleChanged)
    // Rounded modules joined with their dark neighbours: only the corners on the outside of a group are
    // rounded. false - each module rounded on its own. Full modules only (moduleScale 1).
    Q_PROPERTY(bool joinModules READ joinModules WRITE setJoinModules NOTIFY joinModulesChanged)
    // The three finder patterns: the frame (7 modules) and the ball in it (3), shapes of their own; a share
    // of their side: 0 square .. 0.5 - a ring, a dot.
    Q_PROPERTY(float eyeFrameRadius READ eyeFrameRadius WRITE setEyeFrameRadius NOTIFY eyeFrameRadiusChanged)
    Q_PROPERTY(float eyeBallRadius READ eyeBallRadius WRITE setEyeBallRadius NOTIFY eyeBallRadiusChanged)
    // The plate's corners, px; at most 3 quiet zones (a rounder corner would cut the code).
    Q_PROPERTY(float cornerRadius READ cornerRadius WRITE setCornerRadius NOTIFY cornerRadiusChanged)

    // --- The icon in the middle (a logo). Its place is cleared of modules, so it costs data: keep
    // errorCorrection Auto or High, and iconSize at 0.25 and below.
    // asset:///..., file://<path as it is>, an absolute path; a relative one is taken from the assets.
    // Empty - no icon, nothing cleared. Fitted into its square, its proportions kept.
    Q_PROPERTY(QString iconSource READ iconSource WRITE setIconSource NOTIFY iconSourceChanged)
    // Its side, a share of the code's side: 0 .. 0.3.
    Q_PROPERTY(float iconSize READ iconSize WRITE setIconSize NOTIFY iconSizeChanged)
    // The light around it, modules: 0 .. 4.
    Q_PROPERTY(float iconMargin READ iconMargin WRITE setIconMargin NOTIFY iconMarginChanged)
    // Its corners and its place's, a share of the side: 0 square .. 0.5 round.
    Q_PROPERTY(float iconRadius READ iconRadius WRITE setIconRadius NOTIFY iconRadiusChanged)

    // --- The badge: a round picture (a profile photo) on the plate's top edge, half of it above.
    // Addresses as iconSource; cropped to its circle. A badge is there when either is set.
    Q_PROPERTY(QString badgeSource READ badgeSource WRITE setBadgeSource NOTIFY badgeSourceChanged)
    // The disc under the picture, or in its place (no picture, or it cannot be read).
    Q_PROPERTY(QVariant badgeColor READ badgeColor WRITE setBadgeColor NOTIFY badgeColorChanged)
    // Its diameter, a share of the plate's width: 0.05 .. 0.5.
    Q_PROPERTY(float badgeSize READ badgeSize WRITE setBadgeSize NOTIFY badgeSizeChanged)
    // The ring of the plate's colour around it, px.
    Q_PROPERTY(float badgeRing READ badgeRing WRITE setBadgeRing NOTIFY badgeRingChanged)

    // --- What came out.
    // The text is encoded: false - empty, or too long for a QR code (2953 bytes at Low, fewer above).
    Q_PROPERTY(bool valid READ valid NOTIFY validChanged)
    // The code's version, 1 .. 40, and its modules a side (21 .. 177); 0 - none.
    Q_PROPERTY(int version READ version NOTIFY versionChanged)
    Q_PROPERTY(int moduleCount READ moduleCount NOTIFY moduleCountChanged)
    // A module's side on screen, px; 0 - nothing drawn (no code, or the view smaller than a px a module).
    Q_PROPERTY(int moduleSize READ moduleSize NOTIFY moduleSizeChanged)
    // The picture for what is set now is shown (false while it is being drawn, or there is no size yet).
    Q_PROPERTY(bool ready READ ready NOTIFY readyChanged)

public:
    enum ErrorCorrection
    {
        Auto = 0,
        Low = 1,
        Medium = 2,
        Quartile = 3,
        High = 4
    };

    explicit QRView(bb::cascades::Container* parent = 0);
    virtual ~QRView();

    QString text() const { return m_text; }
    void setText(const QString& text);
    ErrorCorrection errorCorrection() const { return m_errorCorrection; }
    void setErrorCorrection(ErrorCorrection level);

    QVariant color() const { return m_color; }
    void setColor(const QVariant& color);
    QVariant gradientColor() const { return m_gradientColor; }
    void setGradientColor(const QVariant& color);
    float gradientAngle() const { return m_gradientAngle; }
    void setGradientAngle(float degrees);
    QVariant backgroundColor() const { return m_backgroundColor; }
    void setBackgroundColor(const QVariant& color);
    QVariant eyeFrameColor() const { return m_eyeFrameColor; }
    void setEyeFrameColor(const QVariant& color);
    QVariant eyeBallColor() const { return m_eyeBallColor; }
    void setEyeBallColor(const QVariant& color);

    int quietZone() const { return m_quietZone; }
    void setQuietZone(int modules);
    float moduleRadius() const { return m_moduleRadius; }
    void setModuleRadius(float share);
    float moduleScale() const { return m_moduleScale; }
    void setModuleScale(float share);
    bool joinModules() const { return m_joinModules; }
    void setJoinModules(bool join);
    float eyeFrameRadius() const { return m_eyeFrameRadius; }
    void setEyeFrameRadius(float share);
    float eyeBallRadius() const { return m_eyeBallRadius; }
    void setEyeBallRadius(float share);
    float cornerRadius() const { return m_cornerRadius; }
    void setCornerRadius(float px);

    QString iconSource() const { return m_iconSource; }
    void setIconSource(const QString& source);
    float iconSize() const { return m_iconSize; }
    void setIconSize(float share);
    float iconMargin() const { return m_iconMargin; }
    void setIconMargin(float modules);
    float iconRadius() const { return m_iconRadius; }
    void setIconRadius(float share);

    QString badgeSource() const { return m_badgeSource; }
    void setBadgeSource(const QString& source);
    QVariant badgeColor() const { return m_badgeColor; }
    void setBadgeColor(const QVariant& color);
    float badgeSize() const { return m_badgeSize; }
    void setBadgeSize(float share);
    float badgeRing() const { return m_badgeRing; }
    void setBadgeRing(float px);

    bool valid() const { return m_valid; }
    int version() const { return m_version; }
    int moduleCount() const { return m_moduleCount; }
    int moduleSize() const { return m_moduleSize; }
    bool ready() const { return m_ready; }

    // The picture as shown - this size, these settings - drawn again on a pool thread and written to `path`
    // as a PNG (the folder made if missing); imageSaved() says how it went. `background` (a Color) is baked
    // in under the transparent parts - a shared picture should not depend on the viewer's page; unset -
    // they stay transparent. Nothing to draw (no text, no size yet) - imageSaved(path, false) at once.
    Q_INVOKABLE void saveImage(const QString& path, const QVariant& background = QVariant());

Q_SIGNALS:
    void textChanged();
    void errorCorrectionChanged();
    void colorChanged();
    void gradientColorChanged();
    void gradientAngleChanged();
    void backgroundColorChanged();
    void eyeFrameColorChanged();
    void eyeBallColorChanged();
    void quietZoneChanged();
    void moduleRadiusChanged();
    void moduleScaleChanged();
    void joinModulesChanged();
    void eyeFrameRadiusChanged();
    void eyeBallRadiusChanged();
    void cornerRadiusChanged();
    void iconSourceChanged();
    void iconSizeChanged();
    void iconMarginChanged();
    void iconRadiusChanged();
    void badgeSourceChanged();
    void badgeColorChanged();
    void badgeSizeChanged();
    void badgeRingChanged();
    void validChanged();
    void versionChanged();
    void moduleCountChanged();
    void moduleSizeChanged();
    void readyChanged();
    void imageSaved(const QString& path, bool ok);

private Q_SLOTS:
    // The picture for what is set now: shown, taken from the cache, or asked of the pool.
    void refresh();
    void onLayoutFrameChanged(const QRectF& frame);
    void onPreferredSizeChanged();
    void onDrawn();
    void onSaved();

private:
    // refresh() once the event loop is back: the properties QML sets one by one make one picture.
    void scheduleRefresh();
    // What to draw for what is set now. False - no size yet.
    bool makeJob(qrview::Job& job) const;
    // Shows a finished picture and what it says about the code.
    void show(const QString& key, const qrview::Picture& picture);
    void setInfo(bool valid, int version, int modules, int module);
    void setReady(bool ready);

    QString m_text;
    ErrorCorrection m_errorCorrection;
    QVariant m_color;
    QVariant m_gradientColor;
    float m_gradientAngle;
    QVariant m_backgroundColor;
    QVariant m_eyeFrameColor;
    QVariant m_eyeBallColor;
    int m_quietZone;
    float m_moduleRadius;
    float m_moduleScale;
    bool m_joinModules;
    float m_eyeFrameRadius;
    float m_eyeBallRadius;
    float m_cornerRadius;
    QString m_iconSource;
    float m_iconSize;
    float m_iconMargin;
    float m_iconRadius;
    QString m_badgeSource;
    QVariant m_badgeColor;
    float m_badgeSize;
    float m_badgeRing;

    bool m_valid;
    int m_version;
    int m_moduleCount;
    int m_moduleSize;
    bool m_ready;

    QSizeF m_frame;                 // laid out, px; empty until measured
    bb::cascades::LayoutUpdateHandler* m_layout;
    QString m_shown;                // the key of what the background shows ("" - nothing of ours)
    QFutureWatcher<qrview::Drawn>* m_drawing;   // the one picture being drawn for this view at a time
    bool m_refreshQueued;
};

} // namespace bbshared

#endif // BBSHARED_QRVIEW_HPP
