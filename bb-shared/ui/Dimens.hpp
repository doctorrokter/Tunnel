/*
 * bb-shared / ui / Dimens.hpp - responsive layout metrics, exposed to QML as `dimens`.
 *
 * The spacing every app of ours lays its pages out with. Design-unit MULTIPLIERS (not pixels), used
 * through ui.du():
 *
 *     leftPadding: ui.du(dimens.pad)
 *     bottomMargin: ui.du(dimens.gap)
 *
 * A normal phone (Z10/Z30, Q10/Classic) gets the standard 2 du; a Passport-class screen (square 1440,
 * ~453 ppi) gets a roomier 3 du, so content is not edge to edge on the wide panel. `wide` flags a
 * screen wide enough for multi-column layouts; screenWidth / screenHeight are the portrait edges in
 * PIXELS (custom ListView rows do not fill the list by themselves - give them preferredWidth).
 *
 * This is bbc::Dimens of BBLichess / BBHealth / BBTube / BBTelega, "ported verbatim, keep in sync" -
 * now kept once (BBTelega the last to move, 2026-10-18). BBTelega's chat-only bubbleMaxWidth stays in BBTelega.
 *
 * Opt-in with CONFIG += bb_shared_dimens, then bbshared::installDimensContext() (BbSharedDimens.hpp).
 * An app that still has its own Dimens.cpp deletes it in the same change: qmake's flat object dir.
 */
#ifndef BBSHARED_DIMENS_HPP
#define BBSHARED_DIMENS_HPP

#include <QObject>

namespace bbshared {

class Dimens : public QObject
{
    Q_OBJECT
    Q_PROPERTY(int pad READ pad CONSTANT)                    // screen edge padding, in du
    Q_PROPERTY(int gap READ gap CONSTANT)                    // spacing between elements, in du
    Q_PROPERTY(bool wide READ wide CONSTANT)                 // wide enough for multi-column layouts
    Q_PROPERTY(bool square READ square CONSTANT)             // a square screen: Passport, Q10, Classic, Q5
    // A small square screen - Q10, Q5, P'9983, Classic: square and not wide, 80 - 90 du against the Passport's
    // 120 (KB 1.42). The one switch for "what has room on a Passport tightens here"; the tall phones (Z10,
    // Z30, Leap) and the Passport are not compact. In a ScreenFrame run it is the pretended screen's.
    Q_PROPERTY(bool compact READ compact CONSTANT)
    Q_PROPERTY(int screenWidth READ screenWidth CONSTANT)    // portrait width (short edge), in px
    Q_PROPERTY(int screenHeight READ screenHeight CONSTANT)  // portrait height (long edge), in px
    // How much smaller this screen is than the base every layout of ours is drawn for - the Passport, 120 du
    // across: on a compact screen its width in du / 120 (Q10, Q5 0.67; Classic 0.75), everywhere else 1 (the
    // Passport, and the tall phones, whose layouts are right as they are). react-native-size-matters' width /
    // guidelineBaseWidth, in du.
    Q_PROPERTY(qreal ratio READ ratio CONSTANT)
    // The factor scale(du) takes when none is passed: 0.5, or what the app set (setScaleFactor). It may change
    // while the app runs (a compactness setting), and says so: a binding that READS it follows at once -
    //     preferredWidth: (dimens.scaleFactor >= 0) ? dimens.scale(13) : 0
    // while one that only calls scale() keeps the size it was made with (scale() is a call, not a property).
    Q_PROPERTY(qreal scaleFactor READ scaleFactor NOTIFY scaleFactorChanged)

public:
    explicit Dimens(QObject* parent = 0);
    virtual ~Dimens();

    // A development tool's smaller screen (bb-shared/debug ScreenFrame: a Q10 laid out on a Passport): what
    // every Dimens made after it reports instead of this phone's - set before installDimensContext(). Pixels at
    // this phone's own design unit; BIG - the roomier Passport spacing; WIDE - multi-column layouts.
    static void pretendScreen(int widthPx, int heightPx, bool big, bool wide);

    // The app's own default factor for scale(du) - at its start, before its QML is loaded (0.5 if never set).
    // One knob for the whole app; a single size that needs another passes its own. Set again later, every
    // Dimens emits scaleFactorChanged (see scaleFactor).
    static void setScaleFactor(qreal factor);

    int pad() const { return m_pad; }
    int gap() const { return m_gap; }
    bool wide() const { return m_wide; }
    bool square() const { return m_square; }
    bool compact() const { return m_square && !m_wide; }
    int screenWidth() const { return m_screenWidth; }
    int screenHeight() const { return m_screenHeight; }
    qreal ratio() const { return m_ratio; }
    qreal scaleFactor() const;

    /*
     * A size in du to PIXELS, as ui.du() - shrunk on a compact screen. Call it wherever a size is set; it
     * decides by itself. react-native-size-matters' moderateScale: du x (1 + (ratio - 1) x factor). FACTOR is
     * how much of the screen's ratio the size takes: 0 = as on the Passport, 1 = the whole ratio; without one
     * the app's default (scaleFactor, 0.5: Q10 x0.83, Classic x0.88). On a compact screen the result is whole
     * pixels (fractional ones cost a line of text, KB 56); with ratio 1 it is exactly ui.du(du), so on a
     * Passport, a Leap or a Z10 nothing moves by a pixel.
     *
     *     preferredHeight: dimens.scale(13)          // the app's default factor
     *     preferredWidth: dimens.scale(8, 0.8)       // the rare one that shrinks more
     */
    Q_INVOKABLE float scale(float du) const;
    Q_INVOKABLE float scale(float du, float factor) const;

signals:
    void scaleFactorChanged();

private:
    int m_pad;
    int m_gap;
    bool m_wide;
    bool m_square;
    int m_screenWidth;
    int m_screenHeight;
    float m_duPx;      // this phone's design unit, px (a ScreenFrame run lays out at this phone's du too)
    qreal m_ratio;
};

} // namespace bbshared

#endif // BBSHARED_DIMENS_HPP
