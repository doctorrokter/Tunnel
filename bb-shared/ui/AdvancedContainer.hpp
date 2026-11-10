/*
 * bb-shared / ui / AdvancedContainer.hpp - a Container with rounded corners and a border, all of it in C++.
 * `import bb.shared 1.0` (bb_shared_ui, registerUiTypes), then use it as a Container:
 *
 *     AdvancedContainer {
 *         color: theme.secondaryBackground
 *         cornerRadius: ui.du(2)          // px; 0 = square
 *         squareCorners: AdvancedContainer.BottomLeft | AdvancedContainer.BottomRight   // optional; 0 = all round
 *         borderWidth: 0.3                // du; 0 = none
 *         borderColor: theme.surfaceBorder
 *         layout: DockLayout { }
 *         Label { text: "..." }
 *     }
 *
 * The whole contract of Container stays - children, layout, paddings, margins, alignment, gestures. What it
 * adds are knobs only, and it knows nothing of any app or setting: the app decides what to pass (a square UI
 * passes cornerRadius 0). The successor of the QML RoundedContainer (bb-shared ui/qml and the apps' own
 * copies): the same knobs, without a QML document, an ImagePaintDefinition, a LayoutUpdateHandler and a JS
 * binding per instance, and without the picture that one rendered to a PNG on disk on the UI thread.
 *
 * What it draws, the cheapest that is right:
 *  - no radius and no border, or a transparent fill with no border: the plain colour (or nothing) - a
 *    Container's own background, no picture at all;
 *  - `nine` and no border, with the app's own tile for the colour (assets/nineslice/<aarrggbb>.amd - Cascades
 *    compiles an .amd at build time, so the tiles are the app's, README): the tile - one per colour, never
 *    redrawn on resize;
 *  - otherwise a picture of the container's size: drawn in memory (no file) the moment the size is known -
 *    the laid-out frame; until then knownWidth / knownHeight when both are set, else preferredWidth /
 *    preferredHeight when both are set (either: from the first frame) - kept in one cache shared by every
 *    instance (by size, radius, colours and border), within a byte budget. `widthStep` rounds the width, so
 *    similar widths share one picture, stretched. While there is no size yet, a square one (radius 0, a
 *    border) shows its plain colour - only the border is late; a rounded one shows nothing.
 * A border with no radius is a picture too: a Container has one background, and a child under the content
 * would take a place in the instance's own layout. The radius is clamped to half the shorter side, so a big
 * one is a capsule (or a circle) at any size. `squareCorners` leaves some corners square (Corner flags) - in the
 * picture's key, so such a picture is shared only with its own kind.
 */
#ifndef BBSHARED_ADVANCEDCONTAINER_HPP
#define BBSHARED_ADVANCEDCONTAINER_HPP

#include <bb/cascades/Color>
#include <bb/cascades/Container>

#include <QRectF>
#include <QSizeF>
#include <QString>
#include <QVariant>

namespace bb { namespace cascades { class LayoutUpdateHandler; } }

namespace bbshared {

class AdvancedContainer: public bb::cascades::Container
{
    Q_OBJECT
    // The fill (a Color). Transparent until set.
    Q_PROPERTY(QVariant color READ color WRITE setColor NOTIFY colorChanged)
    // The corners' radius, px. 0 - square; with no border either, no picture is made at all.
    Q_PROPERTY(float cornerRadius READ cornerRadius WRITE setCornerRadius NOTIFY cornerRadiusChanged)
    // The corners left square in a rounded one (Corner flags, OR-ed: AdvancedContainer.BottomLeft |
    // AdvancedContainer.BottomRight); 0 - all four round. Two such stacked edge to edge, in one colour, are ONE
    // shape: a forum row's bubble in BBTelega's chat list - a topic's name over the message line.
    Q_PROPERTY(int squareCorners READ squareCorners WRITE setSquareCorners NOTIFY squareCornersChanged)
    // The border's width in du (as RoundedContainer's); 0 - none.
    Q_PROPERTY(float borderWidth READ borderWidth WRITE setBorderWidth NOTIFY borderWidthChanged)
    Q_PROPERTY(QVariant borderColor READ borderColor WRITE setBorderColor NOTIFY borderColorChanged)
    // The colour's bundled nine-slice tile instead of a picture of the size (no border only; no tile - the
    // picture).
    Q_PROPERTY(bool nine READ nine WRITE setNine NOTIFY nineChanged)
    // The picture's width rounded to this many px, 0 = exact.
    Q_PROPERTY(float widthStep READ widthStep WRITE setWidthStep NOTIFY widthStepChanged)
    // A size to draw at before the layout reports one, px (both set, or neither is used) - a remembered or
    // an estimated size. It does not size the container; the laid-out frame has the last word.
    Q_PROPERTY(float knownWidth READ knownWidth WRITE setKnownWidth NOTIFY knownWidthChanged)
    Q_PROPERTY(float knownHeight READ knownHeight WRITE setKnownHeight NOTIFY knownHeightChanged)
    // The background asked for is shown (false while a picture waits for a size).
    Q_PROPERTY(bool ready READ ready NOTIFY readyChanged)

public:
    // squareCorners' flags.
    enum Corner {
        TopLeft     = 1,
        TopRight    = 2,
        BottomRight = 4,
        BottomLeft  = 8
    };
    Q_ENUMS(Corner)

    explicit AdvancedContainer(bb::cascades::Container* parent = 0);
    virtual ~AdvancedContainer();

    QVariant color() const { return m_color; }
    void setColor(const QVariant& color);
    float cornerRadius() const { return m_radius; }
    void setCornerRadius(float radius);
    int squareCorners() const { return m_squareCorners; }
    void setSquareCorners(int corners);
    float borderWidth() const { return m_borderDu; }
    void setBorderWidth(float du);
    QVariant borderColor() const { return m_borderColor; }
    void setBorderColor(const QVariant& color);
    bool nine() const { return m_nine; }
    void setNine(bool on);
    float widthStep() const { return m_widthStep; }
    void setWidthStep(float px);
    float knownWidth() const { return m_knownWidth; }
    void setKnownWidth(float px);
    float knownHeight() const { return m_knownHeight; }
    void setKnownHeight(float px);
    bool ready() const { return m_ready; }

Q_SIGNALS:
    void colorChanged();
    void cornerRadiusChanged();
    void squareCornersChanged();
    void borderWidthChanged();
    void borderColorChanged();
    void nineChanged();
    void widthStepChanged();
    void knownWidthChanged();
    void knownHeightChanged();
    void readyChanged();
    // The laid-out size, px, each time it changes - while the size is watched, that is while a picture of
    // the size is drawn (a plain colour or a tile needs no size, and nothing measures it).
    void measured(float frameWidth, float frameHeight);

private Q_SLOTS:
    void onLayoutFrameChanged(const QRectF& frame);
    void onPreferredSizeChanged();

private:
    // The background for what is set now - the plain colour, the tile, or the picture of the size.
    void refresh();
    // Measured from now on (a picture needs the size): the handler is made the first time.
    void watchSize();
    // What the background shows now, and whether it is what is asked for.
    void show(const QString& key, bool ready);

    QVariant m_color;
    QVariant m_borderColor;
    float    m_radius;
    int      m_squareCorners;   // Corner flags
    float    m_borderDu;
    float    m_widthStep;
    float    m_knownWidth;
    float    m_knownHeight;
    bool     m_nine;
    bool     m_ready;
    QSizeF   m_frame;          // laid out, px; empty until measured
    QSizeF   m_reported;       // the size measured() said last
    bb::cascades::LayoutUpdateHandler* m_layout;
    QString  m_shown;          // what the background shows now ("" = nothing set by us)
};

} // namespace bbshared

#endif // BBSHARED_ADVANCEDCONTAINER_HPP
