/*
 * bb-shared / ui / AdvancedContainer.cpp - see AdvancedContainer.hpp.
 */
#include "AdvancedContainer.hpp"

#include <bb/ImageData>
#include <bb/PixelFormat>
#include <bb/cascades/Image>
#include <bb/cascades/ImagePaint>
#include <bb/cascades/LayoutUpdateHandler>
#include <bb/cascades/UIConfig>

#include <QCache>
#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QHash>
#include <QPointer>
#include <QUrl>
#include <QtGui/QImage>
#include <QtGui/QPainter>
#include <QtGui/QPainterPath>
#include <QtGlobal>

#include <math.h>

using namespace bb::cascades;

namespace bbshared {

namespace {

// The pictures of every instance, by what they show; the cost is their bytes. The feed's bubbles are tiles,
// so what lands here is small: pills, plates, round buttons.
const int kCacheBytes = 8 * 1024 * 1024;
// The GPU's texture side (KB: a bigger one is not drawn at all).
const int kMaxSide = 2048;

// HELD BY AN OBJECT DELETED WHEN THE APP IS ABOUT TO QUIT, while Cascades is still there to let the pictures
// go. A static cache let them go in its own destructor at exit, after Cascades had gone - "ApplicationPrivate::
// resourceManager: ERROR called from non-UI thread" on a close (GUI 317). QCoreApplication::exec() delivers
// the deleteLater right after aboutToQuit. One asked for after that is never deleted - the process is ending.
class Pictures : public QObject
{
public:
    Pictures() :
            cache(kCacheBytes)
    {
    }

    QCache<QString, Image> cache;
};

QCache<QString, Image>& pictures()
{
    static QPointer<Pictures> holder;
    if (holder.isNull()) {
        holder = new Pictures();
        if (QCoreApplication::instance() != 0) {
            QObject::connect(QCoreApplication::instance(), SIGNAL(aboutToQuit()), holder, SLOT(deleteLater()));
        }
    }
    return holder->cache;
}

// A Color as "aarrggbb" - the nine-slice tiles' names, and the pictures' keys.
QString hexOf(const Color& c)
{
    if (c.isNull()) {
        return QLatin1String("00000000");
    }
    const int a = qRound(c.alpha() * 255.0f);
    const int r = qRound(c.red() * 255.0f);
    const int g = qRound(c.green() * 255.0f);
    const int b = qRound(c.blue() * 255.0f);
    return QString("%1%2%3%4").arg(a, 2, 16, QChar('0')).arg(r, 2, 16, QChar('0'))
            .arg(g, 2, 16, QChar('0')).arg(b, 2, 16, QChar('0'));
}

Color colorOf(const QVariant& v)
{
    if (!v.isValid()) {
        return Color();
    }
    return v.value<Color>();
}

QColor qcolorOf(const Color& c)
{
    if (c.isNull()) {
        return QColor(0, 0, 0, 0);
    }
    return QColor::fromRgbF(c.red(), c.green(), c.blue(), c.alpha());
}

// Is there a bundled tile for this colour? Looked for once per colour per process.
bool hasNineTile(const QString& hex)
{
    static QHash<QString, bool> known;
    const QHash<QString, bool>::const_iterator it = known.constFind(hex);
    if (it != known.constEnd()) {
        return it.value();
    }
    const bool there = QFile::exists(QDir::currentPath() + QLatin1String("/app/native/assets/nineslice/")
                                     + hex + QLatin1String(".amd"));
    known.insert(hex, there);
    return there;
}

// A rectangle with each corner round (radius r) or square (squareCorners' flags), clockwise from the top left.
QPainterPath cornersPath(const QRectF& rect, qreal r, int squareCorners)
{
    const qreal topLeft     = (squareCorners & AdvancedContainer::TopLeft) ? 0 : r;
    const qreal topRight    = (squareCorners & AdvancedContainer::TopRight) ? 0 : r;
    const qreal bottomRight = (squareCorners & AdvancedContainer::BottomRight) ? 0 : r;
    const qreal bottomLeft  = (squareCorners & AdvancedContainer::BottomLeft) ? 0 : r;
    QPainterPath path;
    path.moveTo(rect.left() + topLeft, rect.top());
    path.lineTo(rect.right() - topRight, rect.top());
    if (topRight > 0) {
        path.arcTo(QRectF(rect.right() - 2 * topRight, rect.top(), 2 * topRight, 2 * topRight), 90, -90);
    }
    path.lineTo(rect.right(), rect.bottom() - bottomRight);
    if (bottomRight > 0) {
        path.arcTo(QRectF(rect.right() - 2 * bottomRight, rect.bottom() - 2 * bottomRight,
                          2 * bottomRight, 2 * bottomRight), 0, -90);
    }
    path.lineTo(rect.left() + bottomLeft, rect.bottom());
    if (bottomLeft > 0) {
        path.arcTo(QRectF(rect.left(), rect.bottom() - 2 * bottomLeft, 2 * bottomLeft, 2 * bottomLeft), 270, -90);
    }
    path.lineTo(rect.left(), rect.top() + topLeft);
    if (topLeft > 0) {
        path.arcTo(QRectF(rect.left(), rect.top(), 2 * topLeft, 2 * topLeft), 180, -90);
    }
    path.closeSubpath();
    return path;
}

// The rounded rectangle, its fill and its border, as a Cascades Image - drawn in memory, synchronous.
Image drawPicture(int w, int h, float radius, int squareCorners, const Color& fill, int borderPx, const Color& border)
{
    QImage img(w, h, QImage::Format_ARGB32_Premultiplied);
    img.fill(Qt::transparent);
    QPainter p(&img);
    p.setRenderHint(QPainter::Antialiasing, true);
    p.setBrush(qcolorOf(fill));
    // A pill asks for a huge radius: clamped to half the shorter side, exactly (not in whole pixels - an odd
    // height would flatten the ends).
    const qreal rr = qMin(qreal(radius), qreal(qMin(w, h)) / 2);
    if (borderPx > 0) {
        // Inset by half the pen, so the stroke stays on the bitmap; the radius in by as much, so the OUTER
        // edge keeps the radius asked for.
        const qreal inset = borderPx / 2.0;
        p.setPen(QPen(qcolorOf(border), (qreal) borderPx));
        if (squareCorners == 0) {
            p.drawRoundedRect(QRectF(inset, inset, w - borderPx, h - borderPx),
                              qMax(qreal(0), rr - inset), qMax(qreal(0), rr - inset));
        } else {
            p.drawPath(cornersPath(QRectF(inset, inset, w - borderPx, h - borderPx), qMax(qreal(0), rr - inset),
                                   squareCorners));
        }
    } else {
        p.setPen(Qt::NoPen);
        if (squareCorners == 0) {
            p.drawRoundedRect(QRectF(0, 0, w, h), rr, rr);
        } else {
            p.drawPath(cornersPath(QRectF(0, 0, w, h), rr, squareCorners));
        }
    }
    p.end();

    // ARGB32_Premultiplied is B,G,R,A in memory on little-endian; Cascades' RGBA_Premultiplied wants R,G,B,A.
    uchar* d = img.bits();
    const int n = w * h;
    for (int i = 0; i < n; ++i) {
        const uchar b = d[i * 4];
        d[i * 4] = d[i * 4 + 2];
        d[i * 4 + 2] = b;
    }
    return Image(bb::ImageData::fromPixels(img.constBits(), bb::PixelFormat::RGBA_Premultiplied, w, h,
                                           img.bytesPerLine()));
}

} // namespace

AdvancedContainer::AdvancedContainer(Container* parent) :
        Container(parent),
        m_radius(0),
        m_squareCorners(0),
        m_borderDu(0),
        m_widthStep(0),
        m_knownWidth(0),
        m_knownHeight(0),
        m_nine(false),
        m_ready(false),
        m_layout(0)
{
    // Nothing set yet is nothing to draw - and that is ready.
    refresh();
}

AdvancedContainer::~AdvancedContainer()
{
}

void AdvancedContainer::setColor(const QVariant& color)
{
    if (color == m_color) {
        return;
    }
    m_color = color;
    emit colorChanged();
    refresh();
}

void AdvancedContainer::setCornerRadius(float radius)
{
    if (qFuzzyCompare(1.0f + radius, 1.0f + m_radius)) {
        return;
    }
    m_radius = radius;
    emit cornerRadiusChanged();
    refresh();
}

void AdvancedContainer::setSquareCorners(int corners)
{
    if (corners == m_squareCorners) {
        return;
    }
    m_squareCorners = corners;
    emit squareCornersChanged();
    refresh();
}

void AdvancedContainer::setBorderWidth(float du)
{
    if (qFuzzyCompare(1.0f + du, 1.0f + m_borderDu)) {
        return;
    }
    m_borderDu = du;
    emit borderWidthChanged();
    refresh();
}

void AdvancedContainer::setBorderColor(const QVariant& color)
{
    if (color == m_borderColor) {
        return;
    }
    m_borderColor = color;
    emit borderColorChanged();
    refresh();
}

void AdvancedContainer::setNine(bool on)
{
    if (on == m_nine) {
        return;
    }
    m_nine = on;
    emit nineChanged();
    refresh();
}

void AdvancedContainer::setWidthStep(float px)
{
    if (qFuzzyCompare(1.0f + px, 1.0f + m_widthStep)) {
        return;
    }
    m_widthStep = px;
    emit widthStepChanged();
    refresh();
}

void AdvancedContainer::setKnownWidth(float px)
{
    if (qFuzzyCompare(1.0f + px, 1.0f + m_knownWidth)) {
        return;
    }
    m_knownWidth = px;
    emit knownWidthChanged();
    refresh();
}

void AdvancedContainer::setKnownHeight(float px)
{
    if (qFuzzyCompare(1.0f + px, 1.0f + m_knownHeight)) {
        return;
    }
    m_knownHeight = px;
    emit knownHeightChanged();
    refresh();
}

void AdvancedContainer::watchSize()
{
    if (m_layout != 0) {
        return;
    }
    m_layout = LayoutUpdateHandler::create(this)
            .onLayoutFrameChanged(this, SLOT(onLayoutFrameChanged(const QRectF&)));
    // A size set ahead is the size until the layout says otherwise: the picture from the first frame.
    connect(this, SIGNAL(preferredWidthChanged(float)), this, SLOT(onPreferredSizeChanged()));
    connect(this, SIGNAL(preferredHeightChanged(float)), this, SLOT(onPreferredSizeChanged()));
    // Laid out already (a square one that turned rounded on screen): that frame now - the layout may not
    // report again until something moves.
    const QRectF frame = m_layout->layoutFrame();
    if (frame.width() >= 1 && frame.height() >= 1) {
        m_frame = frame.size();
    }
}

void AdvancedContainer::onLayoutFrameChanged(const QRectF& frame)
{
    const QSizeF size = frame.size();
    if (size != m_frame) {
        m_frame = size;
        refresh();
    }
    if (size != m_reported) {
        m_reported = size;
        emit measured(size.width(), size.height());
    }
}

void AdvancedContainer::show(const QString& key, bool ready)
{
    m_shown = key;
    if (ready != m_ready) {
        m_ready = ready;
        emit readyChanged();
    }
}

void AdvancedContainer::onPreferredSizeChanged()
{
    if (m_frame.isEmpty()) {
        refresh();
    }
}

void AdvancedContainer::refresh()
{
    const Color fill = colorOf(m_color);
    const bool clear = fill.isNull() || fill.alpha() <= 0.0f;
    const int borderPx = (m_borderDu > 0) ? qMax(1, qRound(ui()->du(m_borderDu))) : 0;

    // Nothing to draw: the plain colour, or nothing at all (a clear fill with no border, whatever the
    // radius) - no picture, no size needed.
    if ((m_radius <= 0 || clear) && borderPx <= 0) {
        const QString key = clear ? QString(QLatin1String("plain:")) : (QLatin1String("plain:") + hexOf(fill));
        if (key != m_shown) {
            if (clear) {
                resetBackground();
            } else {
                setBackground(fill);
            }
        }
        show(key, true);
        return;
    }

    // The colour's own tile in the app's assets: any size, nothing drawn.
    if (m_nine && borderPx <= 0) {
        const QString hex = hexOf(fill);
        if (hasNineTile(hex)) {
            const QString key = QLatin1String("nine:") + hex;
            if (key != m_shown) {
                setBackground(ImagePaint(QUrl(QLatin1String("asset:///nineslice/") + hex
                                              + QLatin1String(".amd"))));
            }
            show(key, true);
            return;
        }
    }

    // A picture of the size: the laid-out frame; until there is one, a size known or set ahead.
    watchSize();
    float width = m_frame.width();
    float height = m_frame.height();
    if (width < 1 || height < 1) {
        if (m_knownWidth >= 1 && m_knownHeight >= 1) {
            width = m_knownWidth;
            height = m_knownHeight;
        } else if (isPreferredWidthSet() && isPreferredHeightSet()) {
            width = preferredWidth();
            height = preferredHeight();
        }
    }
    if (width < 1 || height < 1) {
        // No size yet. Square: the plain colour stands in, only the border is late. Rounded: nothing - a
        // square stand-in would show corners that are not there.
        if (m_radius <= 0 && !clear) {
            const QString key = QLatin1String("wait:") + hexOf(fill);
            if (key != m_shown) {
                setBackground(fill);
            }
            show(key, false);
        } else {
            const QString key = QLatin1String("wait:");
            if (key != m_shown) {
                resetBackground();
            }
            show(key, false);
        }
        return;
    }
    int w = (int) ceilf(width);
    const int h = qMin(kMaxSide, (int) ceilf(height));
    if (m_widthStep > 0) {
        const int step = qMax(1, (int) ceilf(m_widthStep));
        w = qMax(step, ((w + step / 2) / step) * step);
    }
    w = qMin(kMaxSide, w);

    const Color border = colorOf(m_borderColor);
    const QString key = QString("%1x%2/%3/%4/%5/%6/%7").arg(w).arg(h).arg(m_radius).arg(hexOf(fill))
                        .arg(borderPx).arg(borderPx > 0 ? hexOf(border) : QString()).arg(m_squareCorners);
    if (key == m_shown) {
        show(key, true);
        return;
    }
    const Image* cached = pictures().object(key);
    if (cached != 0) {
        setBackground(ImagePaint(*cached));
    } else {
        const Image picture = drawPicture(w, h, m_radius, m_squareCorners, fill, borderPx, border);
        setBackground(ImagePaint(picture));
        // A picture bigger than the whole budget (a full-screen plate on the Passport) is shown, not kept.
        pictures().insert(key, new Image(picture), w * h * 4);
    }
    show(key, true);
}

} // namespace bbshared
