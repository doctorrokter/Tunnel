/*
 * bb-shared / ui / QRView.cpp - see QRView.hpp.
 */
#include "QRView.hpp"

#include "qr/QrDraw.hpp"

#include <bb/ImageData>
#include <bb/PixelFormat>
#include <bb/cascades/Color>
#include <bb/cascades/Image>
#include <bb/cascades/ImagePaint>
#include <bb/cascades/LayoutUpdateHandler>

#include <QCache>
#include <QCoreApplication>
#include <QDateTime>
#include <QDir>
#include <QFileInfo>
#include <QMetaObject>
#include <QPointer>
#include <QScopedPointer>
#include <QStringList>
#include <QtConcurrentRun>
#include <QtGlobal>
#include <QtGui/QImage>
#include <QtGui/QImageReader>

#include <math.h>

using namespace bb::cascades;

namespace bbshared {

namespace qrview {

// What a picture is drawn from - all of it read on the UI thread, so the pool thread touches nothing else.
struct Job
{
    QString key;
    QByteArray text;
    qr::Ecc ecc;
    qr::Style style;
    QString iconPath;
    QString badgePath;
    int width;
    int height;
};

// A drawn picture and what it says about the code; made on a pool thread.
struct Drawn
{
    QString key;
    bb::ImageData data;     // not valid - nothing to show (no code, less than a px a module)
    bool valid;
    int version;
    int modules;
    int module;
};

// What is shown and kept: the picture as Cascades takes it.
struct Picture
{
    Image image;
    bool drawn;             // false - nothing to show
    bool valid;
    int version;
    int modules;
    int module;
};

} // namespace qrview

namespace {

// The pictures of every instance, by what they are made of; the cost is their bytes. A bigger one is shown,
// not kept.
const int kCacheBytes = 4 * 1024 * 1024;
// The GPU's texture side (KB: a bigger one is not drawn at all).
const int kMaxSide = 2048;

// HELD BY AN OBJECT DELETED WHEN THE APP IS ABOUT TO QUIT, while Cascades is still there to let the pictures
// go - as AdvancedContainer's (a static cache lets them go after Cascades has gone: an error on a close).
class Pictures : public QObject
{
public:
    Pictures() :
            cache(kCacheBytes)
    {
    }

    QCache<QString, qrview::Picture> cache;
};

QCache<QString, qrview::Picture>& pictures()
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

Color colorOf(const QVariant& v)
{
    if (!v.isValid()) {
        return Color();
    }
    return v.value<Color>();
}

// A Color as the drawing takes it: R, G, B multiplied by A, 0 .. 255. No colour - transparent.
qr::Rgba rgbaOf(const Color& c)
{
    qr::Rgba out;
    out.r = 0;
    out.g = 0;
    out.b = 0;
    out.a = 0;
    if (c.isNull()) {
        return out;
    }
    const float a = qBound(0.0f, c.alpha(), 1.0f);
    out.r = (unsigned char) qRound(qBound(0.0f, c.red(), 1.0f) * a * 255.0f);
    out.g = (unsigned char) qRound(qBound(0.0f, c.green(), 1.0f) * a * 255.0f);
    out.b = (unsigned char) qRound(qBound(0.0f, c.blue(), 1.0f) * a * 255.0f);
    out.a = (unsigned char) qRound(a * 255.0f);
    return out;
}

QString hexOf(const qr::Rgba& c)
{
    const uint packed = (uint(c.r) << 24) | (uint(c.g) << 16) | (uint(c.b) << 8) | uint(c.a);
    return QString("%1").arg(packed, 8, 16, QChar('0'));
}

// A picture's address as a file path: asset:///x - the app's assets; file://x - x as it is; an absolute
// path; a relative one - from the assets too.
QString filePathOf(const QString& source)
{
    if (source.isEmpty()) {
        return QString();
    }
    const QString assets = QDir::currentPath() + QLatin1String("/app/native/assets/");
    if (source.startsWith(QLatin1String("asset:///"))) {
        return assets + source.mid(9);
    }
    if (source.startsWith(QLatin1String("file://"))) {
        return source.mid(7);
    }
    if (source.startsWith(QLatin1Char('/'))) {
        return source;
    }
    return assets + source;
}

// A file as part of a picture's key: a photo saved again under the same name makes a new picture.
QString stampOf(const QString& path)
{
    if (path.isEmpty()) {
        return QString();
    }
    const QFileInfo info(path);
    return path + QLatin1Char('@') + QString::number(info.lastModified().toMSecsSinceEpoch())
           + QLatin1Char(':') + QString::number(info.size());
}

qr::Ecc eccFor(QRView::ErrorCorrection level, bool icon)
{
    switch (level) {
    case QRView::Low:
        return qr::EccLow;
    case QRView::Medium:
        return qr::EccMedium;
    case QRView::Quartile:
        return qr::EccQuartile;
    case QRView::High:
        return qr::EccHigh;
    default:
        return icon ? qr::EccHigh : qr::EccMedium;
    }
}

// A picture file read for a square of `side` px: fitted into it, its proportions kept, or (`cover`) filling
// it and cropped to it. RGBA premultiplied in the image's memory - the drawing's order, not Qt's. Null - no
// file, or it cannot be read.
QImage readPicture(const QString& path, int side, bool cover)
{
    if (path.isEmpty() || side < 1) {
        return QImage();
    }
    QImageReader reader(path);
    QSize size = reader.size();
    QImage image;
    if (size.isValid() && !size.isEmpty()) {
        // a big photo decoded small (a JPEG at once, the rest scaled after)
        size.scale(side, side, cover ? Qt::KeepAspectRatioByExpanding : Qt::KeepAspectRatio);
        size = size.expandedTo(QSize(1, 1));
        reader.setScaledSize(size);
        image = reader.read();
        if (!image.isNull() && image.size() != size) {
            image = image.scaled(size, Qt::IgnoreAspectRatio, Qt::SmoothTransformation);
        }
    } else {
        image = reader.read();
        if (!image.isNull()) {
            image = image.scaled(side, side, cover ? Qt::KeepAspectRatioByExpanding : Qt::KeepAspectRatio,
                                 Qt::SmoothTransformation);
        }
    }
    if (image.isNull()) {
        qWarning("QRView: cannot read the picture %s", qPrintable(path));
        return QImage();
    }
    if (cover && (image.width() > side || image.height() > side)) {
        image = image.copy((image.width() - side) / 2, (image.height() - side) / 2, side, side);
    }
    image = image.convertToFormat(QImage::Format_ARGB32_Premultiplied);
    // B, G, R, A (this CPU's ARGB32) into R, G, B, A
    for (int y = 0; y < image.height(); ++y) {
        uchar* row = image.scanLine(y);
        for (int x = 0; x < image.width(); ++x) {
            const uchar b = row[x * 4];
            row[x * 4] = row[x * 4 + 2];
            row[x * 4 + 2] = b;
        }
    }
    return image;
}

qr::Bitmap bitmapOf(const QImage& image)
{
    qr::Bitmap bitmap;
    bitmap.pixels = image.constBits();
    bitmap.width = image.width();
    bitmap.height = image.height();
    bitmap.stride = image.bytesPerLine();
    return bitmap;
}

} // namespace

namespace qrview {

// On a pool thread: the text encoded, the pictures read, the code drawn.
Drawn drawPicture(const Job& job)
{
    Drawn out;
    out.key = job.key;
    out.valid = false;
    out.version = 0;
    out.modules = 0;
    out.module = 0;
    // 4 KB: off the pool thread's stack
    QScopedPointer<qr::Symbol> symbol(new qr::Symbol);
    if (!qr::encode(job.text.constData(), job.ecc, *symbol)) {
        return out;
    }
    out.valid = true;
    out.version = symbol->version;
    out.modules = symbol->size;
    const qr::Layout place = qr::layout(*symbol, job.style, job.width, job.height);
    out.module = place.module;
    if (place.module <= 0) {
        return out;
    }
    const QImage icon = readPicture(job.iconPath, place.iconSide, false);
    const QImage badge = readPicture(job.badgePath, place.badgeSide, true);
    const qr::Bitmap iconBitmap = bitmapOf(icon);
    const qr::Bitmap badgeBitmap = bitmapOf(badge);
    bb::ImageData data(bb::PixelFormat::RGBA_Premultiplied, job.width, job.height);
    if (!data.isValid()) {
        return out;
    }
    qr::draw(*symbol, job.style, icon.isNull() ? 0 : &iconBitmap, badge.isNull() ? 0 : &badgeBitmap, data.pixels(),
             job.width, job.height, data.bytesPerLine());
    out.data = data;
    return out;
}

// On a pool thread: the picture drawn again and written as a PNG, `under` baked in when `bake`.
bool savePicture(const Job& job, const QString& path, bool bake, const qr::Rgba& under)
{
    const Drawn drawn = drawPicture(job);
    if (!drawn.data.isValid()) {
        return false;
    }
    QImage image(job.width, job.height, QImage::Format_ARGB32_Premultiplied);
    if (image.isNull()) {
        return false;
    }
    for (int y = 0; y < job.height; ++y) {
        const unsigned char* from = drawn.data.constPixels() + y * drawn.data.bytesPerLine();
        uchar* to = image.scanLine(y);
        for (int x = 0; x < job.width; ++x) {
            int r = from[x * 4];
            int g = from[x * 4 + 1];
            int b = from[x * 4 + 2];
            int a = from[x * 4 + 3];
            if (bake) {
                // the picture over the colour, both premultiplied
                const int keep = 255 - a;
                r += (under.r * keep + 127) / 255;
                g += (under.g * keep + 127) / 255;
                b += (under.b * keep + 127) / 255;
                a += (under.a * keep + 127) / 255;
            }
            // R, G, B, A into this CPU's ARGB32: B, G, R, A
            to[x * 4] = (uchar) qMin(b, a);
            to[x * 4 + 1] = (uchar) qMin(g, a);
            to[x * 4 + 2] = (uchar) qMin(r, a);
            to[x * 4 + 3] = (uchar) a;
        }
    }
    QDir().mkpath(QFileInfo(path).absolutePath());
    const bool ok = image.save(path, "PNG");
    if (!ok) {
        qWarning("QRView: cannot write %s", qPrintable(path));
    }
    return ok;
}

} // namespace qrview

QRView::QRView(Container* parent) :
        Container(parent),
        m_errorCorrection(Auto),
        m_color(QVariant::fromValue(Color::Black)),
        m_gradientAngle(0),
        m_backgroundColor(QVariant::fromValue(Color::White)),
        m_quietZone(4),
        m_moduleRadius(0),
        m_moduleScale(1),
        m_joinModules(true),
        m_eyeFrameRadius(0),
        m_eyeBallRadius(0),
        m_cornerRadius(0),
        m_iconSize(0.2f),
        m_iconMargin(1),
        m_iconRadius(0),
        m_badgeSize(0.25f),
        m_badgeRing(0),
        m_valid(false),
        m_version(0),
        m_moduleCount(0),
        m_moduleSize(0),
        m_ready(true),
        m_layout(0),
        m_drawing(new QFutureWatcher<qrview::Drawn>(this)),
        m_refreshQueued(false)
{
    connect(m_drawing, SIGNAL(finished()), this, SLOT(onDrawn()));
    m_layout = LayoutUpdateHandler::create(this)
            .onLayoutFrameChanged(this, SLOT(onLayoutFrameChanged(const QRectF&)));
    // A size set ahead is the size until the layout says otherwise: the picture from the first frame.
    connect(this, SIGNAL(preferredWidthChanged(float)), this, SLOT(onPreferredSizeChanged()));
    connect(this, SIGNAL(preferredHeightChanged(float)), this, SLOT(onPreferredSizeChanged()));
}

QRView::~QRView()
{
    // A picture still being drawn is let go: its watcher goes with the view, the pool drops the result.
}

void QRView::setText(const QString& text)
{
    if (text == m_text) {
        return;
    }
    m_text = text;
    emit textChanged();
    scheduleRefresh();
}

void QRView::setErrorCorrection(ErrorCorrection level)
{
    if (level == m_errorCorrection) {
        return;
    }
    m_errorCorrection = level;
    emit errorCorrectionChanged();
    scheduleRefresh();
}

void QRView::setColor(const QVariant& color)
{
    if (color == m_color) {
        return;
    }
    m_color = color;
    emit colorChanged();
    scheduleRefresh();
}

void QRView::setGradientColor(const QVariant& color)
{
    if (color == m_gradientColor) {
        return;
    }
    m_gradientColor = color;
    emit gradientColorChanged();
    scheduleRefresh();
}

void QRView::setGradientAngle(float degrees)
{
    if (qFuzzyCompare(1.0f + degrees, 1.0f + m_gradientAngle)) {
        return;
    }
    m_gradientAngle = degrees;
    emit gradientAngleChanged();
    scheduleRefresh();
}

void QRView::setBackgroundColor(const QVariant& color)
{
    if (color == m_backgroundColor) {
        return;
    }
    m_backgroundColor = color;
    emit backgroundColorChanged();
    scheduleRefresh();
}

void QRView::setEyeFrameColor(const QVariant& color)
{
    if (color == m_eyeFrameColor) {
        return;
    }
    m_eyeFrameColor = color;
    emit eyeFrameColorChanged();
    scheduleRefresh();
}

void QRView::setEyeBallColor(const QVariant& color)
{
    if (color == m_eyeBallColor) {
        return;
    }
    m_eyeBallColor = color;
    emit eyeBallColorChanged();
    scheduleRefresh();
}

void QRView::setQuietZone(int modules)
{
    if (modules == m_quietZone) {
        return;
    }
    m_quietZone = modules;
    emit quietZoneChanged();
    scheduleRefresh();
}

void QRView::setModuleRadius(float share)
{
    if (qFuzzyCompare(1.0f + share, 1.0f + m_moduleRadius)) {
        return;
    }
    m_moduleRadius = share;
    emit moduleRadiusChanged();
    scheduleRefresh();
}

void QRView::setModuleScale(float share)
{
    if (qFuzzyCompare(1.0f + share, 1.0f + m_moduleScale)) {
        return;
    }
    m_moduleScale = share;
    emit moduleScaleChanged();
    scheduleRefresh();
}

void QRView::setJoinModules(bool join)
{
    if (join == m_joinModules) {
        return;
    }
    m_joinModules = join;
    emit joinModulesChanged();
    scheduleRefresh();
}

void QRView::setEyeFrameRadius(float share)
{
    if (qFuzzyCompare(1.0f + share, 1.0f + m_eyeFrameRadius)) {
        return;
    }
    m_eyeFrameRadius = share;
    emit eyeFrameRadiusChanged();
    scheduleRefresh();
}

void QRView::setEyeBallRadius(float share)
{
    if (qFuzzyCompare(1.0f + share, 1.0f + m_eyeBallRadius)) {
        return;
    }
    m_eyeBallRadius = share;
    emit eyeBallRadiusChanged();
    scheduleRefresh();
}

void QRView::setCornerRadius(float px)
{
    if (qFuzzyCompare(1.0f + px, 1.0f + m_cornerRadius)) {
        return;
    }
    m_cornerRadius = px;
    emit cornerRadiusChanged();
    scheduleRefresh();
}

void QRView::setIconSource(const QString& source)
{
    if (source == m_iconSource) {
        return;
    }
    m_iconSource = source;
    emit iconSourceChanged();
    scheduleRefresh();
}

void QRView::setIconSize(float share)
{
    if (qFuzzyCompare(1.0f + share, 1.0f + m_iconSize)) {
        return;
    }
    m_iconSize = share;
    emit iconSizeChanged();
    scheduleRefresh();
}

void QRView::setIconMargin(float modules)
{
    if (qFuzzyCompare(1.0f + modules, 1.0f + m_iconMargin)) {
        return;
    }
    m_iconMargin = modules;
    emit iconMarginChanged();
    scheduleRefresh();
}

void QRView::setIconRadius(float share)
{
    if (qFuzzyCompare(1.0f + share, 1.0f + m_iconRadius)) {
        return;
    }
    m_iconRadius = share;
    emit iconRadiusChanged();
    scheduleRefresh();
}

void QRView::setBadgeSource(const QString& source)
{
    if (source == m_badgeSource) {
        return;
    }
    m_badgeSource = source;
    emit badgeSourceChanged();
    scheduleRefresh();
}

void QRView::setBadgeColor(const QVariant& color)
{
    if (color == m_badgeColor) {
        return;
    }
    m_badgeColor = color;
    emit badgeColorChanged();
    scheduleRefresh();
}

void QRView::setBadgeSize(float share)
{
    if (qFuzzyCompare(1.0f + share, 1.0f + m_badgeSize)) {
        return;
    }
    m_badgeSize = share;
    emit badgeSizeChanged();
    scheduleRefresh();
}

void QRView::setBadgeRing(float px)
{
    if (qFuzzyCompare(1.0f + px, 1.0f + m_badgeRing)) {
        return;
    }
    m_badgeRing = px;
    emit badgeRingChanged();
    scheduleRefresh();
}

void QRView::onLayoutFrameChanged(const QRectF& frame)
{
    const QSizeF size = frame.size();
    if (size != m_frame) {
        m_frame = size;
        scheduleRefresh();
    }
}

void QRView::onPreferredSizeChanged()
{
    if (m_frame.isEmpty()) {
        scheduleRefresh();
    }
}

void QRView::scheduleRefresh()
{
    if (m_refreshQueued) {
        return;
    }
    m_refreshQueued = true;
    QMetaObject::invokeMethod(this, "refresh", Qt::QueuedConnection);
}

bool QRView::makeJob(qrview::Job& job) const
{
    // The laid-out frame; until there is one, a size set ahead.
    float width = m_frame.width();
    float height = m_frame.height();
    if (width < 1 || height < 1) {
        if (isPreferredWidthSet() && isPreferredHeightSet()) {
            width = preferredWidth();
            height = preferredHeight();
        }
    }
    if (width < 1 || height < 1) {
        return false;
    }
    job.width = qMin(kMaxSide, (int) ceilf(width));
    job.height = qMin(kMaxSide, (int) ceilf(height));

    const bool icon = !m_iconSource.isEmpty();
    const Color badgeColour = colorOf(m_badgeColor);
    const bool badge = !m_badgeSource.isEmpty() || !badgeColour.isNull();
    job.text = m_text.toUtf8();
    job.ecc = eccFor(m_errorCorrection, icon);
    job.iconPath = filePathOf(m_iconSource);
    job.badgePath = filePathOf(m_badgeSource);

    qr::Style& style = job.style;
    style = qr::defaultStyle();
    style.dark = rgbaOf(colorOf(m_color));
    const Color gradient = colorOf(m_gradientColor);
    style.gradient = !gradient.isNull();
    style.gradientEnd = rgbaOf(gradient);
    style.gradientAngle = m_gradientAngle;
    style.light = rgbaOf(colorOf(m_backgroundColor));
    style.quietZone = m_quietZone;
    style.moduleRadius = m_moduleRadius;
    style.moduleScale = m_moduleScale;
    style.joinModules = m_joinModules;
    const Color eyeFrame = colorOf(m_eyeFrameColor);
    style.eyeFrameOwnColor = !eyeFrame.isNull();
    style.eyeFrame = rgbaOf(eyeFrame);
    style.eyeFrameRadius = m_eyeFrameRadius;
    const Color eyeBall = colorOf(m_eyeBallColor);
    style.eyeBallOwnColor = !eyeBall.isNull();
    style.eyeBall = rgbaOf(eyeBall);
    style.eyeBallRadius = m_eyeBallRadius;
    style.cornerRadius = m_cornerRadius;
    // no icon - no room kept for one
    style.iconSize = icon ? m_iconSize : 0.0f;
    style.iconMargin = m_iconMargin;
    style.iconRadius = m_iconRadius;
    style.badgeSize = badge ? m_badgeSize : 0.0f;
    style.badgeRing = m_badgeRing;
    style.badgeColor = rgbaOf(badgeColour);

    // Everything the picture is made of; the text last, it may hold anything.
    QStringList parts;
    parts << QString::number(job.width) << QString::number(job.height) << QString::number((int) job.ecc)
          << hexOf(style.dark) << (style.gradient ? hexOf(style.gradientEnd) : QString())
          << QString::number(style.gradientAngle) << hexOf(style.light) << QString::number(style.quietZone)
          << QString::number(style.moduleRadius) << QString::number(style.moduleScale)
          << QString::number(style.joinModules ? 1 : 0)
          << (style.eyeFrameOwnColor ? hexOf(style.eyeFrame) : QString()) << QString::number(style.eyeFrameRadius)
          << (style.eyeBallOwnColor ? hexOf(style.eyeBall) : QString()) << QString::number(style.eyeBallRadius)
          << QString::number(style.cornerRadius) << QString::number(style.iconSize)
          << QString::number(style.iconMargin) << QString::number(style.iconRadius) << stampOf(job.iconPath)
          << QString::number(style.badgeSize) << QString::number(style.badgeRing) << hexOf(style.badgeColor)
          << stampOf(job.badgePath) << m_text;
    job.key = parts.join(QLatin1String("|"));
    return true;
}

void QRView::refresh()
{
    m_refreshQueued = false;
    if (m_text.isEmpty()) {
        if (!m_shown.isEmpty()) {
            resetBackground();
            m_shown.clear();
        }
        setInfo(false, 0, 0, 0);
        setReady(true);
        return;
    }
    qrview::Job job;
    if (!makeJob(job)) {
        // no size yet: what is shown stays until there is one
        setReady(false);
        return;
    }
    if (job.key == m_shown) {
        setReady(true);
        return;
    }
    const qrview::Picture* cached = pictures().object(job.key);
    if (cached != 0) {
        show(job.key, *cached);
        return;
    }
    setReady(false);
    if (m_drawing->isRunning()) {
        // onDrawn() looks again
        return;
    }
    m_drawing->setFuture(QtConcurrent::run(&qrview::drawPicture, job));
}

void QRView::onDrawn()
{
    const qrview::Drawn drawn = m_drawing->result();
    qrview::Picture picture;
    picture.drawn = drawn.data.isValid();
    if (picture.drawn) {
        picture.image = Image(drawn.data);
    }
    picture.valid = drawn.valid;
    picture.version = drawn.version;
    picture.modules = drawn.modules;
    picture.module = drawn.module;
    const int cost = picture.drawn ? drawn.data.bytesPerLine() * drawn.data.height() : 1;
    if (cost <= kCacheBytes) {
        pictures().insert(drawn.key, new qrview::Picture(picture), cost);
    }
    // Still what is wanted - shown; else what is wanted now is asked for.
    qrview::Job job;
    if (!m_text.isEmpty() && makeJob(job) && job.key == drawn.key) {
        show(drawn.key, picture);
        return;
    }
    refresh();
}

void QRView::show(const QString& key, const qrview::Picture& picture)
{
    if (picture.drawn) {
        setBackground(ImagePaint(picture.image));
    } else {
        resetBackground();
    }
    m_shown = key;
    setInfo(picture.valid, picture.version, picture.modules, picture.module);
    setReady(true);
}

void QRView::setInfo(bool valid, int version, int modules, int module)
{
    if (valid != m_valid) {
        m_valid = valid;
        emit validChanged();
    }
    if (version != m_version) {
        m_version = version;
        emit versionChanged();
    }
    if (modules != m_moduleCount) {
        m_moduleCount = modules;
        emit moduleCountChanged();
    }
    if (module != m_moduleSize) {
        m_moduleSize = module;
        emit moduleSizeChanged();
    }
}

void QRView::setReady(bool ready)
{
    if (ready != m_ready) {
        m_ready = ready;
        emit readyChanged();
    }
}

void QRView::saveImage(const QString& path, const QVariant& background)
{
    qrview::Job job;
    if (m_text.isEmpty() || path.isEmpty() || !makeJob(job)) {
        emit imageSaved(path, false);
        return;
    }
    const Color under = colorOf(background);
    QFutureWatcher<bool>* saving = new QFutureWatcher<bool>(this);
    saving->setProperty("path", path);
    connect(saving, SIGNAL(finished()), this, SLOT(onSaved()));
    saving->setFuture(QtConcurrent::run(&qrview::savePicture, job, path, !under.isNull(), rgbaOf(under)));
}

void QRView::onSaved()
{
    QFutureWatcher<bool>* saving = static_cast<QFutureWatcher<bool>*>(sender());
    if (saving == 0) {
        return;
    }
    const QString path = saving->property("path").toString();
    const bool ok = saving->result();
    saving->deleteLater();
    emit imageSaved(path, ok);
}

} // namespace bbshared
