/*
 * bb-shared / ui / Dimens.cpp - see Dimens.hpp.
 */
#include "Dimens.hpp"

#include <bb/cascades/Container>
#include <bb/cascades/UIConfig>
#include <bb/device/DisplayInfo>

#include <QDebug>
#include <QList>
#include <QSize>
#include <QSizeF>
#include <QtGlobal>

namespace bbshared {

namespace {

// Dimens::pretendScreen(): a smaller screen than this phone's; widthPx 0 = none.
struct PretendedScreen
{
    int widthPx;
    int heightPx;
    bool big;
    bool wide;
};

PretendedScreen s_pretended = { 0, 0, false, false };

// The base every layout of ours is drawn for: the Passport, 120 du across (KB 1.42).
const qreal kBaseWidthDu = 120.0;

// scale(du)'s factor when none is passed - the app's (Dimens::setScaleFactor).
qreal s_scaleFactor = 0.5;

// Every Dimens alive, to tell when the factor changes.
QList<Dimens*> s_instances;

// This phone's design unit in px: any control knows it (as ScreenFrame reads it).
float designUnitPx()
{
    bb::cascades::Container* probe = new bb::cascades::Container();
    const float px = probe->ui()->du(1);
    delete probe;
    return px;
}

} // namespace

void Dimens::pretendScreen(int widthPx, int heightPx, bool big, bool wide)
{
    s_pretended.widthPx = widthPx;
    s_pretended.heightPx = heightPx;
    s_pretended.big = big;
    s_pretended.wide = wide;
}

void Dimens::setScaleFactor(qreal factor)
{
    if (qFuzzyCompare(1.0 + s_scaleFactor, 1.0 + factor)) {
        return;
    }
    s_scaleFactor = factor;
    for (int i = 0; i < s_instances.size(); ++i) {
        emit s_instances.at(i)->scaleFactorChanged();
    }
}

qreal Dimens::scaleFactor() const
{
    return s_scaleFactor;
}

Dimens::Dimens(QObject* parent) :
        QObject(parent),
        m_pad(2),
        m_gap(2),
        m_wide(false),
        m_square(false),
        m_screenWidth(0),
        m_screenHeight(0),
        m_duPx(designUnitPx()),
        m_ratio(1.0)
{
    s_instances.append(this);
    if (s_pretended.widthPx > 0) {
        m_screenWidth = qMin(s_pretended.widthPx, s_pretended.heightPx);
        m_screenHeight = qMax(s_pretended.widthPx, s_pretended.heightPx);
        m_pad = s_pretended.big ? 3 : 2;
        m_gap = s_pretended.big ? 3 : 2;
        m_wide = s_pretended.wide;
        m_square = (m_screenWidth == m_screenHeight);
    } else {
        bb::device::DisplayInfo display;
        const QSize px = display.pixelSize();
        const QSizeF mm = display.physicalSize(); // millimetres

        const int longEdge = qMax(px.width(), px.height());
        const int shortEdge = qMin(px.width(), px.height());

        m_screenWidth = shortEdge;
        m_screenHeight = longEdge;

        double ppi = 0.0;
        if (mm.width() > 0.0) {
            ppi = px.width() * 25.4 / mm.width();
        }

        // Passport-class = high pixel density (~453 ppi). Everything else (Z10/Z30 ~295-356, Q10/Classic
        // ~294-330) stays on the standard spacing. Density is the reliable signal; only when the physical
        // size is unavailable does the resolution decide, and then only a Passport-sized 1440 counts.
        bool big;
        if (ppi > 0.0) {
            big = (ppi >= 400.0);
        } else {
            big = (longEdge >= 1440);
        }
        m_pad = big ? 3 : 2;
        m_gap = big ? 3 : 2;

        // Wide enough for multi-column layouts: a large short edge (Passport 1440), not the ~720-768 px
        // of the tall and the small square phones.
        m_wide = (shortEdge >= 1000);
        // A square screen, big (Passport) or small (Q10, Classic, Q5): one layout for the square ones.
        m_square = (shortEdge == longEdge);

        qDebug() << "[dimens] px" << px << "mm" << mm << "ppi" << ppi;
    }

    // Only a compact screen is smaller than the base: the tall phones keep their layouts as they are.
    if (compact() && m_duPx > 0) {
        m_ratio = qMin<qreal>(1.0, (m_screenWidth / m_duPx) / kBaseWidthDu);
    }

    qDebug() << "[dimens]" << (s_pretended.widthPx > 0 ? "PRETENDED screen" : "screen")
             << m_screenWidth << "x" << m_screenHeight << "-> pad/gap du" << m_pad << "wide" << m_wide
             << "square" << m_square << "compact" << compact() << "du" << m_duPx << "px ratio" << m_ratio
             << "scale factor" << s_scaleFactor;
}

Dimens::~Dimens()
{
    s_instances.removeAll(this);
}

float Dimens::scale(float du) const
{
    return scale(du, (float) s_scaleFactor);
}

float Dimens::scale(float du, float factor) const
{
    if (m_ratio >= 1.0) {
        return du * m_duPx;   // ui.du(du), to the pixel
    }
    const qreal share = 1.0 + (m_ratio - 1.0) * factor;
    return (float) qRound(du * share * m_duPx);
}

} // namespace bbshared
