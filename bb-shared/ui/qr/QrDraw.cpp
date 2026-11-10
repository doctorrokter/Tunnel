/*
 * bb-shared / ui / qr / QrDraw.cpp - see QrDraw.hpp.
 */
#include "QrDraw.hpp"

#include <math.h>
#include <stddef.h>
#include <string.h>

#include <vector>

namespace bbshared {
namespace qr {

namespace {

// A wider quiet zone only makes the modules smaller.
const int kMaxQuietZone = 40;
const float kMaxIconSize = 0.3f;
const float kMaxIconMargin = 4.0f;
const float kMinBadgeSize = 0.05f;
const float kMaxBadgeSize = 0.5f;
const float kMaxBadgeRing = 512.0f;
// The plate's corners, in quiet zones: a rounder corner would cut the symbol's corner module.
const float kPlateRadiusPerQuietZone = 3.0f;
// A finder pattern's side, modules; with its separator it takes one more.
const int kEye = 7;

// The corners of a shape that are rounded, as bits.
const int kTopLeft = 1;
const int kTopRight = 2;
const int kBottomLeft = 4;
const int kBottomRight = 8;
const int kAllCorners = kTopLeft | kTopRight | kBottomLeft | kBottomRight;

// a * b / 255, rounded; both 0 .. 255.
inline int mul255(int a, int b)
{
    const int t = a * b + 128;
    return (t + (t >> 8)) >> 8;
}

// A share 0 .. 1 as 0 .. 255.
inline int share255(float share)
{
    if (share <= 0.0f) {
        return 0;
    }
    if (share >= 1.0f) {
        return 255;
    }
    return (int) (share * 255.0f + 0.5f);
}

// The value within low .. high; not a number - low.
float clamped(float value, float low, float high)
{
    if (!(value > low)) {
        return low;
    }
    if (value > high) {
        return high;
    }
    return value;
}

int quietZoneOf(const Style& style)
{
    if (style.quietZone < 0) {
        return 0;
    }
    if (style.quietZone > kMaxQuietZone) {
        return kMaxQuietZone;
    }
    return style.quietZone;
}

bool hasBadge(const Style& style)
{
    return style.badgeSize > 0.0f;
}

int badgeRingOf(const Style& style)
{
    if (!hasBadge(style)) {
        return 0;
    }
    return (int) (clamped(style.badgeRing, 0.0f, kMaxBadgeRing) + 0.5f);
}

// How much of the pixel whose centre is (px, py) lies inside the rectangle, its corners in `corners`
// rounded to `radius` (at most half its shorter side): a ramp one px wide across the edge.
int insideRect(float px, float py, float left, float top, float width, float height, float radius, int corners)
{
    const float halfWidth = width / 2.0f;
    const float halfHeight = height / 2.0f;
    const float cx = left + halfWidth;
    const float cy = top + halfHeight;
    const bool right = px > cx;
    const bool bottom = py > cy;
    int corner = kTopLeft;
    if (right && bottom) {
        corner = kBottomRight;
    } else if (right) {
        corner = kTopRight;
    } else if (bottom) {
        corner = kBottomLeft;
    }
    const float r = ((corners & corner) != 0) ? radius : 0.0f;
    // the distance to the edge: outside positive, inside negative
    const float qx = fabsf(px - cx) - halfWidth + r;
    const float qy = fabsf(py - cy) - halfHeight + r;
    const float ox = (qx > 0.0f) ? qx : 0.0f;
    const float oy = (qy > 0.0f) ? qy : 0.0f;
    const float deepest = (qx > qy) ? qx : qy;
    const float distance = sqrtf(ox * ox + oy * oy) + ((deepest < 0.0f) ? deepest : 0.0f) - r;
    return share255(0.5f - distance);
}

inline int insideCircle(float px, float py, float cx, float cy, float radius)
{
    const float dx = px - cx;
    const float dy = py - cy;
    return share255(0.5f - (sqrtf(dx * dx + dy * dy) - radius));
}

inline unsigned char* pixelAt(unsigned char* pixels, int stride, int x, int y)
{
    return pixels + (ptrdiff_t) y * stride + (ptrdiff_t) x * 4;
}

inline void put(unsigned char* p, const Rgba& c)
{
    p[0] = c.r;
    p[1] = c.g;
    p[2] = c.b;
    p[3] = c.a;
}

// The colour, `cover` of it, painted over what the pixel shows.
inline void paintOver(unsigned char* p, const Rgba& c, int cover)
{
    const int a = mul255(c.a, cover);
    const int keep = 255 - a;
    p[0] = (unsigned char) (mul255(c.r, cover) + mul255(p[0], keep));
    p[1] = (unsigned char) (mul255(c.g, cover) + mul255(p[1], keep));
    p[2] = (unsigned char) (mul255(c.b, cover) + mul255(p[2], keep));
    p[3] = (unsigned char) (a + mul255(p[3], keep));
}

// The pixel turned into the colour by `cover` - the colour itself at 255, a transparent one too: the icon's
// place on a transparent plate is a hole.
inline void turnInto(unsigned char* p, const Rgba& c, int cover)
{
    const int keep = 255 - cover;
    p[0] = (unsigned char) (mul255(c.r, cover) + mul255(p[0], keep));
    p[1] = (unsigned char) (mul255(c.g, cover) + mul255(p[1], keep));
    p[2] = (unsigned char) (mul255(c.b, cover) + mul255(p[2], keep));
    p[3] = (unsigned char) (mul255(c.a, cover) + mul255(p[3], keep));
}

// What a dark thing is painted with at a pixel: one colour, or the gradient across the symbol.
struct Paint
{
    Rgba from;
    Rgba to;
    bool gradient;
    bool opaque;
    float cx;       // the symbol's centre
    float cy;
    float ux;       // the gradient's direction, over its length across the symbol
    float uy;

    Rgba at(int x, int y) const
    {
        if (!gradient) {
            return from;
        }
        const float t = clamped(0.5f + (x + 0.5f - cx) * ux + (y + 0.5f - cy) * uy, 0.0f, 1.0f);
        Rgba c;
        c.r = (unsigned char) (from.r + (to.r - from.r) * t + 0.5f);
        c.g = (unsigned char) (from.g + (to.g - from.g) * t + 0.5f);
        c.b = (unsigned char) (from.b + (to.b - from.b) * t + 0.5f);
        c.a = (unsigned char) (from.a + (to.a - from.a) * t + 0.5f);
        return c;
    }
};

Paint flatPaint(const Rgba& colour)
{
    Paint paint;
    paint.from = colour;
    paint.to = colour;
    paint.gradient = false;
    paint.opaque = colour.a == 255;
    paint.cx = 0.0f;
    paint.cy = 0.0f;
    paint.ux = 0.0f;
    paint.uy = 0.0f;
    return paint;
}

Paint modulesPaint(const Style& style, const Layout& place, int size)
{
    Paint paint = flatPaint(style.dark);
    if (!style.gradient) {
        return paint;
    }
    const float side = (float) size * place.module;
    const float angle = (style.gradientAngle == style.gradientAngle) ? style.gradientAngle : 0.0f;
    const float radians = angle * 3.14159265f / 180.0f;
    const float dx = cosf(radians);
    const float dy = sinf(radians);
    // the symbol's square seen along the direction: from one corner to the opposite one
    const float length = side * (fabsf(dx) + fabsf(dy));
    paint.to = style.gradientEnd;
    paint.gradient = true;
    paint.opaque = style.dark.a == 255 && style.gradientEnd.a == 255;
    paint.cx = place.symbolX + side / 2.0f;
    paint.cy = place.symbolY + side / 2.0f;
    paint.ux = dx / length;
    paint.uy = dy / length;
    return paint;
}

inline void paintPixel(unsigned char* pixels, int stride, int x, int y, const Paint& paint, int cover)
{
    const Rgba c = paint.at(x, y);
    unsigned char* p = pixelAt(pixels, stride, x, y);
    if (cover == 255 && c.a == 255) {
        put(p, c);
    } else {
        paintOver(p, c, cover);
    }
}

// A shape's coverage of its square, `side` px: the rectangle at (inset, inset), `drawn` px, rounded.
void makeStamp(std::vector<unsigned char>& stamp, int side, float inset, float drawn, float radius, int corners)
{
    stamp.resize((size_t) side * side);
    for (int j = 0; j < side; ++j) {
        for (int i = 0; i < side; ++i) {
            stamp[(size_t) j * side + i] = (unsigned char) insideRect(i + 0.5f, j + 0.5f, inset, inset, drawn, drawn,
                                                                      radius, corners);
        }
    }
}

// The plate's corners: transparent outside the curve, the light colour by coverage on it. Drawn before
// everything else; the modules never reach that far (kPlateRadiusPerQuietZone).
void roundPlateCorners(unsigned char* pixels, int stride, const Layout& place, const Rgba& light, float radius)
{
    if (radius <= 0.0f) {
        return;
    }
    const int reach = (int) ceilf(radius);
    for (int corner = 0; corner < 4; ++corner) {
        const bool right = (corner == 1 || corner == 3);
        const bool bottom = (corner == 2 || corner == 3);
        for (int j = 0; j < reach; ++j) {
            const int y = bottom ? place.plateY + place.plateHeight - 1 - j : place.plateY + j;
            for (int i = 0; i < reach; ++i) {
                const int x = right ? place.plateX + place.plateWidth - 1 - i : place.plateX + i;
                const int cover = insideRect(x + 0.5f, y + 0.5f, (float) place.plateX, (float) place.plateY,
                                             (float) place.plateWidth, (float) place.plateHeight, radius,
                                             kAllCorners);
                unsigned char* p = pixelAt(pixels, stride, x, y);
                p[0] = (unsigned char) mul255(light.r, cover);
                p[1] = (unsigned char) mul255(light.g, cover);
                p[2] = (unsigned char) mul255(light.b, cover);
                p[3] = (unsigned char) mul255(light.a, cover);
            }
        }
    }
}

// A disc painted over, clipped to the picture.
void paintDisc(unsigned char* pixels, int stride, int width, int height, float cx, float cy, float radius,
               const Rgba& colour)
{
    int x0 = (int) floorf(cx - radius - 1.0f);
    int y0 = (int) floorf(cy - radius - 1.0f);
    int x1 = (int) ceilf(cx + radius + 1.0f);
    int y1 = (int) ceilf(cy + radius + 1.0f);
    x0 = (x0 < 0) ? 0 : x0;
    y0 = (y0 < 0) ? 0 : y0;
    x1 = (x1 > width) ? width : x1;
    y1 = (y1 > height) ? height : y1;
    for (int y = y0; y < y1; ++y) {
        for (int x = x0; x < x1; ++x) {
            const int cover = insideCircle(x + 0.5f, y + 0.5f, cx, cy, radius);
            if (cover > 0) {
                paintOver(pixelAt(pixels, stride, x, y), colour, cover);
            }
        }
    }
}

// The bitmap centred in the square, cut to the square's rounded shape, painted over; clipped to the picture.
void putBitmap(unsigned char* pixels, int stride, int width, int height, const Bitmap& bitmap, int left, int top,
               int side, float radius)
{
    if (bitmap.pixels == 0 || bitmap.width <= 0 || bitmap.height <= 0 || bitmap.stride < bitmap.width * 4) {
        return;
    }
    const int bx = left + (side - bitmap.width) / 2;
    const int by = top + (side - bitmap.height) / 2;
    for (int j = 0; j < bitmap.height; ++j) {
        const int y = by + j;
        if (y < top || y >= top + side || y < 0 || y >= height) {
            continue;
        }
        const unsigned char* row = bitmap.pixels + (ptrdiff_t) j * bitmap.stride;
        for (int i = 0; i < bitmap.width; ++i) {
            const int x = bx + i;
            if (x < left || x >= left + side || x < 0 || x >= width) {
                continue;
            }
            const unsigned char* s = row + (ptrdiff_t) i * 4;
            if (s[3] == 0) {
                continue;
            }
            const int cover = insideRect(x + 0.5f, y + 0.5f, (float) left, (float) top, (float) side, (float) side,
                                         radius, kAllCorners);
            if (cover == 0) {
                continue;
            }
            Rgba c;
            c.r = s[0];
            c.g = s[1];
            c.b = s[2];
            c.a = s[3];
            paintOver(pixelAt(pixels, stride, x, y), c, cover);
        }
    }
}

// The module at (x, y) belongs to a finder pattern - drawn as an eye, not as a module.
bool inEye(int size, int x, int y)
{
    const bool left = x < kEye;
    const bool right = x >= size - kEye;
    const bool top = y < kEye;
    const bool bottom = y >= size - kEye;
    return (left && top) || (right && top) || (left && bottom);
}

// The module at (x, y) is drawn as a module. Outside the symbol - not.
inline bool shownAt(const std::vector<unsigned char>& shown, int size, int x, int y)
{
    if (x < 0 || y < 0 || x >= size || y >= size) {
        return false;
    }
    return shown[(size_t) y * size + x] != 0;
}

} // namespace

Style defaultStyle()
{
    Style style;
    style.dark.r = 0;
    style.dark.g = 0;
    style.dark.b = 0;
    style.dark.a = 255;
    style.gradient = false;
    style.gradientEnd = style.dark;
    style.gradientAngle = 0.0f;
    style.light.r = 255;
    style.light.g = 255;
    style.light.b = 255;
    style.light.a = 255;
    style.quietZone = 4;
    style.moduleRadius = 0.0f;
    style.moduleScale = 1.0f;
    style.joinModules = true;
    style.eyeFrameOwnColor = false;
    style.eyeFrame = style.dark;
    style.eyeFrameRadius = 0.0f;
    style.eyeBallOwnColor = false;
    style.eyeBall = style.dark;
    style.eyeBallRadius = 0.0f;
    style.cornerRadius = 0.0f;
    style.iconSize = 0.2f;
    style.iconMargin = 1.0f;
    style.iconRadius = 0.0f;
    style.badgeSize = 0.0f;
    style.badgeRing = 0.0f;
    style.badgeColor.r = 0;
    style.badgeColor.g = 0;
    style.badgeColor.b = 0;
    style.badgeColor.a = 0;
    return style;
}

bool encode(const char* text, Ecc ecc, Symbol& out)
{
    out.size = 0;
    out.version = 0;
    if (text == 0 || text[0] == '\0') {
        return false;
    }
    // Ecc's values are qrcodegen_Ecc's.
    unsigned char temp[qrcodegen_BUFFER_LEN_MAX];
    if (!qrcodegen_encodeText(text, temp, out.bits, (enum qrcodegen_Ecc) ecc, qrcodegen_VERSION_MIN,
                              qrcodegen_VERSION_MAX, qrcodegen_Mask_AUTO, true)) {
        return false;
    }
    out.size = qrcodegen_getSize(out.bits);
    out.version = (out.size - 17) / 4;
    return true;
}

bool isDark(const Symbol& symbol, int x, int y)
{
    if (symbol.size <= 0 || x < 0 || y < 0 || x >= symbol.size || y >= symbol.size) {
        return false;
    }
    return qrcodegen_getModule(symbol.bits, x, y);
}

Layout layout(const Symbol& symbol, const Style& style, int width, int height)
{
    Layout place;
    memset(&place, 0, sizeof(place));
    if (symbol.size <= 0 || width <= 0 || height <= 0) {
        return place;
    }
    const int quiet = quietZoneOf(style);
    const int total = symbol.size + 2 * quiet;
    const bool badge = hasBadge(style);
    const float badgeShare = badge ? clamped(style.badgeSize, kMinBadgeSize, kMaxBadgeSize) : 0.0f;
    const int ring = badgeRingOf(style);

    // The biggest module that fits: across, the plate; down, the plate and a badge's halves - the upper one
    // above the plate, the lower one on it, each with the ring.
    int module = ((width < height) ? width : height) / total;
    int badgeSide = 0;
    int half = 0;
    for (; module >= 1; --module) {
        const int plateWidth = module * total;
        badgeSide = badge ? (int) (badgeShare * plateWidth + 0.5f) : 0;
        half = badge ? (badgeSide + 1) / 2 + ring : 0;
        if (plateWidth + 2 * half <= height) {
            break;
        }
    }
    if (module < 1) {
        return place;
    }
    place.module = module;
    place.plateWidth = module * total;
    place.plateHeight = place.plateWidth + half;
    place.plateX = (width - place.plateWidth) / 2;
    place.plateY = (height - place.plateWidth - 2 * half) / 2 + half;
    place.symbolX = place.plateX + quiet * module;
    place.symbolY = place.plateY + half + quiet * module;
    if (badgeSide > 0) {
        place.badgeSide = badgeSide;
        place.badgeX = place.plateX + (place.plateWidth - badgeSide) / 2;
        place.badgeY = place.plateY - badgeSide / 2;
    }

    // The icon: in the middle, its place no wider than the room between the finders' separators.
    const float iconShare = clamped(style.iconSize, 0.0f, kMaxIconSize);
    if (iconShare > 0.0f) {
        const float side = (float) symbol.size * module;
        const float margin = clamped(style.iconMargin, 0.0f, kMaxIconMargin) * module;
        const float room = (float) (symbol.size - 2 * (kEye + 1)) * module;
        int iconSide = (int) (iconShare * side + 0.5f);
        float clearSide = iconSide + 2.0f * margin;
        if (clearSide > room) {
            clearSide = room;
            iconSide = (int) (room - 2.0f * margin);
        }
        if (iconSide >= 1) {
            const float centre = side / 2.0f;
            place.iconSide = iconSide;
            place.iconX = place.symbolX + (int) floorf(centre - iconSide / 2.0f + 0.5f);
            place.iconY = place.symbolY + (int) floorf(centre - iconSide / 2.0f + 0.5f);
            place.clearSide = clearSide;
        }
    }
    return place;
}

bool draw(const Symbol& symbol, const Style& style, const Bitmap* icon, const Bitmap* badge, unsigned char* pixels,
          int width, int height, int stride)
{
    if (pixels == 0 || width <= 0 || height <= 0 || stride < width * 4) {
        return false;
    }
    const Layout place = layout(symbol, style, width, height);
    const bool plate = place.module > 0 && style.light.a > 0;

    // The plate's row, the light colour across it, transparent on both sides.
    std::vector<unsigned char> plateRow((size_t) width * 4, 0);
    if (plate) {
        for (int x = place.plateX; x < place.plateX + place.plateWidth; ++x) {
            put(&plateRow[(size_t) x * 4], style.light);
        }
    }
    for (int y = 0; y < height; ++y) {
        unsigned char* row = pixelAt(pixels, stride, 0, y);
        if (plate && y >= place.plateY && y < place.plateY + place.plateHeight) {
            memcpy(row, &plateRow[0], (size_t) width * 4);
        } else {
            memset(row, 0, (size_t) width * 4);
        }
    }
    if (place.module <= 0) {
        return false;
    }

    const int quiet = quietZoneOf(style);
    const int size = symbol.size;
    const int module = place.module;
    if (plate) {
        float plateRadius = clamped(style.cornerRadius, 0.0f, place.plateWidth / 2.0f);
        const float ceiling = kPlateRadiusPerQuietZone * quiet * module;
        if (plateRadius > ceiling) {
            plateRadius = ceiling;
        }
        roundPlateCorners(pixels, stride, place, style.light, plateRadius);
    }

    // The modules drawn as modules: dark, not in an eye, outside the icon's place.
    const bool clearing = icon != 0 && place.iconSide > 0;
    const float iconShape = clamped(style.iconRadius, 0.0f, 0.5f);
    const float clearRadius = iconShape * place.clearSide;
    const float clearLeft = place.iconX + place.iconSide / 2.0f - place.clearSide / 2.0f;
    const float clearTop = place.iconY + place.iconSide / 2.0f - place.clearSide / 2.0f;
    std::vector<unsigned char> shown((size_t) size * size, 0);
    for (int my = 0; my < size; ++my) {
        for (int mx = 0; mx < size; ++mx) {
            if (!qrcodegen_getModule(symbol.bits, mx, my) || inEye(size, mx, my)) {
                continue;
            }
            if (clearing) {
                const float px = place.symbolX + (mx + 0.5f) * module;
                const float py = place.symbolY + (my + 0.5f) * module;
                if (insideRect(px, py, clearLeft, clearTop, place.clearSide, place.clearSide, clearRadius,
                               kAllCorners) >= 128) {
                    continue;
                }
            }
            shown[(size_t) my * size + mx] = 1;
        }
    }

    const Paint paint = modulesPaint(style, place, size);
    const float scale = clamped(style.moduleScale, 0.5f, 1.0f);
    const bool full = scale >= 1.0f;
    const float drawn = scale * module;
    const float inset = (module - drawn) / 2.0f;
    const float radius = clamped(style.moduleRadius, 0.0f, 0.5f) * drawn;
    const bool square = full && radius <= 0.0f;
    const bool join = full && style.joinModules;
    // A full square module in one opaque colour is rows of it, copied; any other is painted through the
    // stamp of its rounded corners.
    std::vector<unsigned char> darkRow((size_t) module * 4);
    for (int i = 0; i < module; ++i) {
        put(&darkRow[(size_t) i * 4], style.dark);
    }
    std::vector<unsigned char> stamps[kAllCorners + 1];
    for (int my = 0; my < size; ++my) {
        for (int mx = 0; mx < size; ++mx) {
            if (!shownAt(shown, size, mx, my)) {
                continue;
            }
            const int left = place.symbolX + mx * module;
            const int top = place.symbolY + my * module;
            if (square && !paint.gradient && paint.opaque) {
                for (int j = 0; j < module; ++j) {
                    memcpy(pixelAt(pixels, stride, left, top + j), &darkRow[0], (size_t) module * 4);
                }
                continue;
            }
            int corners = 0;
            if (radius > 0.0f) {
                corners = kAllCorners;
                if (join) {
                    const bool leftDark = shownAt(shown, size, mx - 1, my);
                    const bool rightDark = shownAt(shown, size, mx + 1, my);
                    const bool upDark = shownAt(shown, size, mx, my - 1);
                    const bool downDark = shownAt(shown, size, mx, my + 1);
                    corners = 0;
                    if (!leftDark && !upDark) {
                        corners |= kTopLeft;
                    }
                    if (!rightDark && !upDark) {
                        corners |= kTopRight;
                    }
                    if (!leftDark && !downDark) {
                        corners |= kBottomLeft;
                    }
                    if (!rightDark && !downDark) {
                        corners |= kBottomRight;
                    }
                }
            }
            std::vector<unsigned char>& stamp = stamps[corners];
            if (stamp.empty()) {
                makeStamp(stamp, module, inset, drawn, radius, corners);
            }
            for (int j = 0; j < module; ++j) {
                const unsigned char* cover = &stamp[(size_t) j * module];
                for (int i = 0; i < module; ++i) {
                    if (cover[i] != 0) {
                        paintPixel(pixels, stride, left + i, top + j, paint, cover[i]);
                    }
                }
            }
        }
    }

    // The eyes: a frame of 7 modules, a ball of 3 in it, one stamp each for all three.
    const Paint framePaint = style.eyeFrameOwnColor ? flatPaint(style.eyeFrame) : paint;
    const Paint ballPaint = style.eyeBallOwnColor ? flatPaint(style.eyeBall) : paint;
    const int eyeSide = kEye * module;
    const float frameRadius = clamped(style.eyeFrameRadius, 0.0f, 0.5f) * eyeSide;
    const float holeRadius = (frameRadius > module) ? frameRadius - module : 0.0f;
    const float ballRadius = clamped(style.eyeBallRadius, 0.0f, 0.5f) * 3 * module;
    std::vector<unsigned char> frameStamp((size_t) eyeSide * eyeSide);
    std::vector<unsigned char> ballStamp((size_t) eyeSide * eyeSide);
    for (int j = 0; j < eyeSide; ++j) {
        for (int i = 0; i < eyeSide; ++i) {
            const float px = i + 0.5f;
            const float py = j + 0.5f;
            const int outer = insideRect(px, py, 0.0f, 0.0f, (float) eyeSide, (float) eyeSide, frameRadius, kAllCorners);
            const int hole = insideRect(px, py, (float) module, (float) module, 5.0f * module, 5.0f * module,
                                        holeRadius, kAllCorners);
            frameStamp[(size_t) j * eyeSide + i] = (unsigned char) mul255(outer, 255 - hole);
            ballStamp[(size_t) j * eyeSide + i] = (unsigned char) insideRect(px, py, 2.0f * module, 2.0f * module,
                                                                             3.0f * module, 3.0f * module,
                                                                             ballRadius, kAllCorners);
        }
    }
    const int eyeColumns[3] = { 0, size - kEye, 0 };
    const int eyeRows[3] = { 0, 0, size - kEye };
    for (int e = 0; e < 3; ++e) {
        const int left = place.symbolX + eyeColumns[e] * module;
        const int top = place.symbolY + eyeRows[e] * module;
        for (int j = 0; j < eyeSide; ++j) {
            for (int i = 0; i < eyeSide; ++i) {
                const int frame = frameStamp[(size_t) j * eyeSide + i];
                if (frame > 0) {
                    paintPixel(pixels, stride, left + i, top + j, framePaint, frame);
                }
                const int ball = ballStamp[(size_t) j * eyeSide + i];
                if (ball > 0) {
                    paintPixel(pixels, stride, left + i, top + j, ballPaint, ball);
                }
            }
        }
    }

    // The icon: its place in the light colour - a clean edge across the modules it cuts - and the icon on it.
    if (clearing) {
        const int x0 = (int) floorf(clearLeft) - 1;
        const int y0 = (int) floorf(clearTop) - 1;
        const int x1 = (int) ceilf(clearLeft + place.clearSide) + 1;
        const int y1 = (int) ceilf(clearTop + place.clearSide) + 1;
        for (int y = y0; y < y1; ++y) {
            for (int x = x0; x < x1; ++x) {
                const int cover = insideRect(x + 0.5f, y + 0.5f, clearLeft, clearTop, place.clearSide,
                                             place.clearSide, clearRadius, kAllCorners);
                if (cover > 0) {
                    turnInto(pixelAt(pixels, stride, x, y), style.light, cover);
                }
            }
        }
        putBitmap(pixels, stride, width, height, *icon, place.iconX, place.iconY, place.iconSide,
                  iconShape * place.iconSide);
    }

    // The badge: the ring, the disc, the picture - round.
    if (place.badgeSide > 0) {
        const float r = place.badgeSide / 2.0f;
        const float cx = place.badgeX + r;
        const float cy = place.badgeY + r;
        const int ring = badgeRingOf(style);
        if (style.light.a > 0 && ring > 0) {
            paintDisc(pixels, stride, width, height, cx, cy, r + ring, style.light);
        }
        if (style.badgeColor.a > 0) {
            paintDisc(pixels, stride, width, height, cx, cy, r, style.badgeColor);
        }
        if (badge != 0) {
            putBitmap(pixels, stride, width, height, *badge, place.badgeX, place.badgeY, place.badgeSide, r);
        }
    }
    return true;
}

} // namespace qr
} // namespace bbshared
