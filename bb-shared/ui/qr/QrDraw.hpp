/*
 * bb-shared / ui / qr / QrDraw.hpp - a QR code: the text encoded (Nayuki's qrcodegen, MIT, the two files
 * beside this one, as they come) and drawn into a picture's pixels. Plain C++ - no Qt, no Cascades - so it
 * runs on any thread, and in a test on a PC (test/run.sh). QRView (ui/QRView.hpp) is the component on top.
 *
 * The picture: a plate of the light colour, the quiet zone included, in the middle, transparent around it.
 * Whole px a module, so every straight edge is sharp; the plate is as big as fits, so up to (modules - 1)
 * px smaller than the picture. What can be styled:
 *  - the modules: square, rounded, round; full or smaller than their cell (apart); joined with their
 *    neighbours (only the corners on the outside of a group rounded) or each on its own;
 *  - the three finder patterns ("eyes") as shapes of their own: the frame and the ball rounded apart from
 *    the modules, each in a colour of its own;
 *  - the colours: the modules' (one, or a linear gradient of two at an angle), the plate's;
 *  - the plate's corners rounded;
 *  - an icon in the middle (a logo), its place cleared of modules, square, rounded or round;
 *  - a badge: a round picture (a profile photo) or a disc on the plate's top edge, half above it, in a ring
 *    of the plate's colour - the plate grows at the top to keep it off the symbol.
 * The curved edges are anti-aliased; at square shapes and one colour every pixel is one of the two colours.
 */
#ifndef BBSHARED_QRDRAW_HPP
#define BBSHARED_QRDRAW_HPP

#include "qrcodegen.h"

namespace bbshared {
namespace qr {

// A colour as Cascades takes pixels (bb::PixelFormat::RGBA_Premultiplied): R, G, B already multiplied by A.
struct Rgba
{
    unsigned char r;
    unsigned char g;
    unsigned char b;
    unsigned char a;
};

// How much of the symbol may be lost - covered by an icon, dirty, cut - and the code still reads: about 7,
// 15, 25 and 30 %. A higher one makes a bigger symbol of the same text.
enum Ecc
{
    EccLow = 0,
    EccMedium = 1,
    EccQuartile = 2,
    EccHigh = 3
};

// An encoded symbol.
struct Symbol
{
    int size;       // modules a side: 21 (version 1) .. 177 (version 40); 0 - nothing encoded
    int version;    // 1 .. 40; 0 - nothing encoded
    unsigned char bits[qrcodegen_BUFFER_LEN_MAX];
};

// What the picture looks like. Every value is clamped to its range; a share that is not a number - the
// lowest.
struct Style
{
    Rgba dark;              // the dark modules
    bool gradient;          // the modules run from `dark` to `gradientEnd` across the symbol
    Rgba gradientEnd;
    float gradientAngle;    // degrees: 0 - left to right, 90 - top to bottom
    Rgba light;             // the plate: the light modules, the quiet zone, the icon's place, the badge's
                            // ring; transparent - no plate

    int quietZone;          // the light margin around the symbol, modules (the standard asks for 4): 0 .. 40
    float moduleRadius;     // a module's corners, a share of its side: 0 square .. 0.5 round
    float moduleScale;      // a module's side, a share of its cell: 0.5 .. 1; below 1 they stand apart
    bool joinModules;       // dark neighbours joined: only the corners on the outside of a group rounded

    bool eyeFrameOwnColor;  // the finders' frames in `eyeFrame`, not in the modules' colours
    Rgba eyeFrame;
    float eyeFrameRadius;   // the frame's corners, a share of its side (7 modules): 0 square .. 0.5 a ring
    bool eyeBallOwnColor;   // the finders' balls in `eyeBall`
    Rgba eyeBall;
    float eyeBallRadius;    // the ball's corners, a share of its side (3 modules): 0 square .. 0.5 round

    float cornerRadius;     // the plate's corners, px - at most half its width and 3 quiet zones

    float iconSize;         // the icon's side, a share of the symbol's side: 0 .. 0.3 (it hides data: EccHigh)
    float iconMargin;       // the light around the icon, modules: 0 .. 4
    float iconRadius;       // the icon's corners and its place's, a share of the side: 0 square .. 0.5 round

    float badgeSize;        // the badge's diameter, a share of the plate's width: 0 - no badge, 0.05 .. 0.5
    float badgeRing;        // the ring of the plate's colour around it, px
    Rgba badgeColor;        // the disc under the badge's picture, or in its place; transparent - none
};

// Black on white, square modules and eyes, the standard quiet zone of 4, no icon, no badge. An icon would
// take 0.2 of the side with a module of margin; a badge, 0.25 of the plate's width.
Style defaultStyle();

// Where things land in a picture of width x height: as big as fits with whole px a module, centred.
struct Layout
{
    int module;         // px a module; 0 - no symbol, or less than one px a module
    int plateX;         // the plate, the quiet zone included
    int plateY;
    int plateWidth;
    int plateHeight;    // its width, and more with a badge (the room under the badge's lower half)
    int symbolX;        // the symbol's top-left corner, the quiet zone not included
    int symbolY;
    int iconSide;       // the square an icon is fitted into, px; 0 - no icon asked for, or no room
    int iconX;
    int iconY;
    float clearSide;    // the place cleared around the icon, its margin included, px - rounded as the icon
    int badgeSide;      // the badge's square, the ring not included, px; 0 - no badge
    int badgeX;         // centred on the plate's top edge
    int badgeY;
};

// A picture to put in: RGBA premultiplied, `stride` bytes a row. Drawn centred in its square (the icon's,
// the badge's), the part outside the square's shape cut off: make an icon at most Layout::iconSide a side,
// a badge exactly Layout::badgeSide (cropped to a square).
struct Bitmap
{
    const unsigned char* pixels;
    int width;
    int height;
    int stride;
};

// The text (UTF-8, NUL-terminated) as the smallest symbol that holds it, the error correction raised where
// the symbol stays as small. False - an empty text, or one too long for a QR code (2953 bytes at EccLow,
// less at a higher one); `out.size` is 0 then.
bool encode(const char* text, Ecc ecc, Symbol& out);

// The module at column x, row y is dark. Outside the symbol - light.
bool isDark(const Symbol& symbol, int x, int y);

Layout layout(const Symbol& symbol, const Style& style, int width, int height);

// Draws the symbol into `pixels` - RGBA premultiplied, `stride` bytes a row, width x height - with the icon
// in the middle (0 - none: nothing is cleared) and the badge's picture (0 - only its disc). Every pixel of
// the picture is written, transparent around the plate; nothing past width in a row. False - the picture
// all transparent - when nothing fits: no symbol, or less than one px a module.
bool draw(const Symbol& symbol, const Style& style, const Bitmap* icon, const Bitmap* badge, unsigned char* pixels,
          int width, int height, int stride);

} // namespace qr
} // namespace bbshared

#endif // BBSHARED_QRDRAW_HPP
