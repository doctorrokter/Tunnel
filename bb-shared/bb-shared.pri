# bb-shared - shared BB10 code, pulled into each project with:
#     include(../bb-shared/bb-shared.pri)
# in the project's .pro (a real shared module, not copy-paste). This copy holds only the parts Tunnel uses.

# Where this module sits, for the few paths an app writes itself (the coffee card's lupdate line):
# the same spelling in every app, however deep the app is nested.
BB_SHARED_DIR = $$PWD

# --- Language layer (L10n): header-only, works in GUI and headless service alike. Links bbsystem:
#     "system" is the device's UI language, asked of bb::system::LocaleHandler. Linked HERE, not
#     left to each app - a Cascades app is a .so, and a missing library there links clean and then
#     dies before main(). ---
INCLUDEPATH += $$PWD/l10n
HEADERS += $$PWD/l10n/L10n.hpp
LIBS += -lbbsystem

# --- DEPENDPATH for every bb-shared folder: without it qmake writes NO dependency on our headers,
#     so changing one leaves every app's objects "up to date" and the next build packs the OLD code. ---
DEPENDPATH += $$PWD/l10n

# --- UI helpers (Repeater, AdvancedContainer, Loader): need Cascades AND are OPT-IN. A GUI project that
#     wants them adds `CONFIG += bb_shared_ui` before include(../bb-shared/bb-shared.pri), then calls
#     bbshared::registerUiTypes() at startup and `import bb.shared 1.0` in QML. The headless service
#     never compiles UI code. ---
bb_shared_ui {
    # AdvancedContainer draws its pictures with QPainter and hands them to Cascades as bb::ImageData (libbb).
    QT += gui
    LIBS += -lbb
    INCLUDEPATH += $$PWD/ui
    DEPENDPATH += $$PWD/ui
    HEADERS += \
        $$PWD/ui/Repeater.hpp \
        $$PWD/ui/AdvancedContainer.hpp \
        $$PWD/ui/Loader.hpp \
        $$PWD/ui/BbSharedUi.hpp
    SOURCES += \
        $$PWD/ui/Repeater.cpp \
        $$PWD/ui/AdvancedContainer.cpp \
        $$PWD/ui/Loader.cpp
}

# --- QRView (ui/QRView.hpp): a QR code drawn in C++ off the UI thread - colours and a gradient, square /
#     rounded / round modules, the finder "eyes" styled apart, an icon in the middle, a round badge on the
#     plate's edge; saveImage() writes the same picture as a PNG to share. The encoder is Nayuki's
#     qrcodegen (MIT) in ui/qr, the file as it comes, compiled as C++ (ui/qr/QrLibrary.cpp): no C99 flag,
#     nothing against the app's precompiled header. The drawing (ui/qr/QrDraw) is plain C++. OPT-IN, GUI
#     only, and it NEEDS bb_shared_ui (registerUiTypes() registers it under the BBSHARED_QR define; QtGui
#     and libbb come with that). ---
bb_shared_qr {
    INCLUDEPATH += $$PWD/ui
    DEPENDPATH += $$PWD/ui $$PWD/ui/qr
    DEFINES += BBSHARED_QR
    HEADERS += \
        $$PWD/ui/QRView.hpp \
        $$PWD/ui/qr/QrDraw.hpp \
        $$PWD/ui/qr/qrcodegen.h
    SOURCES += \
        $$PWD/ui/QRView.cpp \
        $$PWD/ui/qr/QrDraw.cpp \
        $$PWD/ui/qr/QrLibrary.cpp
    OTHER_FILES += \
        $$PWD/ui/qr/qrcodegen.c
}

# --- Dimens (`dimens.pad` / `dimens.gap` / `dimens.wide`): the spacing every app lays its pages out with -
#     2 du on a normal phone, 3 du on a Passport. OPT-IN: `CONFIG += bb_shared_dimens`, then
#     bbshared::installDimensContext() for each QML document. Reads the display, so it links bbdevice itself. ---
bb_shared_dimens {
    INCLUDEPATH += $$PWD/ui
    DEPENDPATH += $$PWD/ui
    HEADERS += \
        $$PWD/ui/Dimens.hpp \
        $$PWD/ui/BbSharedDimens.hpp
    SOURCES += \
        $$PWD/ui/Dimens.cpp
    LIBS += -lbbdevice
}

# --- "Buy me a coffee" (ui/qml/BuyMeACoffee.qml, ui/images, SharedClipboard): the support card of every
#     app's Help sheet, kept once here instead of a copy per app. OPT-IN, and it NEEDS bb_shared_ui
#     (registerUiTypes() registers its SharedClipboard, under the BBSHARED_COFFEE define, and
#     AdvancedContainer - the card's plates). Two steps stay in the app - packing ui/images and listing
#     the QML for its lupdate, which reads every scope of a project whatever CONFIG says. ---
bb_shared_coffee {
    INCLUDEPATH += $$PWD/ui
    DEPENDPATH += $$PWD/ui
    DEFINES += BBSHARED_COFFEE
    HEADERS += \
        $$PWD/ui/SharedClipboard.hpp
    SOURCES += \
        $$PWD/ui/SharedClipboard.cpp
    OTHER_FILES += \
        $$PWD/ui/qml/BuyMeACoffee.qml \
        $$PWD/ui/images/ic_coffee_cup.png \
        $$PWD/ui/images/ic_coffee_steam.png \
        $$PWD/ui/images/ic_copy.png
}
