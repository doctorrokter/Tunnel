APP_NAME = BBTunnel

CONFIG += qt warn_on cascades10

include(config.pri)

# --- Build environment: development (default) or production ------------------
# Chosen at build time by bb-shared/tools/build-bar.sh, which exports BBT_ENV (`-e production`
# for the build that ships to users, development otherwise); qmake reads it from the environment
# here. production compiles out the developer tools (TUNNEL_PRODUCTION) and every qDebug() call
# site (QT_NO_DEBUG_OUTPUT); development - the default, and what a Momentics GUI build gets -
# keeps them, with the demo daemon (docs/APP.md, section 12). This is the ENV axis, independent of
# the debug/release COMPILE axis. First in the file: client.pri below needs to know it.
BBT_ENV = $$(BBT_ENV)
BBT_ENV = $$replace(BBT_ENV, \\r, )
isEmpty(BBT_ENV): BBT_ENV = development
equals(BBT_ENV, production) {
    DEFINES += TUNNEL_PRODUCTION QT_NO_DEBUG_OUTPUT
    message("BBTunnel: PRODUCTION build - developer tools + qDebug() compiled out")
} else {
    CONFIG += tunnel_demo
    message("BBTunnel: development build ($$BBT_ENV) - developer tools and the demo daemon included")
}

# Shared BB10 code - a real module, not copy-paste: the L10n language layer; `dimens`, the spacing
# the service pages of every app are laid out with; the Repeater and the settings rows (bb-shared
# README, sections 3 and 6a); the Help sheet's "Buy me a coffee" card (sections 4-5). bb-shared sits
# next to the Tunnel repository, which puts it two levels up from this project. QRView (section 12):
# the Tailscale login link as a code to scan with another device.
CONFIG += bb_shared_dimens bb_shared_ui bb_shared_coffee bb_shared_qr
include(../../bb-shared/bb-shared.pri)

# QLocalSocket - the daemon's unix socket.
QT += network

# -lbbcascadespickers: bb.cascades.pickers (FilePicker) for "Add from a file";
# -lbbcascadesmultimedia: bb.cascades.multimedia (Camera + BarcodeDetector) for the QR code.
LIBS += -lbb -lbbsystem -lbbcascadespickers -lbbcascadesmultimedia

# The link to the daemon, the profiles and the app's own helpers - the code shared with the service.
# Listed by client.pri, not by Momentics (docs/APP.md, section 2).
CONFIG += tunnel_client_gui
include(../client/client.pri)

# For this project's lupdate: the pages in the asset folders (Momentics lists only those it has seen)
# and the coffee card, whose strings go into OUR catalog under the context "BuyMeACoffee". lupdate
# reads every scope of a project whatever CONFIG says, so bb-shared cannot opt us in - we list it.
lupdate_inclusion {
    SOURCES += \
        $$PWD/assets/*.qml \
        $$PWD/assets/*.js \
        $$PWD/assets/pages/*.qml \
        $$PWD/assets/sheets/*.qml \
        $$PWD/assets/components/*.qml \
        $$PWD/assets/cover/*.qml \
        $$BB_SHARED_DIR/ui/qml/BuyMeACoffee.qml
}

# A Cascades app is a SHARED OBJECT: without this an undefined symbol links silently and the app
# dies before main() on the device, with nothing in the log (KB 2.8).
QMAKE_LFLAGS += -Wl,--no-undefined
