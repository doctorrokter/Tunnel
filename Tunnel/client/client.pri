# client - the C++ shared by BBTunnel and BBTunnelService, compiled into both (docs/APP.md, section 2):
# the link to the daemon over its unix socket and the profiles as the daemon keeps them.
#
#     CONFIG += tunnel_client_gui       # optional, BEFORE the include: the app's own helpers
#     CONFIG += tunnel_client_service   # optional: the service's notifications
#     CONFIG += tunnel_demo             # optional: the demo daemon (development builds only)
#     include(../client/client.pri)
#
# Files are listed HERE, not by Momentics: config.pri is the IDE's and covers only the project's own
# folder (Syno's core.pri does the same). Every file name must be unique across the project: qmake
# builds into one flat object directory.
#
# The protocol is the daemon's own parser, daemon/src/bt_proto.c - C without any I/O, with its tests
# and fuzzer - not a second implementation in Qt.

TUNNEL_CLIENT_DIR = $$PWD
TUNNEL_PROTO_DIR = $$PWD/../daemon/src

INCLUDEPATH += $$TUNNEL_CLIENT_DIR $$TUNNEL_PROTO_DIR
# The root too: "gui/Importer.hpp" from the projects' own files is found only through it, and a
# header change must rebuild what includes it (Syno build 51 - KB 2.10).
DEPENDPATH += $$TUNNEL_CLIENT_DIR $$TUNNEL_PROTO_DIR

# bt_proto.c is gnu99 C, as in the daemon. qcc takes the compiler's own options behind -Wc,
# (a bare -std= is "unknown option"). The projects' precompiled.h keeps its C++ under __cplusplus:
# qmake builds a C header from it too once a C file is in the project.
QMAKE_CFLAGS += -Wc,-std=gnu99

HEADERS += \
    $$TUNNEL_PROTO_DIR/bt_proto.h \
    $$TUNNEL_PROTO_DIR/bt_version.h \
    $$TUNNEL_CLIENT_DIR/DaemonClient.hpp \
    $$TUNNEL_CLIENT_DIR/FileLog.hpp \
    $$TUNNEL_CLIENT_DIR/Profiles.hpp \
    $$TUNNEL_CLIENT_DIR/TunnelSettings.hpp

SOURCES += \
    $$TUNNEL_PROTO_DIR/bt_proto.c \
    $$TUNNEL_CLIENT_DIR/DaemonClient.cpp \
    $$TUNNEL_CLIENT_DIR/FileLog.cpp \
    $$TUNNEL_CLIENT_DIR/Profiles.cpp \
    $$TUNNEL_CLIENT_DIR/TunnelSettings.cpp

# --- The app only: files, QR codes and AmneziaVPN keys into a profile, the release notes ---
tunnel_client_gui {
    DEPENDPATH += $$TUNNEL_CLIENT_DIR/gui
    HEADERS += \
        $$TUNNEL_CLIENT_DIR/gui/Importer.hpp \
        $$TUNNEL_CLIENT_DIR/gui/AmneziaKey.hpp \
        $$TUNNEL_CLIENT_DIR/gui/Changelog.hpp
    SOURCES += \
        $$TUNNEL_CLIENT_DIR/gui/Importer.cpp \
        $$TUNNEL_CLIENT_DIR/gui/AmneziaKey.cpp \
        $$TUNNEL_CLIENT_DIR/gui/Changelog.cpp
    # bb::data::JsonDataAccess reads the release notes and AmneziaVPN keys; bb::system::Clipboard the
    # pasted text; zlib the keys' compressed JSON (bounded - qUncompress is not); bb::device::HardwareInfo
    # the model, for the name the phone asks for in a tailnet.
    LIBS += -lbbdata -lbbdevice -lz
}

# --- The service only: the Hub notifications, the boot start on root v4 ---
tunnel_client_service {
    DEPENDPATH += $$TUNNEL_CLIENT_DIR/service
    HEADERS += \
        $$TUNNEL_CLIENT_DIR/service/Notifier.hpp \
        $$TUNNEL_CLIENT_DIR/service/RootAutostart.hpp
    SOURCES += \
        $$TUNNEL_CLIENT_DIR/service/Notifier.cpp \
        $$TUNNEL_CLIENT_DIR/service/RootAutostart.cpp
    LIBS += -lbbplatform
}

# --- The demo daemon: profiles and events without a daemon, for laying the screens out on the
# simulator (docs/APP.md, section 12). Development builds only - a production build has none of it. ---
tunnel_demo {
    DEFINES += TUNNEL_DEMO
    HEADERS += $$TUNNEL_CLIENT_DIR/DemoDaemon.hpp
    SOURCES += $$TUNNEL_CLIENT_DIR/DemoDaemon.cpp
}

# No lupdate_inclusion here: lupdate reads every scope whatever CONFIG says, so a list here would put
# the service's notification texts into the app's catalog and back. Each .pro lists its own part.
