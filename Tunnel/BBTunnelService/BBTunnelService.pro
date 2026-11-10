APP_NAME = BBTunnelService

CONFIG += qt warn_on

include(config.pri)

# The service's catalogs: the notifications it says in the Hub (client/service/Notifier.cpp).
TRANSLATIONS = $$quote($${TARGET}.ts) $$quote($${TARGET}_ru.ts) $$quote($${TARGET}_pl.ts)

# Shared BB10 code - the same module the GUI links. bb-shared sits next to the Tunnel repository,
# which puts it two levels up from this project.
include(../../bb-shared/bb-shared.pri)

LIBS += -lbb -lbbsystem -lbbplatform
# QLocalSocket - the daemon's unix socket.
QT += network

# The link to the daemon and the profiles - the same code as the app's - plus the notifications.
# Listed by client.pri, not by Momentics (docs/APP.md, section 2).
CONFIG += tunnel_client_service
include(../client/client.pri)

# The notifications' strings for this project's lupdate (client.pri lists none - see there).
lupdate_inclusion {
    SOURCES += $$TUNNEL_CLIENT_DIR/service/Notifier.cpp
    HEADERS += $$TUNNEL_CLIENT_DIR/service/Notifier.hpp
}

# --- Build environment: development (default) or production ------------------
# Mirrors BBTunnel.pro: bb-shared/tools/build-bar.sh exports BBT_ENV (`-e production` for the
# build that ships to users; no env var -> development). A production build drops every qDebug()
# call site via QT_NO_DEBUG_OUTPUT. Same BBT_ENV / TUNNEL_PRODUCTION as the GUI, so one
# `-e production` covers both halves of the package. qWarning() is kept.
BBT_ENV = $$(BBT_ENV)
BBT_ENV = $$replace(BBT_ENV, \\r, )
isEmpty(BBT_ENV): BBT_ENV = development
equals(BBT_ENV, production) {
    DEFINES += TUNNEL_PRODUCTION QT_NO_DEBUG_OUTPUT
    message("BBTunnelService: PRODUCTION build - qDebug() compiled out")
} else {
    message("BBTunnelService: development build ($$BBT_ENV) - full logging")
}
