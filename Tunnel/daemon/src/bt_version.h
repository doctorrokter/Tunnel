/*
 * bt_version - the daemon's version, in one place for the daemon (hello's daemon=) and the app that
 * ships it in the same .bar (client/DaemonClient): after a reinstall the running daemon is still the
 * old binary, and the app tells it by a version other than this one (docs/APP.md, section 9).
 */

#ifndef BT_VERSION_H
#define BT_VERSION_H

#define BT_VERSION      "1.1.0"

#endif /* BT_VERSION_H */
