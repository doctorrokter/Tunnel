/*
 * bt_ctl - the control socket (docs/DAEMON.md, section 3): a unix stream socket the app and its
 * headless service connect to, bt_proto blocks both ways.
 *
 *   -> cmd=<command>, id=<n>, arguments
 *   <- item=<kind> blocks for a list (each with the request's id), then
 *   <- reply=<command>, id=<n>, errno=<code> (+ error=, line=)
 *   <- event=<kind> at any time to clients that asked with `watch`
 *
 * Commands: hello, profile.import / list / get / update / delete, tunnel.up / down, status, watch,
 * settings.get / set, log.tail, log.debug, daemon.restart.
 *
 * The socket file is given to the app's uid, mode 0600: only the app, its service and root reach
 * it; on Linux the peer's uid is checked as well.
 */

#ifndef BT_CTL_H
#define BT_CTL_H

#include <poll.h>
#include <stdint.h>

#include "bt_store.h"
#include "bt_tunnel.h"

#define BT_CTL_CLIENTS      8

enum {
    BT_ERR_OK = 0,
    BT_ERR_REQUEST,                     /* malformed, or an argument missing or wrong */
    BT_ERR_COMMAND,                     /* no such command */
    BT_ERR_PROFILE,                     /* no such profile */
    BT_ERR_CONF,                        /* the .conf is not usable: error= and line= say why */
    BT_ERR_BUSY,                        /* a limit or a conflict */
    BT_ERR_SYSTEM                       /* the system refused: error= says what */
};

typedef struct {
    bt_store*   store;
    const char* version;
    int         owner_uid;              /* -1: no owner (tests) */
    int         owner_gid;
    void      (*restart)(void);         /* daemon.restart: leave once the reply is out */
} bt_ctl_opts;

int  bt_ctl_listen(const char* path, const bt_ctl_opts* o);
void bt_ctl_close(void);

int      bt_ctl_pollfds(struct pollfd* out, int cap);
void     bt_ctl_io(const struct pollfd* pfd);
uint64_t bt_ctl_tick(uint64_t now_ns);              /* statistics to the watchers, the end of
                                                       log.debug; next deadline */
int      bt_ctl_idle(void);                         /* nothing waiting to be written */

void bt_ctl_event_tunnel(bt_tunnel* t);
void bt_ctl_event_profile(const char* id, const char* action);
void bt_ctl_event_network(void);

#endif /* BT_CTL_H */
