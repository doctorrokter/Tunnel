#!/usr/bin/env bash
#
# The boot loop (daemon/boot/bbtunneld-boot.sh) on a fake phone under /tmp: a fake bbtunneld that
# records its starts, the app installed late, updated (copied while its daemon runs, the copy marked
# as made in this boot) and removed (also while its daemon runs),
# the copies in the run folder, daemon.restart, the off switch, a daemon that cannot start (the
# pause growing, the same failure logged once), power cuts within and after the settle time - the
# run folder outlives them, a second run, a pid file left by a loop that is gone or naming another
# process, SIGHUP, stopping by hand, a boot guard that cannot be created; and the script's own
# log - why it waits, starts, stops or exits, in the shared misc folder or the spare one, trimmed;
# another folder for the copies as its argument, and the arguments it refuses; the boot hook of
# root v4 - install mode on stdin, rewritten only when different, the hook's start, the service asked
# for through the navigator, one loop among two boot starts, the folder gone with the app.
# A fake pidin reads /proc. Under dash and bash --posix; the phone's PD KSH 5.2.14 only parses it
# (sh -n over SSH - nothing is written to the phone).
#
#   bash daemon/test/boot/run.sh          (WSL; not as root - root writes into a read-only folder,
#                                          so the boot guard check is skipped then)
#
set -u

HERE=$(cd "$(dirname "$0")" && pwd)
SRC=$HERE/../../boot/bbtunneld-boot.sh
PKG=doctorrokter.BBTunnel.testRel_er_TEST
SETTLE=3
PAUSE=1
IDLE=1
WATCH=1
RETRY="0 3 8"
REPEAT_LOG=2
PASS=0
FAIL=0

check() {
    local name=$1
    shift
    if "$@"; then
        PASS=$((PASS + 1))
        echo "  ok    $name"
    else
        FAIL=$((FAIL + 1))
        echo "  FAIL  $name"
    fi
}

# True as soon as the command is, within the seconds given.
within() {
    local end=$((SECONDS + $1))
    shift
    while :; do
        "$@" && return 0
        [ "$SECONDS" -ge "$end" ] && return 1
        sleep 0.1
    done
}

starts() { cat "$REC" 2> /dev/null | awk '/^start/ { n++ } END { print n + 0 }'; }
starts_are() { [ "$(starts)" = "$1" ]; }
daemon_pid() { cat "$REC" 2> /dev/null | awk '/^start/ { p = $2 } END { print p }'; }
loop_pid() { cat "$W/run/pid" 2> /dev/null; }
alive() { [ -n "$1" ] && kill -0 "$1" 2> /dev/null; }
loop_alive() { alive "$(loop_pid)"; }
loop_gone() { ! loop_alive; }
daemon_alive() { alive "$(daemon_pid)"; }
missing() { [ ! -e "$1" ]; }
logged() { grep -qE -- "$1" "$BLOG"; }
times_logged() { grep -cE -- "$1" "$BLOG"; }
# The pid in the current loop's log lines - its start's, from the start's last line.
loop_tag() {
    grep -E "\] done, exit 0: the loop runs in the background, pid $(loop_pid)\$" "$BLOG" | tail -n 1 |
        sed 's/^.*\[start \([0-9]*\)\].*$/\1/'
}
# The time between the last three starts grew: the second gap is longer than the first by 1 s
# and more.
gaps_grow() {
    tail -n 3 "$W/times" | awk 'NR == 1 { a = $1 } NR == 2 { b = $1 } NR == 3 { c = $1 }
        END { exit !((c - b) - (b - a) >= 1) }'
}
gaps() {
    tail -n 3 "$W/times" | awk 'NR > 1 { printf "%.1f s ", $1 - p } { p = $1 }'
}
# The run folder holds the copies, the same as the package's.
copies_fresh() {
    cmp -s "$W/apps/$PKG/native/bbtunneld" "$W/run/bbtunneld" &&
        cmp -s "$W/apps/$PKG/native/btctl" "$W/run/btctl"
}
no_copies() {
    missing "$W/run/bbtunneld" && missing "$W/run/btctl" &&
        missing "$W/run/bbtunneld.cksum" && missing "$W/run/btctl.cksum"
}

setup() {
    W=$(mktemp -d /tmp/bootloop.XXXXXX)
    REC=$W/rec
    MODE=$W/mode
    SB=$W/appdata/$PKG
    GUARD=$SB/data/boot-guard
    OFF=$W/shared/misc/tunnel-off
    BLOG=$W/shared/misc/bbtunneld-boot.txt
    SLOG=$W/spare.txt
    # another package: /apps on a phone is never empty
    mkdir -p "$W/apps/sys.other" "$W/appdata" "$W/shared/misc" "$W/bin"
    sed -e "s|^PATH=.*|PATH=$W/bin:/bin:/usr/bin:/sbin:/usr/sbin|" \
        -e "s|^APPS=.*|APPS=$W/apps|" \
        -e "s|^APPDATA=.*|APPDATA=$W/appdata|" \
        -e "s|^OFF=.*|OFF=$OFF|" \
        -e "s|^RUN=.*|RUN=$W/run|" \
        -e "s|^LOG=.*|LOG=$BLOG|" \
        -e "s|^LOG_SPARE=.*|LOG_SPARE=$SLOG|" \
        -e "s|^SETTLE=.*|SETTLE=$SETTLE|" \
        -e "s|^PAUSE=.*|PAUSE=$PAUSE|" \
        -e "s|^IDLE=.*|IDLE=$IDLE|" \
        -e "s|^WATCH=.*|WATCH=$WATCH|" \
        -e "s|^RETRY=.*|RETRY=\"$RETRY\"|" \
        -e "s|^REPEAT_LOG=.*|REPEAT_LOG=$REPEAT_LOG|" \
        -e "s|^ADDON=.*|ADDON=$W/var/tunnel|" \
        -e "s|^OTHER_RUNS=.*|OTHER_RUNS=\"$W/run $W/var/tunnel/bbtunneld-boot\"|" \
        -e "s|^NAV=.*|NAV=$W/nav|" \
        -e "s|^SERVICE_TRIES=.*|SERVICE_TRIES=4|" \
        -e "s|^SERVICE_EVERY=.*|SERVICE_EVERY=1|" "$SRC" > "$W/boot.sh"
    # pidin -p PID arg as on the phone: a header, then the pid and its arguments. With no-pidin in
    # the test folder it shows nothing - a pidin that cannot tell.
    cat > "$W/bin/pidin" << EOF
#!/bin/sh
[ -e "$W/no-pidin" ] && exit 1
if [ "\$1" = -F ]; then
    echo "name"
    [ -e "$W/service-running" ] && echo "BBTunnelService"
    exit 0
fi
[ "\$1" = -p ] && [ "\$3" = arg ] || exit 2
echo "     pid Arguments"
if [ -r "/proc/\$2/cmdline" ]; then
    echo "\$2 \$(tr '\0' ' ' < "/proc/\$2/cmdline")"
fi
EOF
    chmod +x "$W/bin/pidin"
    # cksum as on the phone: the CRC and the size right-aligned in 10 columns. The CRC is cut to
    # 8 digits, as build 16's 22166864 was, so it always starts with spaces - which read trims
    # (2026-10-15: every start copied the daemon again).
    cat > "$W/bin/cksum" << 'EOF'
#!/bin/sh
/usr/bin/cksum "$@" | while read -r crc size name; do
    printf '%10s %10s %s\n' "$((crc % 100000000))" "$size" "$name"
done
EOF
    chmod +x "$W/bin/cksum"
}

# The app installed and its service started: the service's log is the app's own file, its owner the
# daemon's. install_app no-service-log - the service not yet.
install_app() {
    mkdir -p "$W/apps/$PKG/native" "$SB/data/logs"
    if [ "${1:-}" != no-service-log ]; then
        : > "$SB/data/logs/service.txt"
    fi
    cat > "$W/apps/$PKG/native/bbtunneld" << EOF
#!/bin/sh
date +%s.%N >> "$W/times"
echo "start \$\$ \$*" >> "$REC"
if [ "\$(cat "$MODE" 2> /dev/null)" = exit ]; then
    echo "fake bbtunneld: cannot start" >&2
    exit 1
fi
if [ "\$(cat "$MODE" 2> /dev/null)" = warn ]; then
    echo "fake bbtunneld: a warning" >&2
fi
trap 'echo "stop \$\$" >> "$REC"; exit 0' TERM
while :; do sleep 0.1; done
EOF
    chmod +x "$W/apps/$PKG/native/bbtunneld"
    echo "fake btctl" > "$W/apps/$PKG/native/btctl"
    chmod +x "$W/apps/$PKG/native/btctl"
}

# The phone goes down: the loop and the daemon die. The run folder is on the disk: it stays.
power_cut() {
    kill -9 "$(loop_pid)" 2> /dev/null
    kill -9 "$(daemon_pid)" 2> /dev/null
    sleep 0.2
}

boot() {
    $SH "$W/boot.sh"
}

teardown() {
    pkill -9 -f "$W/" 2> /dev/null
    rm -rf "$W"
}

suite() {
    SH=$1
    echo "== $SH"
    setup

    check "the copy for the test has all 18 settings replaced" \
        [ "$(grep -cE "^PATH=$W/bin:|^(APPS|APPDATA|OFF|RUN|LOG|LOG_SPARE|ADDON|NAV)=$W|^OTHER_RUNS=\"$W/run |^(SETTLE|PAUSE|IDLE|WATCH|REPEAT_LOG|SERVICE_TRIES|SERVICE_EVERY)=[0-9]+$|^RETRY=\"$RETRY\"$" "$W/boot.sh")" = 18 ]

    # 1. the boot never waits on it: it returns at once, and a caller that reads its output gets
    #    the end of it at once too - the loop holds no copy of the caller's stdout or stderr
    local t0 t1 ms rc fds
    t0=$(date +%s%N)
    boot > "$W/out" 2>&1
    rc=$?
    t1=$(date +%s%N)
    ms=$(((t1 - t0) / 1000000))
    check "returns at once ($ms ms), exit 0, prints nothing" [ "$ms" -lt 1000 -a "$rc" = 0 -a ! -s "$W/out" ]
    check "the loop runs in the background" loop_alive
    check "the run folder is root's alone (0700)" [ "$(stat -c %a "$W/run")" = 700 ]
    check "log: the start's first line, with the time" \
        grep -qE "^[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} \[start [0-9]+\] started: $W/boot.sh, parent pid [0-9]+, uid=" "$BLOG"
    check "log: the start's last line names the loop" logged "\[start [0-9]+\] done, exit 0: the loop runs in the background, pid $(loop_pid)\$"
    # its fds are checked while it waits, not in the middle of a log line ($(date) is a pipe)
    within 2 logged "\[loop [0-9]+\] waiting"
    fds=$(ls -l "/proc/$(loop_pid)/fd" | awk 'NR > 1 { print $NF }' | sort | uniq -c | tr -s ' \n' ' ')
    check "the loop holds nothing of the caller's, only /dev/null and its log: $fds" \
        [ "$(ls -l "/proc/$(loop_pid)/fd" | grep -cv '/dev/null$\|/bbtunneld-boot.txt$\|^total')" = 0 ]
    kill -9 "$(loop_pid)"
    rm -rf "$W/run"
    $SH "$W/boot.sh" 2>&1 | timeout 5 cat > /dev/null
    rc=${PIPESTATUS[1]}
    check "a caller reading its output through a pipe is done at once (cat: $rc)" [ "$rc" = 0 ]
    check "... and the loop runs" loop_alive

    # 2. no app: nothing to start; two looks later - not installed, so a look every WATCH s
    sleep 2
    check "no app - nothing started" starts_are 0
    check "log: why - nothing matches the package" logged "waiting, a look every $IDLE s: nothing matches $W/apps/doctorrokter\.BBTunnel\.\*"
    check "log: then - uninstalled" within 2 logged "waiting, a look every $WATCH s: BBTunnel is uninstalled \(no package and no sandbox\)\$"

    # 3. a second run leaves the loop alone: pidin shows the pid running this script
    local first
    first=$(loop_pid)
    boot
    check "a second run: the same loop" [ "$(loop_pid)" = "$first" ]
    check "log: the second run says why it exits" logged "exit: the loop of this boot already runs \(pid $first: $first .*boot\.sh *\)\$"

    # 4. the app appears: copied into the run folder, started from there with its paths and owner -
    #    the owner of the service's log, so not before the service wrote it
    install_app no-service-log
    sleep 2
    check "the app, its service's log not yet - not started" starts_are 0
    check "log: why" logged "waiting, a look every $IDLE s: no uid:gid of the app's own file \(the service's log\) in: .*$SB/data/logs/service\.txt"
    : > "$SB/data/logs/service.txt"
    check "the service's log there - started" within 3 starts_are 1
    check "the run folder has copies of bbtunneld and btctl" copies_fresh
    check "... runnable by root alone" [ "$(stat -c %a "$W/run/bbtunneld")" = 700 ]
    check "log: what was copied" logged "copied from $W/apps/$PKG/native to $W/run: bbtunneld btctl\$"
    check "arguments: the sandbox's paths, owner = the data folder's uid:gid" \
        grep -qE "^start [0-9]+ --state $SB/data/daemon --socket $SB/data/daemon.sock --log $SB/data/logs/daemon.txt --owner $(id -u):$(id -g)\$" "$REC"
    check "log: the start, from the copy, with the owner" \
        logged "\[loop [0-9]+\] starting $W/run/bbtunneld, owner $(id -u):$(id -g) \(of data/logs/service\.txt\)\$"
    check "log: the daemon's pid" logged "the daemon runs, pid [0-9]+\$"
    check "the guard is there while the start settles" [ -e "$GUARD" ]
    check "the guard is gone once it settled" within $((SETTLE + 1)) missing "$GUARD"
    check "log: the guard off after SETTLE" within 1 logged "$SETTLE s since the start: the boot guard is off\$"
    sleep 1
    check "one daemon, one start (the second run started nothing)" starts_are 1

    # 5. daemon.restart (it leaves after it settled): back after PAUSE, the copies not made again
    kill -TERM "$(daemon_pid)"
    check "daemon.restart - started again within PAUSE" within $((PAUSE + 2)) starts_are 2
    check "log: the daemon left, with its status" logged "the daemon [0-9]+ left with status 0; the next start in $PAUSE s\$"
    check "... the same package - copied once only" [ "$(times_logged "copied from ")" = 1 ]

    # 6. an update while the daemon runs: copied within WATCH s and the daemon goes on (on the phone
    #    a copy made after the boot starts only after a reboot); its next start is from that copy
    within $((SETTLE + 1)) missing "$GUARD"
    local before
    before=$(daemon_pid)
    echo "# version 2" >> "$W/apps/$PKG/native/bbtunneld"
    check "an update - copied while the daemon runs" within $((WATCH + 2)) copies_fresh
    check "... the daemon goes on" alive "$before"
    check "... not started again" starts_are 2
    check "log: only bbtunneld copied, the daemon stays" \
        logged "an update: copied from $W/apps/$PKG/native to $W/run: bbtunneld while the daemon $before runs; it goes on, the new one starts after a reboot\$"
    check "... the copy is marked as made in this boot" [ -e "$W/run/copied-this-boot" ]
    kill -TERM "$before"
    check "the next start - from that copy" within $((PAUSE + 2)) starts_are 3
    check "... not copied again" [ "$(times_logged "copied from ")" = 2 ]

    # 7. SIGHUP does not end the loop
    kill -HUP "$(loop_pid)"
    sleep 0.5
    check "SIGHUP - the loop lives" loop_alive

    # 8. the off switch (a folder here; a file works the same)
    within $((SETTLE + 1)) missing "$GUARD"
    mkdir "$OFF"
    kill -TERM "$(daemon_pid)"
    sleep 3
    check "off switch - not started again" starts_are 3
    check "log: the off switch, once - not on every look" [ "$(grep -c "waiting, a look every $IDLE s: the off switch $OFF is there" "$BLOG")" = 1 ]
    rmdir "$OFF"
    check "off switch removed - started" within $((IDLE + 2)) starts_are 4

    # 9. the daemon's stderr while it runs: in the log once it settled
    within $((SETTLE + 1)) missing "$GUARD"
    echo warn > "$MODE"
    kill -TERM "$(daemon_pid)"
    check "a daemon that warns - its stderr in the log" within $((PAUSE + SETTLE + 2)) logged "\[loop [0-9]+\] the daemon's stderr: fake bbtunneld: a warning\$"
    rm -f "$MODE"

    # 10. a daemon that cannot start: logged once in full, the same again only when the pause
    #     grows (RETRY "0 3 8": starts SETTLE, SETTLE + 3, then SETTLE + 8 s apart; the gaps
    #     differ by 3 s, the check wants 1 s - room for a slow machine)
    within $((SETTLE + 1)) missing "$GUARD"
    local n starting
    n=$(starts)
    starting=$(times_logged "\] starting ")
    echo exit > "$MODE"
    kill -TERM "$(daemon_pid)"
    check "a daemon that cannot start - tried 3 times" within $((PAUSE + 3 * SETTLE + 2 + 4)) starts_are $((n + 3))
    check "... the time between tries grows: $(gaps)" gaps_grow
    check "... the third failed too, the pause now 8 s" within $((SETTLE + 2)) logged "; the next start in 8 s\$"
    check "log: the failure in full, once" \
        [ "$(times_logged "the daemon [0-9]+ left within $SETTLE s with status 1; the next start now\$")" = 1 ]
    check "log: its stderr, once" [ "$(times_logged "the daemon's stderr: fake bbtunneld: cannot start\$")" = 1 ]
    check "log: its copy is from this boot - once, with the failure" \
        [ "$(times_logged "its copy was made after this boot began: on the phone such a copy starts only after a reboot\$")" = 1 ]
    check "log: the same again - only when the pause grew (2 times)" [ "$(times_logged "the same failed start again")" = 2 ]
    check "log: ... the last pause" logged "the same failed start again \(repeat 2; failed starts in a row: 3\); the next start in 8 s\$"
    check "log: one starting line for all the tries" [ "$(times_logged "\] starting ")" = $((starting + 1)) ]
    # the off switch on and off again ends the 8 s pause: started at once
    rm -f "$MODE"
    mkdir "$OFF"
    sleep 1.5
    rmdir "$OFF"
    check "the off switch on and off - started without the pause" within 3 starts_are $((n + 4))
    check "... and it runs" within $((SETTLE + 1)) missing "$GUARD"
    check "... a fresh start: its starting line" [ "$(times_logged "\] starting ")" = $((starting + 2)) ]

    # 11. a few failed starts, then one that works: says after how many
    echo exit > "$MODE"
    n=$(starts)
    kill -TERM "$(daemon_pid)"
    within $((PAUSE + 2)) starts_are $((n + 1))
    within $((SETTLE + 2)) starts_are $((n + 2))
    # the second has read the mode by now: it fails too
    sleep 0.5
    rm -f "$MODE"
    check "it can start again - started" within $((SETTLE + 2 + SETTLE + 2)) starts_are $((n + 3))
    check "log: it runs, after 2 failed starts" within $((SETTLE + 1)) \
        logged "the daemon [0-9]+ runs for $SETTLE s now, after 2 failed starts in a row; the boot guard is off\$"

    # 12. the phone goes down within SETTLE of a start: the next boot skips the daemon, once
    within $((SETTLE + 1)) missing "$GUARD"
    n=$(($(starts) + 1))
    kill -TERM "$(daemon_pid)"
    within $((PAUSE + 2)) starts_are "$n"
    check "a fresh start, the guard is there" [ -e "$GUARD" ]
    power_cut
    local dead
    dead=$(loop_pid)
    boot
    sleep $((SETTLE + 2))
    check "power cut while settling - the next boot starts nothing" starts_are "$n"
    check "... and says so: boot-guard.tripped" [ -e "$GUARD.tripped" -a ! -e "$GUARD" ]
    check "... and its loop is over" loop_gone
    check "log: the pid file of the boot before - a new loop" \
        logged "\] the loop $dead of $W/run/pid is not there \(no process $dead\) - starting a new one\$"
    local tag
    tag=$(loop_tag)
    check "... the log says why" logged "\[loop $tag\] stop: $GUARD was there - the last boot went down within $SETTLE s of a start"
    check "... and that the loop is over" logged "\[loop $tag\] the loop is over\$"

    # 13. the boot after that: started again - from copies made before this boot
    power_cut
    boot
    check "the boot after - started" within 3 starts_are $((n + 1))
    check "... its copies are from before the boot: no mark" missing "$W/run/copied-this-boot"

    # 14. the phone goes down after the start settled: the next boot starts it
    within $((SETTLE + 1)) missing "$GUARD"
    n=$(starts)
    power_cut
    boot
    check "power cut after it settled - the next boot starts it" within 3 starts_are $((n + 1))

    # 14a. a clean shutdown within SETTLE of a start - on the phone every process gets SIGTERM, our
    #      sleep first: not a crash, the guard goes and the next boot starts the daemon
    within $((SETTLE + 1)) missing "$GUARD"
    n=$(($(starts) + 1))
    kill -TERM "$(daemon_pid)"
    within $((PAUSE + 2)) starts_are "$n"
    check "a fresh start, the guard is there" [ -e "$GUARD" ]
    tag=$(loop_tag)
    kill -TERM "$(pgrep -P "$(loop_pid)" -x sleep)"
    check "its sleep got SIGTERM - the loop stops" within 2 loop_gone
    check "... the guard is gone" missing "$GUARD"
    check "log: why" logged "\[loop $tag\] stop: our sleep got signal 15 - the phone shuts down, or a kill by hand\$"
    check "log: the guard off" logged "\[loop $tag\] the boot guard is off: a clean stop, not a crash\$"
    kill -TERM "$(daemon_pid)"
    local tripped
    tripped=$(times_logged "was there - the last boot went down")
    boot
    check "the next boot starts the daemon" within 3 starts_are $((n + 1))
    check "... the guard not tripped" [ "$(times_logged "was there - the last boot went down")" = "$tripped" ]

    # 14b. the same with SIGTERM to the loop itself
    within $((SETTLE + 1)) missing "$GUARD"
    n=$(($(starts) + 1))
    kill -TERM "$(daemon_pid)"
    within $((PAUSE + 2)) starts_are "$n"
    check "a fresh start, the guard is there" [ -e "$GUARD" ]
    tag=$(loop_tag)
    kill -TERM "$(loop_pid)"
    check "the loop got SIGTERM - it stops" within 2 loop_gone
    check "... the guard is gone" missing "$GUARD"
    check "log: the guard off" logged "\[loop $tag\] the boot guard is off: a clean stop, not a crash\$"
    kill -TERM "$(daemon_pid)"
    boot
    check "the next boot starts the daemon" within 3 starts_are $((n + 1))

    # 15. a reboot gave the old loop's pid to another process: not our loop - a new one
    within $((SETTLE + 1)) missing "$GUARD"
    local other
    sleep 300 &
    other=$!
    power_cut
    echo "$other" > "$W/run/pid"
    n=$(starts)
    boot
    check "the pid is another process's - a new loop, started" within 3 starts_are $((n + 1))
    check "... its pid in the pid file" [ "$(loop_pid)" != "$other" ]
    check "log: why" logged "\] the loop $other of $W/run/pid is not there \($other is another process now: $other sleep 300 *\) - starting a new one\$"
    # ...and with a pidin that cannot tell, kill -0 alone: the start keeps off
    within $((SETTLE + 1)) missing "$GUARD"
    power_cut
    echo "$other" > "$W/run/pid"
    : > "$W/no-pidin"
    n=$(starts)
    boot
    sleep 1
    check "a pidin that cannot tell - kill -0 alone, nothing started" starts_are "$n"
    check "log: why" logged "exit: the loop of this boot already runs \(pid $other: pidin cannot tell our loop from another process here, so kill -0 alone\)\$"
    rm -f "$W/no-pidin"
    kill "$other"
    wait "$other" 2> /dev/null

    # 16. the loop killed by hand, its pid file left: a new run takes over
    boot
    within 3 daemon_alive
    within $((SETTLE + 1)) missing "$GUARD"
    kill -9 "$(loop_pid)"
    kill -TERM "$(daemon_pid)"
    sleep 0.5
    n=$(starts)
    boot
    check "the pid file of a gone loop - a new run takes over and starts" within 3 starts_are $((n + 1))
    check "log: the take-over" logged "\] the loop [0-9]+ of $W/run/pid is not there \(no process [0-9]+\) - starting a new one\$"

    # 17. stopped by hand (as in the script's header): nothing comes back
    within $((SETTLE + 1)) missing "$GUARD"
    tag=$(loop_tag)
    kill "$(loop_pid)"
    sleep 0.2
    check "stopped by hand - the loop is gone at once" loop_gone
    check "... the log says why" logged "\[loop $tag\] stop: SIGTERM \(kill by hand, or the phone shuts down\)\$"
    check "... and that the loop is over" logged "\[loop $tag\] the loop is over\$"
    kill -TERM "$(daemon_pid)"
    n=$(starts)
    sleep 4
    check "stopped by hand - nothing comes back" [ "$(starts)" = "$n" ]
    check "... the daemon got SIGTERM and stopped" grep -q "^stop $(daemon_pid)\$" "$REC"

    # 18. uninstalled while the daemon runs. An empty /apps says nothing: all stays. With another
    #     package there: the daemon stopped, the copies removed, a look every WATCH s
    boot
    within 3 daemon_alive
    within $((SETTLE + 1)) missing "$GUARD"
    local d
    d=$(daemon_pid)
    mv "$W/apps/sys.other" "$W/sys.other.away"
    rm -rf "$W/apps/$PKG" "$SB"
    sleep $((3 * WATCH + 1))
    check "/apps empty - the daemon runs on" alive "$d"
    check "... the copies stay" [ -e "$W/run/bbtunneld" -a -e "$W/run/btctl" ]
    mv "$W/sys.other.away" "$W/apps/sys.other"
    check "uninstalled - the daemon got SIGTERM" within $((3 * WATCH + 2)) grep -q "^stop $d\$" "$REC"
    check "log: why" logged "the app is uninstalled: stopping the daemon $d \(SIGTERM - it takes its tunnels, routes and DNS down\)\$"
    check "the copies are removed" within $((PAUSE + 3 * IDLE + 2)) no_copies
    check "log: what was removed" logged "the app is uninstalled: removed from $W/run: bbtunneld bbtunneld.cksum btctl btctl.cksum\$"
    check "log: a look every WATCH s" within 2 logged "waiting, a look every $WATCH s: BBTunnel is uninstalled"
    n=$(starts)
    sleep 2
    check "... nothing started" [ "$(starts)" = "$n" ]
    check "... the loop lives" loop_alive

    # 19. the run folder cannot be made: the start exits and says why
    kill "$(loop_pid)"
    rm -rf "$W/run"
    : > "$W/run"
    boot
    check "no run folder - the start exits and says why" logged "\] exit: cannot create $W/run\$"
    rm -f "$W/run"

    # 20. the shared storage is not there yet (early in the boot): the log goes to the spare file
    mv "$W/shared" "$W/shared.away"
    boot
    check "no misc folder - the log is the spare one" grep -qE "\[start [0-9]+\] started: " "$SLOG"
    check "... the loop's lines too" within 2 grep -qE "\[loop [0-9]+\] waiting" "$SLOG"
    kill "$(loop_pid)"
    rm -rf "$W/run"
    mv "$W/shared.away" "$W/shared"

    # 21. a log over LOG_LIMIT (64 KB) moves to bbtunneld-boot.old.txt at the next start
    head -c 300000 /dev/zero | tr '\0' x >> "$BLOG"
    boot
    check "a big log - moved to .old.txt" [ "$(wc -c < "$W/shared/misc/bbtunneld-boot.old.txt")" -gt 300000 ]
    check "... the new one begins with this start" bash -c "head -n 1 '$BLOG' | grep -qE '\] started: '"
    check "... and is small" [ "$(wc -c < "$BLOG")" -lt 2000 ]
    #     ...and before a daemon start in a running loop - its own stderr follows into the new file
    within 2 logged "\[loop [0-9]+\] waiting"
    head -c 300000 /dev/zero | tr '\0' y >> "$BLOG"
    n=$(starts)
    install_app
    within 3 starts_are $((n + 1))
    check "a big log, the loop running - moved before the start" grep -q y "$W/shared/misc/bbtunneld-boot.old.txt"
    check "... the loop's stderr - the new log, not the old one" [ "$(readlink "/proc/$(loop_pid)/fd/2")" = "$BLOG" ]
    # the next test wants a waiting loop and no app
    kill "$(loop_pid)"
    kill -TERM "$(daemon_pid)"
    rm -rf "$W/apps/$PKG" "$SB"
    boot

    # 22. the boot guard cannot be created (the data folder read-only): no start, the loop waits
    if [ "$(id -u)" = 0 ]; then
        echo "  skip  the boot guard that cannot be created (root writes into a read-only folder)"
    else
        n=$(starts)
        install_app
        chmod 555 "$SB/data"
        sleep 3
        check "no boot guard - nothing started" [ "$(starts)" = "$n" ]
        check "... the loop lives" loop_alive
        check "... the log says why, once - not on every look" \
            [ "$(grep -c "waiting, a look every $IDLE s: cannot create the boot guard, no start without it: .*$GUARD" "$BLOG")" = 1 ]
        chmod 755 "$SB/data"
        check "the guard can be created again - started" within $((IDLE + 2)) starts_are $((n + 1))
    fi

    # 23. another folder for the copies, the one argument: RUN is its bbtunneld-boot subfolder, the
    #     folder itself untouched; a bad one ends the run with why, and makes nothing
    pkill -9 -f "$W/" 2> /dev/null
    sleep 0.3
    # a kill -9 within the settle time is a power cut to the boot guard: its mark goes too
    rm -f "$W/run/pid" "$GUARD" "$GUARD.tripped"
    install_app
    mkdir -p "$W/rootdata2"
    chmod 755 "$W/rootdata2"
    $SH "$W/boot.sh" "$W/rootdata2/"
    check "an argument: the loop's pid in <folder>/bbtunneld-boot" \
        within 2 alive "$(cat "$W/rootdata2/bbtunneld-boot/pid" 2> /dev/null)"
    check "... that subfolder root's alone (0700), the folder itself as it was (0755)" \
        [ "$(stat -c %a "$W/rootdata2/bbtunneld-boot")" = 700 -a "$(stat -c %a "$W/rootdata2")" = 755 ]
    check "... the copies there, and started from there" \
        within 3 logged "starting $W/rootdata2/bbtunneld-boot/bbtunneld, owner"
    check "... nothing in the default run folder" missing "$W/run/pid"
    pkill -9 -f "$W/" 2> /dev/null
    sleep 0.3
    local bad
    for bad in "rootdata2" "$W/rootdata2/../rootdata2" "$W/no-such-folder" "/accounts/1000/shared/misc"; do
        $SH "$W/boot.sh" "$bad"
        check "a bad argument ($bad): the run ends, says why, makes nothing" \
            within 2 logged "exit: the folder for the daemon's copies \(the argument\) is not usable - "
        sed -i 's/exit: the folder for the daemon.s copies (the argument) is not usable - /seen: /' "$BLOG"
    done
    check "... no loop, no run folder from any of them" \
        [ ! -e "$W/run/pid" -a ! -e "$W/no-such-folder" -a "$(ls "$W/rootdata2")" = bbtunneld-boot ]

    # 24. the boot hook (root v4): install mode on stdin, as the service calls it; rewritten only
    #     when different; the hook's start, the service asked for, one loop among two boot starts;
    #     the folder gone with the app
    pkill -9 -f "$W/" 2> /dev/null
    sleep 0.3
    rm -rf "$W/run" "$GUARD" "$GUARD.tripped"
    install_app
    local script=$W/apps/$PKG/native/bbtunneld-boot.sh
    local addon=$W/var/tunnel
    local hookrun=$addon/bbtunneld-boot
    cp "$W/boot.sh" "$script"
    mkdir -p "$W/var"
    $SH -s install "$script" < "$script" > "$W/out" 2>&1
    check "install: the last line is result=ok" [ "$(tail -n 1 "$W/out")" = result=ok ]
    check "... start.sh is the script itself" cmp -s "$script" "$addon/init/start.sh"
    check "... no second script beside it" missing "$addon/bbtunneld-boot.sh"
    check "... only root writes the hook (755)" \
        [ "$(stat -c %a "$addon" "$addon/init" "$addon/init/start.sh" | sort -u)" = 755 ]
    check "... no *.new left" [ -z "$(find "$addon" -name '*.new')" ]
    check "... the daemon's copy already there, root's alone" \
        [ "$(stat -c %a "$hookrun" "$hookrun/bbtunneld" | sort -u)" = 700 ]

    local before after
    before=$(stat -c '%i %Y' "$addon/init/start.sh")
    sleep 1.1
    $SH -s install "$script" < "$script" > "$W/out" 2>&1
    after=$(stat -c '%i %Y' "$addon/init/start.sh")
    check "the same again: result=same" [ "$(tail -n 1 "$W/out")" = result=same ]
    check "... the files left alone" [ "$before" = "$after" ]

    echo "# a newer build" >> "$script"
    $SH -s install "$script" < "$script" > "$W/out" 2>&1
    check "an updated package: result=ok, the copy follows" \
        [ "$(tail -n 1 "$W/out")" = result=ok ] && cmp -s "$script" "$addon/init/start.sh"

    $SH -s install "$W/no-such-script" < "$W/boot.sh" > "$W/out" 2>&1
    check "a script that cannot be read: result=failed" [ "$(tail -n 1 "$W/out")" = result=failed ]
    if [ "$(id -u)" != 0 ]; then
        chmod 555 "$addon/init"
        $SH -s install "$script" < "$script" > "$W/out" 2>&1
        check "a folder that cannot be written: result=failed" [ "$(tail -n 1 "$W/out")" = result=failed ]
        chmod 755 "$addon/init"
    fi

    # the hook at boot: the loop, the daemon from the hook's folder, the service through the navigator
    rm -f "$W/nav"
    sh "$addon/init/start.sh"
    check "the hook: the loop's pid in its folder" within 2 alive "$(cat "$hookrun/pid" 2> /dev/null)"
    check "... started as start.sh itself" logged "started: $addon/init/start.sh, parent pid"
    check "... the daemon starts from there" within 3 logged "starting $hookrun/bbtunneld, owner"
    check "... the navigator is asked for the service" \
        within 3 grep -qF '"target":"doctorrokter.BBTunnelService","action":"bb.action.START"' "$W/nav"
    check "... as one PPS message" grep -qx 'msg::invokeTarget' "$W/nav"
    touch "$W/service-running"
    check "... and no more once it runs" within 3 logged "the app's service runs \(requests sent: [1-9]"
    rm -f "$W/service-running"
    echo "a line of a boot with no misc" > "$addon/bbtunneld-boot.txt"
    $SH -s install "$script" < "$script" > "$W/out" 2>&1
    check "the next install tells the shared log what the spare log holds" logged "install: the spare log: a line of a boot with no misc\$"
    check "... the verdict still the last line" [ "$(tail -n 1 "$W/out")" = result=same ]
    check "... told once: moved aside" missing "$addon/bbtunneld-boot.txt"

    # two boot starts of ours: whichever came second leaves, a stale pid file does not count
    cp "$W/boot.sh" "$W/bbtunneld-boot.sh"
    $SH "$W/bbtunneld-boot.sh"
    check "a hand-made start beside the hook: it leaves, says why" \
        within 2 logged "exit: another boot start already runs the daemon \(pid [0-9]+ in $hookrun"
    check "... no second loop" missing "$W/run/pid"
    pkill -9 -f "$W/" 2> /dev/null
    sleep 0.3
    rm -f "$GUARD" "$GUARD.tripped" "$hookrun/pid"
    $SH "$W/bbtunneld-boot.sh"
    check "the hand-made start first" within 2 alive "$(cat "$W/run/pid" 2> /dev/null)"
    sh "$addon/init/start.sh"
    check "... the hook then leaves" within 2 logged "exit: another boot start already runs the daemon \(pid [0-9]+ in $W/run"
    check "... no second loop" missing "$hookrun/pid"
    pkill -9 -f "$W/" 2> /dev/null
    sleep 0.3
    rm -f "$GUARD" "$GUARD.tripped"
    echo $$ > "$W/run/pid"
    sed -i 's/starting [^ ]*bbtunneld, owner/seen, owner/' "$BLOG"
    sh "$addon/init/start.sh"
    check "a stale pid of the other start (another process): the hook starts" \
        within 3 logged "starting $hookrun/bbtunneld, owner"
    check "... the service never came: says so after its tries" \
        within 8 logged "the app's service did not start after 4 requests"

    # the system may feed start.sh to a shell, and with an argument: still the hook, not a refused folder
    pkill -9 -f "$W/" 2> /dev/null
    sleep 0.3
    rm -f "$GUARD" "$GUARD.tripped"
    sed -i 's/starting [^ ]*bbtunneld, owner/seen, owner/' "$BLOG"
    $SH -s boot < "$addon/init/start.sh"
    check "start.sh on stdin with an argument: the hook starts" \
        within 3 logged "starting $hookrun/bbtunneld, owner"

    # the app uninstalled: the daemon stops, the hook's whole folder goes
    rm -rf "$W/apps/$PKG" "$SB"
    check "uninstalled: the hook's folder is removed" within 12 missing "$addon"
    check "... the log says so" logged "the app is uninstalled: removing the boot hook $addon"
    check "... the daemon stopped" grep -q '^stop ' "$REC"

    teardown
}

echo "== the source"
check "no CR in the script (CRLF breaks sh)" bash -c "! grep -q \$'\\r' '$SRC'"
check "dash -n" dash -n "$SRC"
check "bash --posix -n" bash --posix -n "$SRC"

suite dash
suite "bash --posix"

echo
echo "passed $PASS, failed $FAIL"
[ "$FAIL" = 0 ]
