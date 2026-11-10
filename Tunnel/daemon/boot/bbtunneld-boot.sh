#!/bin/sh
#
# bbtunneld-boot.sh - starts BBTunnel's root daemon at boot, and again whenever it leaves (a crash,
# or daemon.restart after an update - docs/DAEMON.md sections 1 and 12).
#
# Run it as root from whatever starts things at boot:   sh /path/to/bbtunneld-boot.sh [folder]
# It returns at once with 0: the loop goes on in the background, so the boot never waits on it.
#
# The other way in - install, from the app's headless service (client/service/RootAutostart.cpp):
#     /bin/ksh -s install '<this file in the package>' < '<this file in the package>'
# On a root firmware that runs /var/addons/<name>/init/start.sh at boot (root v4) it copies itself to
# $ADDON/init/start.sh: this very file is the boot start, there is no second script. Nothing is
# rewritten when it is the same already; a changed file goes through *.new and mv, so a copy is whole
# or not there. The app's update brings a new one this way (docs/DAEMON.md section 12). The last line
# of the output is the verdict the service reads: result=ok (written), same (nothing to do), failed.
# Run under any name but *boot.sh it counts as started by the system, whatever arguments it got. Then
# it also asks the navigator for the app's service (below, start_service), and when the app is
# uninstalled it removes $ADDON altogether.
#
# Keep it where only root writes - not in the shared storage, where the app hands it over (misc):
# root runs whatever is in this file. The folder, if given, is where only root writes too: the
# daemon's copies go into its bbtunneld-boot subfolder (default: $RUN below).
#
# Written for the phone's /bin/sh (PD KSH 5.2.14) and checked with dash and bash too
# (daemon/test/boot/run.sh). Every tool it runs is from the firmware: ls, mkdir, cp, chmod, mv, rm,
# cksum, sleep, pidin, pathtrust, and for the log date and id. The phone has no head, tr, cmp or rmdir.
#
# The daemon runs from copies in $RUN: the package's native/bbtunneld and native/btctl are copied
# there when they differ from the copies (an update, a reinstall) - before a start, and while the
# daemon runs (a look every $WATCH s). $RUN is root's alone (0700), so nobody else can swap the file
# root runs. btctl is there for checks over SSH.
#
# On the phone a copy made after the boot does not start (Operation not permitted) - only one that
# lay in $RUN when the phone booted (2026-10-15). So an update is copied as soon as it is installed,
# the running daemon goes on, and the new one starts with the next boot. $RUN/copied-this-boot says
# a copy was made in this boot, and a failed start then says so in the log.
#
# Safety:
#   - One loop per boot. $RUN outlives a reboot, so the pid in $RUN/pid can be an earlier boot's
#     and belong to another process by now: the loop counts as running only when pidin shows that
#     pid running this script.
#   - Off switch: a file or a folder named tunnel-off in the shared storage's misc folder (File
#     Manager, or the PC over USB). While it is there the daemon is not started. The running one
#     stops with Diagnostics > Restart the tunnel service, or with the next reboot. Taking the
#     switch away starts the daemon at once, whatever pause a failing daemon was in.
#   - Boot-loop breaker: if the phone went down within $SETTLE s of starting the daemon, the next
#     boot does not start it (once). data/boot-guard.tripped in the app's sandbox says so; its time
#     is the start the phone did not survive. Only a crash or a hard reset counts: a clean stop
#     within those $SETTLE s - a reboot from the menu, a kill by hand - sends a signal, and the
#     guard goes. A guard that cannot be created means no start: the loop waits and looks again
#     every $IDLE s.
#   - A daemon that leaves within $SETTLE s is a failed start. The next one comes 1, 2, 5, then
#     every 10 min after the one before ($RETRY), so a daemon that cannot start costs little. A
#     new package or the off switch starts the count again.
#   - The app uninstalled: its daemon is stopped (SIGTERM - it takes its tunnels, routes and DNS
#     down), else the phone's traffic would stay in a tunnel no app can take down; then the copies
#     in $RUN are removed. Uninstalled means: $APPS can be read (other packages are there) and
#     neither the package nor its sandbox is left, on two looks in a row. An empty or unreadable
#     $APPS says nothing.
#   - The daemon changes nothing on disk outside the app's sandbox; its routes, DNS and tun device
#     live in memory, so a reboot always gives the phone's network back as it was.
#
# App updates need nothing here: the new files are copied while the old daemon runs, the next boot
# starts the new one, and the arguments below are a fixed contract of every daemon version
# (docs/DAEMON.md section 12). The app does not restart an old daemon: it says the service updates
# when the phone restarts (docs/APP.md section 9). A copy set up by hand (root v2) stays as it is
# through an update; a copy in $ADDON (root v4) follows the app. A new version of it works from the
# next boot either way.
#
# Log (this script's own; the daemon's is data/logs/daemon.txt in the app's sandbox):
#   - misc/bbtunneld-boot.txt in the shared storage, next to the off switch (File Manager, the PC
#     over USB). While the misc folder cannot be written (too early in the boot) the log is
#     $LOG_SPARE instead.
#   - A line: the time, [start N] or [loop N] (N is the pid of the start; the loop's own pid is in
#     the start's last line and in $RUN/pid), what happens. Each run begins after an empty line
#     with "started".
#   - No "started" line for a boot - the script did not run. A start ends with "exit: <why>" or
#     "done", a loop with "stop: <why>" and "the loop is over". A loop with no such end was killed
#     hard (SIGKILL, a power cut). Shell errors land here too; the daemon's stderr (a library it
#     cannot load, bad arguments, a log it cannot open) as "the daemon's stderr:" lines.
#   - A failed start is logged once in full: its status and its stderr. The same one again only
#     when the pause grows, and then every $REPEAT_LOG-th time (once an hour at 10 min apart).
#   - Over $LOG_LIMIT bytes it moves to bbtunneld-boot.old.txt (the one before is dropped).
#
# Stop it:
#   - for now, no root needed: create misc/tunnel-off, then Diagnostics > Restart the tunnel service;
#   - as root:   kill $(cat $RUN/pid)   (the loop; $RUN - the default below, or <folder>/bbtunneld-boot)   then
#                slay bbtunneld   (SIGTERM: the daemon takes its tunnels, routes and DNS down
#                cleanly);
#   - for good: take this script out of the boot start and reboot. Uninstalling the app works too:
#     its daemon stops, its copies go, and the loop only looks every $WATCH s.

PATH=/bin:/usr/bin:/sbin:/usr/sbin
export PATH

APPS=/apps
APPDATA=/accounts/1000/appdata
OFF=/accounts/1000/shared/misc/tunnel-off
RUN=/accounts/devuser/rootdata/bbtunneld-boot
LOG=/accounts/1000/shared/misc/bbtunneld-boot.txt
LOG_SPARE=/accounts/devuser/rootdata/bbtunneld-boot.txt
LOG_LIMIT=65536 # bytes; a bigger log moves to *.old.txt at the next run or daemon start
SETTLE=60       # a start counts as survived after this many seconds
PAUSE=2         # before starting again after a daemon that ran left
RETRY="0 60 240 540" # s after a failed start, on top of its SETTLE s: starts 1, 2, 5, 10 min apart
IDLE=10         # between looks while the app is missing or the off switch is on
WATCH=30        # between looks at the app while the daemon runs, and while the app is uninstalled
REPEAT_LOG=6    # the same failed start again: a line every this many times
ADDON=/var/addons/tunnel # the boot hook's folder on root v4: init/start.sh (this script), the copies
# Where a boot start of ours keeps its pid: a phone may have both a hand-made start and the hook, and
# two loops would mean two daemons on one socket.
OTHER_RUNS="/accounts/devuser/rootdata/bbtunneld-boot $ADDON/bbtunneld-boot"
NAV=/pps/system/navigator/control
PATHTRUST=/proc/boot/pathtrust
SERVICE_TRIES=30 # requests for the app's service after a boot from the hook, this many at most
SERVICE_EVERY=30 # s between them: the system's own start of the service fails while root is not up

# Another folder for the copies, from the root setup that starts this script: its one argument,
# a folder only root writes (sh bbtunneld-boot.sh /that/folder). RUN is then its bbtunneld-boot
# subfolder - made here, 0700 - and the spare log its bbtunneld-boot.txt; this script never touches
# the folder itself. Taken only as the full path of a folder that exists, with no "..", and not in
# the shared storage: any app with access to the shared files writes there, and root must not run
# what they put. A bad one ends the run, with why in the log.
root_problem=
mode=boot
from_hook=
loop_name=${0##*/} # what pidin shows of this script's loop
case "$0" in
    *boot.sh) ;;
    *) from_hook=1 ;;
esac
if [ "$1" = install ]; then
    mode=install
    from_hook=
    install_from=$2
    RUN=$ADDON/bbtunneld-boot
    LOG_SPARE=$ADDON/bbtunneld-boot.txt
elif [ -n "$from_hook" ]; then
    loop_name=tunnel/init/start.sh
    RUN=$ADDON/bbtunneld-boot
    LOG_SPARE=$ADDON/bbtunneld-boot.txt
elif [ $# -gt 0 ]; then
    case "$1" in
        /*) ;;
        *) root_problem="not a full path: $1" ;;
    esac
    case "$1" in
        *..*) root_problem="a path with ..: $1" ;;
        /accounts/1000/shared | /accounts/1000/shared/*) root_problem="the shared storage, which apps write: $1" ;;
    esac
    if [ -z "$root_problem" ] && [ ! -d "$1" ]; then
        root_problem="no such folder: $1"
    fi
    if [ -z "$root_problem" ]; then
        RUN=${1%/}/bbtunneld-boot
        LOG_SPARE=${1%/}/bbtunneld-boot.txt
    fi
fi

ERR=$RUN/daemon-stderr.txt # the daemon's stderr of its last start
FRESH=$RUN/copied-this-boot # bbtunneld was copied after this boot began: it starts only after a reboot
nl='
'

# The log comes first, before anything that can fail, so that every run leaves at least its first
# line. A line that cannot be written is dropped; the log never stops the start.
TAG="start $$"

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S' 2> /dev/null) [$TAG] $*" 2> /dev/null >> "$LOG"
}

# The log over LOG_LIMIT bytes - to *.old.txt.
trim_log() {
    if [ "$LOG" = /dev/null ]; then
        return 0
    fi
    set -- $(ls -ln "$LOG" 2> /dev/null)
    case "$5" in
        ''|*[!0-9]*) return 0 ;;
    esac
    if [ "$5" -gt "$LOG_LIMIT" ]; then
        mv -f "$LOG" "${LOG%.txt}.old.txt"
        # The shell's own stderr moves to the new file too: it would stay with the old one, and
        # after the next move with a removed file. exec is a special built-in - a redirection
        # that fails on it ends the shell - so the file is tried with true first.
        if { true >> "$LOG"; } 2> /dev/null; then
            exec 2>> "$LOG"
        fi
    fi
    return 0
}

# The empty line between runs doubles as the test that the log can be written.
if ! echo "" 2> /dev/null >> "$LOG"; then
    LOG=$LOG_SPARE
    if ! echo "" 2> /dev/null >> "$LOG"; then
        LOG=/dev/null
    fi
fi
trim_log
# From here on the shell's own error messages go to the log too, not to the caller.
exec 2>> "$LOG"
log "started: $0, parent pid $PPID, $(id 2>&1)"
if [ -n "$root_problem" ]; then
    log "exit: the folder for the daemon's copies (the argument) is not usable - $root_problem"
    exit 0
fi

# Our paths into pathtrust before anything of ours starts, each result in the log. /dev/null: the
# install and the hook may read this script from stdin, and a tool reading it would eat the rest.
for trust_path in "$ADDON" "$RUN" "$RUN/bbtunneld" "$RUN/btctl"; do
    trust_output=$("$PATHTRUST" "!$trust_path" < /dev/null 2>&1)
    log "pathtrust $trust_path: status $?, $trust_output"
done

# The installed app: sets app (its package folder) and sandbox. Not installed, or never run yet
# (no data folder) - returns 1, and app_problem says which.
find_app() {
    for app in "$APPS"/doctorrokter.BBTunnel.*; do
        sandbox=$APPDATA/${app#$APPS/}
        if [ ! -d "$app" ]; then
            app_problem="nothing matches $APPS/doctorrokter.BBTunnel.* (not installed, or $APPS cannot be read)"
        elif [ ! -x "$app/native/bbtunneld" ]; then
            app_problem="no runnable $app/native/bbtunneld"
        elif [ ! -d "$sandbox/data" ]; then
            app_problem="no $sandbox/data (the app never ran)"
        else
            return 0
        fi
    done
    return 1
}

# Uninstalled for sure: APPS can be read - other packages are there - and neither the package nor
# its sandbox is left. An empty or unreadable APPS says nothing, so no.
app_uninstalled() {
    set -- "$APPS"/*
    if [ ! -e "$1" ]; then
        return 1
    fi
    for left in "$APPS"/doctorrokter.BBTunnel.* "$APPDATA"/doctorrokter.BBTunnel.*; do
        if [ -e "$left" ]; then
            return 1
        fi
    done
    return 0
}

# The app's uid:gid into owner: the owner of a file the app itself made - the service's log, which
# the service writes from its first start (install, boot). Not the data folder's owner: the system
# makes that folder, and on the phone it is 89:10192, not the app (2026-10-15). A socket and a log
# given to it the app cannot open, and the daemon lets into its socket only root and the owner's
# uid. No such file yet, or anything but two numbers - returns 1; listing has what ls said.
find_owner() {
    listing=$(ls -ln "$sandbox/data/logs/service.txt" 2>&1)
    set -- $listing
    case "$3" in
        ''|*[!0-9]*) return 1 ;;
    esac
    case "$4" in
        ''|*[!0-9]*) return 1 ;;
    esac
    owner=$3:$4
    return 0
}

# The package's bbtunneld and btctl into RUN, where the daemon starts from: when the package's file
# differs from the one copied last time (its cksum - the CRC, size and path - is kept beside the
# copy), or the copy is not there. Not by size and time alone: two builds can have the same size,
# and ls shows the time to the minute - a stale daemon would then be restarted by the app forever
# (docs/APP.md section 9). cp into *.new, then mv: a copy is whole or not there. Sets copied (the
# names copied now). bbtunneld that cannot be copied - returns 1, copy_problem says why. btctl
# that cannot is only logged, once per error: the daemon does not need it.
sync_copies() {
    copied=
    for name in bbtunneld btctl; do
        from=$app/native/$name
        to=$RUN/$name
        sum=$(cksum "$from" 2>&1)
        last=
        if [ -f "$to.cksum" ]; then
            # IFS= keeps the leading spaces: the phone's cksum right-aligns the CRC, and a plain read
            # trimmed them - no match, so every start copied the daemon again (2026-10-15)
            IFS= read -r last < "$to.cksum"
        fi
        if [ -f "$to" ] && [ "$sum" = "$last" ]; then
            continue
        fi
        if error=$( { cp "$from" "$to.new" && chmod 700 "$to.new" && mv -f "$to.new" "$to"; } 2>&1 ); then
            echo "$sum" > "$to.cksum"
            copied="$copied $name"
            if [ "$name" = bbtunneld ]; then
                true 2> /dev/null > "$FRESH"
            fi
            continue
        fi
        rm -f "$to.new"
        problem="cannot copy $from to $RUN: $error"
        if [ "$name" = bbtunneld ]; then
            copy_problem=$problem
            return 1
        fi
        if [ "$problem" != "$btctl_problem" ]; then
            log "$problem (btctl only - the daemon starts without it)"
            btctl_problem=$problem
        fi
    done
    return 0
}

# The app is uninstalled: its copies go too. Only our own names, one by one - no rm -r.
remove_copies() {
    removed=
    for name in bbtunneld btctl; do
        for file in "$RUN/$name" "$RUN/$name.cksum" "$RUN/$name.new"; do
            if [ -e "$file" ] && rm -f "$file"; then
                removed="$removed ${file##*/}"
            fi
        done
    done
    rm -f "$ERR" "$FRESH"
    if [ -n "$removed" ]; then
        log "the app is uninstalled: removed from $RUN:$removed"
    fi
}

# Is process $1 our loop? kill -0 says only that some process has that pid, and the pid file
# outlives a reboot: its pid can be an earlier boot's and another process's by now. pidin shows a
# process's arguments, and our loop's name this script. A pidin that does not show even this
# process's cannot tell; then kill -0 alone. Sets why.
is_our_loop() {
    if [ "$1" = "$$" ] || ! kill -0 "$1" 2> /dev/null; then
        why="no process $1"
        return 1
    fi
    case "$(pidin -p $$ arg 2>&1)" in
        *"$loop_name"*) ;;
        *)
            # Started by the system its name may not show at all, and it starts once per boot: a
            # stale pid must not cost that boot its daemon.
            if [ -n "$from_hook" ]; then
                why="pidin does not show the hook's name, and the hook runs once per boot"
                return 1
            fi
            why="pidin cannot tell our loop from another process here, so kill -0 alone"
            return 0
            ;;
    esac
    args=$(pidin -p "$1" arg 2>&1)
    args=${args##*"$nl"}
    case "$args" in
        *"$loop_name"* | *bbtunneld-boot.sh* | *tunnel/init/start.sh*)
            why=$args
            return 0
            ;;
    esac
    why="$1 is another process now: $args"
    return 1
}

# sleep that a signal cuts short: during a plain sleep the shell would run the TERM trap only once
# the sleep is over, during wait it runs it at once. nap_status - the sleep's status, over 128 when
# a signal killed it.
nap() {
    sleep "$1" &
    wait $!
    nap_status=$?
    return $nap_status
}

# A start still settling when the loop stops cleanly - the phone shuts down, or a kill by hand: its
# boot guard goes. The guard is for a daemon that takes the phone down, and then nothing gets a
# signal: a crash or a hard reset leaves it. Without this every reboot within SETTLE s of a start
# would cost the next boot its daemon.
drop_settling_guard() {
    if [ -n "$settling" ]; then
        rm -f "$settling"
        settling=
        log "the boot guard is off: a clean stop, not a crash"
    fi
}

# The loop's sleep ended early: says why. A signal - on a shutdown every process gets SIGTERM, and
# our sleep can get it before the loop does (the shell then says "Terminated") - also drops the
# guard of a start still settling.
stop_on_cut_sleep() {
    if [ "$nap_status" -gt 128 ]; then
        log "stop: our sleep got signal $((nap_status - 128)) - the phone shuts down, or a kill by hand"
        drop_settling_guard
    else
        log "stop: sleep failed with status $nap_status"
    fi
}

# Not now: says why in the log - only when the reason changes, not on every look - and waits $2 s
# (IDLE when not given). The wait cut short - returns 1.
not_now() {
    every=${2:-$IDLE}
    if [ "$every $1" != "$waiting_for" ]; then
        log "waiting, a look every $every s: $1"
        waiting_for="$every $1"
    fi
    nap "$every"
}

# The daemon's stderr of this start: err_text (all of it, to tell one failed start from another)
# and err_lines (how many lines).
read_stderr() {
    err_text=
    err_lines=0
    if [ ! -f "$ERR" ]; then
        return 0
    fi
    while IFS= read -r line || [ -n "$line" ]; do
        err_text="$err_text$line$nl"
        err_lines=$((err_lines + 1))
    done < "$ERR"
}

# Its lines after the first $1 into the log, 20 at most.
log_stderr() {
    if [ ! -f "$ERR" ]; then
        return 0
    fi
    n=0
    while IFS= read -r line || [ -n "$line" ]; do
        n=$((n + 1))
        if [ "$n" -gt "$1" ] && [ "$n" -le $(($1 + 20)) ]; then
            log "the daemon's stderr: $line"
        fi
    done < "$ERR"
    if [ "$n" -gt $(($1 + 20)) ]; then
        log "the daemon's stderr: $((n - $1 - 20)) more lines in $ERR"
    fi
}

# The pause after the fails-th failed start in a row, into retry: that word of RETRY, the last one
# from there on.
retry_after() {
    set -- $RETRY
    i=1
    while [ "$i" -lt "$fails" ] && [ "$#" -gt 1 ]; do
        shift
        i=$((i + 1))
    done
    retry=$1
}

# A failed start into the log: in full when it is new - its status and its stderr. The same one
# again (the status and stderr alike) only when the pause grows, then every REPEAT_LOG-th time.
report_failure() {
    read_stderr
    if [ "$retry" = 0 ]; then
        next="the next start now"
    else
        next="the next start in $retry s"
    fi
    failure="$status $err_text"
    if [ "$failure" != "$last_failure" ]; then
        log "the daemon $daemon left within $SETTLE s with status $status; $next"
        log_stderr 0
        if [ -e "$FRESH" ]; then
            log "its copy was made after this boot began: on the phone such a copy starts only after a reboot"
        fi
        last_failure=$failure
        repeats=0
    else
        repeats=$((repeats + 1))
        if [ "$retry" != "$last_retry" ] || [ $((repeats % REPEAT_LOG)) = 0 ]; then
            log "the same failed start again (repeat $repeats; failed starts in a row: $fails); $next"
        fi
    fi
    last_retry=$retry
}

# The pause after a failed start: $1 s, in looks of IDLE s - the off switch, a new package or the
# app gone end it early. Cut short by a signal - returns 1.
wait_retry() {
    left=$1
    stamp=$(ls -ln "$app/native/bbtunneld" 2>&1)
    while [ "$left" -gt 0 ]; do
        if ! nap "$IDLE"; then
            return 1
        fi
        left=$((left - IDLE))
        if [ -e "$OFF" ] || [ "$(ls -ln "$app/native/bbtunneld" 2>&1)" != "$stamp" ]; then
            return 0
        fi
    done
    return 0
}

# Beside the loop while the daemon runs (the loop waits on the daemon, so it sees it leave at once):
# a look at the app every WATCH s. An update - its files copied at once, the daemon goes on: on the
# phone the new copy starts only after a reboot, and it is in place by then. Uninstalled on two
# looks in a row - the daemon is stopped, as nothing else would stop it: SIGTERM (it takes its
# tunnels, routes and DNS down itself), SIGKILL if it is still there 10 s later. Ends with the
# daemon.
watch_app() {
    gone=0
    watch_problem=
    while kill -0 "$daemon" 2> /dev/null; do
        sleep "$WATCH"
        if app_uninstalled; then
            gone=$((gone + 1))
        else
            gone=0
            if [ -f "$app/native/bbtunneld" ]; then
                if sync_copies; then
                    if [ -n "$copied" ]; then
                        log "an update: copied from $app/native to $RUN:$copied while the daemon $daemon runs; it goes on, the new one starts after a reboot"
                    fi
                    watch_problem=
                elif [ "$copy_problem" != "$watch_problem" ]; then
                    log "an update, not copied yet: $copy_problem"
                    watch_problem=$copy_problem
                fi
            fi
        fi
        if [ "$gone" -ge 2 ] && kill -0 "$daemon" 2> /dev/null; then
            log "the app is uninstalled: stopping the daemon $daemon (SIGTERM - it takes its tunnels, routes and DNS down)"
            kill -TERM "$daemon"
            waited=0
            while kill -0 "$daemon" 2> /dev/null && [ "$waited" -lt 10 ]; do
                sleep 1
                waited=$((waited + 1))
            done
            if kill -0 "$daemon" 2> /dev/null; then
                log "the daemon $daemon is still there 10 s after SIGTERM: SIGKILL"
                kill -KILL "$daemon"
            fi
            return
        fi
    done
}

loop() {
    trap '' HUP
    cd /
    first_start=1
    waiting_for=
    gone_looks=0
    fails=0         # failed starts in a row: the daemon left within SETTLE s
    last_failure=   # the last failed start's status and stderr
    repeats=0       # how many times it came back since it was logged
    last_retry=
    btctl_problem=
    settling=       # the boot guard of a start within its SETTLE s
    # One loop per boot: the copies in RUN now are from before this boot.
    rm -f "$FRESH"
    while :; do
        reason=
        every=$IDLE
        if [ -e "$OFF" ]; then
            reason="the off switch $OFF is there"
        elif ! find_app; then
            reason=$app_problem
        elif ! find_owner; then
            reason="no uid:gid of the app's own file (the service's log) in: $listing"
        fi
        if [ -n "$reason" ] && app_uninstalled; then
            gone_looks=$((gone_looks + 1))
        else
            gone_looks=0
        fi
        if [ "$gone_looks" -ge 2 ]; then
            remove_copies
            if [ -n "$from_hook" ]; then
                log "the app is uninstalled: removing the boot hook $ADDON"
                rm -rf "$ADDON"
                return
            fi
            reason="BBTunnel is uninstalled (no package and no sandbox)"
            every=$WATCH
        fi
        if [ -n "$reason" ]; then
            # Whatever made the loop wait, the next start is a fresh one: no pause before it.
            fails=0
            if ! not_now "$reason" "$every"; then
                stop_on_cut_sleep
                return
            fi
            continue
        fi

        guard=$sandbox/data/boot-guard
        if [ "$first_start" = 1 ] && [ -e "$guard" ]; then
            # The last boot went down within SETTLE s of a start: not this boot. The next one
            # tries again.
            mv -f "$guard" "$guard.tripped"
            log "stop: $guard was there - the last boot went down within $SETTLE s of a start, so not this boot (now boot-guard.tripped)"
            return
        fi
        first_start=0

        if ! sync_copies; then
            if ! not_now "$copy_problem" "$WATCH"; then
                stop_on_cut_sleep
                return
            fi
            continue
        fi
        if [ -n "$copied" ]; then
            log "copied from $app/native to $RUN:$copied"
        fi
        case "$copied" in
            *bbtunneld*)
                # A new daemon: a fresh start, its failures counted and logged anew.
                fails=0
                last_failure=
                ;;
        esac

        trim_log
        # The boot guard, made in a subshell: a failed redirection then cannot end the loop (it did
        # with ":", a special built-in), and the shell's message goes into the log line. No guard -
        # no start: a daemon that takes the phone down would do it again on every boot.
        if ! error=$( { true > "$guard"; } 2>&1 ); then
            if ! not_now "cannot create the boot guard, no start without it: $error"; then
                stop_on_cut_sleep
                return
            fi
            continue
        fi
        settling=$guard
        waiting_for=

        # Within a run of failed starts only the failures are logged (report_failure).
        if [ "$fails" = 0 ]; then
            log "starting $RUN/bbtunneld, owner $owner (of data/logs/service.txt)"
        fi
        rm -f "$ERR"
        "$RUN/bbtunneld" --state "$sandbox/data/daemon" --socket "$sandbox/data/daemon.sock" \
            --log "$sandbox/data/logs/daemon.txt" --owner "$owner" 2>> "$ERR" &
        daemon=$!
        if [ "$fails" = 0 ]; then
            log "the daemon runs, pid $daemon"
        fi
        if ! nap "$SETTLE"; then
            stop_on_cut_sleep
            return
        fi
        rm -f "$guard"
        settling=

        if ! kill -0 "$daemon" 2> /dev/null; then
            # A failed start: the daemon left within SETTLE s.
            wait "$daemon"
            status=$?
            fails=$((fails + 1))
            retry_after
            report_failure
            if ! wait_retry "$retry"; then
                stop_on_cut_sleep
                return
            fi
            continue
        fi

        if [ "$fails" = 0 ]; then
            log "$SETTLE s since the start: the boot guard is off"
        else
            log "the daemon $daemon runs for $SETTLE s now, after $fails failed starts in a row; the boot guard is off"
        fi
        fails=0
        last_failure=
        read_stderr
        log_stderr 0
        err_seen=$err_lines
        watch_app &
        watcher=$!
        wait "$daemon"
        status=$?
        kill "$watcher" 2> /dev/null
        log "the daemon $daemon left with status $status; the next start in $PAUSE s"
        log_stderr "$err_seen"
        if ! nap "$PAUSE"; then
            stop_on_cut_sleep
            return
        fi
    done
}

# A line of the install mode: to the service (its stdout) and into the log.
say() {
    echo "$*"
    log "install: $*"
}

# $1.new takes the place of $1, unless they are the same already (the phone has no cmp): then the
# file is left alone. Sets hook_changed when it wrote. Failed - says why and returns 1.
replace_if_changed() {
    if [ -f "$1" ] && [ "$(cat "$1.new")" = "$(cat "$1")" ]; then
        rm -f "$1.new"
        return 0
    fi
    if ! error=$( { chmod 755 "$1.new" && mv -f "$1.new" "$1"; } 2>&1 ); then
        say "cannot write $1: $error"
        rm -f "$1.new"
        return 1
    fi
    hook_changed=1
    return 0
}

# The boot hook: this script ($1 - the package's file) as init/start.sh in ADDON. Only named files
# get 755, not the whole folder: the copies of the daemon stay root's alone (RUN is 0700).
install_hook() {
    hook_changed=
    if [ ! -r "$1" ]; then
        say "cannot read $1"
        return 1
    fi
    if ! error=$(mkdir -p "$ADDON/init" 2>&1); then
        say "cannot create $ADDON: $error"
        return 1
    fi
    if ! error=$(cp "$1" "$ADDON/init/start.sh.new" 2>&1); then
        say "cannot copy $1 to $ADDON/init: $error"
        rm -f "$ADDON/init/start.sh.new"
        return 1
    fi
    if ! replace_if_changed "$ADDON/init/start.sh"; then
        return 1
    fi
    chmod 755 "$ADDON" "$ADDON/init"
    # What builds 35 and 36 left: the script beside start.sh, and the hook's own note.
    rm -f "$ADDON/bbtunneld-boot.sh" "$ADDON/hook.txt" "$ADDON/hook.txt.seen"

    # The daemon's copies now, not at the first boot: on the phone a copy made after a boot starts
    # only from the next one, so the first reboot after the install would be wasted.
    app=${1%/native/*}
    if [ ! -d "$RUN" ] && ! mkdir "$RUN" 2> /dev/null; then
        say "cannot create $RUN (the boot start tries again)"
        return 0
    fi
    chmod 700 "$RUN"
    if ! sync_copies; then
        say "$copy_problem (the boot start tries again)"
    elif [ -n "$copied" ]; then
        say "copied to $RUN:$copied"
    fi
    return 0
}

# The spare log, where a boot that could not write the misc folder wrote, into the log the app
# shares (the app may not be able to read $ADDON). Moved aside once told, so nothing is told twice.
tell_file() {
    told=0
    while IFS= read -r line || [ -n "$line" ]; do
        told=$((told + 1))
        if [ "$told" -le 40 ]; then
            log "install: $2: $line"
        fi
    done < "$1"
    mv -f "$1" "$1.seen"
}

report_hook() {
    if [ "$LOG" != "$LOG_SPARE" ] && [ -f "$LOG_SPARE" ]; then
        tell_file "$LOG_SPARE" "the spare log"
    fi
}

if [ "$mode" = install ]; then
    report_hook
    if ! install_hook "$install_from"; then
        verdict=failed
    elif [ -n "$hook_changed" ]; then
        say "boot hook written: $ADDON"
        verdict=ok
    else
        verdict=same
    fi
    say "result=$verdict"
    exit 0
fi

# After a boot from the hook: the app's service, through the navigator. The system's own start of
# it (bb.action.system.STARTED) comes long before root and can fail, and nothing tries again; the
# hook runs when root is there. Ends when the service runs, or after SERVICE_TRIES requests.
service_running() {
    case "$(pidin -F '%N' 2>&1)" in
        *BBTunnelService*) return 0 ;;
    esac
    return 1
}

start_service() {
    tries=0
    while [ "$tries" -lt "$SERVICE_TRIES" ]; do
        if service_running; then
            log "the app's service runs (requests sent: $tries)"
            return
        fi
        if app_uninstalled; then
            return
        fi
        # One write, as a PPS message must be: cat with a here-document.
        cat >> "$NAV" << 'PPSEOF'
msg::invokeTarget
dat:json:{"target":"doctorrokter.BBTunnelService","action":"bb.action.START","type":"text/plain","uri":"data://local"}
PPSEOF
        tries=$((tries + 1))
        sleep "$SERVICE_EVERY"
    done
    if service_running; then
        log "the app's service runs (requests sent: $tries)"
    else
        log "the app's service did not start after $tries requests to the navigator"
    fi
}

# The copies' and the pid's folder: root's alone.
if [ ! -d "$RUN" ] && ! mkdir "$RUN" 2> /dev/null; then
    log "exit: cannot create $RUN"
    exit 0
fi
chmod 700 "$RUN"

# One loop per boot. The pid file of a loop that is gone (killed by hand, an earlier boot) - a new
# loop.
pid=
if [ -f "$RUN/pid" ]; then
    read pid < "$RUN/pid"
fi
if [ -n "$pid" ]; then
    if is_our_loop "$pid"; then
        log "exit: the loop of this boot already runs (pid $pid: $why)"
        exit 0
    fi
    log "the loop $pid of $RUN/pid is not there ($why) - starting a new one"
fi
# Another boot start of ours (a hand-made one beside the hook) got here first. Only what pidin shows
# as our loop counts: a stale pid file must not cost this boot its daemon.
for other_run in $OTHER_RUNS; do
    if [ "$other_run" = "$RUN" ] || [ ! -f "$other_run/pid" ]; then
        continue
    fi
    read pid < "$other_run/pid"
    if [ -n "$pid" ] && is_our_loop "$pid"; then
        case "$why" in
            pidin*) ;;
            *)
                log "exit: another boot start already runs the daemon (pid $pid in $other_run: $why)"
                exit 0
                ;;
        esac
    fi
done
# The loop lets go of everything the caller gave it. Redirections on a function call are not
# enough: the shell keeps copies of the old stdout and stderr to put back later (dash does, on
# fds 10 and up), and a caller that reads our output would then wait for an end that never comes.
# exec in a subshell replaces them for good; fds 3-9 are closed in case the caller passed any.
(
    exec < /dev/null > /dev/null 2>> "$LOG" 3>&- 4>&- 5>&- 6>&- 7>&- 8>&- 9>&-
    TAG="loop $$"
    trap 'log "stop: SIGTERM (kill by hand, or the phone shuts down)"; drop_settling_guard; exit 143' TERM
    trap 'log "the loop is over"' EXIT
    log "the loop runs"
    loop
) &
loop_pid=$!
if ! echo "$loop_pid" > "$RUN/pid"; then
    log "cannot write $RUN/pid - a second start of this boot will not see this loop"
fi
if [ -n "$from_hook" ]; then
    (
        exec < /dev/null > /dev/null 2>> "$LOG" 3>&- 4>&- 5>&- 6>&- 7>&- 8>&- 9>&-
        TAG="service $$"
        start_service
    ) &
fi
log "done, exit 0: the loop runs in the background, pid $loop_pid"
exit 0
