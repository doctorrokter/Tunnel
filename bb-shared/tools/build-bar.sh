#!/usr/bin/env bash
#
# build-bar.sh — command-line build of an UNSIGNED Device-Release .bar for a
# Cascades/Qt BB10 project, without Momentics.
#
# Reusable across projects: run it from a project directory that contains a
# single <name>.pro, or pass the project dir as an argument. Produces
# <name>.bar in the project root.
#
#   ./build-bar.sh                       # release build, DEVELOPMENT env (default)
#   ./build-bar.sh -e production         # release build, PRODUCTION env (ships to
#                                        #   users: developer tools compiled out)
#   ./build-bar.sh --clean               # wipe arm/arm-p/x86 first, then build
#   ./build-bar.sh /path/to/app          # build a specific project dir
#   ./build-bar.sh --service ../Svc      # also build a sibling headless service
#                                        #   for ARM first (repeatable). A sibling
#                                        #   <AppName>Service is auto-built anyway.
#   ./build-bar.sh --deploy <IP> <pass>  # build, then install+launch on device
#
# Before it compiles, prebuild-checks.sh checks the project (QML calling C++ by a name the C++ does not have, ...):
# a failure stops a -e production build; a development build only warns.
#
# A project with NO .pro but a bar-descriptor.xml (an app built elsewhere - the
# browser, whose engine deps/build-deps.sh makes in WSL) is only packaged: no
# qmake, no make, buildId bumped as usual, the .bar named after the project's
# folder, packaged exactly as `make package` packages the others (no -devMode, so
# the same testRel_ application id and the same sandbox for -e development and -e
# production). A configuration "Device-Release-production" (see below) is packaged
# for production when the descriptor has one. Its tools/package-checks.sh, when it
# has one, says whether what is staged may be packaged at all.
#
# Deploy needs the device in Development Mode (IP + dev password shown there).
# IP/password can also come from env: BB_DEVICE_IP / BB_DEVICE_PASS.
#
# The .bar is NOT signed — intended for sideloading onto a device that accepts
# unsigned bars (e.g. a rooted device). Add a signing step separately if needed.
#
# SDK paths default to this machine's manually-unpacked NDK; override by
# exporting QNX_HOST / QNX_TARGET before running.

set -euo pipefail

# This script's own folder: prebuild-checks.sh sits beside it (the cwd changes to the project below).
TOOLS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# --- SDK location (override via env) -----------------------------------------
: "${QNX_HOST:=E:/dev/blackberry/bbndk.win32.tools.10.3.1.12/host_10_3_1_12/win32/x86}"
: "${QNX_TARGET:=E:/dev/blackberry/bbndk.win32.libraries.10.3.1.995/target_10_3_1_995/qnx6}"

# Normalise Windows backslashes to forward slashes. The bbndk env scripts
# (bbndk-env_*.bat) export these with backslashes (D:\blackberry\...host\win32\x86).
# When make regenerates arm/Makefile it writes the qmake recipe to a temp .sh and
# runs it via sh, which eats the backslashes as escape sequences
# (D:\blackberry -> D:blackberry) so qmake is "not found" and the build dies at
# mk/cs-base.mk. Forward slashes work for every tool here (Git Bash, qcc, qmake).
QNX_HOST="${QNX_HOST//\\//}"
QNX_TARGET="${QNX_TARGET//\\//}"
export QNX_HOST QNX_TARGET

# Prepend the SDK tools to PATH. Cygwin/MSYS use ":" as the PATH separator, so a
# Windows "D:/..." element splits into "D" + "/..." and breaks command lookup
# (make/qmake "command not found"). Convert to a POSIX path for PATH ONLY; the
# QNX tools themselves still receive the Windows-style QNX_HOST/QNX_TARGET above.
if command -v cygpath >/dev/null 2>&1; then
    export PATH="$(cygpath -u "$QNX_HOST")/usr/bin:$PATH"
else
    export PATH="$QNX_HOST/usr/bin:$PATH"
fi

# The bundled blackberry-nativepackager targets Java 6/7 and reaches into the
# JDK's internal Xerces classes. Modern JDKs (9+) block that behind the module
# system, so open the needed packages. Harmless on older JDKs.
export _JAVA_OPTIONS="\
--add-exports=java.xml/com.sun.org.apache.xerces.internal.parsers=ALL-UNNAMED \
--add-exports=java.xml/com.sun.org.apache.xerces.internal.dom=ALL-UNNAMED \
--add-exports=java.xml/com.sun.org.apache.xerces.internal.jaxp=ALL-UNNAMED \
--add-exports=java.xml/com.sun.org.apache.xerces.internal.util=ALL-UNNAMED"

# --- Args --------------------------------------------------------------------
CLEAN=0
DEPLOY=0
PROJECT_DIR="."
DEVICE_IP="${BB_DEVICE_IP:-}"
DEVICE_PASS="${BB_DEVICE_PASS:-}"
SERVICES=()
# Build environment, exported to qmake as BBT_ENV (the .pro keys BBT_PRODUCTION
# off it). Default development; -e production for the build that ships to users.
BUILD_ENV="development"
while [ "$#" -gt 0 ]; do
    case "$1" in
        --clean) CLEAN=1 ;;
        -e|--env)
            if [ -z "${2:-}" ]; then echo "error: -e needs development|production" >&2; exit 1; fi
            BUILD_ENV="$2"; shift ;;
        --service)
            if [ -z "${2:-}" ]; then echo "error: --service needs a dir" >&2; exit 1; fi
            SERVICES+=("$2"); shift ;;
        --deploy)
            DEPLOY=1
            # Optional inline "IP pass"; otherwise fall back to env.
            if [ "${2:-}" ] && [ "${2#-}" = "$2" ]; then DEVICE_IP="$2"; shift; fi
            if [ "${2:-}" ] && [ "${2#-}" = "$2" ]; then DEVICE_PASS="$2"; shift; fi
            ;;
        -h|--help) sed -n '2,27p' "$0"; exit 0 ;;
        *) PROJECT_DIR="$1" ;;
    esac
    shift
done

case "$BUILD_ENV" in
    development|production) ;;
    *) echo "error: -e must be 'development' or 'production' (got '$BUILD_ENV')" >&2; exit 1 ;;
esac

if [ "$DEPLOY" -eq 1 ] && { [ -z "$DEVICE_IP" ] || [ -z "$DEVICE_PASS" ]; }; then
    echo "error: --deploy needs an IP and password (inline or via BB_DEVICE_IP/BB_DEVICE_PASS)" >&2
    exit 1
fi

# Resolve --service dirs to ABSOLUTE paths now, while we're still in the
# invocation cwd. They're used after we cd into the project (below), so a path
# relative to where the user ran this (e.g. ./BBTelegaService, or ../Svc from
# inside a project) would otherwise be resolved against the wrong dir and fail.
if [ "${#SERVICES[@]}" -gt 0 ]; then
    for i in "${!SERVICES[@]}"; do
        svc="${SERVICES[$i]}"
        case "$svc" in
            /*|[A-Za-z]:*) ;;                     # already absolute (POSIX or Windows drive)
            *) svc="$(cd "$svc" 2>/dev/null && pwd)" \
                 || { echo "error: --service dir not found: ${SERVICES[$i]}" >&2; exit 1; } ;;
        esac
        SERVICES[$i]="$svc"
    done
fi

cd "$PROJECT_DIR"
PROJECT_DIR="$(pwd)"

# --- Locate the .pro ---------------------------------------------------------
shopt -s nullglob
pros=(*.pro)
shopt -u nullglob
PACKAGE_ONLY=0
if [ "${#pros[@]}" -eq 0 ] && [ -f bar-descriptor.xml ]; then
    # Nothing to compile here: package what the descriptor names.
    PACKAGE_ONLY=1
    NAME="$(basename "$PROJECT_DIR")"
    PRO=""
elif [ "${#pros[@]}" -ne 1 ]; then
    echo "error: expected exactly one *.pro in $PROJECT_DIR, found ${#pros[@]}" >&2
    exit 1
else
    PRO="${pros[0]}"
    NAME="${PRO%.pro}"
fi

# Auto-detect a sibling headless-service project named "<AppName>Service" (a
# sibling dir one level up), so `./build-bar.sh ./BBTelega` picks up
# BBTelegaService without an explicit --service. An explicit --service (resolved
# to absolute above) takes precedence and skips this.
if [ "${#SERVICES[@]}" -eq 0 ] && [ "$PACKAGE_ONLY" -eq 0 ]; then
    AUTO_SVC="$(cd "$PROJECT_DIR/.." 2>/dev/null && pwd)/${NAME}Service"
    if [ -d "$AUTO_SVC" ] && ls "$AUTO_SVC"/*.pro >/dev/null 2>&1; then
        echo "== Auto-detected sibling service: $AUTO_SVC"
        SERVICES+=("$AUTO_SVC")
    fi
fi

# The Makefile always emits "<NAME>.bar"; the versioned name is applied after
# packaging (below), once the bumped buildId and the descriptor version are known.
BAR_FILE="$NAME.bar"

echo "== Project : $NAME  ($PROJECT_DIR)"
echo "== QNX_HOST: $QNX_HOST"
echo "== Env     : $BUILD_ENV"
[ "$PACKAGE_ONLY" -eq 1 ] && echo "== Mode    : package only (no .pro)"

# --- Checks ------------------------------------------------------------------
# The mistakes no compiler sees (prebuild-checks.sh - QML finds its C++ names only when a line runs). A production
# .bar is never made with one; a development build says so and goes on. A package-only project has no QML here.
if [ "$PACKAGE_ONLY" -eq 0 ]; then
    if ! bash "$TOOLS_DIR/prebuild-checks.sh" "$PROJECT_DIR"; then
        if [ "$BUILD_ENV" = "production" ]; then
            echo "error: the checks failed - no production .bar (fix what they list above)" >&2
            exit 1
        fi
        echo "warn: the checks failed (see above) - a development .bar anyway" >&2
    fi
elif [ -f "$PROJECT_DIR/tools/package-checks.sh" ]; then
    if ! bash "$PROJECT_DIR/tools/package-checks.sh"; then
        if [ "$BUILD_ENV" = "production" ]; then
            echo "error: the checks failed - no production .bar (fix what they list above)" >&2
            exit 1
        fi
        echo "warn: the checks failed (see above) - a development .bar anyway" >&2
    fi
fi

# Everything from here to the buildId bump compiles - a package-only project
# skips it (the block is left unindented to keep it as it was).
if [ "$PACKAGE_ONLY" -eq 0 ]; then

# --- Build env plumbing ------------------------------------------------------
# The .pro reads BBT_ENV from the environment (development vs production, keyed to
# BBT_PRODUCTION). Two things make this reliable:
#   1. qmake only re-runs when the .pro is newer than the per-arch Makefile, so
#      touch the .pro to force it to re-read BBT_ENV.
#   2. Switching env only flips a DEFINE, which make does NOT count as a reason to
#      recompile - so a changed env forces a clean, or a production .bar could keep
#      development's objects and still ship the developer tools. A marker file
#      remembers the last env so same-env rebuilds stay incremental.
export BBT_ENV="$BUILD_ENV"

ENV_MARKER="$PROJECT_DIR/.build-env"
LAST_ENV=""
[ -f "$ENV_MARKER" ] && LAST_ENV="$(cat "$ENV_MARKER" 2>/dev/null || true)"
if [ "$LAST_ENV" != "$BUILD_ENV" ]; then
    [ -n "$LAST_ENV" ] && echo "== Env changed ($LAST_ENV -> $BUILD_ENV): forcing a clean rebuild"
    CLEAN=1
fi
echo "$BUILD_ENV" > "$ENV_MARKER"
touch "$PRO"

# --- Sanity: tools present ---------------------------------------------------
if [ ! -x "$QNX_HOST/usr/bin/qmake.exe" ] && [ ! -x "$QNX_HOST/usr/bin/qmake" ]; then
    echo "error: qmake not found under QNX_HOST ($QNX_HOST). Set QNX_HOST correctly." >&2
    exit 1
fi

# --- Build -------------------------------------------------------------------
if [ "$CLEAN" -eq 1 ]; then
    echo "== Cleaning previous build dirs"
    make -I "$QNX_TARGET/usr/include" clean || true
fi

# Build any sibling headless services for ARM first (they have no bar-descriptor
# of their own, so we use the build-only Device-Release target, not `package`).
# Their arm/<name> binary is what this app's bar-descriptor packages in.
for svc in "${SERVICES[@]:-}"; do
    [ -z "$svc" ] && continue
    echo "== Building service (ARM release): $svc"
    ( cd "$svc"
      # Touch the service .pro so qmake re-reads BBT_ENV, same reason as the app's
      # `touch "$PRO"` above: otherwise a prod build right after a dev one keeps the
      # service's development DEFINES (qDebug() would NOT be compiled out).
      for p in *.pro; do [ -f "$p" ] && touch "$p"; done
      if [ "$CLEAN" -eq 1 ]; then make -I "$QNX_TARGET/usr/include" clean || true; fi
      # Debug and Release link into the SAME arm/<target> (the headless template has no
      # per-configuration folder), and `make clean` keeps that file: a Momentics Debug
      # build newer than the release objects counts as up to date and would be packaged
      # as it is (KB 2.11). Removing it makes the release link run every time.
      # The target's name from the template Makefile ("QMAKE_TARGET  = <Service>"), read
      # with bash alone: the SDK's tools come first on PATH, and its tr reads '\r' as the
      # letter r - "BBSynoService" came out "BBSynoSevice" and nothing was removed.
      target=""
      if [ -f Makefile ]; then
          while IFS= read -r line || [ -n "$line" ]; do
              case "$line" in
                  QMAKE_TARGET*=*) target="${line#*=}"; break ;;
              esac
          done < Makefile
      fi
      target="${target//[[:space:]]/}"
      [ -n "$target" ] || target="${svc##*/}"
      if [ -f "arm/$target" ]; then
          echo "== Relinking $svc: removing the previous arm/$target"
          rm -f "arm/$target"
      fi
      make -I "$QNX_TARGET/usr/include" Device-Release )
done

fi  # PACKAGE_ONLY -eq 0

# Auto-increment buildId in bar-descriptor.xml so each packaged .bar has a higher
# build number than the last — BB10 treats an install as an update only when the
# buildId rises (ours had been stuck at 1). Bumped just before packaging so the
# .bar carries the new value; if the build later fails the number simply skips,
# which is harmless. buildId is capped at 65535 by BB10.
DESC="$PROJECT_DIR/bar-descriptor.xml"
if [ -f "$DESC" ]; then
    CUR_BUILD_ID="$(sed -n 's:.*<buildId>\([0-9][0-9]*\)</buildId>.*:\1:p' "$DESC" | head -1 || true)"
    if [ -n "$CUR_BUILD_ID" ]; then
        NEXT_BUILD_ID=$((CUR_BUILD_ID + 1))
        sed "s:<buildId>${CUR_BUILD_ID}</buildId>:<buildId>${NEXT_BUILD_ID}</buildId>:" \
            "$DESC" > "$DESC.tmp" && mv "$DESC.tmp" "$DESC"
        echo "== buildId : $CUR_BUILD_ID -> $NEXT_BUILD_ID"

        # Name the .bar after the full version and the environment, e.g.
        # BBTube_1_3_0_25_dev.bar - the descriptor's <versionNumber> (dots ->
        # underscores), the new buildId, and dev or prod, so each artefact says
        # what it is instead of a bare BBTube.bar.
        VERSION="$(sed -n 's:.*<versionNumber>\([0-9.][0-9.]*\)</versionNumber>.*:\1:p' "$DESC" | head -1 || true)"
        if [ -n "$VERSION" ]; then
            if [ "$BUILD_ENV" = "production" ]; then
                ENV_SUFFIX="prod"
            else
                ENV_SUFFIX="dev"
            fi
            BAR_FILE="${NAME}_${VERSION//./_}_${NEXT_BUILD_ID}_${ENV_SUFFIX}.bar"
        fi
    else
        echo "warn: no numeric <buildId> in bar-descriptor.xml — not bumping" >&2
    fi
else
    echo "warn: no bar-descriptor.xml in $PROJECT_DIR — not bumping buildId" >&2
fi

# What goes into the package may depend on the environment: a <configuration>
# named "Device-Release-<env>" in bar-descriptor.xml is packaged for that
# environment instead of "Device-Release". Quake2 has one for production, which
# adds the game's data - a development .bar stays small and reads the data from
# the phone's shared folder. Without such a configuration nothing changes.
PACKAGE_CONFIG="Device-Release"
if [ -f "$DESC" ] && grep -q "<configuration name=\"Device-Release-$BUILD_ENV\">" "$DESC"; then
    PACKAGE_CONFIG="Device-Release-$BUILD_ENV"
fi

if [ "$PACKAGE_ONLY" -eq 1 ]; then
    # No Makefile: the packager itself, the .bat where there is one (see below).
    echo "== Package : configuration $PACKAGE_CONFIG"
    PACKAGER="$QNX_HOST/usr/bin/blackberry-nativepackager"
    [ -f "$PACKAGER.bat" ] && PACKAGER="$PACKAGER.bat"
    rm -f "$NAME.bar"
    # NO -devMode, for either environment: it changes the application id
    # (testDev_ instead of testRel_), and with it the sandbox - a development
    # and a production install of one app would not share their data.
    "$PACKAGER" -package "$NAME.bar" -configuration "$PACKAGE_CONFIG" bar-descriptor.xml
elif [ "$PACKAGE_CONFIG" = "Device-Release" ]; then
    # `package` depends on Device-Release, so this both builds ARM release and
    # packages the (unsigned) .bar via blackberry-nativepackager.
    make -I "$QNX_TARGET/usr/include" package
else
    # The same two steps as `make package` (mk/cs-base.mk), with the other
    # configuration: the rule there names Device-Release itself.
    echo "== Package : configuration $PACKAGE_CONFIG"
    make -I "$QNX_TARGET/usr/include" Device-Release
    # The .bat where there is one, as make itself picks it: the sh launcher joins
    # the Java class path with ':', which splits a Windows path at its drive.
    PACKAGER="$QNX_HOST/usr/bin/blackberry-nativepackager"
    [ -f "$PACKAGER.bat" ] && PACKAGER="$PACKAGER.bat"
    "$PACKAGER" -package "$NAME.bar" -configuration "$PACKAGE_CONFIG" bar-descriptor.xml
fi

# The Makefile wrote "<NAME>.bar"; give it the versioned name worked out above.
if [ "$BAR_FILE" != "$NAME.bar" ] && [ -f "$NAME.bar" ]; then
    mv -f "$NAME.bar" "$BAR_FILE"
fi

echo
if [ -f "$BAR_FILE" ]; then
    echo "== OK: $PROJECT_DIR/$BAR_FILE"
    ls -la "$BAR_FILE"
else
    echo "error: build finished but $BAR_FILE not found" >&2
    exit 1
fi

# --- Deploy ------------------------------------------------------------------
if [ "$DEPLOY" -eq 1 ]; then
    echo
    echo "== Deploying to $DEVICE_IP (install + launch)"
    blackberry-deploy.bat -installApp -launchApp \
        -device "$DEVICE_IP" -password "$DEVICE_PASS" \
        -package "$BAR_FILE"
    echo "== Deployed."
fi
