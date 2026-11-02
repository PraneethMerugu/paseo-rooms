#!/usr/bin/env bash
# Start three disposable Paseo daemons running the rooms plugin (identity v2, the only runtime since
# the I-15 cut-over) with demo state, for a manual check of the Rooms screens in the real Paseo app.
# Never touches ~/.paseo or the main daemon: every CLI call passes --home and PASEO_HOME points under
# plugin/ui-check/.test-homes. Each home carries the test-home marker, because the plugin honours
# PASEO_ROOMS_DEV_* switches (here only the loopback relay of --offline) only on a marked test home.
#
#   v2-owner    127.0.0.1:6912   owns "UI check room v2" (and "SAS demo room"), hosts the lane
#   v2-member   127.0.0.1:6913   member device A (admitted by the real SAS flow)
#   v2-member2  127.0.0.1:6914   the member's second device B (device link, held)
#   fake relay  127.0.0.1:6915   only with --offline; default is the live relay relay.paseo.sh:443
#
# Creates ONE agent on the owner (Claude Haiku, created without a prompt: no model call) for the lane.
# Keys use the protected fallback file (PASEO_ROOMS_KEYSTORE=fallback-file): the keyring is never used.
# Prints no invite code, link code, grant or recovery code. Run ./down-v2.sh to stop and delete.
#
#   ./up-v2.sh             live relay (network: relay.paseo.sh only)
#   ./up-v2.sh --offline   fake relay on 127.0.0.1:6915 (no network)
set -euo pipefail

OFFLINE=0
while [ $# -gt 0 ]; do
  case "$1" in
    --offline) OFFLINE=1 ;;
    *) echo "unknown argument: $1 (only --offline)" >&2; exit 2 ;;
  esac
  shift
done

UI_DIR=$(cd "$(dirname "$0")" && pwd)
PLUGIN_DIR=$(dirname "$UI_DIR")
source "$PLUGIN_DIR/tools/paseo-env.sh"   # sets P (paseo CLI) and NODE; override with PASEO_BIN / PASEO_NODE
TSX=("${NODE[@]}" "$PLUGIN_DIR/node_modules/tsx/dist/cli.mjs")
HOMES=$UI_DIR/.test-homes
OWNER=$HOMES/v2-owner
MEMBER=$HOMES/v2-member
MEMBER2=$HOMES/v2-member2
WORK=$HOMES/work
AGENTS=$HOMES/agents.txt
OWNER_PORT=6912
MEMBER_PORT=6913
MEMBER2_PORT=6914
RELAY_PORT=6915

# ------------------------------------------------------------------ safety gates (before anything runs)
MAIN_HOME=$(realpath -m "$HOME/.paseo")
for h in "$HOMES" "$OWNER" "$MEMBER" "$MEMBER2"; do
  r=$(realpath -m "$h")
  case "$r" in
    "$MAIN_HOME"|"$MAIN_HOME"/*) echo "Refusing: $h resolves to ~/.paseo" >&2; exit 2 ;;
  esac
  case "$r" in
    "$(realpath -m "$UI_DIR")"/.test-homes|"$(realpath -m "$UI_DIR")"/.test-homes/v2-*) ;;
    *) echo "Refusing: $h is not under $UI_DIR/.test-homes" >&2; exit 2 ;;
  esac
done
unset PASEO_HOME   # never inherited; every call sets it explicitly
PORTS=("$OWNER_PORT" "$MEMBER_PORT" "$MEMBER2_PORT")
[ "$OFFLINE" = 1 ] && PORTS+=("$RELAY_PORT")
port_open() { (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; }
for port in "${PORTS[@]}"; do
  if [ "$port" = 6767 ] || [ "$port" -lt 6912 ] || [ "$port" -gt 6919 ]; then
    echo "Refusing: port $port is outside 6912-6919 (or is the main daemon's 6767)" >&2; exit 2
  fi
  if port_open "$port"; then echo "Refusing: 127.0.0.1:$port is already in use. Run down-v2.sh first." >&2; exit 2; fi
done
[ -x "$P" ] || { echo "Paseo CLI not found at $P" >&2; exit 2; }
[ -d "$PLUGIN_DIR/node_modules" ] || { echo "Run 'npm install' in $PLUGIN_DIR first." >&2; exit 2; }
if [ -e "$HOMES" ]; then echo "$HOMES already exists. Run $UI_DIR/down-v2.sh first." >&2; exit 2; fi

# ------------------------------------------------------------------ environment of the test daemons
# Speech off before the first start (no model download).
export PASEO_DICTATION_ENABLED=false PASEO_VOICE_MODE_ENABLED=false
# The protected fallback-file keystore (never the user's keyring).
export PASEO_ROOMS_KEYSTORE=fallback-file
unset PASEO_ROOMS_PROTOCOL   # removed at the cut-over; ignored if set
# No development timers, short grants or test clock: the demo runs on production timings.
unset PASEO_ROOMS_KEK_FILE PASEO_ROOMS_TEST_CLOCK PASEO_ROOMS_DEV_SHORT_GRANTS PASEO_ROOMS_DEV_GRANT_TTL_S PASEO_ROOMS_DEV_MLS_FAST
if [ "$OFFLINE" = 1 ]; then
  # The member accepts a loopback plain-ws relay only with the development flag; an invite cannot set it.
  export PASEO_ROOMS_RELAY_ENDPOINT=127.0.0.1:$RELAY_PORT PASEO_ROOMS_RELAY_TLS=false PASEO_ROOMS_DEV_INSECURE_RELAY=1
  MODE="offline (fake relay 127.0.0.1:$RELAY_PORT)"
else
  unset PASEO_ROOMS_RELAY_ENDPOINT PASEO_ROOMS_RELAY_TLS PASEO_ROOMS_DEV_INSECURE_RELAY   # relay.paseo.sh:443, TLS
  MODE="live relay (relay.paseo.sh:443)"
fi

pa() { local home=$1; shift; PASEO_HOME=$home "$P" "$@" --home "$home" < /dev/null; }

write_config() {
  local home=$1 port=$2
  mkdir -p "$home"; chmod 700 "$home"
  # Written BEFORE the first start: loopback listen, relay registration off, plugins on, speech off.
  cat > "$home/config.json" <<JSON
{
  "daemon": { "listen": "127.0.0.1:$port", "relay": { "enabled": false } },
  "pluginsEnabled": true,
  "features": { "dictation": { "enabled": false }, "voiceMode": { "enabled": false } }
}
JSON
  chmod 600 "$home/config.json"
  # Test-home marker (exact text checked by server/platform/test-clock.ts).
  printf 'paseo-rooms e2e test home; the test clock override may be used here\n' > "$home/rooms-test-home"
  chmod 600 "$home/rooms-test-home"
}

fail() {
  echo
  echo "up-v2.sh failed: $*" >&2
  echo "Daemon logs: $HOMES/v2-*/daemon.log. Plugin logs, for example:" >&2
  echo "  PASEO_HOME=$OWNER $P plugin logs rooms --home $OWNER" >&2
  echo "Run $UI_DIR/down-v2.sh to clean up." >&2
  exit 1
}
trap 'fail "command on line $LINENO exited with status $?"' ERR

echo "== 1/5 mode: $MODE; writing configs under $HOMES"
mkdir -p "$HOMES" "$WORK"; chmod 700 "$HOMES" "$WORK"
write_config "$OWNER" $OWNER_PORT
write_config "$MEMBER" $MEMBER_PORT
write_config "$MEMBER2" $MEMBER2_PORT
: > "$AGENTS"; chmod 600 "$AGENTS"

if [ "$OFFLINE" = 1 ]; then
  echo "== fake relay on 127.0.0.1:$RELAY_PORT"
  setsid "${TSX[@]}" "$UI_DIR/fake-relay-v2.ts" "$RELAY_PORT" > "$HOMES/fake-relay.log" 2>&1 < /dev/null &
  echo $! > "$HOMES/fake-relay.pid"
  for _ in $(seq 1 100); do port_open "$RELAY_PORT" && break; sleep 0.1; done
  port_open "$RELAY_PORT" || fail "fake relay did not start"
fi

echo "== 2/5 starting v2-owner (:$OWNER_PORT), v2-member (:$MEMBER_PORT), v2-member2 (:$MEMBER2_PORT)"
for h in "$OWNER" "$MEMBER" "$MEMBER2"; do pa "$h" daemon start --timeout 120 | tail -1; done

echo "== 3/5 installing the plugin on all three daemons"
for h in "$OWNER" "$MEMBER" "$MEMBER2"; do pa "$h" plugin install "$PLUGIN_DIR" --json > /dev/null; done
for h in "$OWNER" "$MEMBER" "$MEMBER2"; do
  for _ in $(seq 1 60); do
    pa "$h" plugin ls --json 2>/dev/null | grep -q '"running"' && break
    sleep 1
  done
  pa "$h" plugin ls --json | grep -q '"running"' || fail "plugin not running on $(basename "$h")"
  echo "   rooms plugin running on $(basename "$h")"
done

echo "== 4/5 demo state (room, lane, enrollment, chat, device link, pending join)"
UI_OWNER_HOME=$OWNER UI_MEMBER_HOME=$MEMBER UI_MEMBER2_HOME=$MEMBER2 UI_WORK=$WORK UI_AGENTS_FILE=$AGENTS UI_OFFLINE=$OFFLINE \
  "${TSX[@]}" "$UI_DIR/demo-setup-v2.ts"

echo "== 5/5 checking that no model call was made"
# The agent was created without a prompt. A turn would leave timeline entries and usage on the agent,
# and a finished turn logs "Sending push notification" in the daemon log.
AGENT_ID=$(head -1 "$AGENTS")
pa "$OWNER" logs "$AGENT_ID" 2>&1 | grep -q 'No activity to display' || fail "the lane agent has timeline activity"
pa "$OWNER" inspect "$AGENT_ID" --json | grep -q '"LastUsage": null' || fail "the lane agent reports model usage"
for h in "$OWNER" "$MEMBER" "$MEMBER2"; do
  if grep -q 'Sending push notification' "$h/daemon.log"; then fail "$(basename "$h") daemon log shows a finished turn"; fi
done
echo "   lane agent: no timeline activity, no usage; no finished turn in any daemon log"
trap - ERR

cat <<EOF

==================================================================================
 Ready ($MODE). Three v2 test daemons run on loopback with the rooms plugin.

 Add each to the Paseo app (Settings -> Add host -> Direct connection, Use SSL off,
 no password; do not use "Pair device"):
   v2-owner    Host 127.0.0.1   Port $OWNER_PORT
   v2-member   Host 127.0.0.1   Port $MEMBER_PORT
   v2-member2  Host 127.0.0.1   Port $MEMBER2_PORT
 Then open the sidebar row "Rooms" on each host. See README.md, "Identity v2 kit",
 for what each host shows and the checklist.

 Time limit: the pending join in "SAS demo room" times out 15 minutes after setup
 (it then shows as an abandoned attempt). README.md says how to start a new one.

 When done: remove the three hosts from the app, then run $UI_DIR/down-v2.sh
==================================================================================
EOF
