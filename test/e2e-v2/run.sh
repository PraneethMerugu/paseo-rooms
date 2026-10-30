#!/usr/bin/env bash
# Identity v2 end-to-end test (implementation plan I-8 to I-11): room endpoint transport, sessions,
# SAS enrollment, lane grants v2 and device linking between disposable Paseo 0.13.2 test daemons running
# the plugin with PASEO_ROOMS_PROTOCOL=v2. The driver restarts the owner and member daemons once,
# mid-enrollment, views the lane through the member, waits for an idle and a forced grant rotation
# (short grants: 40 s), links a second device of the member (third daemon) and lets the 72 h hold pass
# on the owner's test clock, revokes, and scans every home for invite and link codes (prc2., prl2.) and
# grants (prg2.).
#
#   owner   : plugin/.test-homes/v2-owner    127.0.0.1:6921  (room host, room endpoint, admin daemon)
#   member  : plugin/.test-homes/v2-member   127.0.0.1:6922  (member device A)
#   member2 : plugin/.test-homes/v2-member2  127.0.0.1:6924  (the same person's second device B)
#   relay   : fake relay process             127.0.0.1:6923  (default, offline)
#             or the live relay relay.paseo.sh:443 with --live-relay (network; needs the user's go-ahead)
#
# TEST-ONLY clock: the owner daemon (host and admin daemon) runs with PASEO_ROOMS_TEST_CLOCK=1 and its
# home carries the marker file `rooms-test-home`; the plugin honours the override only on such a home
# under .test-homes (server/platform/test-clock.ts). No other daemon gets the switch.
#
# Never touches ~/.paseo or the main daemon: every CLI call passes --home and PASEO_HOME explicitly.
# Creates ONE agent on the owner for the lane (Claude Haiku, created without a prompt: no model call),
# archived at the end; no other agents, no model or API calls. Keys use the protected fallback file
# (PASEO_ROOMS_KEYSTORE=fallback-file), so the user's keyring is never read or written. The daemons'
# own relay registration stays off in both modes; only the plugin's room endpoint uses the relay.
#
#   bash test/e2e-v2/run.sh                 offline (fake relay on 6923)
#   bash test/e2e-v2/run.sh --live-relay    live relay (network)
#   KEEP_HOMES=1 ...                        keep the v2 homes afterwards (deleted by default)
set -euo pipefail

LIVE=0
while [ $# -gt 0 ]; do
  case "$1" in
    --live-relay) LIVE=1 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
  shift
done

E2E_DIR=$(cd "$(dirname "$0")" && pwd)
PLUGIN_DIR=$(cd "$E2E_DIR/../.." && pwd)
P=/opt/Paseo/resources/bin/paseo
NODE=(env ELECTRON_RUN_AS_NODE=1 /opt/Paseo/Paseo.bin)
TSX=("${NODE[@]}" "$PLUGIN_DIR/node_modules/tsx/dist/cli.mjs")
HOMES=$PLUGIN_DIR/.test-homes
OWNER=$HOMES/v2-owner
MEMBER=$HOMES/v2-member
MEMBER2=$HOMES/v2-member2
OWNER_PORT=6921
MEMBER_PORT=6922
RELAY_PORT=6923
MEMBER2_PORT=6924
RUN_ID=$(date -u +%Y%m%dT%H%M%SZ)
LOGDIR=$E2E_DIR/logs/$RUN_ID          # one directory per run; earlier runs are kept
RELAY_PID=""
SCRATCH=$HOMES/v2-scratch            # the lane agent's working directory

# ------------------------------------------------------------------ safety gates (before anything runs)
MAIN_HOME=$(realpath -m "$HOME/.paseo")
for h in "$OWNER" "$MEMBER" "$MEMBER2"; do
  r=$(realpath -m "$h")
  case "$r" in
    "$MAIN_HOME"|"$MAIN_HOME"/*) echo "Refusing: $h resolves to ~/.paseo" >&2; exit 2 ;;
  esac
  case "$r" in
    "$(realpath -m "$HOMES")"/v2-*) ;;
    *) echo "Refusing: $h is not a v2-* home under $HOMES" >&2; exit 2 ;;
  esac
done
if [ -n "${PASEO_HOME:-}" ] && [ "$(realpath -m "${PASEO_HOME/#\~/$HOME}")" = "$MAIN_HOME" ]; then
  unset PASEO_HOME   # never inherited by our commands; every call sets it explicitly
fi
PORTS=("$OWNER_PORT" "$MEMBER_PORT" "$MEMBER2_PORT")
[ "$LIVE" = 1 ] || PORTS+=("$RELAY_PORT")
for port in "${PORTS[@]}"; do
  if [ "$port" = 6767 ] || [ "$port" -lt 6920 ] || [ "$port" -gt 6929 ]; then
    echo "Refusing: port $port is outside 6920-6929" >&2; exit 2
  fi
  if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then
    echo "Refusing: 127.0.0.1:$port is already in use" >&2; exit 2
  fi
done
[ -x "$P" ] || { echo "paseo CLI not found at $P" >&2; exit 2; }

mkdir -p "$LOGDIR"
export PASEO_DICTATION_ENABLED=false PASEO_VOICE_MODE_ENABLED=false
# Plugin settings for the test daemons (inherited by the daemons and their plugin processes).
export PASEO_ROOMS_PROTOCOL=v2 PASEO_ROOMS_KEYSTORE=fallback-file
# Development short grants (grants-v2 section 5): honoured by the host only; never set outside tests.
export PASEO_ROOMS_DEV_SHORT_GRANTS=1 PASEO_ROOMS_DEV_GRANT_TTL_S=40
# Development MLS timers (I-13): repair delay 0, joiner check 5 s. Honoured by the v2 runtime only.
export PASEO_ROOMS_DEV_MLS_FAST=1
unset PASEO_ROOMS_KEK_FILE
if [ "$LIVE" = 1 ]; then
  unset PASEO_ROOMS_RELAY_ENDPOINT PASEO_ROOMS_RELAY_TLS PASEO_ROOMS_DEV_INSECURE_RELAY   # default: relay.paseo.sh:443 over TLS
  echo "== live relay mode: the room endpoint and the member connect to relay.paseo.sh:443 (network)"
else
  # The member accepts a loopback, plain-ws relay only with the development flag (P-20); an invite
  # can never set it. Not exported in live mode.
  export PASEO_ROOMS_RELAY_ENDPOINT=127.0.0.1:$RELAY_PORT PASEO_ROOMS_RELAY_TLS=false PASEO_ROOMS_DEV_INSECURE_RELAY=1
  echo "== offline mode: fake relay on 127.0.0.1:$RELAY_PORT"
fi

pa() { local home=$1; shift; PASEO_HOME=$home "$P" "$@" --home "$home" < /dev/null; }

write_config() {
  local home=$1 port=$2
  mkdir -p "$home"; chmod 700 "$HOMES" "$home"
  # Written BEFORE the first start: daemon relay registration off, plugins on, speech off (no model download).
  cat > "$home/config.json" <<JSON
{
  "daemon": { "listen": "127.0.0.1:$port", "relay": { "enabled": false } },
  "pluginsEnabled": true,
  "features": { "dictation": { "enabled": false }, "voiceMode": { "enabled": false } }
}
JSON
  chmod 600 "$home/config.json"
}

port_open() { (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; }

# ------------------------------------------------------------------ always-run cleanup
cleanup() {
  local code=$?
  trap - EXIT INT TERM
  echo "== cleanup"
  for h in "$MEMBER2" "$MEMBER" "$OWNER"; do
    [ -d "$h" ] || continue
    pa "$h" plugin logs rooms > "$LOGDIR/plugin-$(basename "$h").log" 2>&1 || true
    pa "$h" plugin remove rooms >/dev/null 2>&1 || true
    pa "$h" daemon stop >/dev/null 2>&1 || true
    cp "$h/daemon.log" "$LOGDIR/daemon-$(basename "$h").log" 2>/dev/null || true
  done
  if [ -n "$RELAY_PID" ]; then
    kill "$RELAY_PID" 2>/dev/null || true
    wait "$RELAY_PID" 2>/dev/null || true
  fi
  if [ -z "${KEEP_HOMES:-}" ]; then rm -rf "$OWNER" "$MEMBER" "$MEMBER2" "$SCRATCH"; echo "deleted v2 test homes"; fi
  if pgrep -f "$HOMES/v2-" >/dev/null; then echo "WARNING: processes still reference the v2 test homes"; code=1; else echo "no test processes left"; fi
  local busy=""
  for port in $(seq 6920 6929); do port_open "$port" && busy="$busy $port"; done
  if [ -n "$busy" ]; then echo "WARNING: ports still open:$busy"; code=1; else echo "ports 6920-6929 free"; fi
  echo "logs: $LOGDIR"
  exit $code
}
trap cleanup EXIT INT TERM

rm -rf "$OWNER" "$MEMBER" "$MEMBER2" "$SCRATCH"
mkdir -p "$HOMES" "$SCRATCH"; chmod 700 "$HOMES" "$SCRATCH"

if [ "$LIVE" != 1 ]; then
  "${TSX[@]}" "$E2E_DIR/fake-relay-main.ts" "$RELAY_PORT" > "$LOGDIR/fake-relay.log" 2>&1 &
  RELAY_PID=$!
  for _ in $(seq 1 100); do port_open "$RELAY_PORT" && break; sleep 0.1; done
  port_open "$RELAY_PORT" || { echo "fake relay did not start" >&2; exit 1; }
fi

write_config "$OWNER" "$OWNER_PORT"
write_config "$MEMBER" "$MEMBER_PORT"
write_config "$MEMBER2" "$MEMBER2_PORT"
# TEST-ONLY clock marker, owner home only (exact text checked by server/platform/test-clock.ts).
printf 'paseo-rooms e2e test home; the test clock override may be used here\n' > "$OWNER/rooms-test-home"
chmod 600 "$OWNER/rooms-test-home"
PASEO_ROOMS_TEST_CLOCK=1 pa "$OWNER" daemon start --timeout 120 | tail -1
for h in "$MEMBER" "$MEMBER2"; do pa "$h" daemon start --timeout 120 | tail -1; done
for h in "$OWNER" "$MEMBER" "$MEMBER2"; do pa "$h" plugin install "$PLUGIN_DIR" --json | tail -3; done

E2E_SCRATCH=$SCRATCH E2E_OWNER_HOME=$OWNER E2E_MEMBER_HOME=$MEMBER E2E_MEMBER2_HOME=$MEMBER2 E2E_LIVE=$LIVE E2E_RELAY_LOG=$LOGDIR/fake-relay.log E2E_PASEO_BIN=$P \
  "${TSX[@]}" "$E2E_DIR/e2e.ts" 2>&1 | tee "$LOGDIR/e2e.log"
test "${PIPESTATUS[0]}" -eq 0
