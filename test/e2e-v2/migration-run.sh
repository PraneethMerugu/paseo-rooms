#!/usr/bin/env bash
# Migration test 3 (docs/specs/identity-v2/migration.md section 6; plan I-15): upgrade from the M1 build.
#
#   M1 build : a temporary git worktree of tag m1-baseline outside the plugin (removed at the end), with
#              this plugin's node_modules linked in (M1's dependencies are a subset, same versions)
#   owner    : plugin/.test-homes/v2-mig-owner   127.0.0.1:6925
#   member   : plugin/.test-homes/v2-mig-member  127.0.0.1:6926
#   relay    : fake relay process                127.0.0.1:6927 (offline; never the live relay)
#
# Both daemons start with the M1 plugin, make an M1 room with a share lane and a membership, then the
# driver replaces the plugin with this directory and restarts both daemons (migration-e2e.ts). Keys use
# the protected fallback file from the start (PASEO_ROOMS_KEYSTORE=fallback-file; M1 ignores it), so
# the user's keyring is never touched. One agent is created without a prompt: no model call.
# Never touches ~/.paseo or the main daemon. KEEP_HOMES=1 keeps the homes.
set -euo pipefail

E2E_DIR=$(cd "$(dirname "$0")" && pwd)
PLUGIN_DIR=$(cd "$E2E_DIR/../.." && pwd)
REPO=$(git -C "$PLUGIN_DIR" rev-parse --show-toplevel)
P=/opt/Paseo/resources/bin/paseo
NODE=(env ELECTRON_RUN_AS_NODE=1 /opt/Paseo/Paseo.bin)
TSX=("${NODE[@]}" "$PLUGIN_DIR/node_modules/tsx/dist/cli.mjs")
HOMES=$PLUGIN_DIR/.test-homes
OWNER=$HOMES/v2-mig-owner
MEMBER=$HOMES/v2-mig-member
SCRATCH=$HOMES/v2-mig-scratch
OWNER_PORT=6925
MEMBER_PORT=6926
RELAY_PORT=6927
RUN_ID=$(date -u +%Y%m%dT%H%M%SZ)
LOGDIR=$E2E_DIR/logs/migration-$RUN_ID
RELAY_PID=""
WT=""

MAIN_HOME=$(realpath -m "$HOME/.paseo")
for h in "$OWNER" "$MEMBER"; do
  case "$(realpath -m "$h")" in "$MAIN_HOME"|"$MAIN_HOME"/*) echo "Refusing: $h resolves to ~/.paseo" >&2; exit 2 ;; esac
done
port_open() { (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; }
for port in "$OWNER_PORT" "$MEMBER_PORT" "$RELAY_PORT"; do
  if port_open "$port"; then echo "Refusing: 127.0.0.1:$port is already in use" >&2; exit 2; fi
done
git -C "$REPO" rev-parse -q --verify "refs/tags/m1-baseline" >/dev/null || { echo "tag m1-baseline not found" >&2; exit 2; }

mkdir -p "$LOGDIR"
export PASEO_DICTATION_ENABLED=false PASEO_VOICE_MODE_ENABLED=false
export PASEO_ROOMS_KEYSTORE=fallback-file PASEO_ROOMS_RELAY_ENDPOINT=127.0.0.1:$RELAY_PORT PASEO_ROOMS_RELAY_TLS=false PASEO_ROOMS_DEV_INSECURE_RELAY=1
unset PASEO_ROOMS_KEK_FILE PASEO_ROOMS_TEST_CLOCK PASEO_ROOMS_PROTOCOL
[ -n "${PASEO_HOME:-}" ] && unset PASEO_HOME

pa() { local home=$1; shift; PASEO_HOME=$home "$P" "$@" --home "$home" < /dev/null; }

write_config() {
  local home=$1 port=$2
  mkdir -p "$home"; chmod 700 "$HOMES" "$home"
  cat > "$home/config.json" <<JSON
{
  "daemon": { "listen": "127.0.0.1:$port", "relay": { "enabled": false } },
  "pluginsEnabled": true,
  "features": { "dictation": { "enabled": false }, "voiceMode": { "enabled": false } }
}
JSON
  chmod 600 "$home/config.json"
  printf 'paseo-rooms e2e test home; the test clock override may be used here\n' > "$home/rooms-test-home"
  chmod 600 "$home/rooms-test-home"
}

cleanup() {
  local code=$?
  trap - EXIT INT TERM
  echo "== cleanup"
  for h in "$MEMBER" "$OWNER"; do
    [ -d "$h" ] || continue
    pa "$h" plugin logs rooms > "$LOGDIR/plugin-$(basename "$h").log" 2>&1 || true
    pa "$h" plugin remove rooms >/dev/null 2>&1 || true
    pa "$h" daemon stop >/dev/null 2>&1 || true
    cp "$h/daemon.log" "$LOGDIR/daemon-$(basename "$h").log" 2>/dev/null || true
  done
  if [ -n "$RELAY_PID" ]; then kill "$RELAY_PID" 2>/dev/null || true; wait "$RELAY_PID" 2>/dev/null || true; fi
  if [ -n "$WT" ]; then
    git -C "$REPO" worktree remove --force "$WT" >/dev/null 2>&1 || true
    rm -rf "$WT"
    git -C "$REPO" worktree prune
    echo "removed the m1-baseline worktree"
  fi
  if [ -z "${KEEP_HOMES:-}" ]; then rm -rf "$OWNER" "$MEMBER" "$SCRATCH"; echo "deleted migration test homes"; fi
  if pgrep -f "$HOMES/v2-mig-" >/dev/null; then echo "WARNING: processes still reference the migration test homes"; code=1; else echo "no test processes left"; fi
  local busy=""
  for port in $(seq 6920 6929); do port_open "$port" && busy="$busy $port"; done
  if [ -n "$busy" ]; then echo "WARNING: ports still open:$busy"; code=1; else echo "ports 6920-6929 free"; fi
  echo "logs: $LOGDIR"
  exit $code
}
trap cleanup EXIT INT TERM

WT=$(mktemp -d /tmp/rooms-m1-baseline-XXXXXX)
rmdir "$WT"
git -C "$REPO" worktree add --detach "$WT" m1-baseline >/dev/null
ln -s "$PLUGIN_DIR/node_modules" "$WT/plugin/node_modules"
echo "== M1 build: worktree of m1-baseline at $WT"

rm -rf "$OWNER" "$MEMBER" "$SCRATCH"
mkdir -p "$HOMES" "$SCRATCH"; chmod 700 "$HOMES" "$SCRATCH"
"${TSX[@]}" "$E2E_DIR/fake-relay-main.ts" "$RELAY_PORT" > "$LOGDIR/fake-relay.log" 2>&1 &
RELAY_PID=$!
for _ in $(seq 1 100); do port_open "$RELAY_PORT" && break; sleep 0.1; done
port_open "$RELAY_PORT" || { echo "fake relay did not start" >&2; exit 1; }

write_config "$OWNER" "$OWNER_PORT"
write_config "$MEMBER" "$MEMBER_PORT"
for h in "$OWNER" "$MEMBER"; do pa "$h" daemon start --timeout 120 | tail -1; done
for h in "$OWNER" "$MEMBER"; do pa "$h" plugin install "$WT/plugin" --json | tail -3; done

E2E_OWNER_HOME=$OWNER E2E_MEMBER_HOME=$MEMBER E2E_PASEO_BIN=$P E2E_M1_PLUGIN=$WT/plugin E2E_V2_PLUGIN=$PLUGIN_DIR E2E_RELAY_LOG=$LOGDIR/fake-relay.log E2E_SCRATCH=$SCRATCH \
  "${TSX[@]}" "$E2E_DIR/migration-e2e.ts" 2>&1 | tee "$LOGDIR/e2e.log"
test "${PIPESTATUS[0]}" -eq 0
