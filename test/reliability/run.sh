#!/usr/bin/env bash
# Reliability modules for the paseo-rooms plugin. Two disposable Paseo 0.13.2 test daemons:
#
#   owner  : test/reliability/.homes/owner   127.0.0.1:6930
#   member : test/reliability/.homes/member  127.0.0.1:6931
#
# Never touches ~/.paseo or the main daemon: every CLI call passes --home and PASEO_HOME explicitly.
# Creates at most two throwaway agents on the owner (a parent with a trivial prompt, and the fork made
# by agent-environment-inspection) and archives them in the always-run cleanup.
#
#   bash test/reliability/run.sh --i-reviewed-this                 all modules
#   bash test/reliability/run.sh --i-reviewed-this --only enrollment-reliability
#   KEEP_HOMES=1 ...                                                keep homes afterwards
#   RL_ENROLL_CYCLES=20 ...                                         enrollment cycles (default 20, max 50)
set -euo pipefail

REVIEWED=0
ONLY=""
while [ $# -gt 0 ]; do
  case "$1" in
    --i-reviewed-this) REVIEWED=1 ;;
    --only) ONLY=${2:-}; shift ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
  shift
done
if [ "$REVIEWED" != 1 ]; then
  echo "Refusing to run: read test/reliability/README.md and the module sources, then pass --i-reviewed-this." >&2
  exit 2
fi

RL_DIR=$(cd "$(dirname "$0")" && pwd)
PLUGIN_DIR=$(cd "$RL_DIR/../.." && pwd)
P=/opt/Paseo/resources/bin/paseo
NODE=(env ELECTRON_RUN_AS_NODE=1 /opt/Paseo/Paseo.bin)
TSX=("${NODE[@]}" "$PLUGIN_DIR/node_modules/tsx/dist/cli.mjs")
HOMES=$RL_DIR/.homes
OWNER=$HOMES/owner
MEMBER=$HOMES/member
OWNER_PORT=6930
MEMBER_PORT=6931
RUN_ID=$(date -u +%Y%m%dT%H%M%SZ)
LOGDIR=$RL_DIR/logs/$RUN_ID          # one directory per run; earlier runs are never overwritten
SCRATCH=$HOMES/scratch               # parent agent cwd (the fork inherits it)
MODULES=(agent-environment-inspection enrollment-reliability restart-persistence)

# ------------------------------------------------------------------ safety gates (before anything runs)
MAIN_HOME=$(realpath -m "$HOME/.paseo")
for h in "$OWNER" "$MEMBER"; do
  r=$(realpath -m "$h")
  case "$r" in
    "$MAIN_HOME"|"$MAIN_HOME"/*) echo "Refusing: $h resolves to ~/.paseo" >&2; exit 2 ;;
  esac
  case "$r" in
    "$(realpath -m "$HOMES")"/*) ;;
    *) echo "Refusing: $h is outside $HOMES" >&2; exit 2 ;;
  esac
done
if [ -n "${PASEO_HOME:-}" ] && [ "$(realpath -m "${PASEO_HOME/#\~/$HOME}")" = "$MAIN_HOME" ]; then
  unset PASEO_HOME   # never inherited by our commands; every call sets it explicitly
fi
for port in "$OWNER_PORT" "$MEMBER_PORT"; do
  if [ "$port" = 6767 ] || [ "$port" -lt 6930 ] || [ "$port" -gt 6939 ]; then
    echo "Refusing: port $port is outside 6930-6939" >&2; exit 2
  fi
  if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then
    echo "Refusing: 127.0.0.1:$port is already in use" >&2; exit 2
  fi
done
if [ -n "$ONLY" ] && [[ ! " ${MODULES[*]} " == *" $ONLY "* ]]; then
  echo "unknown module: $ONLY (one of: ${MODULES[*]})" >&2; exit 2
fi
[ -x "$P" ] || { echo "paseo CLI not found at $P" >&2; exit 2; }

export PASEO_DICTATION_ENABLED=false PASEO_VOICE_MODE_ENABLED=false
pa() { local home=$1; shift; PASEO_HOME=$home "$P" "$@" --home "$home" < /dev/null; }

write_config() {
  local home=$1 port=$2
  mkdir -p "$home"; chmod 700 "$HOMES" "$home"
  # Written BEFORE the first start: relay registration off, plugins on, speech off (no model download).
  cat > "$home/config.json" <<JSON
{
  "daemon": { "listen": "127.0.0.1:$port", "relay": { "enabled": false } },
  "pluginsEnabled": true,
  "features": { "dictation": { "enabled": false }, "voiceMode": { "enabled": false } }
}
JSON
  chmod 600 "$home/config.json"
}

AGENTS_FILE=$LOGDIR/agents.txt
SECRETS_FILE=$HOMES/.secrets-for-scan

# ------------------------------------------------------------------ always-run cleanup
cleanup() {
  local code=$?
  trap - EXIT INT TERM
  echo "== cleanup"
  if [ -s "$AGENTS_FILE" ] && [ -f "$OWNER/config.json" ]; then
    # A failed restart step can leave the owner test daemon stopped; archiving needs it running.
    if ! (exec 3<>"/dev/tcp/127.0.0.1/$OWNER_PORT") 2>/dev/null; then pa "$OWNER" daemon start --timeout 120 >/dev/null 2>&1 || true; fi
    while read -r id; do
      [ -n "$id" ] || continue
      out=$(pa "$OWNER" archive --force "$id" --json 2>&1 || true)
      case "$out" in
        *AGENT_ALREADY_ARCHIVED*) echo "agent ${id:0:8} already archived (archiving a parent archives its fork)" ;;
        *archivedAt*) echo "archived agent ${id:0:8}" ;;
        *) echo "WARNING: could not archive ${id:0:8}" ; code=1 ;;
      esac
    done < "$AGENTS_FILE"
  fi
  for h in "$MEMBER" "$OWNER"; do
    [ -d "$h" ] || continue
    pa "$h" plugin logs rooms > "$LOGDIR/plugin-$(basename "$h").log" 2>&1 || true
    pa "$h" plugin remove rooms >/dev/null 2>&1 || true
    pa "$h" daemon stop >/dev/null 2>&1 || true
    cp "$h/daemon.log" "$LOGDIR/daemon-$(basename "$h").log" 2>/dev/null || true
  done
  if [ -f "$SECRETS_FILE" ]; then
    "${TSX[@]}" "$PLUGIN_DIR/test/e2e/secret-scan.ts" "$SECRETS_FILE" "$HOMES" "$LOGDIR" | tee "$LOGDIR/secret-scan.json" || code=1
    rm -f "$SECRETS_FILE"
  fi
  for port in "$OWNER_PORT" "$MEMBER_PORT"; do
    if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then echo "WARNING: port $port still open"; code=1; fi
  done
  if [ -z "${KEEP_HOMES:-}" ]; then rm -rf "$HOMES"; echo "deleted test homes"; fi
  if pgrep -f "$HOMES" >/dev/null; then echo "WARNING: processes still reference test homes"; code=1; else echo "no test processes left"; fi
  echo "logs: $LOGDIR"
  exit $code
}
trap cleanup EXIT
trap 'exit 130' INT TERM

# ------------------------------------------------------------------ setup
rm -rf "$HOMES"; mkdir -p "$HOMES" "$LOGDIR" "$SCRATCH"; chmod 700 "$HOMES"
: > "$AGENTS_FILE"
write_config "$OWNER" "$OWNER_PORT"
write_config "$MEMBER" "$MEMBER_PORT"
for h in "$OWNER" "$MEMBER"; do pa "$h" daemon start --timeout 120 | tail -1; done
for h in "$OWNER" "$MEMBER"; do pa "$h" plugin install "$PLUGIN_DIR" --json | tail -3; done
for h in "$OWNER" "$MEMBER"; do pa "$h" plugin ls; done

echo "== throwaway parent agent on owner (agent 1 of at most 2)"
# Positive control for the environment inspection: sample the parent's provider process.
"${TSX[@]}" "$RL_DIR/env-sampler.ts" "$LOGDIR/parent-environment.json" 240 "127.0.0.1:$OWNER_PORT" &
SAMPLER=$!
(cd "$SCRATCH" && PASEO_HOME=$OWNER "$P" run --home "$OWNER" --provider claude --model claude-haiku-4-5 --mode default \
   --title "rooms reliability parent" --cwd "$SCRATCH" --wait-timeout 180s --json \
   "Reply with the word OK and nothing else." < /dev/null) > "$LOGDIR/parent-create.json"
kill "$SAMPLER" 2>/dev/null || true; wait "$SAMPLER" 2>/dev/null || true
PARENT=$("${NODE[@]}" -e 'const t=require("fs").readFileSync(process.argv[1],"utf8");console.log(JSON.parse(t.slice(t.indexOf("{"))).agentId)' "$LOGDIR/parent-create.json")
echo "$PARENT" >> "$AGENTS_FILE"
echo "parent ${PARENT:0:8}"

# ------------------------------------------------------------------ modules
export RL_OWNER_HOME=$OWNER RL_MEMBER_HOME=$MEMBER RL_PARENT=$PARENT RL_LOGDIR=$LOGDIR \
       RL_AGENTS_FILE=$AGENTS_FILE RL_SECRETS_FILE=$SECRETS_FILE RL_PARENT_ENV_REPORT=$LOGDIR/parent-environment.json
FAILED=()
# Order: the inspection first (fresh daemon, parent idle), restarts last (most disruptive).
for m in "${MODULES[@]}"; do
  [ -z "$ONLY" ] || [ "$m" = "$ONLY" ] || continue
  echo "== module $m"
  if ! (cd "$PLUGIN_DIR" && "${NODE[@]}" --test --test-concurrency=1 --test-reporter=spec \
        --import ./node_modules/tsx/dist/esm/index.mjs "test/reliability/$m.test.ts") 2>&1 | tee "$LOGDIR/$m.log"; then
    FAILED+=("$m")
  fi
done
echo "== modules failed: ${FAILED[*]:-none}"
[ ${#FAILED[@]} -eq 0 ]
