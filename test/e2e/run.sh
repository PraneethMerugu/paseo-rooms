#!/usr/bin/env bash
# End-to-end test with two disposable Paseo 0.13.2 daemons. Never touches ~/.paseo or the main daemon:
# every CLI call passes --home, and PASEO_HOME is set explicitly.
#
#   owner C  : plugin/.test-homes/owner-c   127.0.0.1:6891  (gateway + embedded host)
#   member A : plugin/.test-homes/member-a  127.0.0.1:6892  (member)
#
# Creates at most two throwaway agents on C (a parent with a trivial prompt, and the room's fork),
# archives both at the end, removes the plugin registrations and stops both daemons (also on failure).
#
#   bash test/e2e/run.sh            full run
#   KEEP_HOMES=1 bash test/e2e/run.sh   keep homes afterwards (they are deleted by default)
set -euo pipefail
cd "$(dirname "$0")/../.."
PLUGIN_DIR=$PWD
P=/opt/Paseo/resources/bin/paseo
NODE=(env ELECTRON_RUN_AS_NODE=1 /opt/Paseo/Paseo.bin)
TSX=("${NODE[@]}" "$PLUGIN_DIR/node_modules/tsx/dist/cli.mjs")
HOMES=$PLUGIN_DIR/.test-homes
C=$HOMES/owner-c
A=$HOMES/member-a
LOGDIR=$PLUGIN_DIR/test/e2e/logs
SCRATCH=$PLUGIN_DIR/test/e2e/scratch
mkdir -p "$LOGDIR" "$SCRATCH/lane-work"
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

cleanup() {
  local code=$?
  echo "== cleanup"
  if [ -f "$LOGDIR/agents.txt" ]; then
    while read -r id; do
      [ -n "$id" ] || continue
      out=$(pa "$C" archive --force "$id" --json 2>&1 || true)
      case "$out" in
        *AGENT_ALREADY_ARCHIVED*) echo "agent ${id:0:8} already archived (archiving a parent archives its fork)";;
        *archivedAt*) echo "archived agent ${id:0:8}";;
        *) echo "WARNING: could not archive ${id:0:8}";;
      esac
    done < "$LOGDIR/agents.txt"
  fi
  for h in "$A" "$C"; do
    pa "$h" plugin logs rooms > "$LOGDIR/plugin-$(basename "$h").log" 2>&1 || true
    pa "$h" plugin remove rooms >/dev/null 2>&1 || true
    pa "$h" daemon stop >/dev/null 2>&1 || true
  done
  for h in "$A" "$C"; do cp "$h/daemon.log" "$LOGDIR/daemon-$(basename "$h").log" 2>/dev/null || true; done
  if [ -n "${E2E_SECRETS_FILE:-}" ] && [ -f "$E2E_SECRETS_FILE" ]; then
    "${TSX[@]}" "$PLUGIN_DIR/test/e2e/secret-scan.ts" "$E2E_SECRETS_FILE" "$HOMES" "$LOGDIR" | tee "$LOGDIR/secret-scan.json" || code=1
    rm -f "$E2E_SECRETS_FILE"
  fi
  if [ -z "${KEEP_HOMES:-}" ]; then rm -rf "$HOMES"; echo "deleted test homes"; fi
  pgrep -f "$HOMES" >/dev/null && echo "WARNING: processes still reference test homes" || echo "no test processes left"
  exit $code
}
trap cleanup EXIT

rm -rf "$HOMES"; mkdir -p "$HOMES"; chmod 700 "$HOMES"
rm -f "$LOGDIR"/*.log "$LOGDIR/agents.txt"
write_config "$C" 6891
write_config "$A" 6892
for h in "$C" "$A"; do pa "$h" daemon start --timeout 120 | tail -1; done
for h in "$C" "$A"; do pa "$h" plugin install "$PLUGIN_DIR" --json | tail -3; done
for h in "$C" "$A"; do pa "$h" plugin ls; done

echo "== throwaway parent agent on C"
# Positive control for the MCP guard: Paseo injects its agent MCP into the parent's provider process.
"${TSX[@]}" "$PLUGIN_DIR/test/e2e/proc-sampler.ts" "$LOGDIR/parent-procs.json" 200 "paseoAgentMcpOnC=127.0.0.1:6891/mcp/agents" &
SAMPLER=$!
(cd "$SCRATCH/lane-work" && PASEO_HOME=$C "$P" run --home "$C" --provider claude --model claude-haiku-4-5 --mode default \
   --title "rooms e2e parent" --cwd "$SCRATCH/lane-work" --wait-timeout 180s --json \
   "Reply with the word OK and nothing else." < /dev/null) > "$LOGDIR/parent-create.json"
kill $SAMPLER 2>/dev/null || true; wait $SAMPLER 2>/dev/null || true
echo "parent provider processes with Paseo MCP (max concurrent): $(cat "$LOGDIR/parent-procs.json")"
PARENT=$("${NODE[@]}" -e 'const t=require("fs").readFileSync(process.argv[1],"utf8");console.log(JSON.parse(t.slice(t.indexOf("{"))).agentId)' "$LOGDIR/parent-create.json")
echo "$PARENT" >> "$LOGDIR/agents.txt"
echo "parent ${PARENT:0:8}"

export E2E_SECRETS_FILE=$HOMES/.secrets-for-scan
E2E_PARENT_PROCS=$LOGDIR/parent-procs.json E2E_OWNER_HOME=$C E2E_MEMBER_HOME=$A E2E_PARENT=$PARENT E2E_AGENTS_FILE=$LOGDIR/agents.txt \
  "${TSX[@]}" "$PLUGIN_DIR/test/e2e/e2e.ts" 2>&1 | tee "$LOGDIR/e2e.log"
test "${PIPESTATUS[0]}" -eq 0
