#!/usr/bin/env bash
# Start two disposable Paseo daemons with the rooms plugin and a demo room, for a manual UI check
# in the real Paseo app. Never touches ~/.paseo or the main daemon: every CLI call passes --home
# and PASEO_HOME points under plugin/ui-check/.homes.
#
#   demo-owner   127.0.0.1:6910   gateway + embedded host; owns the demo room
#   demo-member  127.0.0.1:6911   member; the lane shows up here as a routed host
#
# Creates one throwaway parent agent (Claude Haiku, trivial prompt) plus the room's fork agent.
# Run ./down.sh to archive the agents, stop both daemons and delete .homes.
set -euo pipefail
UI_DIR=$(cd "$(dirname "$0")" && pwd)
PLUGIN_DIR=$(dirname "$UI_DIR")
P=/opt/Paseo/resources/bin/paseo
NODE=(env ELECTRON_RUN_AS_NODE=1 /opt/Paseo/Paseo.bin)
TSX=("${NODE[@]}" "$PLUGIN_DIR/node_modules/tsx/dist/cli.mjs")
HOMES=$UI_DIR/.homes
OWNER=$HOMES/demo-owner
MEMBER=$HOMES/demo-member
OWNER_PORT=6910
MEMBER_PORT=6911
AGENTS=$HOMES/agents.txt
# Speech off before the first start (no model download).
export PASEO_DICTATION_ENABLED=false PASEO_VOICE_MODE_ENABLED=false

pa() { local home=$1; shift; PASEO_HOME=$home "$P" "$@" --home "$home" < /dev/null; }

port_busy() { (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; }

write_config() {
  local home=$1 port=$2
  mkdir -p "$home"; chmod 700 "$HOMES" "$home"
  # Written BEFORE the first start: loopback listen, relay registration off, plugins on, speech off.
  cat > "$home/config.json" <<JSON
{
  "daemon": { "listen": "127.0.0.1:$port", "relay": { "enabled": false } },
  "pluginsEnabled": true,
  "features": { "dictation": { "enabled": false }, "voiceMode": { "enabled": false } }
}
JSON
  chmod 600 "$home/config.json"
}

fail() {
  echo
  echo "up.sh failed: $*" >&2
  echo "Daemon logs: $OWNER/daemon.log, $MEMBER/daemon.log. Plugin logs:" >&2
  echo "  PASEO_HOME=$OWNER $P plugin logs rooms --home $OWNER" >&2
  echo "Run $UI_DIR/down.sh to clean up." >&2
  exit 1
}
trap 'fail "command on line $LINENO exited with status $?"' ERR

# ------------------------------------------------------------------ preflight
[ -x "$P" ] || { echo "Paseo CLI not found at $P" >&2; exit 1; }
[ -d "$PLUGIN_DIR/node_modules" ] || { echo "Run 'npm install' in $PLUGIN_DIR first." >&2; exit 1; }
if [ -e "$HOMES" ]; then
  echo "$HOMES already exists. Run $UI_DIR/down.sh first." >&2; exit 1
fi
for port in $OWNER_PORT $MEMBER_PORT; do
  if port_busy "$port"; then echo "Port $port is in use. Free it or run down.sh first." >&2; exit 1; fi
done

echo "== 1/5 writing configs under $HOMES"
mkdir -p "$HOMES/work"; chmod 700 "$HOMES" "$HOMES/work"
write_config "$OWNER" $OWNER_PORT
write_config "$MEMBER" $MEMBER_PORT
: > "$AGENTS"; chmod 600 "$AGENTS"

echo "== 2/5 starting demo-owner (:$OWNER_PORT) and demo-member (:$MEMBER_PORT)"
for h in "$OWNER" "$MEMBER"; do pa "$h" daemon start --timeout 120 | tail -1; done

echo "== 3/5 installing the plugin on both daemons"
for h in "$OWNER" "$MEMBER"; do pa "$h" plugin install "$PLUGIN_DIR" --json > /dev/null; done
for h in "$OWNER" "$MEMBER"; do
  for _ in $(seq 1 60); do
    pa "$h" plugin ls --json 2>/dev/null | grep -q '"running"' && break
    sleep 1
  done
  pa "$h" plugin ls --json | grep -q '"running"' || fail "plugin not running on $(basename "$h")"
  echo "   rooms plugin running on $(basename "$h")"
done

echo "== 4/5 throwaway parent agent on demo-owner (Claude Haiku, one short turn)"
PARENT_JSON=$(cd "$HOMES/work" && PASEO_HOME=$OWNER "$P" run --home "$OWNER" --provider claude --model claude-haiku-4-5 --mode default \
  --title "UI check parent" --cwd "$HOMES/work" --wait-timeout 180s --json \
  "Reply with the word OK and nothing else." < /dev/null)
PARENT=$("${NODE[@]}" -e 'const t=process.argv[1];console.log(JSON.parse(t.slice(t.indexOf("{"))).agentId)' "$PARENT_JSON")
[ -n "$PARENT" ] && [ "$PARENT" != "undefined" ] || fail "could not read the parent agent id"
echo "$PARENT" >> "$AGENTS"
echo "   parent agent ${PARENT:0:8}"

echo "== 5/5 demo room: fork lane, invite, enrollment of demo-member"
UI_OWNER_HOME=$OWNER UI_MEMBER_HOME=$MEMBER UI_PARENT=$PARENT UI_AGENTS_FILE=$AGENTS \
  "${TSX[@]}" "$UI_DIR/demo-setup.ts"
trap - ERR

cat <<EOF

==================================================================================
 Ready. Two test daemons are running on loopback with the rooms plugin installed.

 Add both to your Paseo app (Settings -> Add host -> Direct connection):
   demo-owner   Host 127.0.0.1   Port $OWNER_PORT   Use SSL: off
   demo-member  Host 127.0.0.1   Port $MEMBER_PORT   Use SSL: off
 No password or other credential is needed: these daemons have no password and
 listen on 127.0.0.1 only (same as a default local daemon). Relay pairing is off,
 so do not use "Pair device"; use Direct connection.

 What to look at
   demo-owner : sidebar "Rooms" -> Rooms screen with "UI check room"
                (Fork lane, Online, 1 of 1 connected, member demo-member).
                Agent "UI check parent": Ctrl+K -> "Open room…" (opens the screen;
                do NOT press "Create room" unless you accept one more Haiku turn).
                The fork agent (lane agent): composer pill "● Room · 1 connected".
   demo-member: sidebar "Rooms" -> "Rooms you joined" shows the room, Connected.
                Host list: routed host "UI check room · Fork lane" under demo-member
                with exactly one agent (the fork), read-only.

 Checklist (each on a wide desktop window AND a narrow/compact window,
 in a light AND a dark theme: Settings -> Appearance)
   [ ] Rooms sidebar row renders with icon and label; highlights when active
   [ ] Rooms screen: headings, cards, badges, buttons readable; no black-on-dark text
   [ ] Open room screen: input placeholders, segmented Fork/Share options, hints
   [ ] Composer pill on the lane agent; pressing it opens Rooms
   [ ] "Create invite" shows the code box; "Hide" clears it (code is a real secret)
   [ ] Routed lane host on demo-member: one agent, timeline renders
   [ ] Disallowed actions on the routed host (send a message, archive, terminals,
       new agent) stay visible and fail with an error ("Room is not authorized…");
       note how each error is shown
   [ ] Errors from plugin buttons appear as toasts and are readable
 Write findings in $UI_DIR/ui-notes.md.

 When done: remove the two hosts from the app (Settings -> host -> Remove host),
 then run $UI_DIR/down.sh
==================================================================================
EOF
