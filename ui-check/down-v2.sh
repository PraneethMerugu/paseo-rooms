#!/usr/bin/env bash
# Tear down the v2 UI check: archive the lane agent, stop the three v2 test daemons and the fake relay,
# delete .test-homes. Safe to run repeatedly and after a failed up-v2.sh. Never touches ~/.paseo or the
# main daemon (6767).
set -uo pipefail
UI_DIR=$(cd "$(dirname "$0")" && pwd)
PLUGIN_DIR=$(dirname "$UI_DIR")
source "$PLUGIN_DIR/tools/paseo-env.sh"   # sets P (paseo CLI) and NODE; override with PASEO_BIN / PASEO_NODE
HOMES=$UI_DIR/.test-homes
OWNER=$HOMES/v2-owner
MEMBER=$HOMES/v2-member
MEMBER2=$HOMES/v2-member2
AGENTS=$HOMES/agents.txt

MAIN_HOME=$(realpath -m "$HOME/.paseo")
case "$(realpath -m "$HOMES")" in
  "$MAIN_HOME"|"$MAIN_HOME"/*) echo "Refusing: $HOMES resolves to ~/.paseo" >&2; exit 2 ;;
esac
unset PASEO_HOME

pa() { local home=$1; shift; PASEO_HOME=$home timeout 60 "$P" "$@" --home "$home" < /dev/null; }
running() { [ -f "$1/paseo.pid" ] && pa "$1" daemon status --json 2>/dev/null | grep -q '"running"'; }
port_open() { (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; }

if [ ! -e "$HOMES" ]; then
  echo "Nothing to do: $HOMES does not exist."
else
  echo "== archiving the lane agent"
  if [ -s "$AGENTS" ] && running "$OWNER"; then
    while read -r id; do
      [ -n "$id" ] || continue
      out=$(pa "$OWNER" archive --force "$id" --json 2>&1 || true)
      case "$out" in
        *archivedAt*|*AGENT_ALREADY_ARCHIVED*) echo "   archived agent ${id:0:8}";;
        *) echo "   WARNING: could not archive ${id:0:8}; it is deleted with the home";;
      esac
    done < "$AGENTS"
  else
    echo "   none recorded, or v2-owner not running (deleted with the home)"
  fi

  echo "== stopping daemons"
  for h in "$MEMBER2" "$MEMBER" "$OWNER"; do
    [ -d "$h" ] || continue
    pa "$h" daemon stop > /dev/null 2>&1; echo "   $(basename "$h") stopped (or was not running)"
  done

  if [ -f "$HOMES/fake-relay.pid" ]; then
    pid=$(cat "$HOMES/fake-relay.pid")
    if [ -n "$pid" ] && ps -p "$pid" -o args= 2>/dev/null | grep -q 'fake-relay-v2.ts'; then
      kill -TERM "$pid" 2>/dev/null; echo "   fake relay stopped"
    fi
  fi

  # Leftover processes started from the v2 homes or the fake relay. Excludes this script and its caller.
  leftovers() { { pgrep -f "$HOMES/"; pgrep -f "$UI_DIR/fake-relay-v2.ts"; } | grep -vx -e "$$" -e "$PPID" || true; }
  for _ in 1 2 3 4 5; do [ -z "$(leftovers)" ] && break; sleep 1; done
  if [ -n "$(leftovers)" ]; then
    echo "   terminating leftover processes"
    leftovers | xargs -r kill -TERM 2>/dev/null; sleep 2
    leftovers | xargs -r kill -KILL 2>/dev/null
  fi

  rm -rf "$HOMES"
  echo "== deleted $HOMES"
  [ -n "$(leftovers)" ] && echo "WARNING: processes still reference $HOMES" || echo "no test processes left"
fi

busy=""
for port in $(seq 6912 6919); do port_open "$port" && busy="$busy $port"; done
if [ -n "$busy" ]; then echo "WARNING: ports still open:$busy"; else echo "ports 6912-6919 free"; fi
echo "Remember to remove the v2-owner, v2-member and v2-member2 hosts (and any routed lane host) from the Paseo app."
