#!/usr/bin/env bash
# Tear down the UI check: archive the demo agents, stop both test daemons, delete .homes.
# Safe to run repeatedly and after a failed up.sh. Never touches ~/.paseo or the main daemon.
set -uo pipefail
UI_DIR=$(cd "$(dirname "$0")" && pwd)
P=/opt/Paseo/resources/bin/paseo
HOMES=$UI_DIR/.homes
OWNER=$HOMES/demo-owner
MEMBER=$HOMES/demo-member
AGENTS=$HOMES/agents.txt

pa() { local home=$1; shift; PASEO_HOME=$home timeout 60 "$P" "$@" --home "$home" < /dev/null; }
running() { [ -f "$1/paseo.pid" ] && pa "$1" daemon status --json 2>/dev/null | grep -q '"running"'; }

if [ ! -e "$HOMES" ]; then
  echo "Nothing to do: $HOMES does not exist."
  exit 0
fi

echo "== archiving demo agents"
if [ -s "$AGENTS" ] && running "$OWNER"; then
  while read -r id; do
    [ -n "$id" ] || continue
    out=$(pa "$OWNER" archive --force "$id" --json 2>&1 || true)
    case "$out" in
      *AGENT_ALREADY_ARCHIVED*) echo "   agent ${id:0:8} already archived (archiving the parent archives its fork)";;
      *archivedAt*) echo "   archived agent ${id:0:8}";;
      *) echo "   WARNING: could not archive ${id:0:8}; it is deleted with the home";;
    esac
  done < "$AGENTS"
else
  echo "   none recorded, or demo-owner not running (agents are deleted with the home)"
fi

echo "== stopping daemons"
for h in "$MEMBER" "$OWNER"; do
  [ -d "$h" ] || continue
  pa "$h" daemon stop > /dev/null 2>&1 ; echo "   $(basename "$h") stopped (or was not running)"
done

# Leftover processes started from the test homes (agents, plugin subprocesses). Excludes this
# script and its caller, whose command lines may mention the path.
leftovers() { pgrep -f "$HOMES/" | grep -vx -e "$$" -e "$PPID" || true; }
for _ in 1 2 3 4 5; do [ -z "$(leftovers)" ] && break; sleep 1; done
if [ -n "$(leftovers)" ]; then
  echo "   terminating leftover processes started from $HOMES"
  leftovers | xargs -r kill -TERM 2>/dev/null; sleep 2
  leftovers | xargs -r kill -KILL 2>/dev/null
fi

rm -rf "$HOMES"
echo "== deleted $HOMES"
[ -n "$(leftovers)" ] && echo "WARNING: processes still reference $HOMES" || echo "no test processes left"
echo "Remember to remove the demo-owner and demo-member hosts from the Paseo app if you added them."
