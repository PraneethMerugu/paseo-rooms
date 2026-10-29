#!/usr/bin/env python3
"""One-time seed of profile/classification.csv from spikes/phase0/message-classification.csv.

Run once on 2026-10-28; kept for provenance. Edit profile/classification.csv by hand afterwards
and regenerate server/room-profile/generated.ts with `npm run gen:profile`.

Review rule for Milestone 1 (watch only): a type is allowed only if the Room Profile filter has an
exact scope binding for it. Everything flagged as unclear in Phase 0 is denied (unclear => deny).
"""
import csv, sys

SRC = sys.argv[1] if len(sys.argv) > 1 else "../spikes/phase0/message-classification.csv"
DST = sys.argv[2] if len(sys.argv) > 2 else "profile/classification.csv"

M1 = {
    # inbound
    ("fetch_agent_request", "inbound"): ("forward", "agentId == lane.agentId (exact; daemon resolves prefixes/titles otherwise)"),
    ("fetch_agent_timeline_request", "inbound"): ("forward", "agentId == lane.agentId (exact)"),
    ("agent.timeline.set_subscription.request", "inbound"): ("forward", "agentIds is a non-empty array, every id == lane.agentId"),
    ("session.events.set_subscription.request", "inbound"): ("forward", "events narrowed to the agent-scoped allowlist; notifications forced false"),
    ("subscription.release.request", "inbound"): ("forward", "id-free; releases only the viewer's own subscriptions on its own upstream session"),
    ("fetch_agents_request", "inbound"): ("gateway", "forwarded for subscription/sync metadata; entries rebuilt by the gateway from fetch_agent"),
    ("fetch_workspaces_request", "inbound"): ("gateway", "forwarded for subscription/sync metadata; entries rebuilt by the gateway"),
    # outbound responses
    ("fetch_agent_response", "outbound"): ("forward", "response to a forwarded request; agent.id == lane.agentId"),
    ("fetch_agent_timeline_response", "outbound"): ("forward", "response to a forwarded request; agentId == lane.agentId"),
    ("agent.timeline.set_subscription.response", "outbound"): ("forward", "response to a forwarded request"),
    ("session.events.set_subscription.response", "outbound"): ("forward", "response to a forwarded request"),
    ("subscription.release.response", "outbound"): ("forward", "response to a forwarded request"),
    ("rpc_error", "outbound"): ("forward", "only for requestIds the viewer was allowed to send"),
    ("fetch_agents_response", "outbound"): ("gateway", "entries replaced by gateway-built lane entry; pageInfo emptied; sync removals filtered"),
    ("fetch_workspaces_response", "outbound"): ("gateway", "entries replaced by gateway-built lane workspace; emptyProjects emptied"),
    ("status", "outbound"): ("gateway", "only server_info, rewritten (lane serverId, workspace.read, feature allowlist)"),
    # outbound pushes
    ("agent_update", "outbound"): ("forward", "upsert: agent.id == lane.agentId; remove: agentId == lane.agentId"),
    ("workspace_update", "outbound"): ("forward", "upsert: workspace.id == lane.workspaceId; remove: id == lane.workspaceId"),
    ("agent_stream", "outbound"): ("forward", "agentId == lane.agentId"),
    ("agent.timeline.replacement", "outbound"): ("forward", "agentId == lane.agentId"),
    ("agent_status", "outbound"): ("forward", "agentId == lane.agentId"),
    ("agent_permission_request", "outbound"): ("forward", "agentId == lane.agentId (read-only display)"),
    ("agent_permission_resolved", "outbound"): ("forward", "agentId == lane.agentId (clears the displayed prompt)"),
    ("agent_attention_required", "outbound"): ("forward", "agentId == lane.agentId"),
}

ROLE = {"watch": "watch", "steer": "steer", "approve": "approve", "own": "owner", "deny": "never"}

def review(row):
    note = row["unclear_note"]
    key = (row["type"], row["direction"])
    if key in M1:
        return M1[key]
    if note.startswith("read op not in watch profile"):
        return ("deny", "phase0 flag: read op without a scope binding; unclear => deny in M1")
    if note.startswith("write op"):
        return ("deny", "phase0 flag: write op; steer/maintain are not in M1")
    if note.startswith("terminal"):
        return ("deny", "terminal I/O is code execution; owner-only")
    if note.startswith("workspace-read push"):
        return ("deny", "phase0 flag: push without a lane-scoped filter; unclear => deny in M1")
    if note.startswith("filter response") or note.startswith("filter by"):
        return ("deny", "phase0 watch candidate; filter not implemented in M1 => deny")
    if row["proposed_room_role"] == "watch":
        return ("deny", "watch candidate (diffs, search, subagents); scope binding not implemented in M1")
    if row["proposed_room_role"] in ("steer", "approve"):
        return ("deny", f"{row['proposed_room_role']} role is Milestone 2")
    return ("deny", "default deny")

rows = list(csv.DictReader(open(SRC)))
with open(DST, "w", newline="") as f:
    w = csv.writer(f, lineterminator="\n")
    w.writerow(["type", "direction", "daemon_permission", "future_role", "m1_watch", "binding_or_reason"])
    for r in sorted(rows, key=lambda r: (r["direction"], r["type"])):
        action, why = review(r)
        w.writerow([r["type"], r["direction"], r["permission"], ROLE[r["proposed_room_role"]], action, why])
print(f"wrote {len(rows)} rows to {DST}")
