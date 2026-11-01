// Realistic daemon objects for leakage tests. Every value that must not reach a room member carries a
// marker from LEAK_MARKERS. Shapes follow @getpaseo/protocol 0.13.2 (AgentSnapshotPayloadSchema,
// WorkspaceDescriptorPayloadSchema, ProjectPlacementPayloadSchema) plus one unknown future field.
export const LANE = { laneId: "lane_0123456789abcdef", laneServerId: `lane_${"L".repeat(32)}`, agentId: "a1b2c3d4-1111-4111-8111-abcdefabcdef", workspaceId: "wks_lane" };
export const OTHER_AGENT = "22222222-2222-4222-8222-222222222222";

/** Strings that must never appear in anything sent to a viewer. */
export const LEAK_MARKERS = [
  "/home/owner",
  "SECRET",
  "PARENT-AGENT-ID",
  "OWNER-LABEL",
  "srv_owner",
  "5173",
  "github.com",
  "proxy.example",
  "term-",
  "FUTURE",
];

export function leaks(value: unknown): string[] {
  const text = JSON.stringify(value);
  return LEAK_MARKERS.filter((m) => text.includes(m));
}

export function agentSnapshot(over: Record<string, unknown> = {}): Record<string, any> {
  return {
    id: LANE.agentId,
    provider: "claude",
    cwd: "/home/owner/secret-project",
    workspaceId: LANE.workspaceId,
    model: "claude-haiku-4-5",
    features: [{ type: "toggle", id: "fast", label: "Fast", value: false }],
    thinkingOptionId: null,
    effectiveThinkingOptionId: null,
    createdAt: "2026-10-28T10:00:00.000Z",
    updatedAt: "2026-10-28T10:05:00.000Z",
    lastUserMessageAt: "2026-10-28T10:04:00.000Z",
    status: "idle",
    activeTurn: null,
    capabilities: { supportsStreaming: true, supportsSessionPersistence: true, supportsDynamicModes: true, supportsMcpServers: true, supportsReasoningStream: true, supportsToolInvocations: true },
    currentModeId: "default",
    availableModes: [{ id: "default", label: "Default" }],
    pendingPermissions: [],
    persistence: {
      provider: "claude",
      sessionId: "sess-SECRET-1",
      nativeHandle: "native-SECRET",
      metadata: {
        systemPrompt: "SYSTEM-PROMPT-SECRET",
        daemonAppendSystemPrompt: "DAEMON-WIDE-PROMPT-SECRET",
        toolPolicy: { preapproved: [{ kind: "mcp", server: "paseo", tool: "SECRET-TOOL" }] },
        cwd: "/home/owner/secret-project",
      },
    },
    runtimeInfo: { provider: "claude", sessionId: "sess-SECRET-1", model: "claude-haiku-4-5", modeId: "default", extra: { apiKeyHint: "EXTRA-SECRET" } },
    lastUsage: { inputTokens: 10, outputTokens: 5 },
    lastError: "ENOENT: /home/owner/secret-project/.env SECRET",
    title: "Room fork",
    labels: { "rooms.lane": LANE.laneId, "rooms.room": "room_0123456789abcdef", "paseo.parent-agent-id": "PARENT-AGENT-ID", "owner.tag": "OWNER-LABEL" },
    requiresAttention: false,
    attentionReason: null,
    attentionTimestamp: null,
    archivedAt: null,
    providerUnavailable: false,
    internal: false,
    futureField: "FUTURE-FIELD-VALUE",
    ...over,
  };
}

export function projectPlacement(): Record<string, any> {
  return {
    projectKey: "host:srv_owner_SECRET:/home/owner/secret-project",
    projectName: "secret-project",
    workspaceName: "main",
    checkout: {
      cwd: "/home/owner/secret-project",
      isGit: true,
      currentBranch: "main",
      remoteUrl: "git@github.com:owner/REMOTE-SECRET.git",
      worktreeRoot: "/home/owner/secret-project",
      isPaseoOwnedWorktree: false,
      mainRepoRoot: null,
      futureCheckoutField: "FUTURE-CHECKOUT",
    },
  };
}

export function workspaceDescriptor(over: Record<string, unknown> = {}): Record<string, any> {
  return {
    id: LANE.workspaceId,
    projectId: "prj_opaque",
    projectDisplayName: "secret-project",
    projectCustomName: null,
    projectCustomIconRevision: "icon-SECRET",
    projectRootPath: "/home/owner/secret-project",
    workspaceDirectory: "/home/owner/secret-project",
    setupStatus: "completed",
    projectKind: "git",
    workspaceKind: "local_checkout",
    name: "main",
    title: null,
    pinnedAt: "2026-10-01T00:00:00.000Z",
    labels: ["OWNER-LABEL"],
    internal: false,
    background: false,
    archivingAt: null,
    // Aggregated over every agent in the workspace: the PARENT is running.
    status: "running",
    statusEnteredAt: "2026-10-28T11:59:00.000Z",
    activityAt: "2026-10-28T11:59:30.000Z",
    createdAt: "2026-10-01T00:00:00.000Z",
    lastUserMessageAt: "2026-10-28T11:59:00.000Z",
    diffStat: { additions: 120, deletions: 7 },
    scripts: [
      {
        scriptName: "web",
        type: "service",
        hostname: "localhost",
        port: 5173,
        localProxyUrl: "http://127.0.0.1:5173",
        publicProxyUrl: "https://SECRET.proxy.example",
        proxyUrl: "https://SECRET.proxy.example",
        lifecycle: "running",
        health: "healthy",
        exitCode: null,
        terminalId: "term-SECRET",
      },
    ],
    gitRuntime: { currentBranch: "main", remoteUrl: "https://github.com/owner/REMOTE-SECRET", isPaseoOwnedWorktree: false, isDirty: true, aheadBehind: { ahead: 3, behind: 0 }, aheadOfOrigin: 3, behindOfOrigin: 0 },
    githubRuntime: {
      featuresEnabled: true,
      pullRequest: { number: 42, url: "https://github.com/owner/REMOTE-SECRET/pull/42", title: "PR-TITLE-SECRET", state: "open", baseRefName: "main", headRefName: "feature", isMerged: false, repoOwner: "owner", repoName: "REMOTE-SECRET" },
      error: null,
      refreshedAt: null,
    },
    forge: "github",
    project: projectPlacement(),
    syncSeq: 9876,
    futureWorkspaceField: "FUTURE-WS",
    ...over,
  };
}

// ------------------------------------------------------------------------------ M1 (v1) data tree

/** Ids and values of the fixture v1 tree (shapes from the M1 build, tag m1-baseline). */
export const V1 = {
  roomId: "room_00112233445566aa",
  shareLane: "lane_aaaaaaaaaaaaaaaa",
  forkLane: "lane_bbbbbbbbbbbbbbbb",
  joinedLane: "lane_cccccccccccccccc",
  shareAgent: "11111111-aaaa-4aaa-8aaa-111111111111",
  forkAgent: "22222222-bbbb-4bbb-8bbb-222222222222",
  registrationId: "reg-v1-joined",
  /** Stand-ins for plaintext v1 secrets (the archive keeps them until the user deletes them). */
  secret: "V1-FIXTURE-SECRET-not-a-real-key",
};

/**
 * Writes the M1 layout under `dataDir` (plugin-data/rooms), owner-only: gateway/state.json (v 1,
 * a share lane and a fork lane, lane keys), gateway/host-key.json, gateway/rooms/<id>/events.jsonl,
 * member/device.json, member/rooms.json (one joined lane with its registration), and limits.json.
 */
export function writeV1Tree(dataDir: string, fs: typeof import("node:fs"), path: typeof import("node:path")): void {
  const dir = (p: string) => fs.mkdirSync(p, { recursive: true, mode: 0o700 });
  const file = (p: string, v: unknown) => fs.writeFileSync(p, typeof v === "string" ? v : JSON.stringify(v, null, 2), { mode: 0o600 });
  const gw = path.join(dataDir, "gateway");
  const mem = path.join(dataDir, "member");
  dir(path.join(gw, "rooms", V1.roomId));
  dir(mem);
  const relay = { endpoint: "relay.paseo.sh:443", useTls: true };
  const lane = (id: string, agentId: string, origin: unknown, label: string) => ({ v: 1, id, roomId: V1.roomId, label, origin, agentId, workspaceId: "wks_1", serverId: `lane_${"S".repeat(32)}`, publicKeyB64: "A".repeat(44), relay, createdAt: "2026-10-28T00:00:00Z", status: "open" });
  file(path.join(gw, "state.json"), {
    v: 1,
    rooms: [{ v: 1, id: V1.roomId, name: "Old room", createdAt: "2026-10-28T00:00:00Z", status: "active" }],
    lanes: [lane(V1.shareLane, V1.shareAgent, { kind: "share", agentId: V1.shareAgent }, "Live"), lane(V1.forkLane, V1.forkAgent, { kind: "fork", parentAgentId: V1.shareAgent, contextItems: 2, contextChars: 40 }, "Fork")],
    laneKeys: { [V1.shareLane]: { publicKeyB64: "A".repeat(44), secretKeyB64: V1.secret } },
    members: [],
    invites: [],
    grants: [],
    revokedGrantIds: [],
  });
  file(path.join(gw, "host-key.json"), { v: 1, alg: "ed25519", keyId: "0123456789abcdef", publicKey: "B".repeat(43), privateKeyPkcs8: V1.secret, createdAt: "2026-10-28T00:00:00Z" });
  file(path.join(gw, "rooms", V1.roomId, "events.jsonl"), `${JSON.stringify({ v: 1, roomId: V1.roomId, seq: 0, type: "room.created" })}\n`);
  file(path.join(mem, "device.json"), { v: 1, alg: "ed25519", keyId: "fedcba9876543210", publicKey: "C".repeat(43), privateKeyPkcs8: V1.secret, createdAt: "2026-10-28T00:00:00Z" });
  file(path.join(mem, "rooms.json"), { v: 1, rooms: [{ v: 1, roomId: "room_99887766554433ff", roomName: "Joined", laneId: V1.joinedLane, laneLabel: "Live", memberId: "mem_0011223344556677", status: "active", registrationId: V1.registrationId }] });
  file(path.join(dataDir, "limits.json"), "{}");
  for (const p of [path.dirname(dataDir), dataDir]) fs.chmodSync(p, 0o700);
}
