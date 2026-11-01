// Policy constants shared by the daemon and the app. Plain values only.

/**
 * Providers whose room agents are VERIFIED to respect the MCP guard (C-iso3, protocol review P-28).
 * Fork lanes are refused for every other provider id, including custom ids and profiles that wrap
 * a verified provider.
 *
 * Identity v2 creates no fork lanes (I-15): the list now gates only agents created with the
 * PASEO_ROOMS_LANE env (agent-guard.ts). How a provider got on this list: the M1 e2e (removed at the
 * cut-over; evidence in test/m1-evidence/) ran with that provider as the parent and had to show
 * (1) the fork's stored config holds only the inert "paseo" MCP server and no preapprovals, (2) during the fork's live turn no process carries the fork's
 * `/mcp/agents?callerAgentId=` URL while the inert server runs, (3) the positive control (the
 * parent's provider process carries its MCP URL) holds. The provider must also take MCP servers only
 * from the agent config (not built in), so the shadow can take effect.
 *
 * "claude": verified by the M1 e2e on Paseo 0.13.2 (M1-RESULTS.md section 3, test/m1-evidence/).
 * Not verified: "codex" (MCP config path not exercised), and "opencode"/"omp" receive Paseo tools
 * natively through the launch context, which no hook can remove.
 */
export const FORK_VERIFIED_PROVIDERS: readonly string[] = ["claude"];

export function providerId(provider: string): string {
  return String(provider).split("/")[0];
}

export function isForkVerifiedProvider(provider: string): boolean {
  return FORK_VERIFIED_PROVIDERS.includes(providerId(provider));
}
