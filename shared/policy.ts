// Policy constants shared by the daemon and the app. Plain values only.

/**
 * Providers whose room agents are VERIFIED to respect the MCP guard (C-iso3, protocol review P-28).
 * Fork lanes are refused for every other provider id, including custom ids and profiles that wrap
 * a verified provider.
 *
 * How a provider gets on this list: run test/e2e/run.sh with that provider as the parent, and the
 * e2e must show (1) the fork's stored config holds only the inert "paseo" MCP server and no
 * preapprovals, (2) during the fork's live turn no process carries the fork's
 * `/mcp/agents?callerAgentId=` URL while the inert server runs, (3) the positive control (the
 * parent's provider process carries its MCP URL) holds. The provider must also take MCP servers only
 * from the agent config (not built in), so the shadow can take effect.
 *
 * "claude": verified by the M1 e2e on Paseo 0.13.2 (M1-RESULTS.md section 3, test/e2e/logs).
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
