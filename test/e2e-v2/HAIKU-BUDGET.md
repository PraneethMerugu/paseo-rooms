# Haiku call budget

Approved by the user 2026-10-29: 20 small Claude Haiku calls on test daemons, then ask again.

| Date | Run | Calls | Running total |
|---|---|---|---|
| 2026-10-29 | M1 e2e after I-1, I-2, I-4, I-16 (pass) | up to 2 (parent prompt; fork process started, counted conservatively) | 2 |
| 2026-10-29 | M1 e2e after I-7, I-8 (pass) | up to 2 | 4 |
| 2026-10-29 | M1 e2e after I-9 (pass) | up to 2 | 6 |
| 2026-10-30 | e2e-v2 (offline x2 by agent, live x1): lane agents created without a prompt, no turns | 0 | 6 |
| 2026-10-30 | M1 e2e after I-10 (pass) | up to 2 | 8 |
| 2026-11-01 | I-15 cut-over: the M1 e2e (`test/e2e/`) is removed; its checks that apply to share-live lanes are ported into `test/e2e-v2` with agents created without a prompt. The fork-only checks (parent prompt, fork turn, MCP positive control) were dropped because v2 has no fork lanes. Offline e2e-v2 runs by the agent: no agent prompted | 0 | 8 |
