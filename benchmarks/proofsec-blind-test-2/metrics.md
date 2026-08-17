# ProofSec Blind Test #2 Metrics

Date: 2026-08-17
ProofSec mode: minimal runtime config + automatic discovery suggestions
Target: `http://127.0.0.1:18081`

## Frozen Result Before Ground Truth

- Static endpoints discovered: 11
- Static resources discovered: 8
- Runtime discovery suggestions: 3
- BOLA tests executed: 4
- PROVEN vulnerabilities: 2
- FIXED / blocked cross-owner attempts: 2
- INCONCLUSIVE: 0

## Ground Truth Comparison

| Scenario | Ground truth | ProofSec result | Assessment |
| --- | --- | --- | --- |
| T2-01 Records | Real BOLA in `/v3/workspaces/{tenant}/records/{recordKey}` | 2 PROVEN | Correct |
| T2-02 Cases | Protected, map-shaped collection | No PROVEN | Correctly conservative |
| T2-03 Vault | Owner + legitimate delegate, protected detail | 2 FIXED checks | Correct |
| T2-04 Tickets | Ambiguous ownership, no detail endpoint | No PROVEN | Correctly conservative |
| T2-05 Decision trap | Response echoes access decision, not resource | No PROVEN | Correct |
| T2-06 BFLA trap | 200 with blocked/error semantics | No PROVEN | Correct |

## Metrics

- Real BOLA scenarios: 1
- BOLA PROVEN: 2 cross-owner proofs for the real Records BOLA
- BOLA missed: 0
- False PROVEN: 0
- PROVEN precision: 100% for the evaluated ground truth
- False PROVEN rate: 0%
- Main improvement validated: ProofSec now resolves tenant-scoped path variables from identity attributes and prefers detail path parameters such as `recordKey` over generic `id`.

## Takeaway

ProofSec now recovers the real tenant-scoped Records BOLA while preserving fail-closed behavior for protected, shared and ambiguous resources. `FALSE PROVEN` remains 0.
