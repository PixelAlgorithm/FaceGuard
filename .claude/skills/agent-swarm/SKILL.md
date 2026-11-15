---
name: agent-swarm
description: Run many subagents in parallel on the HID kiosk project without them clobbering each other or the live demo. Use when the user asks to "use a lot of subagents", "swarm", "parallelise", or to fix several problems at once across edge/, kiosk/, cloud/, depth/, eval/, config/ or docs/. Covers splitting work by owner directory, the brief template, single-writer file rules, demo-freeze rules, the verifier gate, and how to merge results.
---

# Agent swarm (HID kiosk)

A swarm is N subagents launched **in one message** (parallel), each with a narrow scope, then one
verifier pass over everything they changed. The lead (main session) runs the swarm; a subagent only
spawns for work inside its own directory or for read-only checks.

## 1. Rules that prevent damage (learned on 14 Nov)

1. **One writer per path.** Before spawning, assign every file to at most one agent. Ownership:

   | Path | Owner agent |
   |---|---|
   | `edge/` (except below) | `edge-ml` |
   | `edge/policy/**`, `edge/offline/**`, `config/thresholds.yaml`, `config/schedule*.json` | `policy-engine` |
   | `kiosk/` | `kiosk-frontend` |
   | `cloud/` | `cloud-aws` |
   | `depth/` | `depth-iphone` |
   | `eval/` | `eval-metrics` |
   | `docs/`, `CLAUDE.md`, `SKILLS.md`, slides | lead (or one named docs agent) |

   Anyone else sends the owner the exact change + the user's exact words; the owner applies it.
   Two agents editing `config/thresholds.yaml` at once lost edits during a staged swap.
2. **Check before editing a shared file:** `stat -f '%Sm' <file>`; modified in the last ~10 min by
   someone else -> do not edit, message the owner.
3. **Demo freeze:** when the lead declares a freeze, swarm agents are read-only for `edge/`,
   `config/`, `kiosk/` (Vite HMR reloads the live kiosk). Fixes become patches in the report.
4. **Never touch the live edge:** no restart/kill of `:8000`/`:8001`; read-only `GET /v1/health`,
   `/v1/mode`, `/v1/metrics` only. Endpoint tests run on a scratch port with its own `EDGE_DATA_DIR`
   (see `.claude/agents/verifier.md`). Only the lead restarts the edge.
5. **Secrets:** never print or read `.env` values (tokens, keys); pass them through scripts that use
   them without echoing (e.g. `depth/ios/pair.sh`). Tests use dummy values.
6. **Config is the switchboard:** thresholds live only in `config/thresholds.yaml`; turning a check
   "off" by raising its bars to ~1.0 is still removing a check. Do not remove or neuter a check
   (moire, mask M2, device, flash, depth, Rekognition, random challenge) without the user's explicit
   words; quote them in the report.
7. **Honesty:** no number goes on a slide or into a report until the verifier re-measured it.

## 2. Planning a swarm (lead)

1. List the problems; for each: owner, files, done-criterion (test / measurement / screenshot).
2. Merge problems that touch the same file into one agent's brief.
3. Spawn all agents in **one message**. Add `isolation: "worktree"` for risky multi-file refactors.
4. Always add one read-only `verifier` after the fixers, and a `spec-auditor` when docs/config/code
   may have drifted.
5. Typical swarm (5-8 agents): fixers per owner dir + verifier + spec-auditor + a read-only
   demo-readiness checker (`GET` health/mode/metrics, kiosk on :5173, LAN :8001, schedule bundle,
   template count, depth link).

## 3. Brief template (each agent knows only what you write)

```
Goal: <one sentence>.  Owner scope: <dir/files you may edit>; everything else read-only.
Context: <what is already known / ruled out, with file:line evidence>.
User's exact words: "<quote>"  (if the change came from the user)
Constraints: do not restart the live edge; no secrets; check mtime before editing shared files;
  demo freeze = <on/off>.
Done when: <tests to run + expected result / measurement / screenshot>.
Report: root cause, files changed (absolute paths), verification output, open risks. No .md reports.
```

## 4. Merging

- Collect each report; conflicts -> the owner decides. Re-run `edge/.venv/bin/python -m pytest -q
  edge/tests edge/policy/tests depth/tests` and `npm run build` in `kiosk/` once, after all fixers.
- A config change needs an edge restart by the lead; list pre-restart risks (e.g. Rekognition on with
  an empty collection -> NOT_ENROLLED denials; cloud > `latency_budget_ms.rekognition_timeout` ->
  attempts relabelled OFFLINE).
- Update `CLAUDE.md` section 10 checklist only after the verifier returns PASS.
