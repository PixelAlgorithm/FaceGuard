# SKILLS.md — Claude Code skills for this project

Which skills to use, when, and where they come from. Invoke a skill with the Skill tool
(or `/skill-name`). **Use the skill before starting the matching kind of work, not after.**

## 1. Project skills (load automatically from `.claude/skills/`)

| Skill | Use when | Owner agent(s) |
|---|---|---|
| `liveness-kiosk` | Implementing or changing ANY part of capture, quality gate, anti-spoofing (MiniFASNet, device, moiré, colour flash, injection), face matching (ArcFace / Rekognition), iPhone depth (DepthProbe), policy engine, SC1 campus schedule, SC2 offline mode, sync. Where it conflicts with `docs/DECISION_POLICY.md`, `config/thresholds.yaml` or `docs/API.md` v1.1, those win; where it conflicts with the built code, read the code (`reference.md` R1–R7 are pre-build sketches) | edge-ml, policy-engine, kiosk-frontend, depth-iphone, cloud-aws |
| `pad-evaluation` | Collecting test data, computing APCER/BPCER/FAR/FRR/latency, DET curves, dashboard data, demo script, any number that goes on a slide; scenario tests by `docs/POLICY_TEST_CASES.md` ID | eval-metrics, verifier |
| `agent-swarm` | Running many subagents in parallel ("use a lot of subagents"): one writer per path (owner map), brief template, demo-freeze + live-edge rules, verifier gate, merging | lead; any agent spawning helpers |

## 2. Engineering skills (user-level, vendored in `tooling/skills/`)

| Skill | Use when | Typical agent |
|---|---|---|
| `fastapi-patterns` | Writing FastAPI routes, Pydantic v2 schemas, dependencies, async handlers, tests with httpx | edge-ml, policy-engine, cloud-aws |
| `python-patterns` | Any Python module: typing, structure, idioms | all Python agents |
| `test-driven-development` | Policy engine, schedule evaluator, offline/sync logic — write tests from `docs/POLICY_TEST_CASES.md` first | policy-engine |
| `react-patterns` | React components, hooks, state, effects (camera, MediaPipe loop) | kiosk-frontend |
| `frontend-patterns` | App structure, state management, render performance | kiosk-frontend |
| `ui-styling` | Tailwind / shadcn UI for kiosk + admin dashboard, accessibility | kiosk-frontend |
| `deployment-patterns` | Docker, health checks, AWS deploy, rollback/teardown | cloud-aws |
| `systematic-debugging` | Any bug, failing test or unexpected model output — before proposing a fix | all |
| `verification-before-completion` | Before claiming any task is done — run the checks, show output | all (mandatory) |
| `subagent-driven-development` | Orchestrating the parallel workstreams in `docs/BUILD_PLAN.md` (Claude builds everything via subagents; the operator only does physical tasks) | main session |
| `slides` | Building the final pitch deck (HTML + Chart.js) | eval-metrics / main |

## 3. Built-in skills (always available in Claude Code, no install)

| Skill | Use when |
|---|---|
| `dataviz` | Before writing ANY chart: per-species APCER bars, DET curve, latency histogram, dashboard tiles |
| `code-review` | Reviewing a workstream's diff before integration (`/code-review medium`) |
| `security-review` | Before the demo: secrets, biometric data handling, offline store, auth on endpoints |
| `simplify` | Cleaning up a module after it works, if time allows |

## 4. Installation

All skills above are already installed on this machine (user scope `~/.claude/skills/` and the
project `.claude/skills/`). On a backup / second demo laptop run:

```bash
./tooling/install_skills.sh     # copies tooling/skills/* into ~/.claude/skills (skips existing)
```

Then restart Claude Code in `Project/`. Verify with `/skills` or by asking Claude to list skills.

No third-party skills from the internet are used — the vendored copies come from a trusted local
install. Do not install skills from unknown sources during the hackathon (they run as instructions
with your permissions).

## 5. Agents ↔ skills quick map

| Agent (`.claude/agents/`) | Must load |
|---|---|
| kiosk-frontend | liveness-kiosk, react-patterns, frontend-patterns, ui-styling, dataviz |
| edge-ml | liveness-kiosk, fastapi-patterns, python-patterns |
| policy-engine | liveness-kiosk, test-driven-development, python-patterns |
| cloud-aws | liveness-kiosk, fastapi-patterns, deployment-patterns |
| eval-metrics | pad-evaluation, dataviz, slides |
| depth-iphone | liveness-kiosk, python-patterns |
| verifier | verification-before-completion, pad-evaluation |
| spec-auditor | (none required — reads docs) |

## 6. Ground rules for every agent (as built, 2026-11-14)

- Current status and what is verified: `docs/BUILD_PLAN.md` §0. As-built architecture: `docs/ARCHITECTURE.md`.
- **Test on your own port, never against the live `:8000` edge** (or the live kiosk on `:5173`). Start a scratch
  instance with its own `EDGE_DATA_DIR`. Do not reset, reconfigure or load-test the operator's demo.
- Cite only YAML keys that exist in `config/thresholds.yaml`. `docs/research/**` is non-normative pre-build research;
  where it differs from `docs/*.md`, the docs win.
- Honesty switches to check before any claim: `liveness.flash.enforce: false` (colour flash ADVISORY, never claim it
  is enforced), `liveness.depth.enabled: false` (until the H4 calibration), `challenge.random_rate: 0.0`. Dev
  measurements are labelled "dev measurement" and are never presented as eval results.
