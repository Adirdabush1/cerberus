# AgentGuard (APG — Agent Permission Gateway)

An **active firewall / proxy for autonomous AI agents**. AgentGuard sits between an AI
agent (Claude Code, Devin, in-house agents) and its execution environment, intercepts
every **Tool / Function Call**, classifies it by risk policy, and pauses dangerous
executions for **real-time human approval (Human-in-the-Loop)**.

## The three lines of defense
1. **Auto-Approve** — read-only / safe actions (read config, `git status`, internal GET). Passed through in milliseconds and logged.
2. **Auto-Block** — destructive or anomalous actions (`rm -rf`, reading `.env`, runaway loops). Cut off; a synthetic `Permission Denied` is returned to the agent; admin is alerted.
3. **Human-in-the-Loop (HITL)** — state-changing actions (file writes, `git push`, DB migrations, paid external API calls). Request is held pending; a card pops in the dashboard / Slack with an exact diff; on **Approve** the agent continues seamlessly.

## Proposed stack
- **Proxy:** Node.js + TypeScript (Express/Fastify)
- **State:** Redis (pending HITL requests, rate/anomaly tracking)
- **Dashboard:** React + Tailwind + TypeScript — Live Stream · Action Center · Policy Editor
- **Notifications:** Slack + WebSockets / Long-Polling
- **Distribution:** B2B **Open-Core** (OSS proxy + CLI; paid cloud dashboard, multi-seat, log retention, Slack integration)

## Open architectural questions (to resolve in planning)
- **Interception point:** LLM-API proxy vs. MCP gateway vs. runtime/execution hook — how do we guarantee the agent cannot bypass the gate?
- **Classification engine:** hardcoded Rules/Regex vs. a small local LLM classifying intent (or a hybrid).
- **Tool-call format(s)** to support first: OpenAI, Anthropic, MCP.
- **Deployment model** for the OSS core: local CLI/sidecar vs. hosted gateway.

## Status
Planning phase. No production code yet.
