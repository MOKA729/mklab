"""Splunk findings prioritization agent.

Connects to a Splunk MCP server, pulls findings/alerts, and asks Claude to
triage them by risk. The agent uses Claude as an MCP client: Splunk MCP
tools are exposed to Claude via the Anthropic SDK's `async_mcp_tool`
helper, and Claude drives the search + analysis loop itself.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import shlex
import sys
from contextlib import asynccontextmanager
from typing import AsyncIterator

from anthropic import AsyncAnthropic
from anthropic.lib.tools.mcp import async_mcp_tool
from dotenv import load_dotenv
from mcp import ClientSession
from mcp.client.sse import sse_client
from mcp.client.stdio import StdioServerParameters, stdio_client


PRIORITIZATION_RUBRIC = """\
You are a senior detection-engineering analyst. Your job is to triage a
batch of security findings pulled from Splunk and produce a ranked,
actionable priority list.

# Workflow

1. Use the Splunk MCP tools available to you to pull the findings. Run the
   provided search (or a more targeted variant if the user specifies one)
   and gather enough metadata about each finding to score it. If a finding
   references an asset, user, or IOC and a tool exists to enrich it, you
   may pull a small amount of additional context — but do not go on long
   enrichment expeditions; the goal is triage, not investigation.

2. Score every finding against the rubric below. Each factor is scored
   0-5 and combined into a single priority bucket (P0..P4).

3. Produce the final ranked list as the LAST message. Do not interleave
   the ranking with tool calls.

# Scoring rubric (per finding)

| Factor                  | Weight | What "5" looks like                                       |
|-------------------------|--------|-----------------------------------------------------------|
| Severity / CVSS         | 0.25   | Critical / CVSS 9.0+, or labelled severity=critical       |
| Exploitability          | 0.20   | Public PoC, in-the-wild exploitation, KEV-listed CVE       |
| Asset criticality       | 0.20   | Crown-jewel system: prod, internet-facing, sensitive data  |
| Blast radius            | 0.15   | Many hosts/users affected, or lateral movement potential   |
| Recency / freshness     | 0.10   | First seen <1h ago and still active                        |
| Detection confidence    | 0.10   | Low FP rate, multiple correlated signals, named TTP        |

Compute weighted_score = sum(factor_score * weight). Map to bucket:

- P0  (>= 4.2): Page on-call. Active, high-confidence, high-impact.
- P1  (>= 3.4): Same-day investigation. High risk but not actively burning.
- P2  (>= 2.6): This-week queue. Real but not urgent.
- P3  (>= 1.5): Backlog / hardening. Low confidence or low impact.
- P4  (< 1.5):  Likely false positive or informational.

# Heuristics & gotchas

- Treat any finding mapped to MITRE ATT&CK techniques in initial-access,
  credential-access, or lateral-movement tactics with extra weight.
- If two findings share a host, user, or src_ip and arrived within ~30
  minutes, group them into one incident — score the incident, not the
  individual events.
- If a finding's only signal is a single low-fidelity rule (e.g. generic
  threat-intel match, isolated AV detection), default to P3 unless the
  affected asset is crown-jewel.
- If you cannot determine a factor from the data available, mark it
  "unknown" and assume the median (2.5) — do NOT inflate the score to
  hedge.

# Output format

Emit one JSON object per finding inside a fenced ```json block, in
ranked order, plus a short executive summary above it. Schema:

```json
[
  {
    "rank": 1,
    "priority": "P0",
    "weighted_score": 4.55,
    "finding_id": "<splunk event id or rule_id>",
    "title": "<short title>",
    "asset": "<host / user / ip>",
    "first_seen": "<iso8601>",
    "scores": {
      "severity": 5, "exploitability": 5, "asset_criticality": 4,
      "blast_radius": 4, "recency": 5, "confidence": 4
    },
    "rationale": "<2-3 sentences: what is happening and why this rank>",
    "recommended_action": "<one concrete next step>"
  }
]
```
"""


def _load_stdio_params() -> StdioServerParameters:
    command = os.environ.get("SPLUNK_MCP_COMMAND")
    if not command:
        raise SystemExit(
            "SPLUNK_MCP_COMMAND is required for stdio transport. "
            "Set it to the binary that launches your Splunk MCP server "
            "(e.g. 'uvx', 'npx', or an absolute path)."
        )
    args_raw = os.environ.get("SPLUNK_MCP_ARGS", "")
    args = shlex.split(args_raw) if args_raw else []

    # Forward Splunk credentials to the MCP subprocess. The Splunk MCP
    # server reads these from its own environment.
    forwarded = {
        k: v
        for k, v in os.environ.items()
        if k.startswith("SPLUNK_") and k not in {"SPLUNK_MCP_COMMAND", "SPLUNK_MCP_ARGS", "SPLUNK_MCP_TRANSPORT", "SPLUNK_MCP_URL", "SPLUNK_MCP_AUTH_HEADER"}
    }
    return StdioServerParameters(command=command, args=args, env=forwarded)


@asynccontextmanager
async def open_splunk_session() -> AsyncIterator[ClientSession]:
    """Open a connected MCP ClientSession to the Splunk MCP server."""
    transport = os.environ.get("SPLUNK_MCP_TRANSPORT", "stdio").lower()

    if transport == "stdio":
        params = _load_stdio_params()
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                yield session
        return

    if transport == "sse":
        url = os.environ.get("SPLUNK_MCP_URL")
        if not url:
            raise SystemExit("SPLUNK_MCP_URL is required for sse transport.")
        headers: dict[str, str] = {}
        auth = os.environ.get("SPLUNK_MCP_AUTH_HEADER")
        if auth:
            headers["Authorization"] = auth
        async with sse_client(url, headers=headers or None) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                yield session
        return

    raise SystemExit(
        f"Unknown SPLUNK_MCP_TRANSPORT={transport!r}. Use 'stdio' or 'sse'."
    )


def _format_block(block) -> str | None:
    """Render a content block from the Claude response for the console."""
    if block.type == "text":
        return block.text
    if block.type == "tool_use":
        try:
            args = json.dumps(block.input, sort_keys=True)
        except (TypeError, ValueError):
            args = str(block.input)
        if len(args) > 200:
            args = args[:200] + "…"
        return f"\n[tool] {block.name}({args})"
    return None


async def prioritize(user_prompt: str) -> None:
    client = AsyncAnthropic()

    async with open_splunk_session() as mcp:
        tools_result = await mcp.list_tools()
        tools = [async_mcp_tool(t, mcp) for t in tools_result.tools]
        if not tools:
            raise SystemExit(
                "Splunk MCP server exposed no tools. Check the server is "
                "running and configured against a reachable Splunk instance."
            )
        sys.stderr.write(
            f"Connected to Splunk MCP server. {len(tools)} tools available: "
            f"{', '.join(t.name for t in tools_result.tools)}\n"
        )

        runner = client.beta.messages.tool_runner(
            model="claude-opus-4-7",
            max_tokens=16000,
            system=[
                {
                    "type": "text",
                    "text": PRIORITIZATION_RUBRIC,
                    "cache_control": {"type": "ephemeral"},
                }
            ],
            thinking={"type": "adaptive"},
            output_config={"effort": "high"},
            tools=tools,
            messages=[{"role": "user", "content": user_prompt}],
            max_iterations=20,
        )

        async for message in runner:
            for block in message.content:
                rendered = _format_block(block)
                if rendered:
                    print(rendered, end="", flush=True)
        print()


def _build_user_prompt() -> str:
    search = os.environ.get(
        "SPLUNK_FINDINGS_SEARCH",
        "search index=notable earliest=-24h | head 50",
    )
    max_findings = os.environ.get("MAX_FINDINGS", "50")
    return (
        "Pull the latest security findings from Splunk and prioritize them.\n\n"
        f"Use this Splunk search as the primary source: `{search}`\n"
        f"Cap the analysis at {max_findings} findings — if more come back, "
        "rank by severity and score the top N.\n\n"
        "Follow the rubric in your system prompt. Emit the final ranked "
        "list as the last message, in the JSON schema specified."
    )


def main() -> None:
    load_dotenv()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "prompt",
        nargs="?",
        default=None,
        help="Optional override for the user prompt. Defaults to a prompt "
        "built from SPLUNK_FINDINGS_SEARCH / MAX_FINDINGS env vars.",
    )
    args = parser.parse_args()

    user_prompt = args.prompt or _build_user_prompt()
    asyncio.run(prioritize(user_prompt))


if __name__ == "__main__":
    main()
