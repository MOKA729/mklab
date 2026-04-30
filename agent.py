"""Splunk findings prioritization agent.

How it works:
1. Set SPLUNK_MCP_URL and SPLUNK_TOKEN below.
2. Run `python agent.py`. No prompt — the agent runs autonomously.
3. The agent connects to the Splunk MCP server through the `mcp-remote`
   bridge, pulls every notable event, scores each one against the
   prioritization rubric, and writes the classification back to Splunk
   so the priority/score show up alongside each notable in Incident
   Review (or whichever findings page your Splunk surfaces).

Requires Node.js / npm on PATH so `npx` can launch `mcp-remote`. No
global install needed — `-y` lets npx fetch and run it on demand.
"""

# ============================================================================
# CONFIG — edit these two values
# ============================================================================
SPLUNK_MCP_URL = "https://ec2-98-84-5-114.compute-1.amazonaws.com:8089/services/mcp"
SPLUNK_TOKEN = "your-splunk-token-here"
# ============================================================================

import asyncio
import json
import os
import sys

from anthropic import AsyncAnthropic
from anthropic.lib.tools.mcp import async_mcp_tool
from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client


PRIORITIZATION_RUBRIC = """\
You are a senior detection-engineering analyst. Triage every notable event
in the Splunk notable index, score it against the rubric, and write the
classification back to Splunk so it appears as columns alongside each
notable in Incident Review.

# Workflow
1. Use the Splunk MCP tools available to pull every notable event from the
   `notable` index (or the equivalent index/datamodel this Splunk uses for
   findings/alerts). Pull the most recent batch — default to the last 24
   hours, but if the search returns nothing, widen the window.
2. Score every finding against the rubric below.
3. Write the classification BACK to Splunk (see the write-back section).
4. Print a final summary to the terminal: how many findings were
   classified, where the data was written, and the SPL the user should
   add to their notable search to display the new columns.

# Scoring rubric (each factor 0-5)
- Severity / CVSS         (weight 0.25) — Critical / 9.0+ = 5
- Exploitability          (weight 0.20) — KEV-listed, public PoC, ITW = 5
- Asset criticality       (weight 0.20) — crown-jewel / prod / sensitive = 5
- Blast radius            (weight 0.15) — many hosts/users, lateral risk = 5
- Recency                 (weight 0.10) — first seen <1h, still active = 5
- Detection confidence    (weight 0.10) — low FP, correlated, named TTP = 5

weighted_score = sum(score * weight). Bucket:
- P0 >= 4.2: page on-call          (urgency=critical)
- P1 >= 3.4: same-day              (urgency=high)
- P2 >= 2.6: this week             (urgency=medium)
- P3 >= 1.5: backlog               (urgency=low)
- P4 <  1.5: likely FP / informational (urgency=informational)

If a factor is unknown, assume the median (2.5) — do NOT inflate to hedge.

# Write-back to Splunk
For each scored notable, write these fields back, keyed by the notable's
`event_id` (or `_cd` / `rule_id` if no event_id is present):

- ai_priority         (P0..P4)
- ai_score            (float, 2 decimals)
- ai_rationale        (1-2 sentence string)
- ai_recommended_action (short string)

Pick the FIRST of these strategies that the available MCP tools support —
in order of preference, since each maps cleanly to columns in Incident
Review:

  1. **Notable update** — if a tool exists to update a notable event
     (e.g. `update_notable`, `notable_update`, or anything that sets
     urgency/comment/custom fields on a notable by event_id), use it.
     Map ai_priority to the `urgency` field per the rubric, and put
     ai_score + ai_rationale into the comment.

  2. **KV store / lookup write** — if a tool exists to write to a KV store
     collection or CSV lookup, write one row per finding to a collection
     named `claude_findings_classification` with the four fields above
     plus `event_id`.

  3. **Index a summary event** — if neither of the above is available,
     index a new event per finding to index `claude_classifications`
     (sourcetype `ai:findings:classification`) containing all four fields
     plus event_id.

After writing, print:

- How many findings you classified and how many you successfully wrote back.
- Which strategy you used (1, 2, or 3 above).
- The exact SPL the user should append to their notable search to display
  the new columns. Concrete examples:

  Strategy 2 (KV lookup):
      | lookup claude_findings_classification event_id OUTPUT
        ai_priority ai_score ai_rationale ai_recommended_action

  Strategy 3 (summary index):
      | join type=left event_id [ search index=claude_classifications
        | dedup event_id sortby -_time
        | fields event_id ai_priority ai_score ai_rationale
                 ai_recommended_action ]

# Output format

Stream tool calls as you go — that's normal. As your final message, emit:

1. A short executive summary (3-5 lines): how many notables, distribution
   across P0..P4 buckets, top 1-2 things needing attention.
2. The write-back confirmation and the exact SPL to add to the notable
   search.
3. A ```json fenced block with one object per finding in ranked order:

```json
[
  {
    "rank": 1,
    "priority": "P0",
    "weighted_score": 4.55,
    "event_id": "...",
    "title": "...",
    "asset": "...",
    "first_seen": "...",
    "scores": {"severity": 5, "exploitability": 5, "asset_criticality": 4,
               "blast_radius": 4, "recency": 5, "confidence": 4},
    "rationale": "2-3 sentences",
    "recommended_action": "one concrete next step"
  }
]
```
"""


USER_PROMPT = (
    "Pull every notable event from Splunk, classify each one against the "
    "rubric in your system prompt, and write the classification back to "
    "Splunk so the priority and score show up as columns on the notable "
    "events / Incident Review page.\n\n"
    "Discover what tools the Splunk MCP server exposes and pick the best "
    "write-back path per the system prompt. End with a summary and the "
    "exact SPL the user should add to their notable search."
)


def render_block(block) -> None:
    """Stream Claude's content blocks to stdout as they arrive."""
    if block.type == "text":
        print(block.text, end="", flush=True)
    elif block.type == "tool_use":
        try:
            args = json.dumps(block.input, sort_keys=True)
        except (TypeError, ValueError):
            args = str(block.input)
        if len(args) > 200:
            args = args[:200] + "…"
        print(f"\n[tool] {block.name}({args})", flush=True)


async def run() -> None:
    # Launches: npx -y mcp-remote <URL> --header "Authorization: Bearer <TOKEN>"
    # mcp-remote proxies the remote HTTPS MCP endpoint over stdio.
    params = StdioServerParameters(
        command="npx",
        args=[
            "-y",
            "mcp-remote",
            SPLUNK_MCP_URL,
            "--header",
            f"Authorization: Bearer {SPLUNK_TOKEN}",
        ],
        # Splunk on EC2 typically uses a self-signed cert. mcp-remote runs
        # on Node, so we disable Node's TLS verification for this
        # subprocess. Remove this line if your Splunk uses a CA-signed cert.
        env={**os.environ, "NODE_TLS_REJECT_UNAUTHORIZED": "0"},
    )

    client = AsyncAnthropic()
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as mcp:
            await mcp.initialize()
            tools_result = await mcp.list_tools()
            tools = [async_mcp_tool(t, mcp) for t in tools_result.tools]
            if not tools:
                sys.exit("Splunk MCP server exposed no tools — check URL and token.")

            sys.stderr.write(
                f"Connected. {len(tools)} Splunk tools available: "
                f"{', '.join(t.name for t in tools_result.tools)}\n\n"
            )

            runner = client.beta.messages.tool_runner(
                model="claude-opus-4-7",
                max_tokens=16000,
                system=[{
                    "type": "text",
                    "text": PRIORITIZATION_RUBRIC,
                    "cache_control": {"type": "ephemeral"},
                }],
                thinking={"type": "adaptive"},
                output_config={"effort": "high"},
                tools=tools,
                messages=[{"role": "user", "content": USER_PROMPT}],
                max_iterations=40,
            )

            async for message in runner:
                for block in message.content:
                    render_block(block)
            print()


def main() -> None:
    if not os.environ.get("ANTHROPIC_API_KEY"):
        sys.exit("ANTHROPIC_API_KEY environment variable is not set.")
    if "your-splunk-token-here" in SPLUNK_TOKEN:
        sys.exit("Edit SPLUNK_TOKEN at the top of agent.py first.")

    asyncio.run(run())


if __name__ == "__main__":
    main()
