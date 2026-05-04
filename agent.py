"""Splunk findings prioritization agent.

How it works:
1. Set SPLUNK_MCP_URL and SPLUNK_TOKEN below.
2. Run `python agent.py`. No prompt — runs autonomously.
3. The agent pulls notable events via the Splunk MCP server, scores each
   one against the prioritization rubric, and writes a CSV file
   (findings_classification.csv) that you upload to Splunk as a lookup
   table to display the priority/score columns alongside each notable.

Requires Node.js / npm on PATH so `npx` can launch `mcp-remote`. No
global install needed — `-y` lets npx fetch and run it on demand.
"""

# ============================================================================
# CONFIG — edit these values
# ============================================================================
SPLUNK_MCP_URL = "https://ec2-98-84-5-114.compute-1.amazonaws.com:8089/services/mcp"
SPLUNK_TOKEN = "your-splunk-token-here"

# Set True to skip TLS verification on the MCP connection. Required when
# Splunk uses a self-signed cert (typical on EC2). Set False in production
# with a CA-signed cert.
IGNORE_SSL = True

# Model to use. Opus 4.7 gives the best prioritization quality but is
# expensive and rate-limited on lower Anthropic tiers (30K input tokens/min).
# Sonnet 4.6 is ~5x cheaper, less rate-limited, and good enough for most
# triage. Haiku 4.5 is the cheapest but quality drops on borderline cases.
MODEL = "claude-opus-4-7"
# MODEL = "claude-sonnet-4-6"
# MODEL = "claude-haiku-4-5"

# Cap on how many findings Claude analyzes in one run. Keeps token use
# under control. Increase if you've raised your rate limit.
MAX_FINDINGS = 50

# Where to write the classification CSV that you'll upload to Splunk.
OUTPUT_CSV = "findings_classification.csv"
# ============================================================================

import asyncio
import json
import os
import re
import sys

import certifi
import httpx
from anthropic import AsyncAnthropic
from anthropic.lib.tools.mcp import async_mcp_tool
from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client


PRIORITIZATION_RUBRIC = """\
You are a security findings prioritization agent. Be CONCISE — every token
you emit costs money and the user's account is rate-limited.

# Workflow

1. Run ONE Splunk search to pull the most recent notable events:
   `search index=notable earliest=-30d | head 50 | table _time event_id rule_name severity urgency src dest user signature`
   Adjust the time window only if zero results come back.
2. Score every finding against the rubric below.
3. Group findings sharing host/user/src_ip within ~30 minutes into one
   incident — score the incident, not the individual events.
4. Output the deliverable (see OUTPUT below).

# DO NOT attempt to write back to Splunk

This MCP server BLOCKS every SPL write command — `outputlookup`, `collect`,
`outputcsv`, `summaryindex`, `mcollect`, `meventcollect`, `sendalert` are
all forbidden. Don't waste iterations trying. Don't list saved searches.
Don't probe the kv_store. Just pull, score, and emit the CSV. The user
uploads it to Splunk manually.

# Scoring rubric (each factor 0-5)

| Factor             | Weight | "5" looks like                              |
|--------------------|--------|---------------------------------------------|
| Severity           | 0.25   | severity=critical or CVSS 9.0+              |
| Exploitability     | 0.20   | KEV-listed, public PoC, in-the-wild         |
| Asset criticality  | 0.20   | crown-jewel: prod, internet-facing, sens.   |
| Blast radius       | 0.15   | many hosts/users, lateral movement risk     |
| Recency            | 0.10   | first seen <1h ago, still active            |
| Confidence         | 0.10   | low FP rate, correlated, named TTP          |

weighted_score = sum(score * weight). Bucket:
- P0 >= 4.2 — page on-call
- P1 >= 3.4 — same-day
- P2 >= 2.6 — this week
- P3 >= 1.5 — backlog
- P4 <  1.5 — likely FP / informational

If a factor is unknown, use 2.5 (median). Do NOT inflate to hedge.

# OUTPUT — these three sections, in order, as your final message

## 1. Executive summary (3-5 lines max)

How many findings classified, the P0..P4 distribution, and the top 1-2
items needing attention.

## 2. CSV block (this is parsed and written to disk — match the format exactly)

```csv
event_id,ai_priority,ai_score,ai_rationale,ai_recommended_action
NE-20260430-001,P0,4.75,"Brief 1-line rationale","One concrete next step"
...
```

Rules for the CSV:
- Header MUST be exactly: event_id,ai_priority,ai_score,ai_rationale,ai_recommended_action
- Quote any field containing a comma or quote (escape inner quotes by doubling them).
- One row per finding (or per incident if you grouped). Cap rationale at ~120 chars
  and action at ~80 chars.

## 3. Splunk lookup setup instructions

Print these literal steps so the user knows what to do with the CSV:

   a) Splunk Web → Settings → Lookups → Lookup table files → Add new
   b) Upload findings_classification.csv (destination app: search)
   c) Settings → Lookups → Lookup definitions → Add new
      Name: findings_classification, type: File-based, file: findings_classification.csv
   d) Append to your Incident Review (or notable) search:
      ```
      | lookup findings_classification event_id OUTPUT ai_priority ai_score ai_rationale ai_recommended_action
      ```

Keep the entire final message under ~1500 tokens.
"""


USER_PROMPT = (
    f"Pull the {MAX_FINDINGS} most recent notable events from Splunk via "
    "splunk_run_query, score each one against the rubric in your system "
    "prompt, and emit the CSV + summary as specified. ONE pull-search at the "
    "start, then score and write. Do NOT try to write back to Splunk via "
    "MCP — this server blocks all write SPL."
)


def render_block(block) -> None:
    """Stream Claude's content blocks to stdout as they arrive."""
    if block.type == "text":
        if block.text:
            print(block.text, end="", flush=True)
    elif block.type == "tool_use":
        try:
            args = json.dumps(block.input, sort_keys=True)
        except (TypeError, ValueError):
            args = str(block.input)
        if len(args) > 300:
            args = args[:300] + "…"
        print(f"\n[tool] {block.name}({args})", flush=True)
    elif block.type == "thinking":
        text = getattr(block, "thinking", "") or ""
        if text.strip():
            preview = text[:400] + ("…" if len(text) > 400 else "")
            print(f"\n[thinking] {preview}", flush=True)
    else:
        print(f"\n[{block.type}]", flush=True)


def extract_csv_to_file(full_text: str, path: str) -> bool:
    """Pull the first ```csv ... ``` fenced block from the model output and
    write it to `path`. Returns True on success."""
    match = re.search(r"```csv\s*\n(.*?)\n```", full_text, re.DOTALL | re.IGNORECASE)
    if not match:
        return False
    csv_text = match.group(1).strip() + "\n"
    with open(path, "w", encoding="utf-8") as f:
        f.write(csv_text)
    return True


async def run() -> None:
    subprocess_env = {**os.environ}
    if IGNORE_SSL:
        subprocess_env["NODE_TLS_REJECT_UNAUTHORIZED"] = "0"

    params = StdioServerParameters(
        command="npx",
        args=[
            "-y",
            "mcp-remote",
            SPLUNK_MCP_URL,
            "--header",
            f"Authorization: Bearer {SPLUNK_TOKEN}",
        ],
        env=subprocess_env,
    )

    client = AsyncAnthropic(
        http_client=httpx.AsyncClient(verify=False),
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as mcp:
            await mcp.initialize()
            tools_result = await mcp.list_tools()
            tools = [async_mcp_tool(t, mcp) for t in tools_result.tools]
            if not tools:
                sys.exit("Splunk MCP server exposed no tools — check URL and token.")

            sys.stderr.write(
                f"Connected. {len(tools)} Splunk tools available.\n"
                f"Model: {MODEL}, max findings: {MAX_FINDINGS}\n\n"
            )

            runner = client.beta.messages.tool_runner(
                model=MODEL,
                max_tokens=8000,
                system=[{
                    "type": "text",
                    "text": PRIORITIZATION_RUBRIC,
                    "cache_control": {"type": "ephemeral"},
                }],
                thinking={"type": "adaptive", "display": "summarized"},
                output_config={"effort": "medium"},
                tools=tools,
                messages=[{"role": "user", "content": USER_PROMPT}],
                max_iterations=15,
            )

            collected_text: list[str] = []
            iteration = 0
            try:
                async for message in runner:
                    iteration += 1
                    for block in message.content:
                        render_block(block)
                        if block.type == "text" and block.text:
                            collected_text.append(block.text)
                    stop = getattr(message, "stop_reason", None)
                    sys.stderr.write(
                        f"\n[iter {iteration}] stop_reason={stop} "
                        f"in={message.usage.input_tokens} "
                        f"out={message.usage.output_tokens}\n"
                    )
            except Exception as exc:
                sys.stderr.write(f"\n[error] runner raised: {exc!r}\n")
                # Don't re-raise — try to extract whatever CSV we got so far.

            print(f"\n\n[done] {iteration} iterations.")

            full = "".join(collected_text)
            if extract_csv_to_file(full, OUTPUT_CSV):
                sys.stderr.write(
                    f"[saved] Wrote classifications to {OUTPUT_CSV} — "
                    "upload this file to Splunk as a lookup table per the "
                    "instructions above.\n"
                )
            else:
                sys.stderr.write(
                    "[warning] No CSV block found in the model output. "
                    "Check the run above for errors.\n"
                )


def main() -> None:
    if not os.environ.get("ANTHROPIC_API_KEY"):
        sys.exit("ANTHROPIC_API_KEY environment variable is not set.")
    if "your-splunk-token-here" in SPLUNK_TOKEN:
        sys.exit("Edit SPLUNK_TOKEN at the top of agent.py first.")

    asyncio.run(run())


if __name__ == "__main__":
    main()
