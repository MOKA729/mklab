"""Splunk findings prioritization agent.

How it works:
1. Set SPLUNK_MCP_URL and SPLUNK_TOKEN below.
2. Run `python agent.py`. A popup asks for the Splunk search to run.
3. Claude connects to the Splunk MCP server through the `mcp-remote` bridge
   (an `npx` subprocess that proxies the remote HTTPS MCP endpoint over
   stdio), runs the search via Splunk's MCP tools, and prints a ranked
   priority list to the terminal.

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
import tkinter as tk
from tkinter import scrolledtext

from anthropic import AsyncAnthropic
from anthropic.lib.tools.mcp import async_mcp_tool
from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client


PRIORITIZATION_RUBRIC = """\
You are a senior detection-engineering analyst. Triage the security findings
returned by the user's Splunk search and produce a ranked priority list.

# Workflow
1. Use the Splunk MCP tools available to execute the user's SPL search.
2. Score every finding the search returns against the rubric below.
3. Emit the final ranked list as your LAST message — do not interleave the
   ranking with tool calls.

# Scoring rubric (each factor 0-5)
- Severity / CVSS         (weight 0.25) — Critical / 9.0+ = 5
- Exploitability          (weight 0.20) — KEV-listed, public PoC, ITW = 5
- Asset criticality       (weight 0.20) — crown-jewel / prod / sensitive = 5
- Blast radius            (weight 0.15) — many hosts/users, lateral risk = 5
- Recency                 (weight 0.10) — first seen <1h, still active = 5
- Detection confidence    (weight 0.10) — low FP, correlated, named TTP = 5

weighted_score = sum(score * weight). Bucket:
- P0 >= 4.2: page on-call
- P1 >= 3.4: same-day
- P2 >= 2.6: this week
- P3 >= 1.5: backlog
- P4 <  1.5: likely FP / informational

Heuristic: group findings sharing host/user/src_ip within ~30 minutes into
one incident. If a factor is unknown, assume the median (2.5) — do NOT
inflate to hedge.

# Output format
A short executive summary, then a ```json fenced block with one object per
finding in ranked order:

```json
[
  {
    "rank": 1,
    "priority": "P0",
    "weighted_score": 4.55,
    "finding_id": "...",
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


def ask_search() -> str | None:
    """Show a Tkinter popup asking for the Splunk search (SPL) to run."""
    result: dict[str, str | None] = {"text": None}

    root = tk.Tk()
    root.title("Splunk Findings — Search")
    root.geometry("560x320")

    tk.Label(
        root,
        text="Enter the Splunk search (SPL) to run.\n"
             "The agent will execute it and prioritize the results.",
        anchor="w",
        justify="left",
    ).pack(fill=tk.X, padx=10, pady=(10, 4))

    text = scrolledtext.ScrolledText(root, height=10, wrap=tk.WORD, font=("Courier", 10))
    text.pack(padx=10, pady=4, fill=tk.BOTH, expand=True)
    text.insert("1.0", "search index=notable earliest=-24h | head 50")
    text.focus()

    def submit() -> None:
        result["text"] = text.get("1.0", tk.END).strip()
        root.destroy()

    def cancel() -> None:
        root.destroy()

    btns = tk.Frame(root)
    btns.pack(pady=8)
    tk.Button(btns, text="Run", command=submit, width=10).pack(side=tk.LEFT, padx=4)
    tk.Button(btns, text="Cancel", command=cancel, width=10).pack(side=tk.LEFT, padx=4)
    root.protocol("WM_DELETE_WINDOW", cancel)
    root.mainloop()

    return result["text"]


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


async def run(splunk_search: str) -> None:
    user_prompt = (
        "Run this Splunk search and prioritize every finding it returns:\n\n"
        f"```\n{splunk_search}\n```\n\n"
        "Use the Splunk MCP tools available to execute the search. Then "
        "score every finding against the rubric in your system prompt and "
        "emit the final ranked JSON list as your last message."
    )

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
        # Splunk on EC2 typically uses a self-signed cert. mcp-remote runs on
        # Node, so we disable Node's TLS verification for this subprocess.
        # Remove this line if your Splunk uses a CA-signed cert.
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
                messages=[{"role": "user", "content": user_prompt}],
                max_iterations=20,
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

    search = ask_search()
    if not search:
        sys.exit("No search provided — cancelled.")

    asyncio.run(run(search))


if __name__ == "__main__":
    main()
