"""Splunk findings prioritization agent.

How it works:
1. Edit SPLUNK_MCP_URL and SPLUNK_TOKEN below (the MCP bridge auth).
2. SPLUNK_API_TOKEN defaults to SPLUNK_TOKEN — used for the Mission
   Control notes API. Override below if you need a different token.
3. Run `python agent.py`.

The agent connects via the Splunk MCP server, pulls notable events,
scores each one with Claude, writes findings_classification.csv to
disk, then POSTs each classification as a note to Splunk Mission
Control's investigations API:

  POST /servicesNS/nobody/missioncontrol/public/v2/investigations/<event_id>/notes

One note per finding, titled "AI Priorization", with the AI rationale
and recommended action as the body. The endpoint requires real ES
notable event_ids (the `<uuid>@@notable@@time<epoch>` format) — the
agent is instructed to preserve those verbatim from Splunk.
"""

# ============================================================================
# CONFIG — edit these values
# ============================================================================
SPLUNK_MCP_URL = "https://192.168.1.11:8089/services/mcp"
SPLUNK_TOKEN = "your-mcp-token-here"

# Set True to skip TLS verification on the Splunk connection. Required for
# self-signed certs (typical on dev installs and EC2). Set False in
# production with a CA-signed cert.
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

# Where to write the classification CSV (intermediate artifact).
OUTPUT_CSV = "findings_classification.csv"

# Write the AI classification back to each Splunk notable as a note via the
# Splunk Mission Control investigations API. Set False to skip and just
# produce the CSV.
WRITE_NOTES_VIA_API = True

# Splunk REST API base URL. Auto-derived from SPLUNK_MCP_URL by default —
# everything before "/services/mcp". Override if the REST API is on a
# different host/port.
SPLUNK_REST_URL = SPLUNK_MCP_URL.split("/services/")[0]

# Splunk auth token used for the Mission Control notes API. Defaults to the
# MCP token, but if your MCP server uses its own credential layer (and the
# MCP token isn't a valid Splunk auth token), generate a real Splunk auth
# token via Splunk Web → Settings → Tokens → New Token (JWT starting with
# "eyJ...") and paste it here.
SPLUNK_API_TOKEN = SPLUNK_TOKEN
# ============================================================================

import asyncio
import csv as csv_module
import json
import os
import re
import sys
from urllib.parse import quote

import httpx
from anthropic import AsyncAnthropic
from anthropic.lib.tools.mcp import async_mcp_tool
from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client


PRIORITIZATION_RUBRIC = """\
You are a security findings prioritization agent. Be CONCISE.

# Workflow

1. Run ONE Splunk search to pull notable events that have a real event_id:
   `search index=notable earliest=-30d event_id=* | head 50 | table _time event_id rule_name severity urgency src dest user signature`
2. Score each finding against the rubric below.
3. Group findings sharing host/user/src_ip within ~30 minutes into one
   incident — score the incident, not individual events.
4. Output the CSV deliverable.

# CRITICAL: event_id handling

Each row's `event_id` MUST be the EXACT value returned by Splunk —
typically in the format `<uuid>@@notable@@time<epoch>`, e.g.:
  2a2d00e8-ac75-4207-bcbe-992e2049e42d@@notable@@time1777919948

DO NOT synthesize, shorten, reformat, or invent event_ids. They are
used as path parameters in the Splunk Mission Control notes API; any
mismatch makes the note fail. If a finding has no event_id, SKIP it
(do not include it in the CSV).

# Do not try to write back via MCP

This MCP server blocks all write SPL (outputlookup, collect, etc.).
Don't waste iterations probing them. The harness handles write-back
via the Mission Control REST API after you produce the CSV.

# Scoring rubric (each factor 0-5)

- Severity (0.25)         — severity=critical or CVSS 9.0+
- Exploitability (0.20)   — KEV-listed, public PoC, in-the-wild
- Asset criticality (0.20)— prod / internet-facing / sensitive data
- Blast radius (0.15)     — many hosts/users, lateral movement risk
- Recency (0.10)          — first seen <1h ago, still active
- Confidence (0.10)       — low FP rate, correlated, named TTP

weighted_score = sum(score * weight). Bucket:
- P0 >= 4.2 — page on-call
- P1 >= 3.4 — same-day
- P2 >= 2.6 — this week
- P3 >= 1.5 — backlog
- P4 <  1.5 — likely FP / informational

If a factor is unknown, use 2.5 (median). Do NOT inflate to hedge.

# OUTPUT — final message

## 1. Executive summary (3-5 lines max)

How many findings classified, distribution across P0..P4, top 1-2
items needing attention.

## 2. CSV block — match this format exactly:

```csv
event_id,ai_priority,ai_score,ai_rationale,ai_recommended_action
2a2d00e8-ac75-4207-bcbe-992e2049e42d@@notable@@time1777919948,P0,4.75,"Active credential dumping on DC","Isolate dc01, rotate krbtgt twice"
```

Header MUST be exactly: event_id,ai_priority,ai_score,ai_rationale,ai_recommended_action
Quote any field containing commas or quotes (escape inner quotes by doubling).
Rationale ≤120 chars, action ≤80 chars. One row per finding (or per grouped incident).

Keep the entire final message under ~1500 tokens.
"""


USER_PROMPT = (
    f"Pull the {MAX_FINDINGS} most recent notable events that have a "
    "non-empty event_id from Splunk via splunk_run_query. Score each one "
    "against the rubric in your system prompt and emit the CSV + summary "
    "as specified. ONE pull-search at the start. Preserve event_id values "
    "verbatim — they are used as path parameters in the API write-back. "
    "Skip findings with no event_id."
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


async def write_notes_to_mission_control(csv_path: str) -> None:
    """For each row in the classification CSV, POST a note to Splunk
    Mission Control's investigations API so the AI triage shows up as a
    note on the corresponding notable event.

    Endpoint: POST /servicesNS/nobody/missioncontrol/public/v2/investigations/<event_id>/notes
    Payload: {"title": "AI Priorization", "content": "...", "type": "Task"}
    """
    rows: list[dict[str, str]] = []
    with open(csv_path, encoding="utf-8") as f:
        reader = csv_module.DictReader(f)
        rows = list(reader)
    if not rows:
        sys.stderr.write("[notes] CSV had no rows; nothing to write back.\n")
        return

    if not SPLUNK_API_TOKEN:
        raise SystemExit(
            "SPLUNK_API_TOKEN is not set. Set it at the top of agent.py."
        )

    headers = {
        "Authorization": f"Splunk {SPLUNK_API_TOKEN}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    sys.stderr.write(
        f"[notes] Posting {len(rows)} notes to Mission Control at "
        f"{SPLUNK_REST_URL}/servicesNS/nobody/missioncontrol/public/v2/"
        "investigations/<event_id>/notes ...\n"
    )

    success = 0
    failures: list[tuple[str, int, str]] = []

    async with httpx.AsyncClient(verify=not IGNORE_SSL, timeout=30.0) as http:
        for row in rows:
            event_id = (row.get("event_id") or "").strip()
            if not event_id:
                continue

            # event_ids contain '@' and ':' — URL-encode for the path.
            encoded_id = quote(event_id, safe="")
            url = (
                f"{SPLUNK_REST_URL}/servicesNS/nobody/missioncontrol"
                f"/public/v2/investigations/{encoded_id}/notes"
            )

            content = (
                f"**Priority:** {row.get('ai_priority', '')}  \n"
                f"**Score:** {row.get('ai_score', '')}  \n"
                f"**Rationale:** {row.get('ai_rationale', '')}  \n"
                f"**Recommended action:** {row.get('ai_recommended_action', '')}"
            )

            payload = {
                "title": "AI Priorization",
                "content": content,
                "type": "Task",
            }

            try:
                resp = await http.post(url, json=payload, headers=headers)
            except httpx.HTTPError as exc:
                failures.append((event_id, 0, repr(exc)))
                continue

            if 200 <= resp.status_code < 300:
                success += 1
            else:
                failures.append((event_id, resp.status_code, resp.text[:300]))

    sys.stderr.write(
        f"[notes] {success}/{len(rows)} notes posted to Mission Control.\n"
    )
    if failures:
        sys.stderr.write(f"[notes] {len(failures)} failed:\n")
        for event_id, status, body in failures[:5]:
            sys.stderr.write(f"  - {event_id}: HTTP {status} — {body}\n")
        if len(failures) > 5:
            sys.stderr.write(f"  ... and {len(failures) - 5} more.\n")


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

    client = AsyncAnthropic(http_client=httpx.AsyncClient(verify=False))
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

            print(f"\n\n[done] {iteration} iterations.")

            full = "".join(collected_text)
            if extract_csv_to_file(full, OUTPUT_CSV):
                sys.stderr.write(
                    f"[saved] Wrote classifications to {OUTPUT_CSV}.\n"
                )
                if WRITE_NOTES_VIA_API:
                    await write_notes_to_mission_control(OUTPUT_CSV)
                else:
                    sys.stderr.write(
                        "[notes] WRITE_NOTES_VIA_API is False — skipping.\n"
                    )
            else:
                sys.stderr.write(
                    "[warning] No CSV block found in the model output. "
                    "Check the run above for errors.\n"
                )


def main() -> None:
    if not os.environ.get("ANTHROPIC_API_KEY"):
        sys.exit("ANTHROPIC_API_KEY environment variable is not set.")
    if "your-mcp-token-here" in SPLUNK_TOKEN:
        sys.exit("Edit SPLUNK_TOKEN at the top of agent.py first.")
    asyncio.run(run())


if __name__ == "__main__":
    main()
