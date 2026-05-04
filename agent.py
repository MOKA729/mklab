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

# Write the AI classification back to each Splunk notable as a comment/note
# via the Splunk ES REST API (POST /services/notable_update). Bypasses the
# MCP server entirely. Requires Splunk Enterprise Security and a token
# whose role has the `edit_notable_events` capability.
WRITE_NOTES_VIA_API = True

# Splunk REST API base URL. Auto-derived from SPLUNK_MCP_URL by default —
# everything before "/services/mcp". Override here if the REST API is on
# a different host/port.
SPLUNK_REST_URL = SPLUNK_MCP_URL.split("/services/")[0]

# Auth for the Splunk REST API. The MCP token is often NOT a valid Splunk
# auth token — MCP servers commonly use their own credential system and
# translate to Splunk auth internally. If you get HTTP 401 "call not
# properly authenticated", do one of these:
#
#   A. Generate a real Splunk auth token: Splunk Web → Settings → Tokens
#      → New Token. The result is a JWT starting with "eyJ...". Set:
#          SPLUNK_API_TOKEN = "eyJraWQiOi..."
#          SPLUNK_API_AUTH_SCHEME = "Splunk"        # Splunk's native scheme
#      (or "Bearer" — both work for tokens generated this way.)
#
#   B. Use basic auth with username/password:
#          SPLUNK_API_TOKEN = ""
#          SPLUNK_API_USERNAME = "admin"
#          SPLUNK_API_PASSWORD = "your-password"
#
# By default we reuse SPLUNK_TOKEN with the "Splunk" scheme (more likely to
# work for direct REST than "Bearer"). If that 401s, follow option A or B.
SPLUNK_API_TOKEN = SPLUNK_TOKEN
SPLUNK_API_AUTH_SCHEME = "Splunk"     # "Splunk" or "Bearer"
SPLUNK_API_USERNAME = ""              # only used if SPLUNK_API_TOKEN is empty
SPLUNK_API_PASSWORD = ""              # only used if SPLUNK_API_TOKEN is empty

# Also overwrite each notable's urgency field to match the AI priority
# (P0=critical, P1=high, P2=medium, P3=low, P4=informational). Default
# False so we never clobber an analyst's existing urgency. Flip on if
# you want the urgency column auto-set.
UPDATE_URGENCY = False
# ============================================================================

import asyncio
import csv as csv_module
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


_URGENCY_MAP = {
    "P0": "critical",
    "P1": "high",
    "P2": "medium",
    "P3": "low",
    "P4": "informational",
}


def _build_splunk_api_auth() -> tuple[dict[str, str], tuple[str, str] | None]:
    """Return (headers, basic_auth_tuple) for the Splunk REST API call.
    Exactly one of the two will be populated based on the config above."""
    if SPLUNK_API_TOKEN:
        scheme = SPLUNK_API_AUTH_SCHEME or "Splunk"
        return {"Authorization": f"{scheme} {SPLUNK_API_TOKEN}"}, None
    if SPLUNK_API_USERNAME and SPLUNK_API_PASSWORD:
        return {}, (SPLUNK_API_USERNAME, SPLUNK_API_PASSWORD)
    raise SystemExit(
        "Splunk REST API auth not configured. Set SPLUNK_API_TOKEN "
        "(preferred) or SPLUNK_API_USERNAME + SPLUNK_API_PASSWORD."
    )


async def write_notes_to_splunk(csv_path: str) -> None:
    """For each row in the classification CSV, POST a comment to Splunk's
    /services/notable_update endpoint so the AI triage shows up as a note
    on the corresponding notable event in Incident Review."""

    rows: list[dict[str, str]] = []
    with open(csv_path, encoding="utf-8") as f:
        reader = csv_module.DictReader(f)
        rows = list(reader)
    if not rows:
        sys.stderr.write("[notes] CSV had no rows; nothing to write back.\n")
        return

    headers, basic_auth = _build_splunk_api_auth()
    auth_label = (
        "basic auth"
        if basic_auth is not None
        else f"{SPLUNK_API_AUTH_SCHEME} <token>"
    )
    sys.stderr.write(
        f"[notes] Writing {len(rows)} comments to {SPLUNK_REST_URL} "
        f"via POST /services/notable_update (auth: {auth_label}) ...\n"
    )

    success = 0
    failures: list[tuple[str, int, str]] = []

    async with httpx.AsyncClient(
        verify=not IGNORE_SSL, timeout=30.0, auth=basic_auth
    ) as http:
        for row in rows:
            event_id = (row.get("event_id") or "").strip()
            if not event_id:
                continue

            priority = (row.get("ai_priority") or "").strip()
            score = (row.get("ai_score") or "").strip()
            rationale = (row.get("ai_rationale") or "").strip()
            action = (row.get("ai_recommended_action") or "").strip()

            comment = (
                f"[AI Triage] Priority: {priority} (score: {score})\n"
                f"Rationale: {rationale}\n"
                f"Recommended action: {action}"
            )

            data: dict[str, str] = {
                "ruleUIDs": event_id,
                "comment": comment,
            }
            if UPDATE_URGENCY and priority in _URGENCY_MAP:
                data["urgency"] = _URGENCY_MAP[priority]

            try:
                resp = await http.post(
                    f"{SPLUNK_REST_URL}/services/notable_update",
                    data=data,
                    headers=headers,
                )
            except httpx.HTTPError as exc:
                failures.append((event_id, 0, repr(exc)))
                continue

            if 200 <= resp.status_code < 300:
                success += 1
            else:
                failures.append((event_id, resp.status_code, resp.text[:200]))

    sys.stderr.write(f"[notes] {success}/{len(rows)} notable comments written.\n")
    if failures:
        sys.stderr.write(f"[notes] {len(failures)} failed:\n")
        for event_id, status, body in failures[:3]:
            sys.stderr.write(f"  - {event_id}: HTTP {status} — {body}\n")
        if len(failures) > 3:
            sys.stderr.write(f"  ... and {len(failures) - 3} more.\n")
        if all(s == 401 for _, s, _ in failures):
            sys.stderr.write(
                "\n[notes] All requests returned 401. Your token does not "
                "authenticate against the Splunk REST API directly. Fix:\n"
                "  1. Generate a Splunk auth token: Splunk Web → Settings → "
                "Tokens → New Token. The result starts with 'eyJ...'.\n"
                "  2. Set SPLUNK_API_TOKEN to that JWT at the top of agent.py.\n"
                "  3. Try SPLUNK_API_AUTH_SCHEME = 'Splunk' first; if that "
                "still 401s, switch to 'Bearer'.\n"
                "  4. As a fallback, use basic auth (SPLUNK_API_USERNAME + "
                "SPLUNK_API_PASSWORD) and clear SPLUNK_API_TOKEN.\n"
            )


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
                    f"[saved] Wrote classifications to {OUTPUT_CSV}.\n"
                )
                if WRITE_NOTES_VIA_API:
                    await write_notes_to_splunk(OUTPUT_CSV)
                else:
                    sys.stderr.write(
                        "[notes] WRITE_NOTES_VIA_API is False — skipping. "
                        "Upload the CSV manually as a Splunk lookup if you "
                        "still want it visible in Incident Review.\n"
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
