"""Splunk Mission Control investigations prioritization agent.

Fetches existing investigations from Splunk Mission Control, scores each
one with Claude against a triage rubric, and writes the AI prioritization
back as a note on each investigation. No MCP server required — talks to
Mission Control's REST API directly.

How it works:
1. GET /servicesNS/nobody/missioncontrol/public/v2/investigations
2. Pass the investigations to Claude for scoring against the rubric.
3. POST a note to each investigation:
   POST /servicesNS/nobody/missioncontrol/public/v2/investigations/<id>/notes
   {"title": "AI Priorization", "content": "...", "type": "Task"}

Setup: edit SPLUNK_BASE_URL and SPLUNK_API_TOKEN below. The token must be
a real Splunk JWT (Settings → Tokens → New Token, starts with "eyJ...").
"""

# ============================================================================
# CONFIG — edit these values
# ============================================================================
SPLUNK_BASE_URL = "https://192.168.1.11:8089"
SPLUNK_API_TOKEN = "eyJ-paste-your-splunk-jwt-here"

IGNORE_SSL = True
MODEL = "claude-opus-4-7"
# MODEL = "claude-sonnet-4-6"  # cheaper alternative

# Cap on how many investigations to score per run.
MAX_INVESTIGATIONS = 50

# Where to write the intermediate classification CSV.
OUTPUT_CSV = "investigation_classification.csv"

# Set False to skip the note write-back (just produce the CSV).
WRITE_NOTES_VIA_API = True
# ============================================================================

import asyncio
import csv as csv_module
import io
import json
import os
import re
import sys
from urllib.parse import quote

import httpx
from anthropic import AsyncAnthropic


PRIORITIZATION_RUBRIC = """\
You are a security findings prioritization agent. Be CONCISE.

You will receive a JSON list of Splunk Mission Control investigations. Each
investigation may include fields like id, display_id, title, description,
severity, urgency, status, assignee, created_at, and additional metadata.

# Workflow

1. Score every investigation against the rubric below.
2. Group investigations sharing host/user/src_ip within ~30 minutes into
   one incident — score the incident, not individual events.
3. Output the CSV deliverable described below.

# CRITICAL: source_event_id handling

Each investigation has a `source_event_id` field that identifies the
underlying notable event. This is the value the Mission Control notes API
expects as a path parameter. Use the EXACT value as it appears in the input
JSON — do NOT synthesize, shorten, or reformat.

If an investigation has no `source_event_id`, fall back to `id`. If both
are missing, SKIP that investigation (do not include it in the CSV).

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

If a factor is unknown from the investigation data, use 2.5 (median).

# OUTPUT — final message

## 1. Executive summary (3-5 lines)

How many investigations classified, P0..P4 distribution, top 1-2 to act on.

## 2. CSV block — match this format EXACTLY:

```csv
source_event_id,ai_priority,ai_score,ai_rationale,ai_recommended_action
2a2d00e8-ac75-4207-bcbe-992e2049e42d@@notable@@time1777919948,P0,4.75,"Brief rationale","One concrete next step"
```

Header MUST be exactly: source_event_id,ai_priority,ai_score,ai_rationale,ai_recommended_action
Quote any field with commas/quotes (escape inner quotes by doubling).
Rationale ≤120 chars, action ≤80 chars. One row per investigation.

Keep the entire final message under ~1500 tokens.
"""


async def list_investigations(http: httpx.AsyncClient) -> list[dict]:
    """GET the list of Mission Control investigations."""
    url = (
        f"{SPLUNK_BASE_URL}/servicesNS/nobody/missioncontrol"
        "/public/v2/investigations"
    )
    resp = await http.get(
        url,
        headers={
            "Authorization": f"Splunk {SPLUNK_API_TOKEN}",
            "Accept": "application/json",
        },
        params={"count": str(MAX_INVESTIGATIONS)},
    )
    resp.raise_for_status()
    data = resp.json()
    # Mission Control responses can be a bare list or wrapped under a key.
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in ("items", "data", "investigations", "results", "entries"):
            if isinstance(data.get(key), list):
                return data[key]
    raise SystemExit(
        f"Unexpected investigations response shape: keys={list(data.keys()) if isinstance(data, dict) else type(data)}\n"
        f"First 500 chars: {json.dumps(data)[:500]}"
    )


async def score_with_claude(investigations: list[dict]) -> str:
    """Send the investigations to Claude and return the raw response text."""
    client = AsyncAnthropic(http_client=httpx.AsyncClient(verify=False))

    user_prompt = (
        f"Score these {len(investigations)} Splunk Mission Control "
        "investigations against the rubric in your system prompt. Emit the "
        "executive summary + CSV as specified.\n\n"
        "INVESTIGATIONS (JSON):\n```json\n"
        f"{json.dumps(investigations, indent=2, default=str)}\n```"
    )

    response = await client.messages.create(
        model=MODEL,
        max_tokens=8000,
        system=[{
            "type": "text",
            "text": PRIORITIZATION_RUBRIC,
            "cache_control": {"type": "ephemeral"},
        }],
        thinking={"type": "adaptive", "display": "summarized"},
        output_config={"effort": "medium"},
        messages=[{"role": "user", "content": user_prompt}],
    )

    sys.stderr.write(
        f"\n[claude] stop_reason={response.stop_reason} "
        f"in={response.usage.input_tokens} "
        f"out={response.usage.output_tokens}\n"
    )

    parts: list[str] = []
    for block in response.content:
        if block.type == "text" and block.text:
            parts.append(block.text)
            print(block.text, end="", flush=True)
        elif block.type == "thinking":
            text = getattr(block, "thinking", "") or ""
            if text.strip():
                preview = text[:300] + ("…" if len(text) > 300 else "")
                sys.stderr.write(f"\n[thinking] {preview}\n")
    print()
    return "".join(parts)


def extract_csv(full_text: str) -> str | None:
    match = re.search(r"```csv\s*\n(.*?)\n```", full_text, re.DOTALL | re.IGNORECASE)
    return match.group(1).strip() if match else None


async def post_note(
    http: httpx.AsyncClient, investigation_id: str, content: str
) -> tuple[int, str]:
    """POST one note to an investigation. Returns (status_code, body_preview)."""
    encoded_id = quote(str(investigation_id), safe="")
    url = (
        f"{SPLUNK_BASE_URL}/servicesNS/nobody/missioncontrol"
        f"/public/v2/investigations/{encoded_id}/notes"
    )
    payload = {
        "title": "AI Priorization",
        "content": content,
        "type": "Task",
    }
    try:
        resp = await http.post(
            url,
            json=payload,
            headers={
                "Authorization": f"Splunk {SPLUNK_API_TOKEN}",
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
        )
    except httpx.HTTPError as exc:
        return (0, repr(exc))
    return (resp.status_code, resp.text[:300])


def _row_id(row: dict[str, str]) -> str:
    """Pick the path-parameter value from a CSV row. Tries source_event_id
    first (the field Mission Control expects), then event_id, then id."""
    for key in ("source_event_id", "event_id", "id", "display_id"):
        v = (row.get(key) or "").strip()
        if v:
            return v
    return ""


async def write_notes(rows: list[dict[str, str]]) -> None:
    if not rows:
        sys.stderr.write("[notes] No rows to write.\n")
        return

    sys.stderr.write(
        f"[notes] Posting {len(rows)} notes — one POST per source_event_id "
        f"to {SPLUNK_BASE_URL}/servicesNS/nobody/missioncontrol/public/v2/"
        "investigations/<source_event_id>/notes\n"
    )

    success = 0
    skipped = 0
    failures: list[tuple[str, int, str]] = []

    async with httpx.AsyncClient(verify=not IGNORE_SSL, timeout=30.0) as http:
        for i, row in enumerate(rows, 1):
            inv_id = _row_id(row)
            if not inv_id:
                sys.stderr.write(
                    f"  [{i:>3}] SKIP — no source_event_id/event_id/id in row: "
                    f"{list(row.keys())}\n"
                )
                skipped += 1
                continue

            content = (
                f"**Priority:** {row.get('ai_priority', '')}  \n"
                f"**Score:** {row.get('ai_score', '')}  \n"
                f"**Rationale:** {row.get('ai_rationale', '')}  \n"
                f"**Recommended action:** {row.get('ai_recommended_action', '')}"
            )
            status, body = await post_note(http, inv_id, content)

            short_id = inv_id if len(inv_id) <= 60 else inv_id[:57] + "…"
            if 200 <= status < 300:
                success += 1
                sys.stderr.write(f"  [{i:>3}] OK   {status}  {short_id}\n")
            else:
                failures.append((inv_id, status, body))
                body_preview = body.replace("\n", " ")[:160]
                sys.stderr.write(
                    f"  [{i:>3}] FAIL {status}  {short_id}  → {body_preview}\n"
                )

    sys.stderr.write(
        f"[notes] {success}/{len(rows)} posted "
        f"({skipped} skipped, {len(failures)} failed).\n"
    )


async def run() -> None:
    async with httpx.AsyncClient(verify=not IGNORE_SSL, timeout=30.0) as http:
        sys.stderr.write(
            f"Fetching investigations from {SPLUNK_BASE_URL}...\n"
        )
        investigations = await list_investigations(http)
        sys.stderr.write(f"Got {len(investigations)} investigations.\n")
        if not investigations:
            sys.exit(
                "No investigations found in Mission Control. Either generate "
                "some via ES correlation searches or create one manually."
            )
        if len(investigations) > MAX_INVESTIGATIONS:
            investigations = investigations[:MAX_INVESTIGATIONS]
            sys.stderr.write(f"Capped to {MAX_INVESTIGATIONS} most recent.\n")

    full_text = await score_with_claude(investigations)
    csv_text = extract_csv(full_text)
    if not csv_text:
        sys.stderr.write(
            "[warning] No CSV block found in Claude's response. "
            "Check the output above.\n"
        )
        return

    with open(OUTPUT_CSV, "w", encoding="utf-8") as f:
        f.write(csv_text + "\n")
    sys.stderr.write(f"[saved] Wrote {OUTPUT_CSV}\n")

    if WRITE_NOTES_VIA_API:
        rows = list(csv_module.DictReader(io.StringIO(csv_text)))
        await write_notes(rows)
    else:
        sys.stderr.write("[notes] WRITE_NOTES_VIA_API is False — skipping.\n")


def main() -> None:
    if not os.environ.get("ANTHROPIC_API_KEY"):
        sys.exit("ANTHROPIC_API_KEY environment variable is not set.")
    if "paste-your-splunk-jwt-here" in SPLUNK_API_TOKEN:
        sys.exit("Edit SPLUNK_API_TOKEN at the top of mc_agent.py first.")
    asyncio.run(run())


if __name__ == "__main__":
    main()
