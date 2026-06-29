#!/usr/bin/env bash
set -euo pipefail

log() {
  printf '[workflow-alert] %s\n' "$*"
}

if [ -z "${RESEND_API_KEY:-}" ]; then
  log "skipping email alert: RESEND_API_KEY is not configured"
  exit 0
fi

if [ -z "${VEXYL_ALERT_FROM:-}" ]; then
  log "skipping email alert: VEXYL_ALERT_FROM is not configured"
  exit 0
fi

if [ -z "${VEXYL_ALERT_RECIPIENTS:-}" ]; then
  log "skipping email alert: VEXYL_ALERT_RECIPIENTS is not configured"
  exit 0
fi

command -v python3 >/dev/null 2>&1 || {
  log "skipping email alert: python3 is not available"
  exit 0
}

python3 - <<'PY'
import json
import os
import sys
import urllib.error
import urllib.request


def split_recipients(value: str) -> list[str]:
    recipients = []
    for raw in value.replace("\n", ",").split(","):
        item = raw.strip()
        if item:
            recipients.append(item)
    return recipients


api_key = os.environ["RESEND_API_KEY"]
from_addr = os.environ["VEXYL_ALERT_FROM"]
recipients = split_recipients(os.environ["VEXYL_ALERT_RECIPIENTS"])
if not recipients:
    print("[workflow-alert] skipping email alert: recipient list is empty")
    sys.exit(0)

server_url = os.environ.get("GITHUB_SERVER_URL", "https://github.com")
repository = os.environ.get("GITHUB_REPOSITORY", "unknown/repository")
run_id = os.environ.get("GITHUB_RUN_ID", "")
run_attempt = os.environ.get("GITHUB_RUN_ATTEMPT", "")
workflow = os.environ.get("GITHUB_WORKFLOW", "Unknown workflow")
job = os.environ.get("GITHUB_JOB", "unknown-job")
event_name = os.environ.get("GITHUB_EVENT_NAME", "unknown")
ref_name = os.environ.get("GITHUB_REF_NAME", "")
sha = os.environ.get("GITHUB_SHA", "")
actor = os.environ.get("GITHUB_ACTOR", "")
run_url = f"{server_url}/{repository}/actions/runs/{run_id}" if run_id else f"{server_url}/{repository}/actions"

short_sha = sha[:12] if sha else "unknown"
subject = os.environ.get(
    "VEXYL_ALERT_SUBJECT",
    f"Vexyl Guard workflow failed: {workflow}",
)

body = "\n".join(
    [
        f"Vexyl Guard workflow failure",
        "",
        f"Workflow: {workflow}",
        f"Job: {job}",
        f"Repository: {repository}",
        f"Event: {event_name}",
        f"Ref: {ref_name or 'unknown'}",
        f"Commit: {short_sha}",
        f"Actor: {actor or 'unknown'}",
        f"Run attempt: {run_attempt or 'unknown'}",
        f"Run URL: {run_url}",
        "",
        "Open the run URL to inspect the failing step and logs.",
    ]
)

payload = {
    "from": from_addr,
    "to": recipients,
    "subject": subject,
    "text": body,
}

reply_to = os.environ.get("VEXYL_ALERT_REPLY_TO", "").strip()
if reply_to:
    payload["reply_to"] = reply_to

request = urllib.request.Request(
    "https://api.resend.com/emails",
    data=json.dumps(payload).encode("utf-8"),
    headers={
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    },
    method="POST",
)

try:
    with urllib.request.urlopen(request, timeout=20) as response:
        response_body = response.read().decode("utf-8", errors="replace")
        print(f"[workflow-alert] sent failure email via Resend: {response.status} {response_body}")
except urllib.error.HTTPError as exc:
    error_body = exc.read().decode("utf-8", errors="replace")
    print(f"[workflow-alert] Resend returned HTTP {exc.code}: {error_body}", file=sys.stderr)
    sys.exit(0)
except Exception as exc:
    print(f"[workflow-alert] could not send failure email: {exc}", file=sys.stderr)
    sys.exit(0)
PY
