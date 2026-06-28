from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from .database import default_db_path, init_db, search_threats, seed_db, validate_seed_file
from .models import RuntimeAIEvent
from .scoring import evaluate_agent_plan, evaluate_tool_call, scan_external_content, scan_prompt, score_ai_event


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="vexyl", description="Vexyl Guard local defensive tooling.")
    subparsers = parser.add_subparsers(dest="command")

    threat = subparsers.add_parser("threat", help="Manage and use local AI threat intelligence.")
    threat.add_argument("--db", default=None, help=f"SQLite DB path. Default: {default_db_path()}")
    threat_sub = threat.add_subparsers(dest="threat_command")

    threat_sub.add_parser("init-db", help="Initialize the local AI threat intelligence database.")

    seed = threat_sub.add_parser("seed", help="Load bundled AI threat seed records.")
    seed.add_argument("--seed-file", default=None, help="Optional JSONL seed file path.")

    validate_seed = threat_sub.add_parser("validate-seed", help="Validate seed data safety and shape.")
    validate_seed.add_argument("--seed-file", default=None, help="Optional JSONL seed file path.")

    search = threat_sub.add_parser("search", help="Search the local AI threat database.")
    search.add_argument("query")
    search.add_argument("--limit", type=int, default=25)
    search.add_argument("--json", action="store_true", help="Emit JSON instead of a compact text table.")

    score_event = threat_sub.add_parser("score-event", help="Score a v1 runtime AI event JSON file.")
    score_event.add_argument("event_json")
    score_event.add_argument("--record", action="store_true", help="Store a redacted runtime event record.")

    scan_prompt_parser = threat_sub.add_parser("scan-prompt", help="Scan a prompt text file.")
    scan_prompt_parser.add_argument("file")
    scan_prompt_parser.add_argument("--data-classification", default="unknown")
    scan_prompt_parser.add_argument("--input-channel", default="chat")
    scan_prompt_parser.add_argument("--origin", default="user")

    scan_rag_parser = threat_sub.add_parser("scan-rag-doc", help="Scan an external/RAG document as untrusted data.")
    scan_rag_parser.add_argument("file")
    scan_rag_parser.add_argument("--source-name", default=None)
    scan_rag_parser.add_argument("--signed-trusted-corpus", action="store_true")
    scan_rag_parser.add_argument("--data-classification", default="unknown")

    eval_plan = threat_sub.add_parser("evaluate-agent-plan", help="Evaluate an agent plan JSON/text file.")
    eval_plan.add_argument("file")
    eval_plan.add_argument("--tool-manifest", default=None)
    eval_plan.add_argument("--user-scope", default=None)

    eval_tool = threat_sub.add_parser("evaluate-tool-call", help="Evaluate a tool call JSON file.")
    eval_tool.add_argument("file")
    eval_tool.add_argument("--context", default=None)

    args = parser.parse_args(argv)
    if args.command != "threat":
        parser.print_help()
        return 2
    if not args.threat_command:
        threat.print_help()
        return 2

    db_path = args.db
    if args.threat_command == "init-db":
        path = init_db(db_path)
        print_json({"ok": True, "db": str(path)})
        return 0

    if args.threat_command == "seed":
        counts = seed_db(db_path, args.seed_file)
        print_json({"ok": True, "db": str(db_path or default_db_path()), "seeded": counts})
        return 0

    if args.threat_command == "validate-seed":
        count = validate_seed_file(args.seed_file)
        print_json({"ok": True, "records": count, "safety_boundary": "defensive summaries only"})
        return 0

    if args.threat_command == "search":
        results = search_threats(args.query, db_path=db_path, limit=args.limit)
        if args.json:
            print_json({"ok": True, "query": args.query, "count": len(results), "results": results})
        else:
            print_search_results(results)
        return 0

    if args.threat_command == "score-event":
        event_data = read_json_file(args.event_json)
        event = RuntimeAIEvent.from_dict(event_data)
        decision = score_ai_event(event, db_path=db_path)
        if args.record:
            from .database import record_runtime_event

            record_runtime_event(event.to_dict(), decision.to_dict(), db_path=db_path)
        print_json({"ok": True, "decision": decision.to_dict()})
        return 0

    if args.threat_command == "scan-prompt":
        text = read_text_file(args.file)
        decision = scan_prompt(
            text,
            {
                "data_classification": args.data_classification,
                "input_channel": args.input_channel,
                "data_origin": args.origin,
            },
            db_path=db_path,
        )
        print_json({"ok": True, "decision": decision.to_dict()})
        return 0

    if args.threat_command == "scan-rag-doc":
        text = read_text_file(args.file)
        decision = scan_external_content(
            text,
            {
                "source_name": args.source_name,
                "signed_trusted_corpus": args.signed_trusted_corpus,
                "data_classification": args.data_classification,
            },
            db_path=db_path,
        )
        print_json({"ok": True, "decision": decision.to_dict()})
        return 0

    if args.threat_command == "evaluate-agent-plan":
        plan = read_maybe_json_file(args.file)
        tool_manifest = read_maybe_json_file(args.tool_manifest) if args.tool_manifest else None
        user_scope = read_maybe_json_file(args.user_scope) if args.user_scope else None
        decision = evaluate_agent_plan(plan, tool_manifest, user_scope, db_path=db_path)
        print_json({"ok": True, "decision": decision.to_dict()})
        return 0

    if args.threat_command == "evaluate-tool-call":
        tool_call = read_json_file(args.file)
        context = read_json_file(args.context) if args.context else {}
        decision = evaluate_tool_call(tool_call, context, db_path=db_path)
        print_json({"ok": True, "decision": decision.to_dict()})
        return 0

    threat.print_help()
    return 2


def read_text_file(path: str) -> str:
    return Path(path).read_text(encoding="utf-8")


def read_json_file(path: str | None) -> dict[str, Any]:
    if not path:
        return {}
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise SystemExit(f"{path} must contain a JSON object")
    return data


def read_maybe_json_file(path: str | None) -> Any:
    if not path:
        return None
    text = read_text_file(path)
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return text


def print_json(payload: dict[str, Any]) -> None:
    json.dump(payload, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")


def print_search_results(results: list[dict[str, Any]]) -> None:
    if not results:
        print("No matching AI threat records.")
        return
    for result in results:
        print(
            f"{result['attack_id']}\t{result['name']}\t"
            f"family={result['family']}\tseverity={result['severity']}"
        )
        print(f"  {result['summary']}")


if __name__ == "__main__":
    raise SystemExit(main())
