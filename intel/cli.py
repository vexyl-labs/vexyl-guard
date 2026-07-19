from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

from .database import (
    default_db_path,
    init_db,
    purge_runtime_history,
    runtime_history_status,
    search_threats,
    seed_db,
    validate_seed_file,
)
from .client import GatewayClientError, VexylGatewayClient
from .gateway import (
    DEFAULT_DB_PATH as DEFAULT_GATEWAY_DB_PATH,
    DEFAULT_MAX_BODY_BYTES,
    DEFAULT_SOCKET_PATH,
    DEFAULT_TOKEN_FILE,
    GatewayConfigurationError,
    create_gateway_token_file,
    parse_socket_mode,
    read_gateway_token,
    serve_gateway,
)
from .models import RuntimeAIEvent
from .scoring import (
    evaluate_agent_plan,
    evaluate_tool_call,
    scan_external_content,
    scan_prompt,
    score_ai_event,
    score_and_record_ai_event,
)
from .updates import (
    DEFAULT_REVOKED_KEYS_FILE,
    DEFAULT_TOKEN_FILE as DEFAULT_INTEL_TOKEN_FILE,
    DEFAULT_TRUSTED_KEY_DIR,
    IntelUpdateError,
    apply_intel_bundle,
    intel_update_status,
    recover_intel_database,
    rollback_intel_bundle,
    sync_intel_bundle,
    verify_intel_bundle,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="vexyl", description="Vexyl Guard local defensive tooling."
    )
    subparsers = parser.add_subparsers(dest="command")

    threat = subparsers.add_parser(
        "threat", help="Manage and use local AI threat intelligence."
    )
    threat.add_argument(
        "--db", default=None, help=f"SQLite DB path. Default: {default_db_path()}"
    )
    threat_sub = threat.add_subparsers(dest="threat_command")

    threat_sub.add_parser(
        "init-db", help="Initialize the local AI threat intelligence database."
    )

    seed = threat_sub.add_parser("seed", help="Load bundled AI threat seed records.")
    seed.add_argument(
        "--seed-file", default=None, help="Optional JSONL seed file path."
    )

    validate_seed = threat_sub.add_parser(
        "validate-seed", help="Validate seed data safety and shape."
    )
    validate_seed.add_argument(
        "--seed-file", default=None, help="Optional JSONL seed file path."
    )

    search = threat_sub.add_parser(
        "search", help="Search the local AI threat database."
    )
    search.add_argument("query")
    search.add_argument("--limit", type=int, default=25)
    search.add_argument(
        "--json", action="store_true", help="Emit JSON instead of a compact text table."
    )

    score_event = threat_sub.add_parser(
        "score-event", help="Score a v1 runtime AI event JSON file."
    )
    score_event.add_argument("event_json")
    score_event.add_argument(
        "--record", action="store_true", help="Store a redacted runtime event record."
    )
    score_event.add_argument(
        "--policy-exit-code",
        action="store_true",
        help="Return 3 for approval-required decisions or 4 for deny/quarantine decisions.",
    )

    scan_prompt_parser = threat_sub.add_parser(
        "scan-prompt", help="Scan a prompt text file."
    )
    scan_prompt_parser.add_argument("file")
    scan_prompt_parser.add_argument("--data-classification", default="unknown")
    scan_prompt_parser.add_argument("--input-channel", default="chat")
    scan_prompt_parser.add_argument("--origin", default="user")

    scan_rag_parser = threat_sub.add_parser(
        "scan-rag-doc", help="Scan an external/RAG document as untrusted data."
    )
    scan_rag_parser.add_argument("file")
    scan_rag_parser.add_argument("--source-name", default=None)
    scan_rag_parser.add_argument("--signed-trusted-corpus", action="store_true")
    scan_rag_parser.add_argument("--data-classification", default="unknown")

    eval_plan = threat_sub.add_parser(
        "evaluate-agent-plan", help="Evaluate an agent plan JSON/text file."
    )
    eval_plan.add_argument("file")
    eval_plan.add_argument("--tool-manifest", default=None)
    eval_plan.add_argument("--user-scope", default=None)

    eval_tool = threat_sub.add_parser(
        "evaluate-tool-call", help="Evaluate a tool call JSON file."
    )
    eval_tool.add_argument("file")
    eval_tool.add_argument("--context", default=None)

    threat_sub.add_parser(
        "runtime-status", help="Show privacy-safe runtime-correlation history counts."
    )

    purge_history = threat_sub.add_parser(
        "purge-runtime-history", help="Delete local runtime-correlation history."
    )
    purge_history.add_argument(
        "--yes",
        action="store_true",
        help="Confirm deletion without an interactive prompt.",
    )

    verify_bundle = threat_sub.add_parser(
        "verify-intel-bundle",
        help="Verify a signed defensive intelligence bundle without applying it.",
    )
    verify_bundle.add_argument("bundle")
    add_intel_trust_arguments(verify_bundle)

    apply_bundle = threat_sub.add_parser(
        "apply-intel-bundle",
        help="Verify and atomically activate a signed intelligence bundle.",
    )
    apply_bundle.add_argument("bundle")
    add_intel_trust_arguments(apply_bundle, include_lkg=True)

    sync_intel = threat_sub.add_parser(
        "sync-intel",
        help="Download, verify, and atomically activate signed intelligence.",
    )
    sync_intel.add_argument(
        "--url",
        default=os.environ.get("VEXYL_INTEL_BUNDLE_URL"),
        help="HTTPS bundle endpoint. Defaults to VEXYL_INTEL_BUNDLE_URL.",
    )
    sync_intel.add_argument(
        "--token-file",
        default=os.environ.get("VEXYL_INTEL_TOKEN_FILE", DEFAULT_INTEL_TOKEN_FILE),
        help="Private bearer token file used for bundle download.",
    )
    sync_intel.add_argument(
        "--timeout",
        type=float,
        default=float(os.environ.get("VEXYL_INTEL_SYNC_TIMEOUT", "15")),
    )
    add_intel_trust_arguments(sync_intel, include_lkg=True)

    intel_status = threat_sub.add_parser(
        "intel-status",
        help="Show signed intelligence version, freshness, and recovery status.",
    )
    intel_status.add_argument(
        "--lkg",
        default=os.environ.get("VEXYL_INTEL_LKG_DB"),
        help="Optional last-known-good database path.",
    )

    rollback_intel = threat_sub.add_parser(
        "rollback-intel",
        help="Explicitly restore the last-known-good intelligence records.",
    )
    rollback_intel.add_argument(
        "--lkg",
        default=os.environ.get("VEXYL_INTEL_LKG_DB"),
        help="Optional last-known-good database path.",
    )
    rollback_intel.add_argument("--yes", action="store_true")

    recover_intel = threat_sub.add_parser(
        "recover-intel",
        help="Recover a corrupt intelligence database from last-known-good.",
    )
    recover_intel.add_argument(
        "--lkg",
        default=os.environ.get("VEXYL_INTEL_LKG_DB"),
        help="Optional last-known-good database path.",
    )
    recover_intel.add_argument("--yes", action="store_true")

    gateway = subparsers.add_parser(
        "gateway", help="Run or query the authenticated local AI decision gateway."
    )
    gateway.add_argument(
        "--db",
        default=os.environ.get("VEXYL_AI_GATEWAY_DB", DEFAULT_GATEWAY_DB_PATH),
        help="SQLite threat database path.",
    )
    gateway.add_argument(
        "--socket",
        default=os.environ.get("VEXYL_AI_GATEWAY_SOCKET", DEFAULT_SOCKET_PATH),
        help="Unix socket path.",
    )
    gateway.add_argument(
        "--token-file",
        default=os.environ.get("VEXYL_AI_GATEWAY_TOKEN_FILE", DEFAULT_TOKEN_FILE),
        help="Bearer token file path.",
    )
    gateway_sub = gateway.add_subparsers(dest="gateway_command")

    init_token = gateway_sub.add_parser(
        "init-token", help="Create a private local gateway bearer token."
    )
    init_token.add_argument("--force", action="store_true")
    init_token.add_argument(
        "--group",
        default=os.environ.get("VEXYL_AI_GATEWAY_SOCKET_GROUP") or None,
        help="Optional group granted read access to the token.",
    )

    serve = gateway_sub.add_parser(
        "serve", help="Serve authenticated decisions over a local Unix socket."
    )
    serve.add_argument(
        "--max-body-bytes",
        type=int,
        default=int(
            os.environ.get("VEXYL_AI_GATEWAY_MAX_BODY_BYTES", DEFAULT_MAX_BODY_BYTES)
        ),
    )
    serve.add_argument(
        "--socket-mode",
        default=os.environ.get("VEXYL_AI_GATEWAY_SOCKET_MODE", "0660"),
    )
    serve.add_argument(
        "--socket-group",
        default=os.environ.get("VEXYL_AI_GATEWAY_SOCKET_GROUP") or None,
    )

    gateway_sub.add_parser("health", help="Check the authenticated local gateway.")
    gateway_score = gateway_sub.add_parser(
        "score-event", help="Submit a redacted event JSON file to the local gateway."
    )
    gateway_score.add_argument("event_json")
    gateway_score.add_argument("--policy-exit-code", action="store_true")

    args = parser.parse_args(argv)
    if args.command == "gateway":
        return handle_gateway_command(args, gateway)
    if args.command != "threat":
        parser.print_help()
        return 2
    if not args.threat_command:
        threat.print_help()
        return 2

    db_path = args.db
    if args.threat_command in {
        "verify-intel-bundle",
        "apply-intel-bundle",
        "sync-intel",
        "intel-status",
        "rollback-intel",
        "recover-intel",
    }:
        return handle_intel_update_command(args)

    if args.threat_command == "init-db":
        path = init_db(db_path)
        print_json({"ok": True, "db": str(path)})
        return 0

    if args.threat_command == "seed":
        counts = seed_db(db_path, args.seed_file)
        print_json(
            {"ok": True, "db": str(db_path or default_db_path()), "seeded": counts}
        )
        return 0

    if args.threat_command == "validate-seed":
        count = validate_seed_file(args.seed_file)
        print_json(
            {
                "ok": True,
                "records": count,
                "safety_boundary": "defensive summaries only",
            }
        )
        return 0

    if args.threat_command == "search":
        results = search_threats(args.query, db_path=db_path, limit=args.limit)
        if args.json:
            print_json(
                {
                    "ok": True,
                    "query": args.query,
                    "count": len(results),
                    "results": results,
                }
            )
        else:
            print_search_results(results)
        return 0

    if args.threat_command == "score-event":
        event_data = read_json_file(args.event_json)
        event = RuntimeAIEvent.from_dict(event_data)
        decision = (
            score_and_record_ai_event(event, db_path=db_path)
            if args.record
            else score_ai_event(event, db_path=db_path)
        )
        print_json({"ok": True, "decision": decision.to_dict()})
        if args.policy_exit_code:
            if decision.score >= 70:
                return 4
            if decision.score >= 50:
                return 3
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
        tool_manifest = (
            read_maybe_json_file(args.tool_manifest) if args.tool_manifest else None
        )
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

    if args.threat_command == "runtime-status":
        print_json({"ok": True, "runtime_history": runtime_history_status(db_path)})
        return 0

    if args.threat_command == "purge-runtime-history":
        if not args.yes:
            raise SystemExit("Refusing to purge runtime history without --yes")
        deleted = purge_runtime_history(db_path)
        print_json(
            {
                "ok": True,
                "deleted_events": deleted,
                "db": str(db_path or default_db_path()),
            }
        )
        return 0

    threat.print_help()
    return 2


def add_intel_trust_arguments(
    parser: argparse.ArgumentParser, *, include_lkg: bool = False
) -> None:
    parser.add_argument(
        "--trusted-key-dir",
        default=os.environ.get("VEXYL_INTEL_TRUSTED_KEY_DIR", DEFAULT_TRUSTED_KEY_DIR),
        help="Directory containing trusted RSA public keys named by bundle key id.",
    )
    parser.add_argument(
        "--revoked-keys-file",
        default=os.environ.get(
            "VEXYL_INTEL_REVOKED_KEYS_FILE", DEFAULT_REVOKED_KEYS_FILE
        ),
        help="File containing revoked signing key ids.",
    )
    if include_lkg:
        parser.add_argument(
            "--lkg",
            default=os.environ.get("VEXYL_INTEL_LKG_DB"),
            help="Optional last-known-good database path.",
        )


def handle_intel_update_command(args: argparse.Namespace) -> int:
    try:
        if args.threat_command == "verify-intel-bundle":
            verified = verify_intel_bundle(
                args.bundle,
                trusted_key_dir=args.trusted_key_dir,
                revoked_keys_file=args.revoked_keys_file,
            )
            print_json({"ok": True, "bundle": verified.public_metadata()})
            return 0

        if args.threat_command == "apply-intel-bundle":
            print_json(
                apply_intel_bundle(
                    args.bundle,
                    db_path=args.db,
                    trusted_key_dir=args.trusted_key_dir,
                    revoked_keys_file=args.revoked_keys_file,
                    lkg_path=args.lkg,
                )
            )
            return 0

        if args.threat_command == "sync-intel":
            if not args.url:
                raise IntelUpdateError("VEXYL_INTEL_BUNDLE_URL is not configured")
            print_json(
                sync_intel_bundle(
                    url=args.url,
                    token_file=args.token_file,
                    db_path=args.db,
                    trusted_key_dir=args.trusted_key_dir,
                    revoked_keys_file=args.revoked_keys_file,
                    lkg_path=args.lkg,
                    timeout=args.timeout,
                )
            )
            return 0

        if args.threat_command == "intel-status":
            print_json(
                {
                    "ok": True,
                    "intelligence": intel_update_status(args.db, lkg_path=args.lkg),
                }
            )
            return 0

        if args.threat_command == "rollback-intel":
            print_json(
                rollback_intel_bundle(
                    args.db,
                    lkg_path=args.lkg,
                    confirmed=args.yes,
                )
            )
            return 0

        if args.threat_command == "recover-intel":
            if not args.yes:
                raise IntelUpdateError(
                    "explicit confirmation is required for intelligence recovery"
                )
            print_json(
                recover_intel_database(
                    args.db,
                    lkg_path=args.lkg,
                    only_if_corrupt=True,
                )
            )
            return 0
    except IntelUpdateError as exc:
        print(f"Intelligence update error: {exc}", file=sys.stderr)
        return 2

    return 2


def handle_gateway_command(
    args: argparse.Namespace, parser: argparse.ArgumentParser
) -> int:
    if not args.gateway_command:
        parser.print_help()
        return 2
    try:
        if args.gateway_command == "init-token":
            path = create_gateway_token_file(
                args.token_file, force=args.force, group=args.group
            )
            print_json({"ok": True, "token_file": str(path), "token_printed": False})
            return 0

        if args.gateway_command == "serve":
            token = read_gateway_token(args.token_file)
            serve_gateway(
                db_path=args.db,
                socket_path=args.socket,
                token=token,
                max_body_bytes=args.max_body_bytes,
                socket_mode=parse_socket_mode(args.socket_mode),
                socket_group=args.socket_group,
            )
            return 0

        client = VexylGatewayClient(
            socket_path=args.socket,
            token_file=args.token_file,
        )
        if args.gateway_command == "health":
            print_json(client.health())
            return 0
        if args.gateway_command == "score-event":
            response = client.score(read_json_file(args.event_json))
            print_json(response)
            return (
                int(response.get("policy_exit_code") or 0)
                if args.policy_exit_code
                else 0
            )
    except FileExistsError:
        print(
            f"Gateway token already exists: {args.token_file}. Use --force to rotate it.",
            file=sys.stderr,
        )
        return 2
    except (GatewayConfigurationError, GatewayClientError) as exc:
        print(f"Gateway error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 0

    parser.print_help()
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
