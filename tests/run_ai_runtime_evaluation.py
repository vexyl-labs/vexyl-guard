from __future__ import annotations

import argparse
import json
import math
import re
import sqlite3
import tempfile
from pathlib import Path
from typing import Any

from intel.database import PUBLIC_SCHEMA_SQL, PUBLIC_SEED_RECORDS, seed_records_into_db
from intel.gateway import decision_policy_exit_code
from intel.integration import GatewayEventError, validate_gateway_event
from intel.scoring import redact_text, score_ai_event

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_FIXTURE_PATH = ROOT / "tests/fixtures/evaluation/ai-runtime-evaluation.json"
SUITE_SCHEMA = "vexyl.ai_runtime_evaluation.v1"
REPORT_SCHEMA = "vexyl.ai_runtime_evaluation_report.v1"
LABELS = {"benign", "risk"}
ALLOWED_SUITE_FIELDS = {
    "schema",
    "description",
    "content_policy",
    "detection_threshold",
    "thresholds",
    "event_defaults",
    "cases",
}
EXPECTED_ACTIONS = {
    "allow/log",
    "warn/log",
    "require human approval or policy verifier",
    "quarantine/block tool action",
    "block and open incident",
}
ALLOWED_CASE_FIELDS = {
    "id",
    "title",
    "category",
    "label",
    "fixture_type",
    "requires_intervention",
    "event",
    "expected",
}
ALLOWED_EXPECTED_FIELDS = {
    "min_score",
    "max_score",
    "policy_exit_code",
    "suggested_action",
    "trust_level",
    "deny_tool_call",
    "required_attack_ids",
}
FORBIDDEN_CONTENT_KEYS = {
    "command_line",
    "exploit",
    "exploit_code",
    "full_prompt",
    "full_text_ref",
    "malware_code",
    "payload",
    "raw_log",
    "raw_prompt",
    "raw_text",
    "secret",
    "shell_command",
}
FORBIDDEN_TEXT_PATTERNS = (
    re.compile(r"https?://", re.IGNORECASE),
    re.compile(r"```"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"^#!", re.MULTILINE),
)


class EvaluationFixtureError(ValueError):
    """Raised when the evaluation corpus violates its schema or safety boundary."""


def load_suite(path: Path = DEFAULT_FIXTURE_PATH) -> dict[str, Any]:
    try:
        suite = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise EvaluationFixtureError(f"unable to load evaluation suite: {exc}") from exc
    validate_suite(suite)
    return suite


def validate_suite(suite: dict[str, Any]) -> None:
    if not isinstance(suite, dict):
        raise EvaluationFixtureError("evaluation suite must be a JSON object")
    if set(suite) != ALLOWED_SUITE_FIELDS:
        raise EvaluationFixtureError("evaluation suite fields do not match the schema")
    _validate_safe_content(suite, "suite")
    if suite.get("schema") != SUITE_SCHEMA:
        raise EvaluationFixtureError("unsupported evaluation suite schema")
    if suite.get("content_policy") != "synthetic_defensive_summaries_only":
        raise EvaluationFixtureError("evaluation suite must declare its content policy")

    detection_threshold = suite.get("detection_threshold")
    if (
        isinstance(detection_threshold, bool)
        or not isinstance(detection_threshold, int)
        or not 0 <= detection_threshold <= 100
    ):
        raise EvaluationFixtureError(
            "detection_threshold must be an integer from 0 to 100"
        )

    thresholds = suite.get("thresholds")
    if not isinstance(thresholds, dict):
        raise EvaluationFixtureError("thresholds must be an object")
    expected_thresholds = {
        "min_precision",
        "min_recall",
        "min_specificity",
        "min_accuracy",
        "max_benign_intervention_rate",
        "min_critical_intervention_recall",
    }
    if set(thresholds) != expected_thresholds:
        raise EvaluationFixtureError("evaluation thresholds do not match the schema")
    for name, value in thresholds.items():
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not 0 <= float(value) <= 1
        ):
            raise EvaluationFixtureError(f"{name} must be between 0 and 1")

    event_defaults = suite.get("event_defaults")
    if not isinstance(event_defaults, dict):
        raise EvaluationFixtureError("event_defaults must be an object")
    _validate_safe_content(event_defaults, "event_defaults")

    cases = suite.get("cases")
    if not isinstance(cases, list) or not cases:
        raise EvaluationFixtureError("cases must be a non-empty array")

    case_ids: set[str] = set()
    labels: set[str] = set()
    categories: set[str] = set()
    for index, case in enumerate(cases, start=1):
        location = f"case {index}"
        if not isinstance(case, dict):
            raise EvaluationFixtureError(f"{location} must be an object")
        unknown = sorted(set(case) - ALLOWED_CASE_FIELDS)
        if unknown:
            raise EvaluationFixtureError(
                f"{location} has unsupported field: {unknown[0]}"
            )

        case_id = case.get("id")
        if not isinstance(case_id, str) or not re.fullmatch(
            r"[a-z0-9-]{3,80}", case_id
        ):
            raise EvaluationFixtureError(f"{location} has an invalid id")
        if case_id in case_ids:
            raise EvaluationFixtureError(f"duplicate case id: {case_id}")
        case_ids.add(case_id)

        title = case.get("title")
        if not isinstance(title, str) or not title.strip() or len(title) > 120:
            raise EvaluationFixtureError(f"{case_id} has an invalid title")
        category = case.get("category")
        if not isinstance(category, str) or not re.fullmatch(
            r"[a-z0-9_]{3,80}", category
        ):
            raise EvaluationFixtureError(f"{case_id} has an invalid category")
        categories.add(category)

        label = case.get("label")
        if label not in LABELS:
            raise EvaluationFixtureError(f"{case_id} has an invalid label")
        labels.add(label)
        if case.get("fixture_type") != "defensive_summary":
            raise EvaluationFixtureError(f"{case_id} is not a defensive summary")
        if not isinstance(case.get("requires_intervention"), bool):
            raise EvaluationFixtureError(
                f"{case_id} requires_intervention must be boolean"
            )
        if label == "benign" and case["requires_intervention"]:
            raise EvaluationFixtureError(
                f"{case_id} cannot label a benign case as requiring intervention"
            )

        event = case.get("event")
        if not isinstance(event, dict):
            raise EvaluationFixtureError(f"{case_id} event must be an object")
        _validate_safe_content(event, f"{case_id}.event")
        merged_event = {**event_defaults, **event, "event_id": case_id}
        try:
            validate_gateway_event(merged_event)
        except GatewayEventError as exc:
            raise EvaluationFixtureError(f"{case_id} event is invalid: {exc}") from exc

        expected = case.get("expected")
        _validate_expected(case_id, expected)
        expected_intervention = expected["policy_exit_code"] in {3, 4}
        if case["requires_intervention"] != expected_intervention:
            raise EvaluationFixtureError(
                f"{case_id} intervention label does not match its policy outcome"
            )
        if label == "benign" and expected["required_attack_ids"]:
            raise EvaluationFixtureError(
                f"{case_id} benign fixtures cannot require attack matches"
            )

    if labels != LABELS:
        raise EvaluationFixtureError("suite must contain both benign and risk cases")
    if len(categories) < 2:
        raise EvaluationFixtureError("suite must cover more than one category")


def evaluate_suite(suite: dict[str, Any]) -> dict[str, Any]:
    validate_suite(suite)
    detection_threshold = int(suite["detection_threshold"])
    case_results: list[dict[str, Any]] = []

    with tempfile.TemporaryDirectory(prefix="vexyl-evaluation-") as directory:
        root = Path(directory)
        for case in suite["cases"]:
            db_path = root / f"{case['id']}.sqlite"
            with sqlite3.connect(db_path) as connection:
                connection.executescript(PUBLIC_SCHEMA_SQL)
            # Keep the regression corpus independent from optional local intel files.
            seed_records_into_db(db_path, PUBLIC_SEED_RECORDS)
            event_data = {
                **suite["event_defaults"],
                **case["event"],
                "event_id": case["id"],
            }
            event = validate_gateway_event(event_data)
            decision = score_ai_event(event, db_path=str(db_path))
            decision_data = decision.to_dict()
            policy_exit_code = decision_policy_exit_code(decision_data)
            predicted_label = (
                "risk" if decision.score >= detection_threshold else "benign"
            )
            failures = _case_failures(
                case,
                decision_data,
                policy_exit_code,
                predicted_label,
            )
            case_results.append(
                {
                    "id": case["id"],
                    "title": case["title"],
                    "category": case["category"],
                    "label": case["label"],
                    "predicted_label": predicted_label,
                    "requires_intervention": case["requires_intervention"],
                    "intervened": policy_exit_code in {3, 4},
                    "score": decision.score,
                    "policy_exit_code": policy_exit_code,
                    "suggested_action": decision.suggested_action,
                    "trust_level": decision.trust_level,
                    "deny_tool_call": decision.deny_tool_call,
                    "matched_attack_ids": sorted(decision.matched_attack_ids),
                    "passed": not failures,
                    "failures": failures,
                }
            )

    metrics = _classification_metrics(case_results)
    operational = _operational_metrics(case_results)
    coverage = _coverage(case_results)
    threshold_failures = _threshold_failures(suite["thresholds"], metrics, operational)
    case_failures = [
        f"{case['id']}: {failure}"
        for case in case_results
        for failure in case["failures"]
    ]
    failures = case_failures + threshold_failures
    return {
        "schema": REPORT_SCHEMA,
        "suite_schema": suite["schema"],
        "content_policy": suite["content_policy"],
        "case_count": len(case_results),
        "detection_threshold": detection_threshold,
        "classification": metrics,
        "operations": operational,
        "coverage": coverage,
        "thresholds": suite["thresholds"],
        "passed": not failures,
        "failures": failures,
        "cases": case_results,
    }


def _validate_expected(case_id: str, expected: Any) -> None:
    if not isinstance(expected, dict):
        raise EvaluationFixtureError(f"{case_id} expected must be an object")
    unknown = sorted(set(expected) - ALLOWED_EXPECTED_FIELDS)
    if unknown:
        raise EvaluationFixtureError(
            f"{case_id} expected has unsupported field: {unknown[0]}"
        )
    if set(expected) != ALLOWED_EXPECTED_FIELDS:
        raise EvaluationFixtureError(f"{case_id} expected fields are incomplete")
    minimum = expected["min_score"]
    maximum = expected["max_score"]
    if (
        isinstance(minimum, bool)
        or isinstance(maximum, bool)
        or not isinstance(minimum, int)
        or not isinstance(maximum, int)
        or not 0 <= minimum <= maximum <= 100
    ):
        raise EvaluationFixtureError(f"{case_id} expected score range is invalid")
    if expected["policy_exit_code"] not in {0, 3, 4}:
        raise EvaluationFixtureError(f"{case_id} expected policy code is invalid")
    if expected["suggested_action"] not in EXPECTED_ACTIONS:
        raise EvaluationFixtureError(f"{case_id} expected action is invalid")
    if not isinstance(expected["trust_level"], str):
        raise EvaluationFixtureError(f"{case_id} expected trust level is invalid")
    if not isinstance(expected["deny_tool_call"], bool):
        raise EvaluationFixtureError(f"{case_id} expected deny flag is invalid")
    attack_ids = expected["required_attack_ids"]
    if not isinstance(attack_ids, list) or any(
        not isinstance(attack_id, str) for attack_id in attack_ids
    ):
        raise EvaluationFixtureError(f"{case_id} required attack ids are invalid")
    public_ids = {record["attack_id"] for record in PUBLIC_SEED_RECORDS}
    unknown_ids = sorted(set(attack_ids) - public_ids)
    if unknown_ids:
        raise EvaluationFixtureError(
            f"{case_id} references unknown attack id: {unknown_ids[0]}"
        )


def _validate_safe_content(value: Any, location: str) -> None:
    if isinstance(value, dict):
        for key, nested in value.items():
            normalized_key = str(key).lower()
            if normalized_key in FORBIDDEN_CONTENT_KEYS:
                raise EvaluationFixtureError(
                    f"{location} contains forbidden content field: {key}"
                )
            _validate_safe_content(nested, f"{location}.{key}")
        return
    if isinstance(value, list):
        for index, nested in enumerate(value):
            _validate_safe_content(nested, f"{location}[{index}]")
        return
    if not isinstance(value, str):
        return
    if len(value) > 600:
        raise EvaluationFixtureError(f"{location} text exceeds the fixture limit")
    if any(pattern.search(value) for pattern in FORBIDDEN_TEXT_PATTERNS):
        raise EvaluationFixtureError(f"{location} contains disallowed runnable content")
    if redact_text(value, limit=10_000) != value:
        raise EvaluationFixtureError(f"{location} contains redactable sensitive data")


def _case_failures(
    case: dict[str, Any],
    decision: dict[str, Any],
    policy_exit_code: int,
    predicted_label: str,
) -> list[str]:
    expected = case["expected"]
    failures: list[str] = []
    score = int(decision["score"])
    if not expected["min_score"] <= score <= expected["max_score"]:
        failures.append(
            f"score {score} outside {expected['min_score']}-{expected['max_score']}"
        )
    if predicted_label != case["label"]:
        failures.append(f"classified {predicted_label}, expected {case['label']}")
    comparisons = {
        "policy_exit_code": policy_exit_code,
        "suggested_action": decision["suggested_action"],
        "trust_level": decision["trust_level"],
        "deny_tool_call": decision["deny_tool_call"],
    }
    for name, actual in comparisons.items():
        if actual != expected[name]:
            failures.append(f"{name} was {actual!r}, expected {expected[name]!r}")
    missing_ids = sorted(
        set(expected["required_attack_ids"]) - set(decision["matched_attack_ids"])
    )
    if missing_ids:
        failures.append(f"missing attack ids: {', '.join(missing_ids)}")
    if case["requires_intervention"] and policy_exit_code not in {3, 4}:
        failures.append("critical case did not trigger intervention")
    return failures


def _classification_metrics(cases: list[dict[str, Any]]) -> dict[str, Any]:
    true_positive = sum(
        case["label"] == "risk" and case["predicted_label"] == "risk" for case in cases
    )
    true_negative = sum(
        case["label"] == "benign" and case["predicted_label"] == "benign"
        for case in cases
    )
    false_positive = sum(
        case["label"] == "benign" and case["predicted_label"] == "risk"
        for case in cases
    )
    false_negative = sum(
        case["label"] == "risk" and case["predicted_label"] == "benign"
        for case in cases
    )
    return {
        "true_positive": true_positive,
        "true_negative": true_negative,
        "false_positive": false_positive,
        "false_negative": false_negative,
        "precision": _ratio(true_positive, true_positive + false_positive),
        "recall": _ratio(true_positive, true_positive + false_negative),
        "specificity": _ratio(true_negative, true_negative + false_positive),
        "accuracy": _ratio(true_positive + true_negative, len(cases)),
    }


def _operational_metrics(cases: list[dict[str, Any]]) -> dict[str, float | int]:
    benign = [case for case in cases if case["label"] == "benign"]
    critical = [case for case in cases if case["requires_intervention"]]
    benign_interventions = sum(case["intervened"] for case in benign)
    critical_interventions = sum(case["intervened"] for case in critical)
    return {
        "benign_case_count": len(benign),
        "benign_intervention_count": benign_interventions,
        "benign_intervention_rate": _ratio(benign_interventions, len(benign)),
        "critical_case_count": len(critical),
        "critical_intervention_count": critical_interventions,
        "critical_intervention_recall": _ratio(critical_interventions, len(critical)),
    }


def _coverage(cases: list[dict[str, Any]]) -> dict[str, Any]:
    public_attack_ids = sorted(record["attack_id"] for record in PUBLIC_SEED_RECORDS)
    matched_attack_ids = sorted(
        {attack_id for case in cases for attack_id in case["matched_attack_ids"]}
    )
    missing_public_attack_ids = sorted(set(public_attack_ids) - set(matched_attack_ids))
    return {
        "categories": sorted({case["category"] for case in cases}),
        "public_attack_ids": public_attack_ids,
        "matched_attack_ids": matched_attack_ids,
        "missing_public_attack_ids": missing_public_attack_ids,
        "public_attack_coverage": _ratio(
            len(public_attack_ids) - len(missing_public_attack_ids),
            len(public_attack_ids),
        ),
    }


def _threshold_failures(
    thresholds: dict[str, float],
    classification: dict[str, Any],
    operations: dict[str, Any],
) -> list[str]:
    observed = {
        "min_precision": classification["precision"],
        "min_recall": classification["recall"],
        "min_specificity": classification["specificity"],
        "min_accuracy": classification["accuracy"],
        "max_benign_intervention_rate": operations["benign_intervention_rate"],
        "min_critical_intervention_recall": operations["critical_intervention_recall"],
    }
    failures: list[str] = []
    for name, threshold in thresholds.items():
        value = float(observed[name])
        if name.startswith("max_"):
            passed = value <= float(threshold)
        else:
            passed = value >= float(threshold)
        if not passed:
            failures.append(f"{name} was {value:.4f}, threshold {threshold:.4f}")
    return failures


def _ratio(numerator: int, denominator: int) -> float:
    if denominator == 0:
        return 1.0
    value = numerator / denominator
    return round(value, 6) if math.isfinite(value) else 0.0


def format_summary(report: dict[str, Any]) -> str:
    classification = report["classification"]
    operations = report["operations"]
    coverage = report["coverage"]
    status = "PASS" if report["passed"] else "FAIL"
    lines = [
        f"AI runtime evaluation: {status}",
        (
            f"Cases: {report['case_count']} "
            f"(TP={classification['true_positive']}, "
            f"TN={classification['true_negative']}, "
            f"FP={classification['false_positive']}, "
            f"FN={classification['false_negative']})"
        ),
        (
            "Precision/recall/specificity/accuracy: "
            f"{classification['precision']:.3f}/"
            f"{classification['recall']:.3f}/"
            f"{classification['specificity']:.3f}/"
            f"{classification['accuracy']:.3f}"
        ),
        (
            "Benign intervention rate / critical intervention recall: "
            f"{operations['benign_intervention_rate']:.3f}/"
            f"{operations['critical_intervention_recall']:.3f}"
        ),
        (
            "Public attack-family coverage: "
            f"{len(coverage['matched_attack_ids'])}/"
            f"{len(coverage['public_attack_ids'])}"
        ),
    ]
    lines.extend(f"Failure: {failure}" for failure in report["failures"])
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run the synthetic Vexyl AI runtime regression evaluation."
    )
    parser.add_argument(
        "--fixture",
        type=Path,
        default=DEFAULT_FIXTURE_PATH,
        help="Path to an evaluation fixture JSON file.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print the privacy-safe report as JSON.",
    )
    args = parser.parse_args(argv)
    try:
        report = evaluate_suite(load_suite(args.fixture))
    except EvaluationFixtureError as exc:
        print(f"AI runtime evaluation: FAIL\nFixture error: {exc}")
        return 2
    print(
        json.dumps(report, indent=2, sort_keys=True)
        if args.json
        else format_summary(report)
    )
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
