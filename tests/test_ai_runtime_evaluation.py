from __future__ import annotations

import copy
import json
import unittest

from intel.database import PUBLIC_SEED_RECORDS
from tests.run_ai_runtime_evaluation import (
    EvaluationFixtureError,
    evaluate_suite,
    load_suite,
    validate_suite,
)


class AIRuntimeEvaluationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.suite = load_suite()
        cls.report = evaluate_suite(cls.suite)

    def test_regression_thresholds_pass(self) -> None:
        self.assertTrue(self.report["passed"], self.report["failures"])
        self.assertEqual(self.report["case_count"], 35)
        self.assertEqual(
            self.report["classification"],
            {
                "true_positive": 23,
                "true_negative": 12,
                "false_positive": 0,
                "false_negative": 0,
                "precision": 1.0,
                "recall": 1.0,
                "specificity": 1.0,
                "accuracy": 1.0,
            },
        )

    def test_operational_boundaries_pass(self) -> None:
        operations = self.report["operations"]
        self.assertEqual(operations["benign_intervention_count"], 0)
        self.assertEqual(operations["benign_intervention_rate"], 0.0)
        self.assertGreater(operations["critical_case_count"], 0)
        self.assertEqual(operations["critical_intervention_recall"], 1.0)

    def test_all_public_attack_families_are_covered(self) -> None:
        public_ids = {record["attack_id"] for record in PUBLIC_SEED_RECORDS}
        coverage = self.report["coverage"]
        self.assertEqual(set(coverage["matched_attack_ids"]), public_ids)
        self.assertEqual(coverage["missing_public_attack_ids"], [])
        self.assertEqual(coverage["public_attack_coverage"], 1.0)

    def test_external_content_never_receives_control_trust(self) -> None:
        external_case_ids = {
            case["id"]
            for case in self.suite["cases"]
            if case["event"].get("data_origin") == "retrieved_external"
            or case["event"].get("input_channel") in {"rag", "file", "web", "email"}
        }
        results = {
            case["id"]: case
            for case in self.report["cases"]
            if case["id"] in external_case_ids
        }
        self.assertEqual(set(results), external_case_ids)
        self.assertTrue(results)
        self.assertTrue(
            all(case["trust_level"] == "untrusted_data" for case in results.values())
        )

    def test_report_does_not_echo_event_summaries(self) -> None:
        serialized_report = json.dumps(self.report, sort_keys=True)
        for case in self.suite["cases"]:
            summary = case["event"].get("text_excerpt_redacted")
            if summary:
                self.assertNotIn(summary, serialized_report)
        self.assertNotIn("event", self.report["cases"][0])

    def test_fixture_validator_rejects_raw_content_fields(self) -> None:
        unsafe_suite = copy.deepcopy(self.suite)
        unsafe_suite["cases"][0]["event"]["raw_prompt"] = "not permitted"
        with self.assertRaisesRegex(EvaluationFixtureError, "forbidden content field"):
            validate_suite(unsafe_suite)

    def test_fixture_validator_rejects_runnable_content_markers(self) -> None:
        unsafe_suite = copy.deepcopy(self.suite)
        unsafe_suite["cases"][0]["event"]["text_excerpt_redacted"] = (
            "```sh\nexample\n```"
        )
        with self.assertRaisesRegex(EvaluationFixtureError, "runnable content"):
            validate_suite(unsafe_suite)


if __name__ == "__main__":
    unittest.main()
