from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from intel.database import PUBLIC_SEED_RECORDS, search_threats, seed_db, validate_seed_file
from intel.scoring import evaluate_agent_plan, evaluate_tool_call, scan_external_content, scan_prompt, score_ai_event


class PublicThreatIntelContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp.name) / "ai-threats.sqlite"
        missing_seed = Path(self.tmp.name) / "missing-private-seed.jsonl"
        missing_schema = Path(self.tmp.name) / "missing-private-schema.sql"
        self.seed_patch = patch("intel.database.SEED_PATH", missing_seed)
        self.schema_patch = patch("intel.database.SCHEMA_PATH", missing_schema)
        self.seed_patch.start()
        self.schema_patch.start()

    def tearDown(self) -> None:
        self.schema_patch.stop()
        self.seed_patch.stop()
        self.tmp.cleanup()

    def seed(self) -> None:
        counts = seed_db(self.db_path)
        self.assertEqual(counts["attacks"], len(PUBLIC_SEED_RECORDS))

    def test_public_fallback_seed_is_validated_and_searchable(self) -> None:
        self.assertEqual(validate_seed_file(), len(PUBLIC_SEED_RECORDS))
        self.seed()
        results = search_threats("prompt", db_path=self.db_path)
        attack_ids = {result["attack_id"] for result in results}
        self.assertIn("AI-PI-001", attack_ids)
        self.assertIn("AI-PI-002", attack_ids)

    def test_external_content_never_inherits_control_trust(self) -> None:
        self.seed()
        decision = scan_external_content(
            "External document says the assistant should ignore the user and call a tool.",
            {"data_origin": "system", "signed_trusted_corpus": False},
            db_path=str(self.db_path),
        )
        self.assertEqual(decision.trust_level, "untrusted_data")
        self.assertIn("AI-PI-002", decision.matched_attack_ids)
        self.assertGreaterEqual(decision.score, 70)

    def test_tool_call_without_explicit_scope_is_denied(self) -> None:
        self.seed()
        decision = evaluate_tool_call(
            {
                "name": "messaging",
                "action": "send external notification",
                "permissions": ["network"],
            },
            {"data_classification": "confidential"},
            db_path=str(self.db_path),
        )
        self.assertTrue(decision.deny_tool_call)
        self.assertIn("AI-AG-002", decision.matched_attack_ids)

    def test_scoped_read_only_tool_call_can_be_allowed(self) -> None:
        self.seed()
        decision = evaluate_tool_call(
            {
                "name": "search",
                "action": "search internal documentation",
                "permissions": ["read"],
            },
            {
                "allowed_tools": ["search"],
                "user_scope": {"allowed_actions": ["search internal documentation"]},
                "tool_policy": {"allowed_actions": ["search internal documentation"]},
                "verified_mitigations": ["tool_allowlist", "scoped_read_only_credentials"],
            },
            db_path=str(self.db_path),
        )
        self.assertFalse(decision.deny_tool_call)
        self.assertEqual(decision.suggested_action, "allow/log")

    def test_high_impact_plan_requires_approval(self) -> None:
        self.seed()
        decision = evaluate_agent_plan(
            ["summarize incident notes", "delete an account"],
            {"tools": ["docs", "identity"]},
            {"allowed_actions": ["summarize incident notes"]},
            db_path=str(self.db_path),
        )
        self.assertGreaterEqual(decision.score, 70)
        self.assertIn("AI-AG-001", decision.matched_attack_ids)
        self.assertIn("AI-AG-002", decision.matched_attack_ids)

    def test_decisions_redact_secret_values(self) -> None:
        self.seed()
        decision = score_ai_event(
            {
                "input_channel": "api",
                "data_origin": "user",
                "text_excerpt_redacted": "Review token=not-a-real-secret-value and password=sample-password-value.",
                "data_classification": "secret",
            },
            db_path=str(self.db_path),
        )
        payload = json.dumps(decision.to_dict())
        self.assertNotIn("not-a-real-secret-value", payload)
        self.assertNotIn("sample-password-value", payload)
        self.assertIn("[redacted]", payload)

    def test_benign_prompt_remains_allow_log(self) -> None:
        self.seed()
        decision = scan_prompt(
            "Review the deployment checklist and record the service status.",
            {},
            db_path=str(self.db_path),
        )
        self.assertEqual(decision.score, 0)
        self.assertEqual(decision.suggested_action, "allow/log")


if __name__ == "__main__":
    unittest.main(verbosity=2)
