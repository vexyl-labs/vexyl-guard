from __future__ import annotations

import base64
import json
import stat
import subprocess
import tempfile
import threading
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from intel.cli import main as cli_main
from intel.database import (
    PUBLIC_SEED_RECORDS,
    runtime_history_status,
    search_threats,
    seed_db,
)
from intel.scoring import score_and_record_ai_event
from intel.updates import (
    INTEL_PAYLOAD_SCHEMA,
    IntelUpdateError,
    apply_intel_bundle,
    intel_update_status,
    records_sha256,
    recover_intel_database,
    rollback_intel_bundle,
    sync_intel_bundle,
    verify_intel_bundle,
)


class SignedIntelUpdateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.key_tmp = tempfile.TemporaryDirectory()
        cls.key_root = Path(cls.key_tmp.name)
        cls.private_key = cls.key_root / "private.pem"
        cls.key_dir = cls.key_root / "trusted"
        cls.key_dir.mkdir(mode=0o700)
        cls.public_key = cls.key_dir / "test-intel-key.pem"
        subprocess.run(
            [
                "openssl",
                "genpkey",
                "-algorithm",
                "RSA",
                "-pkeyopt",
                "rsa_keygen_bits:2048",
                "-out",
                str(cls.private_key),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        cls.private_key.chmod(0o600)
        subprocess.run(
            [
                "openssl",
                "pkey",
                "-in",
                str(cls.private_key),
                "-pubout",
                "-out",
                str(cls.public_key),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        cls.public_key.chmod(0o644)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.key_tmp.cleanup()

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.db_path = self.root / "ai-threats.sqlite"
        self.lkg_path = self.root / "ai-threats.sqlite.lkg"
        self.revoked_keys = self.root / "revoked-keys.txt"
        self.revoked_keys.write_text("", encoding="utf-8")
        self.revoked_keys.chmod(0o644)
        self.now = datetime(2026, 7, 19, 4, 0, tzinfo=timezone.utc)
        self.seed_patch = patch(
            "intel.database.SEED_PATH", self.root / "missing-private-seed.jsonl"
        )
        self.schema_patch = patch(
            "intel.database.SCHEMA_PATH", self.root / "missing-private-schema.sql"
        )
        self.seed_patch.start()
        self.schema_patch.start()

    def tearDown(self) -> None:
        self.schema_patch.stop()
        self.seed_patch.stop()
        self.tmp.cleanup()

    def records(self, *extra_ids: str) -> list[dict[str, object]]:
        records = json.loads(json.dumps(PUBLIC_SEED_RECORDS))
        records.extend(self.safe_record(attack_id) for attack_id in extra_ids)
        return records

    def safe_record(self, attack_id: str) -> dict[str, object]:
        return {
            "attack_id": attack_id,
            "name": f"Defensive Test Pattern {attack_id}",
            "family": "runtime_integrity",
            "attack_surface": "api",
            "lifecycle_stage": "runtime",
            "summary": "A bounded defensive test record for signed update verification.",
            "severity": 6,
            "likelihood": 5,
            "confidence": 8,
            "tags": ["OWASP:LLM01"],
            "defensive_signals": ["unexpected trusted runtime change"],
            "default_actions": ["policy_verifier"],
        }

    def signed_bundle(
        self,
        records: list[dict[str, object]],
        *,
        sequence: int,
        issued_at: datetime | None = None,
        expires_at: datetime | None = None,
    ) -> dict[str, object]:
        issued = issued_at or self.now
        expires = expires_at or issued + timedelta(days=1)
        payload = {
            "schema": INTEL_PAYLOAD_SCHEMA,
            "bundle_id": f"test-intel-{sequence}",
            "sequence": sequence,
            "issued_at": self.timestamp(issued),
            "expires_at": self.timestamp(expires),
            "record_count": len(records),
            "records_sha256": records_sha256(records),
            "records": records,
        }
        payload_bytes = json.dumps(
            payload, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        payload_b64 = (
            base64.urlsafe_b64encode(payload_bytes).decode("ascii").rstrip("=")
        )
        message_path = self.root / f"message-{sequence}.txt"
        signature_path = self.root / f"signature-{sequence}.bin"
        message_path.write_text(payload_b64, encoding="ascii")
        subprocess.run(
            [
                "openssl",
                "dgst",
                "-sha256",
                "-sign",
                str(self.private_key),
                "-out",
                str(signature_path),
                str(message_path),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        signature = (
            base64.urlsafe_b64encode(signature_path.read_bytes())
            .decode("ascii")
            .rstrip("=")
        )
        return {
            "version": 1,
            "alg": "RS256",
            "kid": "test-intel-key",
            "payload_b64": payload_b64,
            "signature": signature,
        }

    @staticmethod
    def timestamp(value: datetime) -> str:
        return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

    def apply(self, bundle: dict[str, object]) -> dict[str, object]:
        return apply_intel_bundle(
            bundle,
            db_path=self.db_path,
            trusted_key_dir=self.key_dir,
            revoked_keys_file=self.revoked_keys,
            lkg_path=self.lkg_path,
            now=self.now,
        )

    def test_signed_bundle_activates_atomically_and_preserves_runtime_history(
        self,
    ) -> None:
        seed_db(self.db_path)
        score_and_record_ai_event(
            {
                "event_id": "update-history-1",
                "session_id_hash": "opaque-update-session",
                "input_channel": "chat",
                "data_origin": "user",
                "text_excerpt_redacted": "Review the approved deployment checklist.",
            },
            db_path=self.db_path,
        )
        bundle = self.signed_bundle(self.records("AI-UPDATE-001"), sequence=1)

        result = self.apply(bundle)

        self.assertEqual(result["action"], "activated")
        self.assertEqual(runtime_history_status(self.db_path)["event_count"], 1)
        self.assertIn(
            "AI-UPDATE-001",
            {row["attack_id"] for row in search_threats("AI-UPDATE-001", self.db_path)},
        )
        status = intel_update_status(self.db_path, lkg_path=self.lkg_path, now=self.now)
        self.assertEqual(status["active"]["sequence"], 1)
        self.assertEqual(status["highest_sequence"], 1)
        self.assertEqual(status["integrity"], "ok")
        self.assertEqual(status["last_known_good"]["integrity"], "ok")
        self.assertEqual(stat.S_IMODE(self.lkg_path.stat().st_mode), 0o600)

    def test_invalid_expired_and_revoked_bundles_are_rejected(self) -> None:
        valid = self.signed_bundle(self.records(), sequence=1)
        invalid_version = dict(valid)
        invalid_version["version"] = True
        with self.assertRaisesRegex(IntelUpdateError, "version is not supported"):
            verify_intel_bundle(
                invalid_version,
                trusted_key_dir=self.key_dir,
                revoked_keys_file=self.revoked_keys,
                now=self.now,
            )

        tampered = dict(valid)
        tampered["signature"] = "A" + str(valid["signature"])[1:]
        with self.assertRaisesRegex(IntelUpdateError, "signature verification failed"):
            verify_intel_bundle(
                tampered,
                trusted_key_dir=self.key_dir,
                revoked_keys_file=self.revoked_keys,
                now=self.now,
            )

        expired = self.signed_bundle(
            self.records(),
            sequence=1,
            issued_at=self.now - timedelta(days=2),
            expires_at=self.now - timedelta(days=1),
        )
        with self.assertRaisesRegex(IntelUpdateError, "expired"):
            verify_intel_bundle(
                expired,
                trusted_key_dir=self.key_dir,
                revoked_keys_file=self.revoked_keys,
                now=self.now,
            )

        self.revoked_keys.write_text("test-intel-key\n", encoding="utf-8")
        with self.assertRaisesRegex(IntelUpdateError, "revoked"):
            verify_intel_bundle(
                valid,
                trusted_key_dir=self.key_dir,
                revoked_keys_file=self.revoked_keys,
                now=self.now,
            )

    def test_local_trust_and_token_files_require_safe_permissions(self) -> None:
        valid = self.signed_bundle(self.records(), sequence=1)
        self.public_key.chmod(0o666)
        with self.assertRaisesRegex(IntelUpdateError, "permissions are unsafe"):
            verify_intel_bundle(
                valid,
                trusted_key_dir=self.key_dir,
                revoked_keys_file=self.revoked_keys,
                now=self.now,
            )
        self.public_key.chmod(0o644)

        self.revoked_keys.unlink()
        with self.assertRaisesRegex(IntelUpdateError, "revocation list is unavailable"):
            verify_intel_bundle(
                valid,
                trusted_key_dir=self.key_dir,
                revoked_keys_file=self.revoked_keys,
                now=self.now,
            )
        self.revoked_keys.write_text("", encoding="utf-8")
        self.revoked_keys.chmod(0o644)

        token_file = self.root / "unsafe-intel.token"
        token_file.write_text(
            "test-token-value-that-is-long-enough-123456\n", encoding="utf-8"
        )
        token_file.chmod(0o644)
        with self.assertRaisesRegex(IntelUpdateError, "token permissions are unsafe"):
            sync_intel_bundle(
                url="https://api.vexyl.dev/v1/ai-intel.bundle.json",
                token_file=token_file,
                db_path=self.db_path,
                trusted_key_dir=self.key_dir,
                revoked_keys_file=self.revoked_keys,
                lkg_path=self.lkg_path,
                now=self.now,
            )

    def test_sequence_high_water_rejects_downgrade_and_equivocation(self) -> None:
        self.apply(self.signed_bundle(self.records("AI-UPDATE-002"), sequence=2))

        with self.assertRaisesRegex(IntelUpdateError, "below the high-water mark"):
            self.apply(self.signed_bundle(self.records(), sequence=1))
        with self.assertRaisesRegex(IntelUpdateError, "conflicts with trusted history"):
            self.apply(self.signed_bundle(self.records("AI-UPDATE-OTHER"), sequence=2))

        status = intel_update_status(self.db_path, lkg_path=self.lkg_path, now=self.now)
        self.assertEqual(status["active"]["sequence"], 2)
        self.assertIn(
            "AI-UPDATE-002",
            {row["attack_id"] for row in search_threats("AI-UPDATE-002", self.db_path)},
        )

    def test_equal_sequence_same_records_refreshes_expiry_without_replacing_data(
        self,
    ) -> None:
        records = self.records("AI-UPDATE-REFRESH")
        self.apply(self.signed_bundle(records, sequence=1))
        refreshed_now = self.now + timedelta(hours=2)
        refreshed = self.signed_bundle(
            records,
            sequence=1,
            issued_at=refreshed_now,
            expires_at=refreshed_now + timedelta(days=2),
        )

        result = apply_intel_bundle(
            refreshed,
            db_path=self.db_path,
            trusted_key_dir=self.key_dir,
            revoked_keys_file=self.revoked_keys,
            lkg_path=self.lkg_path,
            now=refreshed_now,
        )

        self.assertEqual(result["action"], "metadata_refreshed")
        status = intel_update_status(
            self.db_path, lkg_path=self.lkg_path, now=refreshed_now
        )
        self.assertEqual(
            status["active"]["expires_at"],
            self.timestamp(refreshed_now + timedelta(days=2)),
        )

    def test_explicit_rollback_preserves_history_and_sequence_high_water(self) -> None:
        self.apply(self.signed_bundle(self.records("AI-UPDATE-V1"), sequence=1))
        score_and_record_ai_event(
            {
                "event_id": "rollback-history-1",
                "session_id_hash": "opaque-rollback-session",
                "input_channel": "chat",
                "data_origin": "user",
                "text_excerpt_redacted": "Review the approved rollback plan.",
            },
            db_path=self.db_path,
        )
        self.apply(self.signed_bundle(self.records("AI-UPDATE-V2"), sequence=2))

        result = rollback_intel_bundle(
            self.db_path,
            lkg_path=self.lkg_path,
            confirmed=True,
            now=self.now + timedelta(minutes=1),
        )

        self.assertEqual(result["active"]["sequence"], 1)
        self.assertEqual(result["highest_sequence"], 2)
        self.assertEqual(runtime_history_status(self.db_path)["event_count"], 1)
        self.assertTrue(search_threats("AI-UPDATE-V1", self.db_path))
        self.assertFalse(search_threats("AI-UPDATE-V2", self.db_path))
        with self.assertRaisesRegex(IntelUpdateError, "below the high-water mark"):
            self.apply(self.signed_bundle(self.records("AI-UPDATE-V1"), sequence=1))

    def test_corrupt_active_database_recovers_from_last_known_good(self) -> None:
        self.apply(self.signed_bundle(self.records("AI-RECOVERY-V1"), sequence=1))
        self.apply(self.signed_bundle(self.records("AI-RECOVERY-V2"), sequence=2))
        self.db_path.write_bytes(b"not a sqlite database")

        result = recover_intel_database(
            self.db_path, lkg_path=self.lkg_path, only_if_corrupt=True
        )

        self.assertEqual(result["action"], "recovered")
        status = intel_update_status(self.db_path, lkg_path=self.lkg_path, now=self.now)
        self.assertEqual(status["integrity"], "ok")
        self.assertEqual(status["active"]["sequence"], 1)
        self.assertTrue(search_threats("AI-RECOVERY-V1", self.db_path))

    def test_sync_uses_bearer_auth_without_exposing_token(self) -> None:
        bundle_bytes = json.dumps(
            {"ok": True, "bundle": self.signed_bundle(self.records(), sequence=1)}
        ).encode("utf-8")
        received: dict[str, str | None] = {}

        class Handler(BaseHTTPRequestHandler):
            def do_GET(handler_self) -> None:
                received["authorization"] = handler_self.headers.get("Authorization")
                handler_self.send_response(200)
                handler_self.send_header("Content-Type", "application/json")
                handler_self.send_header("Content-Length", str(len(bundle_bytes)))
                handler_self.end_headers()
                handler_self.wfile.write(bundle_bytes)

            def log_message(self, format: str, *args: object) -> None:
                return

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        token = "test-token-value-that-is-long-enough-123456"
        token_file = self.root / "intel.token"
        token_file.write_text(f"{token}\n", encoding="utf-8")
        token_file.chmod(0o600)
        try:
            result = sync_intel_bundle(
                url=f"http://127.0.0.1:{server.server_port}/v1/ai-intel.bundle.json",
                token_file=token_file,
                db_path=self.db_path,
                trusted_key_dir=self.key_dir,
                revoked_keys_file=self.revoked_keys,
                lkg_path=self.lkg_path,
                now=self.now,
            )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

        self.assertEqual(result["action"], "activated")
        self.assertEqual(received["authorization"], f"Bearer {token}")
        self.assertNotIn(token, json.dumps(result))

    def test_bundle_rejects_records_outside_defensive_shape(self) -> None:
        records = self.records()
        records[0].pop("summary")
        bundle = self.signed_bundle(records, sequence=1)
        with self.assertRaisesRegex(IntelUpdateError, "defensive data boundary"):
            verify_intel_bundle(
                bundle,
                trusted_key_dir=self.key_dir,
                revoked_keys_file=self.revoked_keys,
                now=self.now,
            )

    def test_seed_cannot_mutate_an_active_signed_bundle(self) -> None:
        attack_id = "AI-SIGNED-SEED-GUARD"
        signed_records = self.records(attack_id)
        self.apply(self.signed_bundle(signed_records, sequence=1))
        replacement = self.safe_record(attack_id)
        replacement["name"] = "Unsigned Replacement"
        seed_file = self.root / "replacement.jsonl"
        seed_file.write_text(json.dumps(replacement) + "\n", encoding="utf-8")

        result = seed_db(self.db_path, seed_file)

        self.assertEqual(result["signed_bundle_preserved"], 1)
        matches = search_threats(attack_id, self.db_path)
        self.assertEqual(matches[0]["name"], f"Defensive Test Pattern {attack_id}")

    def test_cli_verify_apply_and_status_contract(self) -> None:
        current = datetime.now(timezone.utc)
        bundle = self.signed_bundle(
            self.records("AI-CLI-UPDATE"),
            sequence=1,
            issued_at=current - timedelta(minutes=1),
            expires_at=current + timedelta(days=1),
        )
        bundle_path = self.root / "bundle.json"
        bundle_path.write_text(json.dumps(bundle), encoding="utf-8")
        common = [
            "--trusted-key-dir",
            str(self.key_dir),
            "--revoked-keys-file",
            str(self.revoked_keys),
        ]

        verify_stdout = StringIO()
        with redirect_stdout(verify_stdout), redirect_stderr(StringIO()):
            verify_result = cli_main(
                ["threat", "verify-intel-bundle", str(bundle_path), *common]
            )
        self.assertEqual(verify_result, 0)
        self.assertEqual(json.loads(verify_stdout.getvalue())["bundle"]["sequence"], 1)

        apply_stdout = StringIO()
        with redirect_stdout(apply_stdout), redirect_stderr(StringIO()):
            apply_result = cli_main(
                [
                    "threat",
                    "--db",
                    str(self.db_path),
                    "apply-intel-bundle",
                    str(bundle_path),
                    *common,
                    "--lkg",
                    str(self.lkg_path),
                ]
            )
        self.assertEqual(apply_result, 0)
        self.assertEqual(json.loads(apply_stdout.getvalue())["action"], "activated")

        status_stdout = StringIO()
        with redirect_stdout(status_stdout), redirect_stderr(StringIO()):
            status_result = cli_main(
                [
                    "threat",
                    "--db",
                    str(self.db_path),
                    "intel-status",
                    "--lkg",
                    str(self.lkg_path),
                ]
            )
        status = json.loads(status_stdout.getvalue())["intelligence"]
        self.assertEqual(status_result, 0)
        self.assertEqual(status["active"]["sequence"], 1)
        self.assertEqual(status["freshness"], "current")


if __name__ == "__main__":
    unittest.main(verbosity=2)
