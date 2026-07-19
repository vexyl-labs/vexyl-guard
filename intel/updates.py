from __future__ import annotations

import base64
import binascii
import fcntl
import hashlib
import hmac
import ipaddress
import json
import os
import re
import sqlite3
import stat
import subprocess
import tempfile
import urllib.error
import urllib.request
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator
from urllib.parse import urlparse

from .database import (
    connect,
    default_db_path,
    init_db,
    seed_records_into_db,
    validate_seed_record,
)

INTEL_BUNDLE_VERSION = 1
INTEL_PAYLOAD_SCHEMA = "vexyl.ai_intel_payload.v1"
DEFAULT_TRUSTED_KEY_DIR = "/etc/vexyl/policy-keys.d"
DEFAULT_REVOKED_KEYS_FILE = "/etc/vexyl/revoked-policy-keys.txt"
DEFAULT_TOKEN_FILE = "/etc/vexyl/intel-update.token"
MAX_BUNDLE_BYTES = 8 * 1024 * 1024
MAX_RECORDS = 5_000
MAX_VALIDITY = timedelta(days=14)
MAX_CLOCK_SKEW = timedelta(minutes=5)
MAX_SEQUENCE = 9_223_372_036_854_775_807

INSERT_ORDER = (
    "sources",
    "frameworks",
    "attack_patterns",
    "observations",
    "indicators",
    "detection_rules",
    "mitigations",
    "attack_mitigation_map",
    "technique_mappings",
    "watch_items",
)
DELETE_ORDER = tuple(reversed(INSERT_ORDER))
KEY_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
BUNDLE_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


class IntelUpdateError(RuntimeError):
    """Raised when signed intelligence cannot be verified or activated safely."""


@dataclass(frozen=True)
class VerifiedIntelBundle:
    bundle_id: str
    sequence: int
    issued_at: str
    expires_at: str
    records_sha256: str
    payload_sha256: str
    key_id: str
    records: tuple[dict[str, Any], ...]

    def public_metadata(self) -> dict[str, Any]:
        return {
            "bundle_id": self.bundle_id,
            "sequence": self.sequence,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "records_sha256": self.records_sha256,
            "payload_sha256": self.payload_sha256,
            "key_id": self.key_id,
            "record_count": len(self.records),
            "safety_boundary": "defensive summaries only",
        }


def records_sha256(records: list[dict[str, Any]] | tuple[dict[str, Any], ...]) -> str:
    return hashlib.sha256(_canonical_records(records)).hexdigest()


def verify_intel_bundle(
    bundle: str | Path | bytes | dict[str, Any],
    *,
    trusted_key_dir: str | Path = DEFAULT_TRUSTED_KEY_DIR,
    revoked_keys_file: str | Path = DEFAULT_REVOKED_KEYS_FILE,
    now: datetime | None = None,
) -> VerifiedIntelBundle:
    envelope = _load_bundle_envelope(bundle)
    if set(envelope) != {"version", "alg", "kid", "payload_b64", "signature"}:
        raise IntelUpdateError("intelligence bundle envelope has unsupported fields")
    version = envelope.get("version")
    if (
        not isinstance(version, int)
        or isinstance(version, bool)
        or version != INTEL_BUNDLE_VERSION
    ):
        raise IntelUpdateError("intelligence bundle version is not supported")
    if envelope.get("alg") != "RS256":
        raise IntelUpdateError("intelligence bundle must use RS256")

    key_id = _required_identifier(envelope.get("kid"), "signing key id", KEY_ID_PATTERN)
    if ".." in key_id:
        raise IntelUpdateError("intelligence bundle signing key id is invalid")
    if key_id in _read_revoked_key_ids(revoked_keys_file):
        raise IntelUpdateError("intelligence bundle signing key is revoked")

    payload_b64 = _required_string(
        envelope.get("payload_b64"), "payload", MAX_BUNDLE_BYTES * 2
    )
    signature_b64 = _required_string(envelope.get("signature"), "signature", 16_384)
    payload_bytes = _decode_base64url(payload_b64, "payload")
    if len(payload_bytes) > MAX_BUNDLE_BYTES:
        raise IntelUpdateError("intelligence bundle payload exceeds the size limit")
    signature = _decode_base64url(signature_b64, "signature")
    _verify_rs256_signature(
        payload_b64.encode("ascii"),
        signature,
        key_id=key_id,
        trusted_key_dir=trusted_key_dir,
    )

    try:
        payload = json.loads(payload_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise IntelUpdateError("intelligence bundle payload is not valid JSON") from exc
    if not isinstance(payload, dict):
        raise IntelUpdateError("intelligence bundle payload must be an object")

    allowed_payload_fields = {
        "schema",
        "bundle_id",
        "sequence",
        "issued_at",
        "expires_at",
        "record_count",
        "records_sha256",
        "records",
    }
    if set(payload) != allowed_payload_fields:
        raise IntelUpdateError("intelligence bundle payload has unsupported fields")
    if payload.get("schema") != INTEL_PAYLOAD_SCHEMA:
        raise IntelUpdateError("intelligence bundle payload schema is not supported")

    bundle_id = _required_identifier(
        payload.get("bundle_id"), "bundle id", BUNDLE_ID_PATTERN
    )
    sequence = payload.get("sequence")
    if (
        not isinstance(sequence, int)
        or isinstance(sequence, bool)
        or sequence < 1
        or sequence > MAX_SEQUENCE
    ):
        raise IntelUpdateError("intelligence bundle sequence is invalid")

    checked_now = _normalized_now(now)
    issued_at = _parse_timestamp(payload.get("issued_at"), "issued_at")
    expires_at = _parse_timestamp(payload.get("expires_at"), "expires_at")
    if issued_at > checked_now + MAX_CLOCK_SKEW:
        raise IntelUpdateError("intelligence bundle was issued too far in the future")
    if expires_at <= checked_now:
        raise IntelUpdateError("intelligence bundle has expired")
    if expires_at <= issued_at or expires_at - issued_at > MAX_VALIDITY:
        raise IntelUpdateError("intelligence bundle validity window is invalid")

    records = payload.get("records")
    if not isinstance(records, list) or not 1 <= len(records) <= MAX_RECORDS:
        raise IntelUpdateError("intelligence bundle record count is invalid")
    record_count = payload.get("record_count")
    if (
        not isinstance(record_count, int)
        or isinstance(record_count, bool)
        or record_count != len(records)
    ):
        raise IntelUpdateError("intelligence bundle record count does not match")

    checked_records: list[dict[str, Any]] = []
    attack_ids: set[str] = set()
    for index, record in enumerate(records, start=1):
        if not isinstance(record, dict):
            raise IntelUpdateError(f"intelligence record {index} must be an object")
        try:
            validate_seed_record(record, index)
        except (TypeError, ValueError) as exc:
            raise IntelUpdateError(
                f"intelligence record {index} violates the defensive data boundary"
            ) from exc
        attack_id = record.get("attack_id")
        if not isinstance(attack_id, str) or not attack_id:
            raise IntelUpdateError(f"intelligence record {index} has an invalid id")
        if attack_id in attack_ids:
            raise IntelUpdateError("intelligence bundle contains duplicate attack ids")
        attack_ids.add(attack_id)
        checked_records.append(record)

    declared_records_hash = payload.get("records_sha256")
    if not isinstance(declared_records_hash, str) or not re.fullmatch(
        r"[0-9a-f]{64}", declared_records_hash
    ):
        raise IntelUpdateError("intelligence bundle record hash is invalid")
    calculated_records_hash = records_sha256(checked_records)
    if not _constant_time_equal(declared_records_hash, calculated_records_hash):
        raise IntelUpdateError("intelligence bundle record hash does not match")

    return VerifiedIntelBundle(
        bundle_id=bundle_id,
        sequence=sequence,
        issued_at=_format_timestamp(issued_at),
        expires_at=_format_timestamp(expires_at),
        records_sha256=calculated_records_hash,
        payload_sha256=hashlib.sha256(payload_bytes).hexdigest(),
        key_id=key_id,
        records=tuple(checked_records),
    )


def apply_intel_bundle(
    bundle: str | Path | bytes | dict[str, Any],
    *,
    db_path: str | Path | None = None,
    trusted_key_dir: str | Path = DEFAULT_TRUSTED_KEY_DIR,
    revoked_keys_file: str | Path = DEFAULT_REVOKED_KEYS_FILE,
    lkg_path: str | Path | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    verified = verify_intel_bundle(
        bundle,
        trusted_key_dir=trusted_key_dir,
        revoked_keys_file=revoked_keys_file,
        now=now,
    )
    active_path = Path(db_path) if db_path else default_db_path()
    backup_path = Path(lkg_path) if lkg_path else default_lkg_path(active_path)
    _validate_update_paths(active_path, backup_path)

    with _update_lock(active_path):
        init_db(active_path)
        current = _read_bundle_state(active_path)
        _validate_sequence(current, verified)

        if (
            current["active_sequence"] == verified.sequence
            and current["active_records_sha256"] == verified.records_sha256
        ):
            _refresh_active_state(active_path, current, verified, now=now)
            return {
                "ok": True,
                "action": "metadata_refreshed",
                "db": str(active_path),
                "last_known_good": str(backup_path),
                "bundle": verified.public_metadata(),
            }

        staging_path = _build_staging_database(active_path, verified)
        try:
            _create_last_known_good(active_path, backup_path)
            new_state = _state_for_activation(current, verified, now=now)
            _replace_intelligence_tables(active_path, staging_path, new_state)
        finally:
            staging_path.unlink(missing_ok=True)

    return {
        "ok": True,
        "action": "activated",
        "db": str(active_path),
        "last_known_good": str(backup_path),
        "bundle": verified.public_metadata(),
    }


def sync_intel_bundle(
    *,
    url: str,
    token_file: str | Path = DEFAULT_TOKEN_FILE,
    db_path: str | Path | None = None,
    trusted_key_dir: str | Path = DEFAULT_TRUSTED_KEY_DIR,
    revoked_keys_file: str | Path = DEFAULT_REVOKED_KEYS_FILE,
    lkg_path: str | Path | None = None,
    timeout: float = 15.0,
    now: datetime | None = None,
) -> dict[str, Any]:
    token = _read_bearer_token(token_file)
    bundle_bytes = _download_bundle(url, token=token, timeout=timeout)
    return apply_intel_bundle(
        bundle_bytes,
        db_path=db_path,
        trusted_key_dir=trusted_key_dir,
        revoked_keys_file=revoked_keys_file,
        lkg_path=lkg_path,
        now=now,
    )


def intel_update_status(
    db_path: str | Path | None = None,
    *,
    lkg_path: str | Path | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    active_path = Path(db_path) if db_path else default_db_path()
    backup_path = Path(lkg_path) if lkg_path else default_lkg_path(active_path)
    checked_now = _normalized_now(now)

    active_integrity = _database_integrity(active_path)
    active_state: dict[str, Any] | None = None
    if active_integrity == "ok":
        init_db(active_path)
        active_state = _read_bundle_state(active_path)

    backup_integrity = _database_integrity(backup_path)
    backup_state = _read_bundle_state(backup_path) if backup_integrity == "ok" else None
    expires_at = None
    freshness = "unsigned"
    if active_state and active_state.get("active_expires_at_utc"):
        try:
            expires_at = _parse_timestamp(
                active_state.get("active_expires_at_utc"), "expires_at"
            )
            freshness = "stale" if expires_at <= checked_now else "current"
        except IntelUpdateError:
            freshness = "invalid"

    return {
        "db": str(active_path),
        "exists": active_path.exists(),
        "integrity": active_integrity,
        "active": _public_state(active_state),
        "highest_sequence": int(active_state.get("highest_sequence") or 0)
        if active_state
        else 0,
        "stale": freshness in {"stale", "invalid"},
        "freshness": freshness,
        "last_known_good": {
            "path": str(backup_path),
            "exists": backup_path.exists(),
            "integrity": backup_integrity,
            "active": _public_state(backup_state),
        },
        "rollback_available": backup_integrity == "ok",
    }


def rollback_intel_bundle(
    db_path: str | Path | None = None,
    *,
    lkg_path: str | Path | None = None,
    confirmed: bool = False,
    now: datetime | None = None,
) -> dict[str, Any]:
    if not confirmed:
        raise IntelUpdateError(
            "explicit confirmation is required for intelligence rollback"
        )
    active_path = Path(db_path) if db_path else default_db_path()
    backup_path = Path(lkg_path) if lkg_path else default_lkg_path(active_path)
    _validate_update_paths(active_path, backup_path)

    with _update_lock(active_path):
        if _database_integrity(active_path) != "ok":
            raise IntelUpdateError("active intelligence database is not healthy")
        if _database_integrity(backup_path) != "ok":
            raise IntelUpdateError(
                "last-known-good intelligence database is unavailable"
            )
        init_db(active_path)
        current = _read_bundle_state(active_path)
        previous = _read_bundle_state(backup_path)
        if _same_active_state(current, previous):
            raise IntelUpdateError("last-known-good intelligence is already active")

        current_snapshot = _create_database_snapshot(
            active_path, backup_path.parent, f".{backup_path.name}.rollback-"
        )
        try:
            rollback_state = dict(previous)
            rollback_state["highest_sequence"] = current["highest_sequence"]
            rollback_state["highest_records_sha256"] = current["highest_records_sha256"]
            rollback_state["rollback_from_sequence"] = current["active_sequence"]
            rollback_state["activated_at_utc"] = _format_timestamp(_normalized_now(now))
            rollback_state["updated_at_utc"] = rollback_state["activated_at_utc"]
            _replace_intelligence_tables(active_path, backup_path, rollback_state)
            _install_snapshot(current_snapshot, backup_path)
        finally:
            current_snapshot.unlink(missing_ok=True)

    state = _read_bundle_state(active_path)
    return {
        "ok": True,
        "action": "rolled_back",
        "db": str(active_path),
        "last_known_good": str(backup_path),
        "active": _public_state(state),
        "highest_sequence": state["highest_sequence"],
    }


def recover_intel_database(
    db_path: str | Path | None = None,
    *,
    lkg_path: str | Path | None = None,
    only_if_corrupt: bool = True,
) -> dict[str, Any]:
    active_path = Path(db_path) if db_path else default_db_path()
    backup_path = Path(lkg_path) if lkg_path else default_lkg_path(active_path)
    _validate_update_paths(active_path, backup_path)

    with _update_lock(active_path):
        active_integrity = _database_integrity(active_path)
        if only_if_corrupt and active_integrity in {"ok", "missing"}:
            return {
                "ok": True,
                "action": "not_needed",
                "db": str(active_path),
                "integrity": active_integrity,
            }
        if _database_integrity(backup_path) != "ok":
            raise IntelUpdateError(
                "last-known-good intelligence database is unavailable"
            )
        recovered = _create_database_snapshot(
            backup_path, active_path.parent, f".{active_path.name}.recovery-"
        )
        try:
            _install_snapshot(recovered, active_path)
        finally:
            recovered.unlink(missing_ok=True)

    return {
        "ok": True,
        "action": "recovered",
        "db": str(active_path),
        "last_known_good": str(backup_path),
        "integrity": _database_integrity(active_path),
    }


def recover_intel_database_if_needed(
    db_path: str | Path | None = None,
    *,
    lkg_path: str | Path | None = None,
) -> bool:
    active_path = Path(db_path) if db_path else default_db_path()
    if _database_integrity(active_path) != "corrupt":
        return False
    result = recover_intel_database(
        active_path, lkg_path=lkg_path, only_if_corrupt=True
    )
    return result["action"] == "recovered"


def default_lkg_path(db_path: str | Path) -> Path:
    path = Path(db_path)
    return path.with_name(f"{path.name}.lkg")


def _load_bundle_envelope(
    bundle: str | Path | bytes | dict[str, Any],
) -> dict[str, Any]:
    if isinstance(bundle, dict):
        parsed: Any = bundle
    else:
        if isinstance(bundle, bytes):
            raw = bundle
        else:
            path = Path(bundle)
            try:
                if path.stat().st_size > MAX_BUNDLE_BYTES * 2:
                    raise IntelUpdateError("intelligence bundle exceeds the size limit")
                raw = path.read_bytes()
            except OSError as exc:
                raise IntelUpdateError("unable to read intelligence bundle") from exc
        if len(raw) > MAX_BUNDLE_BYTES * 2:
            raise IntelUpdateError("intelligence bundle exceeds the size limit")
        try:
            parsed = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise IntelUpdateError("intelligence bundle is not valid JSON") from exc

    if not isinstance(parsed, dict):
        raise IntelUpdateError("intelligence bundle must be an object")
    if "bundle" in parsed:
        if parsed.get("ok") is not True or not isinstance(parsed.get("bundle"), dict):
            raise IntelUpdateError("intelligence bundle response is invalid")
        parsed = parsed["bundle"]
    return parsed


def _build_staging_database(active_path: Path, verified: VerifiedIntelBundle) -> Path:
    active_path.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
    descriptor, name = tempfile.mkstemp(
        prefix=f".{active_path.name}.staging-", dir=active_path.parent
    )
    os.close(descriptor)
    staging_path = Path(name)
    staging_path.chmod(0o600)
    try:
        try:
            counts = seed_records_into_db(staging_path, verified.records)
        except (KeyError, TypeError, ValueError, sqlite3.DatabaseError) as exc:
            raise IntelUpdateError(
                "staged intelligence records could not be loaded safely"
            ) from exc
        if counts["attacks"] != len(verified.records):
            raise IntelUpdateError("staged intelligence record count does not match")
        if _database_integrity(staging_path) != "ok":
            raise IntelUpdateError(
                "staged intelligence database failed integrity checks"
            )
        return staging_path
    except Exception:
        staging_path.unlink(missing_ok=True)
        raise


def _validate_sequence(current: dict[str, Any], verified: VerifiedIntelBundle) -> None:
    highest = int(current.get("highest_sequence") or 0)
    highest_hash = current.get("highest_records_sha256")
    if verified.sequence < highest:
        raise IntelUpdateError(
            "intelligence bundle sequence is below the high-water mark"
        )
    if (
        verified.sequence == highest
        and highest > 0
        and highest_hash != verified.records_sha256
    ):
        raise IntelUpdateError(
            "intelligence bundle sequence conflicts with trusted history"
        )


def _state_for_activation(
    current: dict[str, Any], verified: VerifiedIntelBundle, *, now: datetime | None
) -> dict[str, Any]:
    activated_at = _format_timestamp(_normalized_now(now))
    highest = int(current.get("highest_sequence") or 0)
    return {
        "active_sequence": verified.sequence,
        "active_bundle_id": verified.bundle_id,
        "active_issued_at_utc": verified.issued_at,
        "active_expires_at_utc": verified.expires_at,
        "active_records_sha256": verified.records_sha256,
        "active_payload_sha256": verified.payload_sha256,
        "active_key_id": verified.key_id,
        "active_record_count": len(verified.records),
        "activated_at_utc": activated_at,
        "highest_sequence": max(highest, verified.sequence),
        "highest_records_sha256": (
            verified.records_sha256
            if verified.sequence >= highest
            else current.get("highest_records_sha256")
        ),
        "rollback_from_sequence": None,
        "updated_at_utc": activated_at,
    }


def _refresh_active_state(
    active_path: Path,
    current: dict[str, Any],
    verified: VerifiedIntelBundle,
    *,
    now: datetime | None,
) -> None:
    refreshed = dict(current)
    refreshed.update(
        {
            "active_bundle_id": verified.bundle_id,
            "active_issued_at_utc": verified.issued_at,
            "active_expires_at_utc": verified.expires_at,
            "active_payload_sha256": verified.payload_sha256,
            "active_key_id": verified.key_id,
            "active_record_count": len(verified.records),
            "rollback_from_sequence": None,
            "updated_at_utc": _format_timestamp(_normalized_now(now)),
        }
    )
    with connect(active_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        _write_bundle_state(conn, refreshed)


def _replace_intelligence_tables(
    active_path: Path, source_path: Path, state: dict[str, Any]
) -> None:
    with connect(active_path) as conn:
        conn.execute("PRAGMA synchronous = FULL")
        conn.execute("ATTACH DATABASE ? AS incoming", (str(source_path),))
        try:
            conn.execute("BEGIN IMMEDIATE")
            for table in DELETE_ORDER:
                _require_matching_table_columns(conn, table)
                conn.execute(f'DELETE FROM "{table}"')
            for table in INSERT_ORDER:
                columns = _table_columns(conn, "main", table)
                quoted = ", ".join(f'"{column}"' for column in columns)
                conn.execute(
                    f'INSERT INTO "{table}" ({quoted}) '
                    f'SELECT {quoted} FROM incoming."{table}"'
                )
            _write_bundle_state(conn, state)
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.execute("DETACH DATABASE incoming")


def _require_matching_table_columns(conn: sqlite3.Connection, table: str) -> None:
    if _table_columns(conn, "main", table) != _table_columns(conn, "incoming", table):
        raise IntelUpdateError(f"intelligence table schema mismatch: {table}")


def _table_columns(conn: sqlite3.Connection, database: str, table: str) -> list[str]:
    rows = conn.execute(f'PRAGMA {database}.table_info("{table}")').fetchall()
    columns = [str(row[1]) for row in rows]
    if not columns:
        raise IntelUpdateError(f"intelligence table is missing: {table}")
    return columns


def _write_bundle_state(conn: sqlite3.Connection, state: dict[str, Any]) -> None:
    conn.execute("DELETE FROM intel_bundle_state")
    conn.execute(
        """INSERT INTO intel_bundle_state (
          state_id, active_sequence, active_bundle_id, active_issued_at_utc,
          active_expires_at_utc, active_records_sha256, active_payload_sha256,
          active_key_id, active_record_count, activated_at_utc, highest_sequence,
          highest_records_sha256, rollback_from_sequence, updated_at_utc
        ) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            int(state.get("active_sequence") or 0),
            state.get("active_bundle_id"),
            state.get("active_issued_at_utc"),
            state.get("active_expires_at_utc"),
            state.get("active_records_sha256"),
            state.get("active_payload_sha256"),
            state.get("active_key_id"),
            int(state.get("active_record_count") or 0),
            state.get("activated_at_utc"),
            int(state.get("highest_sequence") or 0),
            state.get("highest_records_sha256"),
            state.get("rollback_from_sequence"),
            state.get("updated_at_utc") or _format_timestamp(_normalized_now(None)),
        ),
    )


def _read_bundle_state(path: Path) -> dict[str, Any]:
    default = _empty_state()
    if _database_integrity(path) != "ok":
        return default
    try:
        with sqlite3.connect(path) as conn:
            conn.row_factory = sqlite3.Row
            exists = conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'intel_bundle_state'"
            ).fetchone()
            if not exists:
                return default
            row = conn.execute(
                "SELECT * FROM intel_bundle_state WHERE state_id = 1"
            ).fetchone()
    except sqlite3.DatabaseError:
        return default
    if not row:
        return default
    result = default
    result.update(dict(row))
    return result


def _empty_state() -> dict[str, Any]:
    return {
        "active_sequence": 0,
        "active_bundle_id": None,
        "active_issued_at_utc": None,
        "active_expires_at_utc": None,
        "active_records_sha256": None,
        "active_payload_sha256": None,
        "active_key_id": None,
        "active_record_count": 0,
        "activated_at_utc": None,
        "highest_sequence": 0,
        "highest_records_sha256": None,
        "rollback_from_sequence": None,
        "updated_at_utc": None,
    }


def _public_state(state: dict[str, Any] | None) -> dict[str, Any] | None:
    if not state or int(state.get("active_sequence") or 0) == 0:
        return None
    return {
        "sequence": int(state["active_sequence"]),
        "bundle_id": state.get("active_bundle_id"),
        "issued_at": state.get("active_issued_at_utc"),
        "expires_at": state.get("active_expires_at_utc"),
        "records_sha256": state.get("active_records_sha256"),
        "payload_sha256": state.get("active_payload_sha256"),
        "key_id": state.get("active_key_id"),
        "record_count": int(state.get("active_record_count") or 0),
        "activated_at": state.get("activated_at_utc"),
        "rollback_from_sequence": state.get("rollback_from_sequence"),
    }


def _same_active_state(first: dict[str, Any], second: dict[str, Any]) -> bool:
    return first.get("active_sequence") == second.get("active_sequence") and first.get(
        "active_records_sha256"
    ) == second.get("active_records_sha256")


def _create_last_known_good(active_path: Path, backup_path: Path) -> None:
    snapshot = _create_database_snapshot(
        active_path, backup_path.parent, f".{backup_path.name}.new-"
    )
    try:
        _install_snapshot(snapshot, backup_path)
    finally:
        snapshot.unlink(missing_ok=True)


def _create_database_snapshot(source: Path, directory: Path, prefix: str) -> Path:
    directory.mkdir(mode=0o750, parents=True, exist_ok=True)
    descriptor, name = tempfile.mkstemp(prefix=prefix, dir=directory)
    os.close(descriptor)
    snapshot = Path(name)
    snapshot.chmod(0o600)
    try:
        with sqlite3.connect(source) as source_conn, sqlite3.connect(snapshot) as dest:
            source_conn.backup(dest)
        if _database_integrity(snapshot) != "ok":
            raise IntelUpdateError("database snapshot failed integrity checks")
        _fsync_file(snapshot)
        return snapshot
    except Exception:
        snapshot.unlink(missing_ok=True)
        raise


def _install_snapshot(snapshot: Path, destination: Path) -> None:
    if destination.exists() and destination.is_symlink():
        raise IntelUpdateError("database snapshot destination cannot be a symlink")
    snapshot.chmod(0o600)
    os.replace(snapshot, destination)
    destination.chmod(0o600)
    _fsync_directory(destination.parent)


def _database_integrity(path: Path) -> str:
    if not path.exists():
        return "missing"
    try:
        path_stat = path.lstat()
        if not stat.S_ISREG(path_stat.st_mode) or path.is_symlink():
            return "unsafe"
        with sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True) as conn:
            result = conn.execute("PRAGMA quick_check").fetchone()
        return "ok" if result and result[0] == "ok" else "corrupt"
    except (OSError, sqlite3.DatabaseError):
        return "corrupt"


def _validate_update_paths(active_path: Path, backup_path: Path) -> None:
    if active_path.resolve(strict=False) == backup_path.resolve(strict=False):
        raise IntelUpdateError("active and last-known-good database paths must differ")
    for path in (active_path, backup_path):
        if path.exists():
            _require_secure_regular_file(path, "intelligence database")
        if path.parent.exists():
            _require_secure_directory(path.parent, "intelligence database directory")


@contextmanager
def _update_lock(active_path: Path) -> Iterator[None]:
    active_path.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
    _require_secure_directory(active_path.parent, "intelligence database directory")
    lock_path = active_path.with_name(f".{active_path.name}.update.lock")
    flags = os.O_CREAT | os.O_RDWR
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(lock_path, flags, 0o600)
    except OSError as exc:
        raise IntelUpdateError("unable to open intelligence update lock") from exc
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise IntelUpdateError("intelligence update lock path is unsafe")
        os.fchmod(descriptor, 0o600)
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def _verify_rs256_signature(
    message: bytes,
    signature: bytes,
    *,
    key_id: str,
    trusted_key_dir: str | Path,
) -> None:
    key_directory = Path(trusted_key_dir)
    _require_secure_directory(key_directory, "trusted intelligence key directory")
    key_path = key_directory / f"{key_id}.pem"
    try:
        _require_secure_regular_file(key_path, "trusted intelligence signing key")
    except OSError as exc:
        raise IntelUpdateError(
            "trusted intelligence signing key is unavailable"
        ) from exc

    with tempfile.TemporaryDirectory(prefix="vexyl-intel-verify-") as directory:
        message_path = Path(directory) / "message"
        signature_path = Path(directory) / "signature"
        message_path.write_bytes(message)
        signature_path.write_bytes(signature)
        message_path.chmod(0o600)
        signature_path.chmod(0o600)
        try:
            result = subprocess.run(
                [
                    "openssl",
                    "dgst",
                    "-sha256",
                    "-verify",
                    str(key_path),
                    "-signature",
                    str(signature_path),
                    str(message_path),
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=10,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise IntelUpdateError(
                "unable to verify intelligence bundle signature"
            ) from exc
    if result.returncode != 0:
        raise IntelUpdateError("intelligence bundle signature verification failed")


def _read_revoked_key_ids(path: str | Path) -> set[str]:
    revoked_path = Path(path)
    try:
        path_stat = _require_secure_regular_file(
            revoked_path, "intelligence key revocation list"
        )
        if path_stat.st_size > 65_536:
            raise IntelUpdateError("intelligence key revocation list is too large")
        lines = revoked_path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as exc:
        raise IntelUpdateError(
            "unable to read intelligence key revocation list"
        ) from exc
    return {
        line.strip()
        for line in lines
        if line.strip() and not line.lstrip().startswith("#")
    }


def _download_bundle(url: str, *, token: str, timeout: float) -> bytes:
    _validate_bundle_url(url)
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/json",
            "Authorization": f"Bearer {token}",
            "User-Agent": "Vexyl-Guard-Intel-Updater",
        },
        method="GET",
    )
    opener = urllib.request.build_opener(_NoRedirectHandler())
    try:
        with opener.open(request, timeout=max(1.0, min(60.0, timeout))) as response:
            _validate_bundle_url(response.geturl())
            declared_length = response.headers.get("Content-Length")
            if declared_length and int(declared_length) > MAX_BUNDLE_BYTES * 2:
                raise IntelUpdateError(
                    "intelligence bundle download exceeds the size limit"
                )
            body = response.read(MAX_BUNDLE_BYTES * 2 + 1)
    except IntelUpdateError:
        raise
    except (OSError, ValueError, urllib.error.URLError) as exc:
        raise IntelUpdateError("intelligence bundle download failed") from exc
    if len(body) > MAX_BUNDLE_BYTES * 2:
        raise IntelUpdateError("intelligence bundle download exceeds the size limit")
    return body


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str
    ) -> None:
        return None


def _validate_bundle_url(url: str) -> None:
    parsed = urlparse(url)
    if parsed.username or parsed.password or parsed.fragment:
        raise IntelUpdateError("intelligence bundle URL is invalid")
    if parsed.scheme == "https" and parsed.hostname:
        return
    if parsed.scheme == "http" and _is_loopback_host(parsed.hostname):
        return
    raise IntelUpdateError("intelligence bundle URL must use HTTPS")


def _is_loopback_host(hostname: str | None) -> bool:
    if not hostname:
        return False
    if hostname.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return False


def _read_bearer_token(path: str | Path) -> str:
    token_path = Path(path)
    try:
        path_stat = _require_secure_regular_file(
            token_path, "intelligence update token"
        )
        if stat.S_IMODE(path_stat.st_mode) & 0o077:
            raise IntelUpdateError("intelligence update token permissions are unsafe")
        token = token_path.read_text(encoding="utf-8").strip()
    except IntelUpdateError:
        raise
    except (OSError, UnicodeDecodeError) as exc:
        raise IntelUpdateError("unable to read intelligence update token") from exc
    if not 32 <= len(token) <= 256 or any(character.isspace() for character in token):
        raise IntelUpdateError("intelligence update token is invalid")
    return token


def _require_secure_regular_file(path: Path, label: str) -> os.stat_result:
    try:
        path_stat = path.lstat()
    except OSError as exc:
        raise IntelUpdateError(f"{label} is unavailable") from exc
    if not stat.S_ISREG(path_stat.st_mode) or path.is_symlink():
        raise IntelUpdateError(f"{label} path is unsafe")
    if stat.S_IMODE(path_stat.st_mode) & 0o022:
        raise IntelUpdateError(f"{label} permissions are unsafe")
    if path_stat.st_uid not in {0, os.geteuid()}:
        raise IntelUpdateError(f"{label} ownership is unsafe")
    return path_stat


def _require_secure_directory(path: Path, label: str) -> os.stat_result:
    try:
        path_stat = path.lstat()
    except OSError as exc:
        raise IntelUpdateError(f"{label} is unavailable") from exc
    if not stat.S_ISDIR(path_stat.st_mode) or path.is_symlink():
        raise IntelUpdateError(f"{label} path is unsafe")
    if stat.S_IMODE(path_stat.st_mode) & 0o022:
        raise IntelUpdateError(f"{label} permissions are unsafe")
    if path_stat.st_uid not in {0, os.geteuid()}:
        raise IntelUpdateError(f"{label} ownership is unsafe")
    return path_stat


def _canonical_records(
    records: list[dict[str, Any]] | tuple[dict[str, Any], ...],
) -> bytes:
    try:
        return json.dumps(
            records,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError) as exc:
        raise IntelUpdateError("intelligence records are not canonical JSON") from exc


def _decode_base64url(value: str, field: str) -> bytes:
    if not re.fullmatch(r"[A-Za-z0-9_-]+={0,2}", value):
        raise IntelUpdateError(f"intelligence bundle {field} encoding is invalid")
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (binascii.Error, ValueError) as exc:
        raise IntelUpdateError(
            f"intelligence bundle {field} encoding is invalid"
        ) from exc


def _required_string(value: Any, field: str, maximum: int) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise IntelUpdateError(f"intelligence bundle {field} is invalid")
    return value


def _required_identifier(value: Any, field: str, pattern: re.Pattern[str]) -> str:
    checked = _required_string(value, field, 128)
    if not pattern.fullmatch(checked):
        raise IntelUpdateError(f"intelligence bundle {field} is invalid")
    return checked


def _parse_timestamp(value: Any, field: str) -> datetime:
    if not isinstance(value, str) or len(value) > 64:
        raise IntelUpdateError(f"intelligence bundle {field} is invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise IntelUpdateError(f"intelligence bundle {field} is invalid") from exc
    if parsed.tzinfo is None:
        raise IntelUpdateError(f"intelligence bundle {field} must include a timezone")
    return parsed.astimezone(timezone.utc)


def _normalized_now(value: datetime | None) -> datetime:
    checked = value or datetime.now(timezone.utc)
    if checked.tzinfo is None:
        checked = checked.replace(tzinfo=timezone.utc)
    return checked.astimezone(timezone.utc)


def _format_timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _constant_time_equal(first: str, second: str) -> bool:
    return hmac.compare_digest(first, second)


def _fsync_file(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
