from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import Case, EvidenceLedger

GENESIS_PREVIOUS_HASH = "0" * 64


def _normalize_ts_iso(ts: datetime | str | None) -> str:
    """Normalize datetime or ISO string to canonical UTC string without tz variance."""
    if not ts:
        return ""
    if isinstance(ts, str):
        # Strip trailing Z or +00:00 if present for uniform representation
        clean = ts.replace("Z", "").split("+")[0]
        return clean
    if isinstance(ts, datetime):
        if ts.tzinfo is not None:
            ts = ts.astimezone(timezone.utc).replace(tzinfo=None)
        return ts.isoformat()
    return str(ts)


def canonical_hash(data: Any) -> str:
    """Compute deterministic SHA-256 hex digest for arbitrary data."""
    if isinstance(data, str) and len(data) == 64 and all(c in "0123456789abcdefABCDEF" for c in data):
        return data.lower()

    canonical = json.dumps(
        data,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def compute_entry_hash(
    sequence_number: int,
    entry_type: str,
    reference_id: str,
    data_hash: str,
    previous_hash: str,
    timestamp: datetime | str | None,
) -> str:
    """Computes a SHA-256 block hash for an EvidenceLedger record."""
    ts_str = _normalize_ts_iso(timestamp)
    block_payload = f"{sequence_number}|{entry_type}|{reference_id}|{data_hash}|{previous_hash}|{ts_str}"
    return hashlib.sha256(block_payload.encode("utf-8")).hexdigest()


def compute_merkle_root(hashes: list[str]) -> str:
    """Computes the binary Merkle root hash for a list of SHA-256 hex strings."""
    if not hashes:
        return "0" * 64

    current_layer = [h.lower() for h in hashes]

    while len(current_layer) > 1:
        next_layer: list[str] = []
        # If odd number of nodes, duplicate the last node
        if len(current_layer) % 2 == 1:
            current_layer.append(current_layer[-1])

        for i in range(0, len(current_layer), 2):
            combined = current_layer[i] + current_layer[i + 1]
            parent_hash = hashlib.sha256(combined.encode("utf-8")).hexdigest()
            next_layer.append(parent_hash)

        current_layer = next_layer

    return current_layer[0]


def record_ledger_entry(
    db: Session,
    case_id: int,
    entry_type: str,
    data_or_hash: Any,
    reference_id: str = "",
    metadata: dict[str, Any] | None = None,
) -> EvidenceLedger:
    """
    Append an immutable, cryptographically chained block to the case's Evidence Ledger.
    Automatically generates a Genesis block (sequence=1) if none exists.
    """
    case = db.get(Case, case_id)
    if not case:
        raise ValueError(f"Case with ID {case_id} not found.")

    # Find the latest ledger entry for this case
    stmt = (
        select(EvidenceLedger)
        .where(EvidenceLedger.case_id == case_id)
        .order_by(EvidenceLedger.sequence_number.desc())
    )
    latest_entry = db.scalars(stmt).first()

    # If no entries exist and current request is not GENESIS, create GENESIS block first
    if latest_entry is None and entry_type != "GENESIS":
        gen_time = datetime.now(timezone.utc)
        gen_data_hash = canonical_hash({"case_number": case.case_number, "title": case.title, "genesis": True})
        gen_entry_hash = compute_entry_hash(
            sequence_number=1,
            entry_type="GENESIS",
            reference_id=case.case_number,
            data_hash=gen_data_hash,
            previous_hash=GENESIS_PREVIOUS_HASH,
            timestamp=gen_time,
        )
        genesis_block = EvidenceLedger(
            case_id=case_id,
            sequence_number=1,
            entry_type="GENESIS",
            reference_id=case.case_number,
            data_hash=gen_data_hash,
            previous_hash=GENESIS_PREVIOUS_HASH,
            entry_hash=gen_entry_hash,
            metadata_json=json.dumps({"description": f"Genesis block for case {case.case_number}"}),
            timestamp=gen_time,
        )
        db.add(genesis_block)
        db.commit()
        db.refresh(genesis_block)
        latest_entry = genesis_block

    # Calculate fields for the new entry
    seq = (latest_entry.sequence_number + 1) if latest_entry else 1
    prev_hash = latest_entry.entry_hash if latest_entry else GENESIS_PREVIOUS_HASH
    data_h = canonical_hash(data_or_hash)
    now = datetime.now(timezone.utc)

    block_hash = compute_entry_hash(
        sequence_number=seq,
        entry_type=entry_type,
        reference_id=str(reference_id),
        data_hash=data_h,
        previous_hash=prev_hash,
        timestamp=now,
    )

    new_block = EvidenceLedger(
        case_id=case_id,
        sequence_number=seq,
        entry_type=entry_type,
        reference_id=str(reference_id),
        data_hash=data_h,
        previous_hash=prev_hash,
        entry_hash=block_hash,
        metadata_json=json.dumps(metadata or {}, ensure_ascii=False),
        timestamp=now,
    )
    db.add(new_block)
    db.commit()
    db.refresh(new_block)
    return new_block


def get_case_ledger(db: Session, case_id: int) -> list[EvidenceLedger]:
    """Retrieve all ledger entries for a case ordered by sequence_number."""
    stmt = (
        select(EvidenceLedger)
        .where(EvidenceLedger.case_id == case_id)
        .order_by(EvidenceLedger.sequence_number.asc())
    )
    return list(db.scalars(stmt).all())


def verify_case_ledger(db: Session, case_id: int) -> dict[str, Any]:
    """
    Cryptographically verify the integrity of the evidence ledger for a given case.
    Re-hashes every block, checks previous_hash chaining, and computes the Merkle root.
    """
    case = db.get(Case, case_id)
    if not case:
        return {
            "case_id": case_id,
            "status": "not_found",
            "is_valid": False,
            "total_entries": 0,
            "verified_entries": 0,
            "first_break_at": None,
            "merkle_root": "0" * 64,
            "latest_entry_hash": None,
            "message": f"Case ID {case_id} does not exist.",
        }

    entries = get_case_ledger(db, case_id)
    if not entries:
        return {
            "case_id": case_id,
            "status": "empty",
            "is_valid": True,
            "total_entries": 0,
            "verified_entries": 0,
            "first_break_at": None,
            "merkle_root": "0" * 64,
            "latest_entry_hash": None,
            "message": "No ledger entries recorded yet for this case.",
        }

    expected_prev_hash = GENESIS_PREVIOUS_HASH
    entry_hashes: list[str] = []

    for idx, entry in enumerate(entries, start=1):
        # 1. Verify sequence order
        if entry.sequence_number != idx:
            return {
                "case_id": case_id,
                "status": "tampered",
                "is_valid": False,
                "total_entries": len(entries),
                "verified_entries": idx - 1,
                "first_break_at": entry.sequence_number,
                "break_reason": f"Sequence discontinuity: expected {idx}, found {entry.sequence_number}.",
                "merkle_root": None,
                "latest_entry_hash": None,
            }

        # 2. Verify previous_hash linkage
        if entry.previous_hash != expected_prev_hash:
            return {
                "case_id": case_id,
                "status": "tampered",
                "is_valid": False,
                "total_entries": len(entries),
                "verified_entries": idx - 1,
                "first_break_at": entry.sequence_number,
                "break_reason": f"Previous hash mismatch at block #{entry.sequence_number}.",
                "merkle_root": None,
                "latest_entry_hash": None,
            }

        # 3. Recompute entry_hash and compare
        expected_entry_hash = compute_entry_hash(
            sequence_number=entry.sequence_number,
            entry_type=entry.entry_type,
            reference_id=entry.reference_id,
            data_hash=entry.data_hash,
            previous_hash=entry.previous_hash,
            timestamp=entry.timestamp,
        )

        if entry.entry_hash != expected_entry_hash:
            return {
                "case_id": case_id,
                "status": "tampered",
                "is_valid": False,
                "total_entries": len(entries),
                "verified_entries": idx - 1,
                "first_break_at": entry.sequence_number,
                "break_reason": f"Entry hash signature invalid for block #{entry.sequence_number}.",
                "merkle_root": None,
                "latest_entry_hash": None,
            }

        entry_hashes.append(entry.entry_hash)
        expected_prev_hash = entry.entry_hash

    # All blocks verified
    merkle_root = compute_merkle_root(entry_hashes)
    return {
        "case_id": case_id,
        "status": "intact",
        "is_valid": True,
        "total_entries": len(entries),
        "verified_entries": len(entries),
        "first_break_at": None,
        "merkle_root": merkle_root,
        "latest_entry_hash": entries[-1].entry_hash,
        "message": f"Ledger integrity verified: {len(entries)} blocks chained and valid.",
    }
