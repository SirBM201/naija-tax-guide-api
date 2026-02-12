#!/usr/bin/env python3
"""
Backfill canonical_key for qa_library (and optionally qa_cache).

Usage:
  # from project root
  python scripts/backfill_canonical_key.py

Env required:
  SUPABASE_URL
  SUPABASE_SERVICE_ROLE_KEY   (recommended for bulk updates)
Optional:
  BACKFILL_TABLE=qa_library   (default qa_library)
  BATCH_SIZE=500
"""

from __future__ import annotations

import os
import sys
from typing import Any, Dict, List, Optional

# Import your existing supabase client + canonicalizer
# (these paths match your project layout)
from app.core.supabase_client import supabase
from app.services.question_canonicalizer import canonical_key, basic_normalize


def env(name: str, default: str = "") -> str:
    return (os.getenv(name, default) or "").strip()


def _pick_text(row: Dict[str, Any]) -> str:
    """
    Prefer question -> normalized_question -> empty.
    """
    q = (row.get("question") or "").strip()
    if q:
        return q
    nq = (row.get("normalized_question") or "").strip()
    return nq


def _safe_select_cols(db, table: str) -> List[str]:
    """
    Select only columns that exist (Supabase will error on unknown columns).
    We'll probe with minimal selects.
    """
    # must-have columns
    cols = ["id", "canonical_key"]

    # try question
    try:
        db.table(table).select("question").limit(1).execute()
        cols.append("question")
    except Exception:
        pass

    # try normalized_question
    try:
        db.table(table).select("normalized_question").limit(1).execute()
        cols.append("normalized_question")
    except Exception:
        pass

    return cols


def backfill(table: str, batch_size: int = 500) -> None:
    db = supabase()

    cols = _safe_select_cols(db, table)
    sel = ",".join(cols)

    print(f"[info] Backfilling {table}. Selecting columns: {sel}")
    print(f"[info] Batch size: {batch_size}")

    updated = 0
    scanned = 0
    page = 0

    while True:
        start = page * batch_size
        end = start + batch_size - 1

        try:
            res = db.table(table).select(sel).range(start, end).execute()
        except Exception as e:
            print(f"[error] select failed at page={page}: {e}")
            sys.exit(1)

        rows = res.data or []
        if not rows:
            break

        scanned += len(rows)

        for row in rows:
            rid = row.get("id")
            if not rid:
                continue

            # Skip if canonical_key already present and non-empty
            existing_ck = (row.get("canonical_key") or "").strip()
            if existing_ck:
                continue

            text = _pick_text(row)
            if not text:
                # as last resort, store normalized version of empty -> skip
                continue

            ck = canonical_key(text)
            # keep normalized_question consistent (optional)
            nq = basic_normalize(text)

            payload = {"canonical_key": ck}
            # only update normalized_question if that column exists in table
            if "normalized_question" in cols:
                # If normalized_question already exists, don't overwrite non-empty
                cur_nq = (row.get("normalized_question") or "").strip()
                if not cur_nq:
                    payload["normalized_question"] = nq

            try:
                db.table(table).update(payload).eq("id", rid).execute()
                updated += 1
            except Exception as e:
                # Keep going (best-effort), but print so you can inspect
                print(f"[warn] update failed id={rid}: {e}")

        page += 1

    print(f"[done] scanned={scanned}, updated={updated}")


if __name__ == "__main__":
    # Quick env sanity
    if not env("SUPABASE_URL") or not (env("SUPABASE_SERVICE_ROLE_KEY") or env("SUPABASE_ANON_KEY")):
        print("[error] Missing SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY (recommended).")
        print("        Set env vars and re-run.")
        sys.exit(1)

    table = env("BACKFILL_TABLE", "qa_library")
    batch_size = int(env("BATCH_SIZE", "500") or "500")

    backfill(table=table, batch_size=batch_size)
