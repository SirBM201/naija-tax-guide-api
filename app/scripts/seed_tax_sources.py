from __future__ import annotations

from typing import Any, Dict, List

from app.core.supabase_client import supabase


SOURCE_ID = "firs_vat_guidance_2024"


def _sb():
    return supabase() if callable(supabase) else supabase


def _as_list(value: Any) -> List[Dict[str, Any]]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return []


def _source_payload() -> Dict[str, Any]:
    return {
        "source_id": SOURCE_ID,
        "title": "FIRS VAT Guidance 2024",
        "source_type": "guidance",
        "jurisdiction": "NG",
        "tax_type": "vat",
        "law_family": "VAT Act / Finance Act / PITA",
        "authority_rank": 0.95,
        "source_url": "https://www.firs.gov.ng/",
    }


def _chunk_payloads() -> List[Dict[str, Any]]:
    return [
        {
            "chunk_id": "firs_vat_guidance_2024_vat_definition",
            "source_id": SOURCE_ID,
            "topic": "vat",
            "intent_type": "definition",
            "relevance_tier": "medium",
            "jurisdiction": "NG",
            "text_content": "Value Added Tax (VAT) is a consumption tax charged on taxable goods and services in Nigeria.",
            "summary": "Definition of VAT",
            "keywords": ["vat", "value added tax", "vat meaning", "what is vat"],
            "is_active": True,
        },
        {
            "chunk_id": "firs_vat_guidance_2024_vat_rate",
            "source_id": SOURCE_ID,
            "topic": "vat",
            "intent_type": "rate",
            "relevance_tier": "high",
            "jurisdiction": "NG",
            "text_content": "The standard VAT rate in Nigeria is 7.5 percent.",
            "summary": "VAT rate in Nigeria",
            "keywords": ["vat rate", "7.5%", "nigeria vat rate"],
            "is_active": True,
        },
        {
            "chunk_id": "firs_vat_guidance_2024_vat_exemptions",
            "source_id": SOURCE_ID,
            "topic": "vat",
            "intent_type": "exemption",
            "relevance_tier": "medium",
            "jurisdiction": "NG",
            "text_content": "Certain supplies may be exempt or zero-rated depending on the applicable Nigerian tax rules, schedules, and current FIRS guidance.",
            "summary": "VAT exemptions",
            "keywords": ["vat exemptions", "vat exempt items", "zero rated vat"],
            "is_active": True,
        },
        {
            "chunk_id": "firs_vat_guidance_2024_paye_definition",
            "source_id": SOURCE_ID,
            "topic": "paye",
            "intent_type": "definition",
            "relevance_tier": "medium",
            "jurisdiction": "NG",
            "text_content": "PAYE means Pay As You Earn, a system where employers deduct personal income tax from employee salaries and remit it to the relevant tax authority.",
            "summary": "PAYE definition",
            "keywords": ["paye", "what is paye", "paye meaning"],
            "is_active": True,
        },
        {
            "chunk_id": "firs_vat_guidance_2024_paye_computation",
            "source_id": SOURCE_ID,
            "topic": "paye",
            "intent_type": "computation",
            "relevance_tier": "high",
            "jurisdiction": "NG",
            "text_content": "PAYE is computed using taxable income after allowable reliefs and the applicable progressive tax bands under Nigerian personal income tax rules.",
            "summary": "PAYE computation basics",
            "keywords": ["paye calculation", "how to compute paye", "paye nigeria"],
            "is_active": True,
        },
        {
            "chunk_id": "firs_vat_guidance_2024_freelancer_guidance",
            "source_id": SOURCE_ID,
            "topic": "freelancer",
            "intent_type": "guidance",
            "relevance_tier": "medium",
            "jurisdiction": "NG",
            "text_content": "Freelancers in Nigeria may have personal income tax obligations depending on the nature of income, tax residence, and applicable state tax rules.",
            "summary": "Freelancer tax basics",
            "keywords": ["freelancer tax", "self employed tax", "creator tax nigeria"],
            "is_active": True,
        },
    ]


def _find_source(sb, source_id: str) -> List[Dict[str, Any]]:
    res = (
        sb.table("tax_source_registry")
        .select("source_id")
        .eq("source_id", source_id)
        .limit(1)
        .execute()
    )
    return _as_list(getattr(res, "data", None))


def _find_chunk_by_chunk_id(sb, chunk_id: str) -> List[Dict[str, Any]]:
    res = (
        sb.table("tax_source_chunks")
        .select("chunk_id")
        .eq("chunk_id", chunk_id)
        .limit(1)
        .execute()
    )
    return _as_list(getattr(res, "data", None))


def _count_existing_chunks(sb, source_id: str) -> int:
    res = (
        sb.table("tax_source_chunks")
        .select("chunk_id")
        .eq("source_id", source_id)
        .execute()
    )
    return len(_as_list(getattr(res, "data", None)))


def _delete_existing_chunks(sb, source_id: str) -> int:
    count = _count_existing_chunks(sb, source_id)
    if count > 0:
        sb.table("tax_source_chunks").delete().eq("source_id", source_id).execute()
    return count


def seed_sources(*, allow_reseed: bool = False) -> Dict[str, Any]:
    sb = _sb()

    source = _source_payload()
    chunks = _chunk_payloads()

    existing_source = _find_source(sb, SOURCE_ID)

    sb.table("tax_source_registry").upsert(source, on_conflict="source_id").execute()

    chunks_deleted = 0
    chunks_inserted = 0
    chunks_skipped = 0

    if allow_reseed:
        chunks_deleted = _delete_existing_chunks(sb, SOURCE_ID)

    for chunk in chunks:
        existing_chunk = _find_chunk_by_chunk_id(sb, chunk["chunk_id"])

        if existing_chunk and not allow_reseed:
            chunks_skipped += 1
            continue

        if existing_chunk and allow_reseed:
            sb.table("tax_source_chunks").delete().eq("chunk_id", chunk["chunk_id"]).execute()

        sb.table("tax_source_chunks").insert(chunk).execute()
        chunks_inserted += 1

    final_chunk_count = _count_existing_chunks(sb, SOURCE_ID)

    return {
        "status": "seed_completed",
        "source_id": SOURCE_ID,
        "source_inserted": True,
        "source_already_exists": bool(existing_source),
        "allow_reseed": allow_reseed,
        "chunks_deleted": chunks_deleted,
        "chunks_inserted": chunks_inserted,
        "chunks_skipped": chunks_skipped,
        "final_chunk_count": final_chunk_count,
    }


if __name__ == "__main__":
    print(seed_sources(allow_reseed=False))
