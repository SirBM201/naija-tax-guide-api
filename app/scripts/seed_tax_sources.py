from __future__ import annotations

from typing import Any, Dict, List

from app.core.supabase_client import supabase


def _sb():
    return supabase() if callable(supabase) else supabase


def seed_sources() -> Dict[str, Any]:
    sb = _sb()

    source = {
        "source_id": "firs_vat_guidance_2024",
        "title": "FIRS VAT Guidance 2024",
        "source_type": "guidance",
        "jurisdiction": "NG",
        "tax_type": "vat",
        "law_family": "VAT Act / Finance Act",
        "authority_rank": 0.95,
        "source_url": "https://www.firs.gov.ng/",
    }

    chunks: List[Dict[str, Any]] = [
        {
            "source_id": "firs_vat_guidance_2024",
            "topic": "vat",
            "intent_type": "definition",
            "jurisdiction": "NG",
            "summary": "Definition of VAT",
            "text_content": "Value Added Tax (VAT) is a consumption tax charged on taxable goods and services in Nigeria.",
            "keywords": ["vat", "value added tax", "vat meaning", "what is vat"],
        },
        {
            "source_id": "firs_vat_guidance_2024",
            "topic": "vat",
            "intent_type": "rate",
            "jurisdiction": "NG",
            "summary": "VAT rate in Nigeria",
            "text_content": "The standard VAT rate in Nigeria is 7.5 percent.",
            "keywords": ["vat rate", "7.5%", "nigeria vat rate"],
        },
        {
            "source_id": "firs_vat_guidance_2024",
            "topic": "vat",
            "intent_type": "exemption",
            "jurisdiction": "NG",
            "summary": "VAT exemptions",
            "text_content": "Some items may be exempt or zero-rated depending on the applicable Nigerian tax rules and guidance.",
            "keywords": ["vat exemptions", "vat exempt items", "zero rated vat"],
        },
        {
            "source_id": "firs_vat_guidance_2024",
            "topic": "paye",
            "intent_type": "definition",
            "jurisdiction": "NG",
            "summary": "PAYE definition",
            "text_content": "PAYE means Pay As You Earn, a system where employers deduct personal income tax from employee salaries and remit it to the relevant tax authority.",
            "keywords": ["paye", "what is paye", "paye meaning"],
        },
        {
            "source_id": "firs_vat_guidance_2024",
            "topic": "paye",
            "intent_type": "computation",
            "jurisdiction": "NG",
            "summary": "PAYE computation basics",
            "text_content": "PAYE is computed using taxable income after allowable reliefs and the applicable progressive tax bands.",
            "keywords": ["paye calculation", "how to compute paye", "paye nigeria"],
        },
        {
            "source_id": "firs_vat_guidance_2024",
            "topic": "freelancer",
            "intent_type": "guidance",
            "jurisdiction": "NG",
            "summary": "Freelancer tax basics",
            "text_content": "Freelancers in Nigeria may have personal income tax obligations depending on the nature of income, residency, and applicable state tax rules.",
            "keywords": ["freelancer tax", "self employed tax", "creator tax nigeria"],
        },
    ]

    sb.table("tax_source_registry").upsert(source, on_conflict="source_id").execute()

    inserted = 0
    for chunk in chunks:
        sb.table("tax_source_chunks").insert(chunk).execute()
        inserted += 1

    return {
        "source_id": source["source_id"],
        "chunks_inserted": inserted,
    }


if __name__ == "__main__":
    print(seed_sources())
