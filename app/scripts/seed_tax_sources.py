# app/scripts/seed_tax_sources.py

from app.core.supabase_client import supabase


def seed_sources():
    sb = supabase()

    print("Seeding Nigerian tax knowledge...")

    # 1️⃣ Register source
    source = {
        "source_id": "firs_vat_guidance_2024",
        "title": "FIRS VAT Guidance",
        "jurisdiction": "Nigeria",
        "tax_type": "VAT",
        "authority_rank": 0.95,
        "source_url": "https://www.firs.gov.ng"
    }

    sb.table("tax_source_registry").upsert(source).execute()

    # 2️⃣ Knowledge chunks
    chunks = [

        {
            "topic": "vat",
            "intent_type": "definition",
            "summary": "Definition of VAT",
            "text_content":
            "Value Added Tax (VAT) is a consumption tax charged on goods and services in Nigeria.",
            "keywords": ["vat", "value added tax", "meaning of vat"]
        },

        {
            "topic": "vat",
            "intent_type": "rate",
            "summary": "VAT rate Nigeria",
            "text_content":
            "The standard VAT rate in Nigeria is 7.5% as provided under the Finance Act.",
            "keywords": ["vat rate", "vat percentage", "7.5 vat nigeria"]
        },

        {
            "topic": "vat",
            "intent_type": "exemption",
            "summary": "VAT exemptions",
            "text_content":
            "Basic food items, medical services, educational materials, and rent on residential property are exempt from VAT in Nigeria.",
            "keywords": ["vat exemption", "goods exempt vat"]
        },

        {
            "topic": "paye",
            "intent_type": "definition",
            "summary": "PAYE definition",
            "text_content":
            "PAYE (Pay As You Earn) is a system where employers deduct income tax from employees' salaries and remit it to the tax authority.",
            "keywords": ["paye tax", "meaning paye nigeria"]
        },

        {
            "topic": "paye",
            "intent_type": "computation",
            "summary": "PAYE computation basics",
            "text_content":
            "PAYE tax in Nigeria is computed based on the Personal Income Tax Act using progressive tax rates after allowable reliefs.",
            "keywords": ["paye calculation", "paye nigeria"]
        },

        {
            "topic": "freelancer",
            "intent_type": "guidance",
            "summary": "Freelancer tax basics",
            "text_content":
            "Freelancers earning income in Nigeria are required to register for tax and may be subject to personal income tax depending on their income level.",
            "keywords": ["freelancer tax nigeria", "self employed tax nigeria"]
        }

    ]

    for chunk in chunks:
        sb.table("tax_source_chunks").insert(chunk).execute()

    print("Tax knowledge seeded successfully.")


if __name__ == "__main__":
    seed_sources()
    
