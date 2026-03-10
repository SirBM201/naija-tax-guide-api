from app.core.supabase_client import supabase
from .embedding_service import generate_embedding


def store_semantic_cache(question, answer, cache_id):

    embedding = generate_embedding(question)

    supabase.table("qa_embeddings").insert(
        {
            "cache_id": cache_id,
            "question": question,
            "embedding": embedding,
        }
    ).execute()
