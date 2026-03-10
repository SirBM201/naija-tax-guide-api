import os
import requests

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

def generate_embedding(text: str):
    response = requests.post(
        "https://api.openai.com/v1/embeddings",
        headers={
            "Authorization": f"Bearer {OPENAI_API_KEY}",
            "Content-Type": "application/json",
        },
        json={
            "model": "text-embedding-3-small",
            "input": text,
        },
    )

    data = response.json()
    return data["data"][0]["embedding"]
