# app/services/voice.py
from typing import Tuple, Optional

def ensure_voice_for_text(normalized_question: str, text: str, provider: str, style: str) -> Tuple[Optional[str], bool]:
    """
    Returns (audio_url, generated_now).
    Stubbed: voice generation disabled for now.
    """
    return None, False
