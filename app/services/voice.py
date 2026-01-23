# app/services/voice.py
from typing import Tuple, Optional

def ensure_voice_for_text(normalized_q: str, text: str, provider: str, style: str) -> Tuple[Optional[str], bool]:
    # Voice not enabled yet: return (no audio_url, not generated)
    return None, False
