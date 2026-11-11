"""Text cleanup applied before matching, so invisible characters cannot hide keywords."""

import re
import unicodedata

# Zero-width and other invisible formatting characters that attackers insert inside words
INVISIBLE_CHARACTERS = re.compile(r"[\u00ad\u200b-\u200f\u2060-\u2064\ufeff]")


def clean_text(text: str) -> str:
    """Normalize special variants of characters (e.g. full-width letters) and remove invisible ones."""
    return INVISIBLE_CHARACTERS.sub("", unicodedata.normalize("NFKC", text))