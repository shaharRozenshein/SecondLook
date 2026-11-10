"""Signal: pressure and urgency, in words (English and Hebrew) and in formatting.

Pressure alone is capped below the 'Suspicious' threshold: legitimate marketing emails
use urgency too ("Last chance!!"), so it should only add weight to stronger signals.
"""

import re

from models import EmailInput, Reason

MAX_PRESSURE_POINTS = 20
POINTS_PER_PHRASE = 5
MAX_PHRASE_POINTS = 15
POINTS_PER_FORMAT_HIT = 5
MAX_FORMAT_POINTS = 10

PRESSURE_PHRASES = [
    # General (English)
    "urgent", "immediately", "act now", "action required", "final notice", "last warning",
    "within 24 hours", "click here", "verify your account", "confirm your identity",
    "account will be suspended", "account has been suspended", "account will be locked",
    "suspicious activity", "unusual activity", "password will expire",
    # Cloud and developer accounts: the lures Upwind's users receive
    "unusual sign-in", "mfa reset", "reset your mfa", "api key exposed", "credentials exposed",
    "billing issue", "payment failed", "update your payment",
    # Hebrew
    "דחוף", "מיידי", "לחץ כאן", "לחצו כאן", "החשבון שלך ייחסם", "החשבון שלך נחסם",
    "החשבון יושעה", "פעילות חשודה", "תוך 24 שעות", "הודעה אחרונה", "אמתו את פרטיכם",
    "חבילה ממתינה", "התשלום נכשל",
]

REPEATED_PUNCTUATION = re.compile(r"[!?]{2,}")
SHOUTING_WORD = re.compile(r"\b[A-Z]{4,}\b")
WARNING_SYMBOLS = ("⚠", "‼", "🚨", "❗", "⛔")


def check_pressure(email: EmailInput) -> list[Reason]:
    text = f"{email.subject}\n{email.body_text}"
    lowered = text.lower()

    phrases = [phrase for phrase in PRESSURE_PHRASES if phrase in lowered]
    phrase_points = min(len(phrases) * POINTS_PER_PHRASE, MAX_PHRASE_POINTS)

    format_hits = []
    if REPEATED_PUNCTUATION.search(text):
        format_hits.append("repeated exclamation marks")
    if len(SHOUTING_WORD.findall(email.subject)) >= 2:
        format_hits.append("words in ALL CAPS")
    if any(symbol in text for symbol in WARNING_SYMBOLS):
        format_hits.append("warning symbols")
    format_points = min(len(format_hits) * POINTS_PER_FORMAT_HIT, MAX_FORMAT_POINTS)
    # Keep the total within the pressure cap
    format_points = min(format_points, MAX_PRESSURE_POINTS - phrase_points)

    reasons = []
    if phrase_points:
        examples = ", ".join(f'"{phrase}"' for phrase in phrases[:3])
        reasons.append(Reason(signal="pressure_language",
                              detail=f"Uses pressure or urgency wording such as {examples}",
                              points=phrase_points))
    if format_points:
        reasons.append(Reason(signal="pressure_formatting",
                              detail="Uses alarming formatting: " + ", ".join(format_hits),
                              points=format_points))
    return reasons