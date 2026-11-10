"""Runs all signal checks and turns their findings into a score and a verdict."""

import logging

from models import AnalysisResult, EmailInput, Reason
from signals.auth import check_authentication
from signals.sender import check_display_name, check_lookalike_domain, check_reply_to, check_sender_format
from signals.attachments import check_attachments
from signals.links import check_links
from signals.pressure import check_pressure
logger = logging.getLogger(__name__)

MAX_SCORE = 100
SUSPICIOUS_THRESHOLD = 25
PHISHING_THRESHOLD = 60

# Each check receives the email and returns a list of Reasons (empty if nothing was found).
CHECKS = [
    check_authentication,
    check_sender_format,
    check_display_name,
    check_lookalike_domain,
    check_reply_to,
    check_links,
    check_pressure,
    check_attachments,
]

def verdict_for(score: int) -> str:
    """Translate a numeric score into a verdict."""
    if score >= PHISHING_THRESHOLD:
        return "Likely phishing"
    if score >= SUSPICIOUS_THRESHOLD:
        return "Suspicious"
    return "Low risk"


def analyze_email(email: EmailInput) -> AnalysisResult:
    """Run every check, sum the points, and build the result."""
    reasons: list[Reason] = []
    for check in CHECKS:
        try:
            reasons.extend(check(email))
        except Exception:
            # Email content is untrusted: one failing check must not break the whole analysis
            logger.exception("Check %s failed", check.__name__)

    score = min(sum(reason.points for reason in reasons), MAX_SCORE)
    reasons.sort(key=lambda reason: reason.points, reverse=True)
    return AnalysisResult(score=score, verdict=verdict_for(score), reasons=reasons)