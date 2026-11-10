"""Signals about who sent the email: malformed sender, brand impersonation,
look-alike domains and a mismatched Reply-To."""

import re
from difflib import SequenceMatcher

from brands import BRANDS, FREE_MAIL_DOMAINS
from domains import base_domain, belongs_to, main_label, normalize_homoglyphs, parse_address
from models import EmailInput, Reason

SIMILARITY_THRESHOLD = 0.83
MIN_FUZZY_LENGTH = 5  # short names (aws, okta) must match exactly, to avoid false alarms


def _is_legit_for(domain: str, brand: dict) -> bool:
    return any(belongs_to(domain, legit) for legit in brand["domains"])


def _mentions(text: str, keyword: str) -> bool:
    """Whole-word match: 'aws' matches 'AWS Billing' but not 'Dawson'."""
    return re.search(rf"(?<![a-z]){re.escape(keyword)}(?![a-z])", text) is not None

def _lookalike_labels(brand: dict) -> set[str]:
    """Names an imitating domain might use: the primary domain's name plus one-word English keywords."""
    labels = {main_label(brand["domains"][0])}
    labels.update(k for k in brand["keywords"] if k.isascii() and " " not in k and len(k) >= 3)
    return labels


def _similar(token: str, label: str) -> bool:
    if token == label:
        return True
    if len(token) < MIN_FUZZY_LENGTH or len(label) < MIN_FUZZY_LENGTH:
        return False
    return SequenceMatcher(None, token, label).ratio() >= SIMILARITY_THRESHOLD


def check_sender_format(email: EmailInput) -> list[Reason]:
    _, domain = parse_address(email.sender)
    if not domain or "." not in domain:
        return [Reason(signal="malformed_sender",
                       detail="The sender address is missing or malformed", points=20)]
    return []


def check_display_name(email: EmailInput) -> list[Reason]:
    """Display name mentions a brand, but the address is not from that brand's domain."""
    name, domain = parse_address(email.sender)
    if not name or not domain:
        return []
    lowered = name.lower()
    for brand_name, brand in BRANDS.items():
        if any(_mentions(lowered, keyword) for keyword in brand["keywords"]) and not _is_legit_for(domain, brand):
            return [Reason(signal="display_name_impersonation",
                           detail=f"Display name mentions {brand_name}, but the email was sent from {domain}",
                           points=30)]
    return []

def _imitated_brand(domain: str) -> str | None:
    """Return the brand a domain imitates (paypa1.com, aws-billing.net), or None."""
    if base_domain(domain) in FREE_MAIL_DOMAINS:
        return None
    if any(_is_legit_for(domain, brand) for brand in BRANDS.values()):
        return None

    # Brand domain hidden inside a longer domain: paypal.com.evil.net
    for brand_name, brand in BRANDS.items():
        if any(f".{legit}." in f".{domain}." for legit in brand["domains"]):
            return brand_name

    tokens = normalize_homoglyphs(main_label(domain)).split("-")
    for brand_name, brand in BRANDS.items():
        for label in _lookalike_labels(brand):
            if any(_similar(token, label) for token in tokens):
                return brand_name
    return None

def check_lookalike_domain(email: EmailInput) -> list[Reason]:
    _, domain = parse_address(email.sender)
    if not domain:
        return []
    reasons = []
    if domain.startswith("xn--") or ".xn--" in domain:
        reasons.append(Reason(signal="punycode_domain",
                              detail=f"The sender domain {domain} uses encoded characters that can hide look-alike letters",
                              points=20))
    brand = _imitated_brand(domain)
    if brand:
        reasons.append(Reason(signal="lookalike_domain",
                              detail=f"The sender domain {domain} imitates {brand} but does not belong to it",
                              points=35))
    return reasons


def check_reply_to(email: EmailInput) -> list[Reason]:
    """Replies would go to a different organization than the one that sent the email."""
    if not email.reply_to.strip():
        return []
    _, sender_domain = parse_address(email.sender)
    _, reply_domain = parse_address(email.reply_to)
    if sender_domain and reply_domain and base_domain(sender_domain) != base_domain(reply_domain):
        return [Reason(signal="reply_to_mismatch",
                       detail=f"Replies would go to {reply_domain}, not to the sender's domain {sender_domain}",
                       points=15)]
    return []