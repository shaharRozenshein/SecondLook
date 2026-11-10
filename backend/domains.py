"""Helpers for parsing email addresses and comparing domains."""

from email.utils import parseaddr

# Suffixes where the registrable domain has three parts (e.g. leumi.co.il)
MULTI_PART_SUFFIXES = {"co.il", "org.il", "gov.il", "ac.il", "net.il", "co.uk", "org.uk", "com.au"}

# Characters attackers swap in so a domain looks like a brand (paypa1 -> paypal)
HOMOGLYPHS = {"0": "o", "1": "l", "3": "e", "5": "s", "rn": "m", "vv": "w"}


def parse_address(raw: str) -> tuple[str, str]:
    """Split 'Name <user@domain>' into (display name, lowercase domain). Domain is '' if missing."""
    name, address = parseaddr(raw or "")
    domain = address.rsplit("@", 1)[1].lower().strip() if "@" in address else ""
    return name.strip(), domain


def base_domain(domain: str) -> str:
    """Registrable domain: mail.paypal.com -> paypal.com, x.leumi.co.il -> leumi.co.il."""
    labels = domain.split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in MULTI_PART_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def main_label(domain: str) -> str:
    """The name part of the registrable domain: paypal.com -> paypal."""
    return base_domain(domain).split(".")[0]


def normalize_homoglyphs(text: str) -> str:
    """Replace common look-alike characters: paypa1 -> paypal, rnicrosoft -> microsoft."""
    for fake, real in HOMOGLYPHS.items():
        text = text.replace(fake, real)
    return text


def belongs_to(domain: str, legit_domain: str) -> bool:
    """True if domain is legit_domain itself or one of its subdomains."""
    return domain == legit_domain or domain.endswith("." + legit_domain)