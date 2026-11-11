"""Signals about links in the email body. Links are only parsed as text, never opened."""

import ipaddress
import re
from html.parser import HTMLParser
from urllib.parse import urlparse

from domains import base_domain
from models import EmailInput, Reason
from signals.sender import imitated_brand
from signals.sender import brand_in_subdomain, imitated_brand

MAX_LINKS = 200
URL_IN_TEXT = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
LOOKS_LIKE_URL = re.compile(r"^(https?://)?([a-z0-9-]+\.)+[a-z]{2,}(:\d+)?(/\S*)?$", re.IGNORECASE)
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
              "cutt.ly", "rebrand.ly", "shorturl.at"}


class _LinkCollector(HTMLParser):
    """Collects (href, visible text) pairs from <a> tags. Parsing only: nothing is loaded or run."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links: list[tuple[str, str]] = []
        self._href: str | None = None
        self._text: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._href = dict(attrs).get("href") or ""
            self._text = []

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            self.links.append((self._href.strip(), "".join(self._text).strip()))
            self._href = None


def extract_links(email: EmailInput) -> list[tuple[str, str]]:
    """All links in the email as (href, visible text). Plain-text links have no visible text."""
    collector = _LinkCollector()
    collector.feed(email.body_html)
    links = collector.links + [(url, "") for url in URL_IN_TEXT.findall(email.body_text)]
    return links[:MAX_LINKS]


def _host(url: str) -> str:
    """Lowercase hostname of an http(s) URL, or '' if it is not a web link."""
    try:
        parsed = urlparse(url)
        if parsed.scheme.lower() not in ("http", "https"):
            return ""
        return (parsed.hostname or "").lower()
    except ValueError:
        return ""


def _has_userinfo(url: str) -> bool:
    """True for links like https://paypal.com@evil.net, where the real host comes after the @."""
    try:
        return urlparse(url).username is not None
    except ValueError:
        return False


def _shown_host(text: str) -> str:
    """If the visible link text looks like a web address, return its host."""
    if not LOOKS_LIKE_URL.match(text):
        return ""
    return _host(text if "://" in text else "http://" + text)


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False

def check_links(email: EmailInput) -> list[Reason]:
    findings: dict[str, Reason] = {}

    def add(signal: str, detail: str, points: int) -> None:
        # Report each kind of problem once, using the first link that shows it
        findings.setdefault(signal, Reason(signal=signal, detail=detail, points=points))

    for href, text in extract_links(email):
        host = _host(href)
        if not host:
            continue
        shown = _shown_host(text)
        if shown and base_domain(shown) != base_domain(host):
            add("deceptive_link", f"A link shows {shown} but actually leads to {host}", 30)
        if _has_userinfo(href):
            add("hidden_link_destination", f"A link uses an '@' trick to disguise its real destination ({host})", 25)
        if _is_ip(host):
            add("ip_address_link", f"A link points to a raw IP address ({host}) instead of a named website", 20)
        if base_domain(host) in SHORTENERS:
            add("shortened_link", f"A link uses a URL shortener ({host}) that hides its destination", 10)
        brand = imitated_brand(host)
        if brand:
            add("lookalike_link", f"A link leads to {host}, which imitates {brand}", 30)
        else:
            sub_brand = brand_in_subdomain(host)
            if sub_brand:
                add("brand_subdomain_link",
                    f"A link leads to {host}, which uses the name {sub_brand} on a domain that does not belong to it", 20)
    return list(findings.values())