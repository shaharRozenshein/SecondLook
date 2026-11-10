"""Signal: did the sender pass Gmail's authentication checks (SPF, DKIM, DMARC)?"""

import re

from models import EmailInput, Reason

# Only trust results stamped by Gmail itself: a sender can add a forged
# Authentication-Results header of their own, but cannot fake Gmail's server name at the top
TRUSTED_AUTHSERV_ID = "mx.google.com"
RESULT_PATTERN = re.compile(r"\b(spf|dkim|dmarc)=([a-z]+)", re.IGNORECASE)
FAILING_RESULTS = {"fail", "softfail", "permerror"}

POINTS = {"dmarc": 30, "spf": 15, "dkim": 15}
DETAILS = {
    "dmarc": "Failed DMARC: the sender's domain does not vouch for this email, so the address may be forged",
    "spf": "Failed SPF: the email came from a server not authorized to send for this domain",
    "dkim": "Failed DKIM: the email's digital signature is invalid, so it may have been altered",
}


def check_authentication(email: EmailInput) -> list[Reason]:
    header = email.auth_results.strip()
    if not header.lower().startswith(TRUSTED_AUTHSERV_ID):
        return []

    # Collect every result per method (an email can carry several DKIM signatures)
    results: dict[str, set[str]] = {}
    for method, result in RESULT_PATTERN.findall(header):
        results.setdefault(method.lower(), set()).add(result.lower())

    reasons = []
    for method, points in POINTS.items():
        outcomes = results.get(method, set())
        # One passing result is enough; flag only when there is a failure and no pass
        if outcomes & FAILING_RESULTS and "pass" not in outcomes:
            reasons.append(Reason(signal=f"{method}_fail", detail=DETAILS[method], points=points))
    return reasons