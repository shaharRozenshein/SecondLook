"""Scenario tests for the scoring engine: each case is an email and the expected outcome."""

import pytest

from models import EmailInput
from scoring import analyze_email

FAILED_AUTH = ("mx.google.com; spf=fail smtp.mailfrom=company.com; dkim=none; "
               "dmarc=fail header.from=company.com")

CASES = [
    # --- Sender and authentication ---
    pytest.param({"sender": "PayPal Security <alert@paypa1-secure.com>", "subject": "Your account"},
                 65, "Likely phishing", {"lookalike_domain", "display_name_impersonation"},
                 id="paypal-impersonation"),
    pytest.param({"sender": "PayPal <service@paypal.com>", "subject": "Your receipt"},
                 0, "Low risk", set(), id="real-paypal"),
    pytest.param({"sender": "בנק לאומי <info@leumi-update.net>", "subject": "עדכון פרטים"},
                 65, "Likely phishing", {"lookalike_domain", "display_name_impersonation"},
                 id="hebrew-bank-impersonation"),
    pytest.param({"sender": "Dana <dana@company.com>", "reply_to": "dana.payments@gmail.com",
                  "subject": "Invoice", "auth_results": FAILED_AUTH},
                 60, "Likely phishing", {"dmarc_fail", "spf_fail", "reply_to_mismatch"},
                 id="failed-auth-and-reply-to"),
    pytest.param({"sender": "Dana <dana@company.com>", "subject": "Hi",
                  "auth_results": "evil-server.com; dmarc=fail"},
                 0, "Low risk", set(), id="forged-auth-header-ignored"),
    pytest.param({"sender": "AWS Billing <billing@aws-account-billing.com>",
                  "subject": "Your account will be suspended"},
                 70, "Likely phishing",
                 {"lookalike_domain", "display_name_impersonation", "pressure_language"},
                 id="aws-impersonation"),
    pytest.param({"sender": "Upwind Security <alerts@upwind-security.io>", "subject": "Critical runtime alert"},
                 65, "Likely phishing", {"lookalike_domain", "display_name_impersonation"},
                 id="upwind-impersonation"),
    pytest.param({"sender": "Dawson Laws <dawson@gmail.com>", "subject": "Lunch tomorrow?"},
                 0, "Low risk", set(), id="no-false-alarm-on-dawson"),
    pytest.param({"sender": "Support Team", "subject": "Hi"},
                 20, "Low risk", {"malformed_sender"}, id="malformed-sender"),
    pytest.param({"sender": "Support <help@xn--pypal-4ve.com>", "subject": "Hi"},
                 55, "Suspicious", {"punycode_domain", "lookalike_domain"}, id="punycode-domain"),
    pytest.param({"sender": "Amazon <orders@amazom.com>", "subject": "Your order"},
                 65, "Likely phishing", {"lookalike_domain", "display_name_impersonation"},
                 id="near-identical-domain"),
    pytest.param({"sender": "PayPal <service@mail.paypal.com>", "subject": "Receipt"},
                 0, "Low risk", set(), id="legit-subdomain"),
    pytest.param({"sender": "PayPal <service@paypal.com.evil.net>", "subject": "Receipt"},
                 65, "Likely phishing", {"lookalike_domain", "display_name_impersonation"},
                 id="brand-domain-hidden-in-longer-domain"),
    pytest.param({"sender": "AWS1 Billing <billing@example.com>", "subject": "Invoice"},
                 30, "Suspicious", {"display_name_impersonation"}, id="digit-next-to-brand"),
    pytest.param({"sender": "ביטוח לאומי <info@btl.gov.il>", "subject": "עדכון"},
                 0, "Low risk", set(), id="national-insurance-not-confused-with-bank"),
    pytest.param({"sender": "Dana <dana@company.com>", "subject": "Hi",
                  "auth_results": "mx.google.com; dkim=pass header.i=@company.com; "
                                  "dkim=fail header.i=@list.org; spf=pass; dmarc=pass"},
                 0, "Low risk", set(), id="one-passing-dkim-is-enough"),
    pytest.param({"sender": "Dana <dana@mail.company.com>", "reply_to": "support@company.com", "subject": "Hi"},
                 0, "Low risk", set(), id="reply-to-same-organization"),
    pytest.param({"sender": "Google Security <alerts.google@gmail.com>", "subject": "Sign-in alert"},
                 30, "Suspicious", {"display_name_impersonation"}, id="brand-name-from-free-mail"),
    # --- Links ---
    pytest.param({"sender": "Support <support@company.com>", "subject": "Hi",
                  "body_html": "<a href='http://evil-site.net/login'>https://www.paypal.com</a>"},
                 30, "Suspicious", {"deceptive_link"}, id="deceptive-link"),
    pytest.param({"sender": "Support <support@company.com>", "subject": "Hi",
                  "body_text": "Visit http://192.168.10.5/login or https://bit.ly/abc123"},
                 30, "Suspicious", {"ip_address_link", "shortened_link"}, id="ip-and-shortener"),
    pytest.param({"sender": "Support <support@company.com>", "subject": "Hi",
                  "body_html": "<a href='https://aws-console-login.com/signin'>Sign in to the console</a>"},
                 30, "Suspicious", {"lookalike_link"}, id="fake-aws-console"),
    pytest.param({"sender": "Support <support@company.com>", "subject": "Hi",
                  "body_html": "<a href='https://www.paypal.com@evil.net/login'>Log in</a>"},
                 25, "Suspicious", {"hidden_link_destination"}, id="at-sign-trick"),
    pytest.param({"sender": "GitHub <noreply@github.com>", "subject": "New sign-in",
                  "body_html": "<a href='https://github.com/settings'>https://github.com/settings</a>"},
                 0, "Low risk", set(), id="legit-link"),
    # --- Pressure ---
    pytest.param({"sender": "Support <support@company.com>", "subject": "URGENT: ACCOUNT SUSPENDED!!! ⚠️",
                  "body_text": "Your account will be suspended within 24 hours. Click here to verify your account."},
                 20, "Low risk", {"pressure_language", "pressure_formatting"}, id="english-pressure-capped"),
    pytest.param({"sender": "Support <support@company.com>", "subject": "דחוף!! החשבון שלך ייחסם",
                  "body_text": "לחצו כאן תוך 24 שעות כדי לאמת את פרטיכם"},
                 20, "Low risk", {"pressure_language", "pressure_formatting"}, id="hebrew-pressure-capped"),
    pytest.param({"sender": "Shop <deals@shop.co.il>", "subject": "Last chance!! Sale ends tonight",
                  "body_text": "Don't miss our biggest sale"},
                 5, "Low risk", {"pressure_formatting"}, id="marketing-email-barely-scored"),
    pytest.param({"sender": "AWS Billing <billing@aws-account-billing.com>", "subject": "URGENT: payment failed",
                  "body_text": "Update your payment within 24 hours: https://aws-account-billing.com/pay"},
                 100, "Likely phishing",
                 {"lookalike_domain", "display_name_impersonation", "lookalike_link", "pressure_language"},
                 id="full-aws-phishing-capped-at-100"),
    # --- Attachments ---
    pytest.param({"sender": "Accounts <ap@vendor.com>", "subject": "Invoice",
                  "attachments": [{"name": "invoice.pdf.exe"}], "attachment_count": 1},
                 40, "Suspicious", {"double_extension"}, id="double-extension"),
    pytest.param({"sender": "Accounts <ap@vendor.com>", "subject": "Invoice",
                  "attachments": [{"name": "invoice\u202efdp.exe"}], "attachment_count": 1},
                 40, "Suspicious", {"rtl_override_filename"}, id="rtl-override-character"),
    pytest.param({"sender": "Accounts <ap@vendor.com>", "subject": "Report",
                  "attachments": [{"name": "report.xlsm"}, {"name": "Secure_Message.html"}],
                  "attachment_count": 2},
                 45, "Suspicious", {"macro_attachment", "web_content_attachment"}, id="macro-and-html"),
    pytest.param({"sender": "Accounts <ap@vendor.com>", "subject": "Photos",
                  "attachments": [{"name": "photo1.jpg"}], "attachment_count": 35},
                 15, "Low risk", {"many_attachments"}, id="too-many-attachments"),
    pytest.param({"sender": "Accounts <ap@vendor.com>", "subject": "Report",
                  "attachments": [{"name": "report.pdf"}], "attachment_count": 1},
                 0, "Low risk", set(), id="normal-attachment"),
]


@pytest.mark.parametrize("fields, expected_score, expected_verdict, expected_signals", CASES)
def test_scenarios(fields, expected_score, expected_verdict, expected_signals):
    result = analyze_email(EmailInput(**fields))
    assert result.score == expected_score
    assert result.verdict == expected_verdict
    assert {reason.signal for reason in result.reasons} == expected_signals


def test_malformed_html_does_not_crash():
    """Untrusted input: a broken link must not break the analysis."""
    result = analyze_email(EmailInput(sender="A <a@company.com>", body_html="<a href='http://[::1'>x</a>"))
    assert result.verdict == "Low risk"