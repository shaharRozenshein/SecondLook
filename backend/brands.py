"""Brands commonly impersonated in phishing, with the domains they really send from.
Tailored to Upwind's users: cloud, DevOps and security teams are targeted with fake
cloud-console, code-hosting and SSO emails, so those platforms come first.
Israeli brands and Hebrew names are included because local phishing often targets them.
The first domain of each brand is its primary domain, used for look-alike detection.
"""

BRANDS = {
    # Cloud, developer and identity platforms used by Upwind's customers
    "AWS": {"keywords": ["aws", "amazon web services"], "domains": ["amazonaws.com", "amazon.com"]},
    "Microsoft": {"keywords": ["microsoft", "azure", "outlook", "office 365", "מיקרוסופט"],
                  "domains": ["microsoft.com", "azure.com", "office.com"]},
    "Google": {"keywords": ["google", "google cloud", "gcp", "gmail", "גוגל"], "domains": ["google.com"]},
    "GitHub": {"keywords": ["github"], "domains": ["github.com"]},
    "Okta": {"keywords": ["okta"], "domains": ["okta.com"]},
    "Slack": {"keywords": ["slack"], "domains": ["slack.com"]},
    "Atlassian": {"keywords": ["atlassian", "jira"], "domains": ["atlassian.com", "atlassian.net"]},
    "DocuSign": {"keywords": ["docusign"], "domains": ["docusign.com", "docusign.net"]},
    "Upwind": {"keywords": ["upwind"], "domains": ["upwind.io"]},
    # Widely impersonated consumer brands
    "PayPal": {"keywords": ["paypal", "פייפאל"], "domains": ["paypal.com"]},
    "Apple": {"keywords": ["apple", "icloud", "אפל"], "domains": ["apple.com"]},
    "Amazon": {"keywords": ["amazon", "אמזון"], "domains": ["amazon.com", "amazon.co.uk", "amazon.de"]},
    "Netflix": {"keywords": ["netflix", "נטפליקס"], "domains": ["netflix.com"]},
    "DHL": {"keywords": ["dhl"], "domains": ["dhl.com"]},
    # Israeli brands
    "Israel Post": {"keywords": ["israel post", "דואר ישראל"], "domains": ["israelpost.co.il"]},
    "Bank Leumi": {"keywords": ["bank leumi", "בנק לאומי"], "domains": ["leumi.co.il"]},
    "Bank Hapoalim": {"keywords": ["hapoalim", "בנק הפועלים"], "domains": ["bankhapoalim.co.il"]},
    "Discount Bank": {"keywords": ["discount bank", "בנק דיסקונט"], "domains": ["discountbank.co.il"]},
    "Isracard": {"keywords": ["isracard", "ישראכרט"], "domains": ["isracard.co.il"]},
    "National Insurance": {"keywords": ["bituach leumi", "ביטוח לאומי"], "domains": ["btl.gov.il"]},
}

# Free mailbox providers: anyone can open an account there, so they are never
# treated as a brand's official domain, and never flagged as look-alikes themselves
FREE_MAIL_DOMAINS = {
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", "yahoo.com",
    "icloud.com", "aol.com", "proton.me", "protonmail.com", "walla.co.il", "mail.ru",
}