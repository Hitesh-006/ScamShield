from api_checks import (
    extract_emails,
    extract_urls,
    verify_company_domain,
    calculate_risk
)

# =====================================
# SAMPLE TEXT
# =====================================

text = """
Meta Hiring Team

Contact:
metahrjobs@gmail.com

Visit:
https://fake-meta-careers.xyz
"""

# =====================================
# EXTRACT EMAILS & URLS
# =====================================

emails = extract_emails(text)

urls = extract_urls(text)

print("\nEmails Found:")

print(emails)

print("\nURLs Found:")

print(urls)

# =====================================
# DOMAIN VERIFICATION
# =====================================

if len(emails) > 0:

    domain_result = verify_company_domain(
        "Meta",
        emails[0]
    )

    print("\nDomain Check:")

    print(domain_result)

    suspicious = (
        domain_result == "Suspicious Domain"
    )

else:

    suspicious = False

# =====================================
# FINAL RISK SCORE
# =====================================

risk = calculate_risk(
    ml_probability=0.62,
    suspicious_domain=suspicious,
    suspicious_url=True
)

print("\nFinal Risk Score:")

print(risk)
# =====================================
# EXTRACT PHONE NUMBERS
# =====================================

def extract_phone_numbers(text):

    phones = re.findall(
        r'(\+?\d[\d\s\-\(\)]{7,}\d)',
        text
    )

    return phones