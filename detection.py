from urllib.parse import urlparse
import ipaddress
import re


# List of common phishing-related words often used in fake links.
SUSPICIOUS_KEYWORDS = [
    "login",
    "verify",
    "update",
    "secure",
    "account",
    "bank",
    "paypal",
    "password",
    "confirm",
]


# Enticing "bait" words used to lure victims (e.g. fake giveaways).
LURE_KEYWORDS = [
    "free",
    "gift",
    "reward",
    "claim",
    "prize",
    "bonus",
]


# Words tied to credentials / account access.
CREDENTIAL_KEYWORDS = [
    "login",
    "account",
    "verify",
    "password",
]


# Common URL shortening services.
SHORTENING_SERVICES = [
    "bit.ly",
    "tinyurl.com",
    "goo.gl",
    "t.co",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "adf.ly",
    "tiny.cc",
    "shorturl.at",
]


# Well-known brand names that attackers often imitate in URLs.
TRUSTED_BRANDS = [
    "paypal",
    "bank",
    "google",
    "apple",
    "facebook",
    "amazon",
    "microsoft",
]


# Full official domains for well-known brands. Used to detect when one of
# these appears inside a hostname while the real registered domain differs.
TRUSTED_BRAND_DOMAINS = [
    "apple.com",
    "paypal.com",
    "google.com",
    "microsoft.com",
    "amazon.com",
    "facebook.com",
    "instagram.com",
    "netflix.com",
    "bankofamerica.com",
]


IP_SENSITIVE_KEYWORDS = [
    "login",
    "password",
    "account",
    "verify",
    "confirm",
    "bank",
]


AT_SYMBOL_HIGH_RISK_WORDS = [
    "google",
    "paypal",
    "bank",
    "login",
    "account",
    "verify",
]


COMMON_MULTI_PART_SUFFIXES = {
    "ac.uk",
    "co.uk",
    "org.uk",
    "gov.uk",
    "edu.au",
    "com.au",
    "net.au",
    "co.jp",
    "com.sg",
    "edu.sg",
    "com.my",
    "edu.my",
}



def normalize_url(url):
    """Add http:// if the user does not provide any scheme."""
    url = url.strip()

    if "://" not in url:
        return "http://" + url

    return url



def is_ip_address(hostname):
    """Check whether the hostname is an IP address."""
    if not hostname:
        return False

    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False



def is_private_or_local_ip(hostname):
    """
    Check whether the hostname is a private, loopback, or local address.

    Covers 'localhost' and the private/local IPv4 ranges:
      10.0.0.0    - 10.255.255.255
      172.16.0.0  - 172.31.255.255
      192.168.0.0 - 192.168.255.255
      127.0.0.0   - 127.255.255.255 (loopback)
    """
    if not hostname:
        return False

    if hostname.lower() == "localhost":
        return True

    try:
        ip = ipaddress.ip_address(hostname)
    except ValueError:
        return False

    return ip.is_private or ip.is_loopback



def count_subdomains(hostname):
    """Count how many real subdomains appear before the registered domain."""
    if not hostname:
        return 0

    hostname = hostname.lower().strip(".")

    if is_ip_address(hostname):
        return 0

    if hostname.startswith("www."):
        hostname = hostname[4:]

    parts = hostname.split(".")

    if len(parts) <= 2:
        return 0

    suffix_length = 2
    last_two_labels = ".".join(parts[-2:])

    if last_two_labels in COMMON_MULTI_PART_SUFFIXES:
        suffix_length = 3

    registered_domain_length = suffix_length
    subdomain_count = len(parts) - registered_domain_length

    if subdomain_count < 0:
        return 0

    return subdomain_count



def has_misleading_domain_pattern(hostname):
    """
    Detect brand-like names combined with extra words or unusual endings.
    Example: paypal-login-security.com

    Official trusted registered domains (e.g. apple.com, including legitimate
    subdomains such as appleid.apple.com) are never flagged.
    """
    if not hostname:
        return False

    # If the site is genuinely registered under an official brand domain,
    # it is not an imitation (e.g. appleid.apple.com -> apple.com).
    if get_registered_domain(hostname) in TRUSTED_BRAND_DOMAINS:
        return False

    domain_without_www = hostname.lower()
    if domain_without_www.startswith("www."):
        domain_without_www = domain_without_www[4:]

    main_part = domain_without_www.split(".")[0]

    for brand in TRUSTED_BRANDS:
        if brand in main_part and main_part != brand:
            return True

    return False



def get_registered_domain(hostname):
    """
    Return the registered domain (the real owner of the site), e.g.
    'secure.apple.com.example.org' -> 'example.org'.
    Accounts for common multi-part suffixes such as 'co.uk'.
    """
    if not hostname:
        return ""

    hostname = hostname.lower().strip(".")

    if is_ip_address(hostname):
        return hostname

    parts = hostname.split(".")

    if len(parts) <= 2:
        return ".".join(parts)

    suffix_length = 2
    last_two_labels = ".".join(parts[-2:])

    if last_two_labels in COMMON_MULTI_PART_SUFFIXES:
        suffix_length = 3

    registered_parts = parts[-suffix_length:]
    return ".".join(registered_parts)



def has_brand_impersonation(hostname):
    """
    Detect when a full trusted brand domain (e.g. 'apple.com') appears inside
    the hostname as a run of labels, but the real registered domain is
    something else.

    Example: 'secure.apple.com.account-login.example.org' contains 'apple.com'
    but is really registered under 'example.org', so this is impersonation.
    """
    if not hostname:
        return False

    hostname = hostname.lower().strip(".")

    if is_ip_address(hostname):
        return False

    labels = hostname.split(".")
    registered_domain = get_registered_domain(hostname)

    for brand_domain in TRUSTED_BRAND_DOMAINS:
        if registered_domain == brand_domain:
            # The site really belongs to this brand: not impersonation.
            continue

        brand_labels = brand_domain.split(".")

        # Look for the brand domain as a contiguous run of labels.
        for i in range(len(labels) - len(brand_labels) + 1):
            if labels[i:i + len(brand_labels)] == brand_labels:
                return True

    return False



def analyze_url(url):
    """
    Analyze a URL using simple rule-based phishing checks.

    Returns a dictionary containing:
    - original_url
    - total_score
    - risk_level
    - detected_features
    - explanations
    - recommendations
    """
    original_url = url
    normalized_url = normalize_url(url)
    parsed_url = urlparse(normalized_url)

    hostname = parsed_url.hostname or ""
    path = parsed_url.path or ""
    query = parsed_url.query or ""
    full_url_lower = normalized_url.lower()

    total_score = 0
    detected_features = []
    explanations = []
    recommendations = []

    def add_finding(feature, score, explanation, recommendation):
        """Store one suspicious finding in the result."""
        nonlocal total_score
        total_score += score
        detected_features.append(feature)
        explanations.append(explanation)
        recommendations.append(recommendation)

    # 1. URL length
    if len(normalized_url) > 75:
        add_finding(
            feature="Long URL",
            score=1,
            explanation="The URL is longer than normal. Very long URLs can be used to hide suspicious parts of the address.",
            recommendation="Check the full URL carefully before opening it, especially the domain name.",
        )

    # 2. Use of IP address instead of domain name
    if is_ip_address(hostname):
        if is_private_or_local_ip(hostname):
            add_finding(
                feature="Private/local IP address used",
                score=1,
                explanation="The URL uses a private or local IP address (such as localhost, 10.x, 172.16-31.x, or 192.168.x). This is unusual for a public website but is lower risk than a public IP address.",
                recommendation="Be cautious: public links should normally use a domain name, not a private or local address.",
            )
        else:
            add_finding(
                feature="IP address used",
                score=2,
                explanation="The URL uses a public IP address instead of a normal domain name. Phishing links sometimes do this to hide their real identity.",
                recommendation="Avoid entering personal information on websites that use only an IP address.",
            )

    # 3. Lack of HTTPS
    if parsed_url.scheme != "https":
        add_finding(
            feature="No HTTPS",
            score=1,
            explanation="The website does not use HTTPS. This means the connection may be less secure.",
            recommendation="Be careful with websites that do not use HTTPS, especially when they ask for login or payment details.",
        )

    # 4. Suspicious keywords (graduated scoring by how many match)
    matched_keywords = []
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in full_url_lower:
            matched_keywords.append(keyword)

    if matched_keywords:
        keyword_count = len(matched_keywords)
        if keyword_count == 1:
            keyword_score = 1
        elif keyword_count <= 3:
            keyword_score = 2
        else:
            keyword_score = 3

        add_finding(
            feature="Suspicious keywords",
            score=keyword_score,
            explanation=f"The URL contains suspicious words: {', '.join(matched_keywords)}. These words are often used in phishing links.",
            recommendation="Do not trust a link just because it contains familiar security-related words.",
        )

    # 4a. Password keyword is an especially strong signal.
    if "password" in full_url_lower:
        add_finding(
            feature="Password keyword",
            score=2,
            explanation="The URL contains the word 'password'. Legitimate sites rarely place this word directly in a link.",
            recommendation="Never enter your password through a link you do not fully trust.",
        )

    # 4b. Login + account + verify appearing together is a typical credential-harvesting pattern.
    credential_combo = ["login", "account", "verify"]
    if all(word in full_url_lower for word in credential_combo):
        add_finding(
            feature="Combined credential keywords",
            score=2,
            explanation="The URL combines 'login', 'account', and 'verify'. This wording is common in fake account-verification scams.",
            recommendation="Go to the official website directly instead of following links that ask you to verify your account.",
        )

    # 4c. Lure words combined with credential words suggest a bait-and-steal scheme.
    lure_matches = [word for word in LURE_KEYWORDS if word in full_url_lower]
    credential_matches = [word for word in CREDENTIAL_KEYWORDS if word in full_url_lower]
    if lure_matches and credential_matches:
        add_finding(
            feature="Lure and credential keywords combined",
            score=2,
            explanation="The URL mixes enticing words (such as free, gift, or prize) with credential words (such as login or password). This is a common trick to lure victims into giving up their details.",
            recommendation="Be very cautious with links that promise rewards and also ask for login or account details.",
        )

    # Extra high-risk rule for PUBLIC IP address + sensitive keywords.
    # Private/local IPs are intentionally excluded so they stay lower risk.
    if is_ip_address(hostname) and not is_private_or_local_ip(hostname):
        ip_sensitive_matches = []
        for keyword in IP_SENSITIVE_KEYWORDS:
            if keyword in full_url_lower:
                ip_sensitive_matches.append(keyword)

        if ip_sensitive_matches:
            add_finding(
                feature="IP address with sensitive keywords",
                score=2,
                explanation="The URL uses a public IP address together with sensitive words such as login, password, account, or verify. This can be a strong phishing indicator.",
                recommendation="Do not enter login details or personal information on websites using only an IP address.",
            )

    # 5. Too many subdomains
    subdomain_count = count_subdomains(hostname)
    if not is_ip_address(hostname) and subdomain_count >= 2:
        add_finding(
            feature="Too many subdomains",
            score=1,
            explanation="The URL has many subdomains. Attackers sometimes use this to make a fake link look more trustworthy.",
            recommendation="Focus on the main domain name, not the extra words before it.",
        )

    # 6. Use of @ symbol
    if "@" in normalized_url:
        add_finding(
            feature="@ symbol used",
            score=1,
            explanation="The URL contains an @ symbol. This can be used to hide the real destination of the link.",
            recommendation="Avoid clicking links that contain an @ symbol unless you fully trust the source.",
        )

        at_symbol_high_risk_matches = []
        for keyword in AT_SYMBOL_HIGH_RISK_WORDS:
            if keyword in full_url_lower:
                at_symbol_high_risk_matches.append(keyword)

        if at_symbol_high_risk_matches:
            add_finding(
                feature="Misleading @ symbol with trusted or sensitive words",
                score=1,
                explanation="The URL contains an @ symbol together with trusted or sensitive words. This may mislead users about the real destination of the link.",
                recommendation="Do not trust URLs that contain @ symbols. Check the real domain carefully before opening the link.",
            )

    # 7. Too many special characters
    special_character_count = len(re.findall(r"[^a-zA-Z0-9]", normalized_url))
    if special_character_count > 10:
        add_finding(
            feature="Too many special characters",
            score=1,
            explanation="The URL contains many special characters, which can make it look confusing or misleading.",
            recommendation="Be cautious when a URL looks overly complex or contains too many symbols.",
        )

    # 8. Misleading domain patterns
    if has_misleading_domain_pattern(hostname):
        add_finding(
            feature="Misleading domain pattern",
            score=2,
            explanation="The domain name looks like it may be imitating a trusted brand by adding extra words.",
            recommendation="Check whether the main domain is the official website and not an imitation.",
        )

    # 8a. Brand impersonation in subdomains: a full trusted brand domain
    # (e.g. apple.com) appears in the hostname, but the real registered
    # domain is something different.
    if has_brand_impersonation(hostname):
        add_finding(
            feature="Brand impersonation in subdomain",
            score=4,
            explanation=f"The hostname contains a trusted brand domain, but the real registered domain is '{get_registered_domain(hostname)}'. Attackers place brand names in subdomains to make a fake site look official.",
            recommendation="Check the end of the domain name (the registered domain) rather than the brand name that appears earlier in the address.",
        )

    # 9. URL shortening services
    if hostname.lower() in SHORTENING_SERVICES:
        add_finding(
            feature="Shortened URL",
            score=2,
            explanation="The URL uses a shortening service, which hides the final destination.",
            recommendation="Preview the full destination before opening shortened links.",
        )

    # 10. Hyphen in domain name
    if "-" in hostname:
        add_finding(
            feature="Hyphen in domain",
            score=1,
            explanation="The domain name contains a hyphen. Some phishing websites use hyphens to imitate real brands.",
            recommendation="Check carefully whether the hyphenated domain is the official site.",
        )

    # Extra check for repeated slashes after the domain.
    if "//" in path or "//" in query:
        add_finding(
            feature="Unusual slash pattern",
            score=1,
            explanation="The URL contains repeated slashes in an unusual place, which may be suspicious.",
            recommendation="Inspect the link carefully before opening it.",
        )

    # Final risk classification.
    if total_score <= 2:
        risk_level = "Safe"
    elif 3 <= total_score <= 6:
        risk_level = "Suspicious"
    else:
        risk_level = "High Risk"

    return {
        "original_url": original_url,
        "total_score": total_score,
        "risk_level": risk_level,
        "detected_features": detected_features,
        "explanations": explanations,
        "recommendations": recommendations,
    }


if __name__ == "__main__":
    sample_url = input("Enter a URL to analyze: ")
    result = analyze_url(sample_url)

    print("\nScan Result")
    print("-" * 40)
    print(f"URL: {result['original_url']}")
    print(f"Score: {result['total_score']}")
    print(f"Risk Level: {result['risk_level']}")

    if result["detected_features"]:
        print("\nDetected suspicious features:")
        for i, feature in enumerate(result["detected_features"], start=1):
            print(f"{i}. {feature}")
            print(f"   Explanation: {result['explanations'][i - 1]}")
            print(f"   Recommendation: {result['recommendations'][i - 1]}")
    else:
        print("\nNo suspicious features were detected.")
