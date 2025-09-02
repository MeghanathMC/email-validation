import dns.resolver
from typing import Optional

resolver = dns.resolver.Resolver(configure=False)
resolver.nameservers = ['8.8.8.8']
resolver.timeout = 2
resolver.lifetime = 4


def _safe_txt_query(name: str) -> Optional[list]:
    """Utility – return list of TXT strings or None on failure."""
    try:
        answers = resolver.resolve(name, 'TXT')
        return [b"".join(r.strings).decode() for r in answers]
    except Exception:
        return None


def has_spf(domain: str) -> bool:
    """True if domain publishes an SPF TXT record."""
    records = _safe_txt_query(domain)
    if not records:
        return False
    return any(r.lower().startswith('v=spf1') for r in records)


def has_dmarc(domain: str) -> bool:
    """True if domain has a DMARC policy record."""
    records = _safe_txt_query(f'_dmarc.{domain}')
    if not records:
        return False
    return any('v=dmarc1' in r.lower() for r in records)


def has_dkim(domain: str) -> bool:
    """Heuristic: returns True if at least one DKIM selector TXT is found.
    Because selector names vary, we try common defaults (selector1/selector2/ default).
    This is a best-effort and not guaranteed."""
    common_selectors = ['selector1', 'selector2', 'default', 'dkim', 'google', 'mail']
    for sel in common_selectors:
        recs = _safe_txt_query(f'{sel}._domainkey.{domain}')
        if recs and any('v=dkim1' in r.lower() for r in recs):
            return True
    return False


def check_auth_protocols(domain: str):
    """Return dict with SPF, DKIM, DMARC boolean presence for convenience."""
    return {
        'spf': has_spf(domain),
        'dkim': has_dkim(domain),
        'dmarc': has_dmarc(domain)
    }
