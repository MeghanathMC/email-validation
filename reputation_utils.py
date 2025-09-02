import socket
import dns.resolver

DNSBL_HOSTS = [
    'zen.spamhaus.org',  # widely used composite blocklist
    'bl.spamcop.net'
]

resolver = dns.resolver.Resolver(configure=False)
resolver.nameservers = ['8.8.8.8', '1.1.1.1']
resolver.timeout = 2
resolver.lifetime = 4


def _reverse_ip(ip: str) -> str:
    return '.'.join(reversed(ip.split('.')))


def lookup_dnsbl(ip: str) -> bool:
    """Return True if IP is listed in any DNSBL_HOSTS."""
    reversed_ip = _reverse_ip(ip)
    for bl in DNSBL_HOSTS:
        query = f'{reversed_ip}.{bl}'
        try:
            resolver.resolve(query, 'A')
            # If resolution succeeds, IP is listed
            return True
        except Exception:
            continue
    return False
