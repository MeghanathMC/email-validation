import os
import time
import requests
from typing import Set

BLACKLIST_URLS = [
    'https://raw.githubusercontent.com/andreis/disposable-email-domains/master/domains.txt',
    'https://raw.githubusercontent.com/wesbos/burner-email-providers/master/emails.txt',
    'https://raw.githubusercontent.com/disposable/disposable-email-domains/master/domains.txt'
]

CACHE_FILE = 'disposable_cache.txt'
CACHE_TTL = 24 * 60 * 60  # 1 day


def _refresh_cache() -> None:
    domains: Set[str] = set()
    for url in BLACKLIST_URLS:
        try:
            resp = requests.get(url, timeout=10)
            if resp.status_code == 200:
                domains.update(line.strip().lower() for line in resp.text.split('\n') if line)
        except Exception:
            continue

    with open(CACHE_FILE, 'w', encoding='utf-8') as f:
        f.write('\n'.join(domains))

    os.utime(CACHE_FILE, None)  # update mtime


def _cache_expired() -> bool:
    if not os.path.exists(CACHE_FILE):
        return True
    return (time.time() - os.path.getmtime(CACHE_FILE)) > CACHE_TTL


def load_disposable_domains() -> Set[str]:
    """Return a set of disposable domains; refresh cache if stale."""
    if _cache_expired():
        _refresh_cache()

    with open(CACHE_FILE, 'r', encoding='utf-8') as f:
        return set(line.strip().lower() for line in f if line.strip())
