import re
import dns.resolver
import smtplib
import requests
import threading
import queue
import dns.reversename
from email_validator import validate_email, EmailNotValidError
from dns_utils import has_spf, has_dmarc, has_dkim
import socket
from reputation_utils import lookup_dnsbl
from disposable_cache import load_disposable_domains
from greylist_db import upsert_greylist_sync

CACHE_TTL = 600

# Initialize a DNS resolver with caching enabled
resolver = dns.resolver.Resolver(configure=False)
resolver.nameservers = ['8.8.8.8']
resolver.cache = dns.resolver.Cache()


def is_valid_email(email: str) -> bool:
    """RFC-compliant syntax validation using email_validator package."""
    try:
        validate_email(email, check_deliverability=False)
        return True
    except EmailNotValidError:
        return False

# mx record validation
# Set the cache TTL (in seconds)

def query_dns(record_type, domain):
    try:
        # Try to resolve the record from cache first
        record_name = domain if record_type == 'MX' else f'{domain}.'
        cache_result = resolver.cache.get((record_name, record_type))
        if cache_result is not None and (dns.resolver.mtime() - cache_result.time) < CACHE_TTL:
            return True

        # Otherwise, perform a fresh DNS query
        resolver.timeout = 2
        resolver.lifetime = 2
        resolver.resolve(record_name, record_type)
        return True
    except dns.resolver.NXDOMAIN:
        # The domain does not exist
        return False
    except dns.resolver.NoAnswer:
        # No record of the requested type was found
        return False
    except dns.resolver.Timeout:
        # The query timed out
        return False
    except:
        # An unexpected error occurred
        return False


def has_valid_mx_record(domain):
    # Define a function to handle each DNS query in a separate thread
    def query_mx(results_queue):
        results_queue.put(query_dns('MX', domain))

    def query_a(results_queue):
        results_queue.put(query_dns('A', domain))

    # Start multiple threads to query the MX and A records simultaneously
    mx_queue = queue.Queue()
    a_queue = queue.Queue()
    mx_thread = threading.Thread(target=query_mx, args=(mx_queue,))
    a_thread = threading.Thread(target=query_a, args=(a_queue,))
    mx_thread.start()
    a_thread.start()

    # Wait for both threads to finish and retrieve the results from the queues
    mx_thread.join()
    a_thread.join()
    mx_result = mx_queue.get()
    a_result = a_queue.get()

    return mx_result or a_result


# smtp connection
def verify_email(email):
    """Return True if mailbox exists, False if definitely invalid, None if greylisted/pending."""
    domain = email.split('@')[1]
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
    except dns.resolver.NoAnswer:
        return False
    
    for mx in mx_records:
        host = str(mx.exchange).rstrip('.')
        try:
            try:
                server = smtplib.SMTP(host, 587, timeout=2)
                server.starttls()
            except (socket.gaierror, smtplib.SMTPConnectError, OSError):
                try:
                    server = smtplib.SMTP(host, 25, timeout=2)
                except (socket.gaierror, smtplib.SMTPConnectError, OSError):
                    try:
                        server = smtplib.SMTP_SSL(host, 465, timeout=2)
                    except Exception:
                        continue
            
            server.ehlo()
            server.mail('')
            code, _ = server.rcpt(email)
            server.quit()
            
            if code == 250:
                return True
            if 400 <= code < 500:  # greylist temporary failure
                upsert_greylist_sync(email, host, retry_delay=600)
                return None
                
        except Exception:
            continue
    return False


# temporary domain
def is_disposable(domain):
    disposable_set = load_disposable_domains()
    return domain.lower() in disposable_set


def check_mx_reputation(domain):
    """Return 'Bad' if any MX IP is listed in DNSBL, else 'Normal'"""
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        for mx in mx_records:
            host = str(mx.exchange).rstrip('.')
            ips = dns.resolver.resolve(host, 'A')
            for ip in ips:
                if lookup_dnsbl(ip.to_text()):
                    return 'Bad'
    except Exception:
        pass
    return 'Normal'


def check_auth_protocols(domain: str):
    """Return dict with SPF, DKIM, DMARC boolean presence."""
    return {
        'spf': has_spf(domain),
        'dkim': has_dkim(domain),
        'dmarc': has_dmarc(domain)
    }
