import asyncio
from aiosmtplib import SMTP, SMTPStatus
import dns.resolver
from greylist_db import fetch_due, delete_entry, upsert_greylist
from source_code import is_valid_email  # syntax check reuse
from datetime import timedelta

RETRY_DELAY_BASE = 600  # 10 minutes
MAX_TRIES = 3

async def retry_worker():
    while True:
        due_items = await fetch_due()
        for email, mx_host, tries in due_items:
            success = await probe_email(mx_host, email)
            if success is True or tries >= MAX_TRIES:
                await delete_entry(email)
            else:
                # Exponential backoff
                await upsert_greylist(email, mx_host, RETRY_DELAY_BASE * (2 ** tries), tries)
        await asyncio.sleep(120)

async def probe_email(mx_host: str, email: str) -> bool:
    try:
        smtp = SMTP(hostname=mx_host, port=25, timeout=5)
        await smtp.connect()
        await smtp.helo("verify.local")
        await smtp.mail("")
        code, _ = await smtp.rcpt(email)
        await smtp.quit()
        return code == SMTPStatus.completed
    except Exception:
        return False

# Safely start background task, regardless of current event loop context
try:
    _loop = asyncio.get_running_loop()
except RuntimeError:
    _loop = None

if _loop and _loop.is_running():
    _loop.create_task(retry_worker())
else:
    import threading
    def _start_loop():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(retry_worker())
    threading.Thread(target=_start_loop, daemon=True).start()
