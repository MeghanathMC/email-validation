import aiosqlite
import asyncio
from typing import Optional, List, Tuple
import time
import sqlite3

DB_PATH = 'greylist.sqlite'

CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS greylist (
    email TEXT PRIMARY KEY,
    mx_host TEXT,
    last_try INTEGER,
    next_try INTEGER,
    tries INTEGER
);
"""

async def init_db():
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(CREATE_TABLE_SQL)
        await db.commit()

# Initialize table synchronously to avoid event loop issues during import
import sqlite3 as _sl
with _sl.connect(DB_PATH) as _conn:
    _conn.execute(CREATE_TABLE_SQL)

SYNC_DB_CONN = sqlite3.connect(DB_PATH, check_same_thread=False)
SYNC_DB_CONN.execute(CREATE_TABLE_SQL)
SYNC_DB_CONN.commit()

async def upsert_greylist(email: str, mx_host: str, retry_delay: int, tries: int):
    now = int(time.time())
    next_try = now + retry_delay
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""
        INSERT INTO greylist(email, mx_host, last_try, next_try, tries)
        VALUES (?, ?, ?, ?, 1)
        ON CONFLICT(email) DO UPDATE SET
            mx_host = excluded.mx_host,
            last_try = excluded.last_try,
            next_try = excluded.next_try,
            tries = greylist.tries + 1;
        """, (email, mx_host, now, next_try))
        await db.commit()

def upsert_greylist_sync(email: str, mx_host: str, retry_delay: int, tries: int = 1):
    now = int(time.time())
    next_try = now + retry_delay
    SYNC_DB_CONN.execute(
        """
        INSERT INTO greylist(email, mx_host, last_try, next_try, tries)
        VALUES (?, ?, ?, ?, 1)
        ON CONFLICT(email) DO UPDATE SET
            mx_host = excluded.mx_host,
            last_try = excluded.last_try,
            next_try = excluded.next_try,
            tries   = greylist.tries + 1
        """,
        (email, mx_host, now, next_try))
    SYNC_DB_CONN.commit()

async def fetch_due(limit: int = 50) -> List[Tuple[str, str, int]]:
    now = int(time.time())
    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute(
            "SELECT email, mx_host, tries FROM greylist WHERE next_try <= ? LIMIT ?",
            (now, limit))
        rows = await cursor.fetchall()
        return rows

async def delete_entry(email: str):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("DELETE FROM greylist WHERE email = ?", (email,))
        await db.commit()
