"""
database.py — SQLite storage for messages and alerts
"""

import sqlite3
import logging
from datetime import datetime

logger = logging.getLogger(__name__)


def get_connection(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path: str):
    """Create tables if they don't exist."""
    conn = get_connection(db_path)
    cur = conn.cursor()

    cur.executescript("""
        CREATE TABLE IF NOT EXISTS messages (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            message_id      INTEGER,
            channel         TEXT,
            sender          TEXT,
            text            TEXT,
            date            TEXT,
            has_alert       INTEGER DEFAULT 0,
            ingested_at     TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS alerts (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            message_id      INTEGER,
            channel         TEXT,
            category        TEXT,
            matched_keyword TEXT,
            message_text    TEXT,
            date            TEXT,
            misp_event_id   TEXT,
            created_at      TEXT DEFAULT (datetime('now'))
        );

        CREATE INDEX IF NOT EXISTS idx_messages_channel ON messages(channel);
        CREATE INDEX IF NOT EXISTS idx_alerts_category  ON alerts(category);
        CREATE INDEX IF NOT EXISTS idx_alerts_created   ON alerts(created_at);
    """)

    conn.commit()
    conn.close()
    logger.info("Database initialised.")


def save_message(db_path: str, message_id: int, channel: str,
                 sender: str, text: str, date: str, has_alert: bool = False):
    conn = get_connection(db_path)
    conn.execute("""
        INSERT OR IGNORE INTO messages
            (message_id, channel, sender, text, date, has_alert)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (message_id, channel, sender, text, date, int(has_alert)))
    conn.commit()
    conn.close()


def save_alert(db_path: str, message_id: int, channel: str,
               category: str, matched_keyword: str,
               message_text: str, date: str, misp_event_id: str = None):
    conn = get_connection(db_path)
    conn.execute("""
        INSERT INTO alerts
            (message_id, channel, category, matched_keyword,
             message_text, date, misp_event_id)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (message_id, channel, category, matched_keyword,
          message_text, date, misp_event_id))
    conn.commit()
    conn.close()


def message_exists(db_path: str, message_id: int, channel: str) -> bool:
    conn = get_connection(db_path)
    row = conn.execute("""
        SELECT 1 FROM messages
        WHERE message_id = ? AND channel = ?
    """, (message_id, channel)).fetchone()
    conn.close()
    return row is not None


def get_recent_alerts(db_path: str, limit: int = 20) -> list:
    conn = get_connection(db_path)
    rows = conn.execute("""
        SELECT * FROM alerts
        ORDER BY created_at DESC
        LIMIT ?
    """, (limit,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_stats(db_path: str) -> dict:
    conn = get_connection(db_path)
    stats = {}
    stats["total_messages"] = conn.execute(
        "SELECT COUNT(*) FROM messages").fetchone()[0]
    stats["total_alerts"] = conn.execute(
        "SELECT COUNT(*) FROM alerts").fetchone()[0]
    stats["alerts_by_category"] = {
        row[0]: row[1] for row in conn.execute(
            "SELECT category, COUNT(*) FROM alerts GROUP BY category"
        ).fetchall()
    }
    conn.close()
    return stats
