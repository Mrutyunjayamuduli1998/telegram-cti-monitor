"""
monitor.py — Core Telegram CTI Monitor
Connects via Telethon, listens to configured channels in real time,
runs keyword/IOC matching, stores to SQLite, and pushes hits to MISP.
"""

import asyncio
import logging
import os
import sys
import yaml
import colorlog
from datetime import datetime
from pathlib import Path
from telethon import TelegramClient, events
from telethon.errors import (
    FloodWaitError, ChannelPrivateError,
    InviteHashExpiredError, UserNotParticipantError
)

from database  import init_db, save_message, save_alert, message_exists, get_stats
from alerter   import Alerter
from misp_push import push_to_misp


# ── Logging ────────────────────────────────────────────────────────────────

def setup_logging(log_path: str):
    fmt = "%(log_color)s%(asctime)s [%(levelname)s]%(reset)s %(message)s"
    handler = colorlog.StreamHandler()
    handler.setFormatter(colorlog.ColoredFormatter(fmt, datefmt="%H:%M:%S"))

    file_handler = logging.FileHandler(log_path)
    file_handler.setFormatter(
        logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))

    root = logging.getLogger()
    root.setLevel(logging.INFO)
    root.addHandler(handler)
    root.addHandler(file_handler)


logger = logging.getLogger(__name__)


# ── Config loader ──────────────────────────────────────────────────────────

def load_config(path: str = "config.yaml") -> dict:
    with open(path) as f:
        cfg = yaml.safe_load(f)

    # Basic validation
    missing = []
    if cfg["telegram"]["api_id"] == "YOUR_API_ID":
        missing.append("telegram.api_id")
    if cfg["telegram"]["api_hash"] == "YOUR_API_HASH":
        missing.append("telegram.api_hash")
    if cfg["misp"]["auth_key"] == "YOUR_MISP_AUTH_KEY":
        missing.append("misp.auth_key")
    if missing:
        print(f"\n❌  Please fill in config.yaml: {', '.join(missing)}\n")
        sys.exit(1)
    return cfg


def load_channels(path: str = "channels.txt") -> list:
    if not Path(path).exists():
        logger.warning(f"{path} not found — no channels to monitor.")
        return []
    channels = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                channels.append(line)
    logger.info(f"Loaded {len(channels)} channel(s) from {path}")
    return channels


# ── Monitor class ──────────────────────────────────────────────────────────

class CTIMonitor:
    def __init__(self, cfg: dict, channels: list):
        self.cfg      = cfg
        self.channels = channels
        self.alerter  = Alerter(cfg["keywords"])
        self.db_path  = cfg["monitor"]["db_path"]
        self.rate_limit = cfg["monitor"].get("rate_limit_seconds", 1)

        self._me = None
        self.client = None

    async def start(self):
        tg = self.cfg["telegram"]
        self.client = TelegramClient(
            tg["session_name"],
            int(tg["api_id"]),
            tg["api_hash"]
        )
        await self.client.start()
        self._me = await self.client.get_me()
        logger.info(f"Logged in as: {self._me.username or self._me.phone}")

        init_db(self.db_path)
        await self._join_channels()
        self._register_handler()

        logger.info("=" * 55)
        logger.info("  CTI Monitor is LIVE — listening for messages...")
        logger.info("  Press Ctrl+C to stop.")
        logger.info("=" * 55)

        await self.client.run_until_disconnected()

    async def _join_channels(self):
        """Resolve channels and fetch recent history on startup."""
        history_limit = self.cfg["monitor"].get("history_fetch_limit", 100)
        resolved = []

        for ch in self.channels:
            try:
                entity = await self.client.get_entity(ch)
                resolved.append(entity)
                logger.info(f"✓  Monitoring: {ch}")

                # Fetch recent history to backfill DB
                count = 0
                async for msg in self.client.iter_messages(
                        entity, limit=history_limit):
                    if msg.text and not message_exists(
                            self.db_path, msg.id, ch):
                        await self._process_message(msg, ch, from_history=True)
                        count += 1
                        await asyncio.sleep(0.1)
                if count:
                    logger.info(f"   ↳ Backfilled {count} messages from history")

            except ChannelPrivateError:
                logger.warning(f"✗  Private/inaccessible: {ch}")
            except InviteHashExpiredError:
                logger.warning(f"✗  Invite link expired: {ch}")
            except UserNotParticipantError:
                logger.warning(f"✗  Not a member of: {ch} — join first")
            except FloodWaitError as e:
                logger.warning(f"  Rate limited — waiting {e.seconds}s")
                await asyncio.sleep(e.seconds)
            except Exception as e:
                logger.warning(f"✗  Could not resolve {ch}: {e}")

        self._resolved_channels = resolved

    def _register_handler(self):
        """Register real-time message handler for all monitored channels."""
        @self.client.on(events.NewMessage(chats=self._resolved_channels))
        async def handler(event):
            msg  = event.message
            chat = await event.get_chat()
            ch_name = getattr(chat, "username", None) or str(chat.id)
            ch_name = f"@{ch_name}" if not ch_name.startswith("@") else ch_name
            await self._process_message(msg, ch_name)
            await asyncio.sleep(self.rate_limit)

    async def _process_message(self, msg, channel: str,
                                from_history: bool = False):
        """Core processing: scan → store → alert → MISP push."""
        text = msg.text or ""
        if not text.strip():
            return

        date_str = msg.date.isoformat() if msg.date else datetime.utcnow().isoformat()
        sender   = str(msg.sender_id) if msg.sender_id else "unknown"

        result = self.alerter.scan(text)

        # Always store the message
        save_message(
            self.db_path, msg.id, channel,
            sender, text, date_str, has_alert=result.has_alert
        )

        if not result.has_alert:
            return

        tag = "[HISTORY]" if from_history else "[LIVE]"
        top = result.top_match
        logger.warning(
            f"{tag} 🚨 {channel} | "
            f"Category: {top.category} | "
            f"Keyword: '{top.keyword}'"
        )

        # Collect IOC matches for MISP
        ioc_values = [m.keyword for m in result.matches if m.is_ioc]

        misp_event_id = None
        # Push to MISP (only for live messages to avoid flooding on startup)
        if not from_history:
            alert_data = {
                "channel":         channel,
                "category":        top.category,
                "matched_keyword": top.keyword,
                "message_text":    text,
                "date":            date_str,
                "ioc_matches":     ioc_values,
            }
            misp_event_id = push_to_misp(self.cfg["misp"], alert_data)
            if misp_event_id:
                logger.info(f"  ↳ MISP event created: {misp_event_id}")

            # Self-notify via Telegram DM
            if self.cfg["alerts"].get("notify_self") and self._me:
                summary = self.alerter.format_alert_summary(
                    result, channel, text)
                try:
                    await self.client.send_message("me", summary)
                except Exception as e:
                    logger.warning(f"Self-notify failed: {e}")

        # Save each unique keyword hit as a separate alert row
        seen_kw = set()
        for match in result.matches:
            if match.keyword in seen_kw:
                continue
            seen_kw.add(match.keyword)
            save_alert(
                self.db_path, msg.id, channel,
                match.category, match.keyword,
                text, date_str, misp_event_id
            )


# ── Stats command ──────────────────────────────────────────────────────────

def print_stats(db_path: str):
    stats = get_stats(db_path)
    print("\n── CTI Monitor Stats ─────────────────────")
    print(f"  Total messages ingested : {stats['total_messages']}")
    print(f"  Total alerts triggered  : {stats['total_alerts']}")
    if stats["alerts_by_category"]:
        print("  Alerts by category:")
        for cat, count in sorted(stats["alerts_by_category"].items(),
                                  key=lambda x: -x[1]):
            print(f"    {cat:<22} {count}")
    print("──────────────────────────────────────────\n")


# ── Entry point ────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Telegram CTI Monitor")
    parser.add_argument("--config",   default="config.yaml")
    parser.add_argument("--channels", default="channels.txt")
    parser.add_argument("--stats",    action="store_true",
                        help="Print DB stats and exit")
    args = parser.parse_args()

    cfg = load_config(args.config)
    setup_logging(cfg["monitor"]["log_path"])

    if args.stats:
        print_stats(cfg["monitor"]["db_path"])
        sys.exit(0)

    channels = load_channels(args.channels)
    if not channels:
        logger.error("No channels configured. Add entries to channels.txt")
        sys.exit(1)

    monitor = CTIMonitor(cfg, channels)
    try:
        asyncio.run(monitor.start())
    except KeyboardInterrupt:
        logger.info("Stopped by user.")
        print_stats(cfg["monitor"]["db_path"])
