"""
misp_push.py — Push alerts to MISP as events with attributes
"""

import logging
import re
from datetime import datetime
from typing import Optional

logger = logging.getLogger(__name__)


def _try_import_misp():
    try:
        from pymisp import PyMISP, MISPEvent, MISPAttribute
        return PyMISP, MISPEvent, MISPAttribute
    except ImportError:
        logger.error("pymisp not installed. Run: pip install pymisp")
        return None, None, None


# IOC type detection patterns
_IP_RE     = re.compile(r'^\d{1,3}(\.\d{1,3}){3}$')
_DOMAIN_RE = re.compile(r'^[a-zA-Z0-9\-]+\.[a-zA-Z]{2,}$')
_MD5_RE    = re.compile(r'^[a-fA-F0-9]{32}$')
_SHA1_RE   = re.compile(r'^[a-fA-F0-9]{40}$')
_SHA256_RE = re.compile(r'^[a-fA-F0-9]{64}$')
_CVE_RE    = re.compile(r'^CVE-\d{4}-\d+$', re.IGNORECASE)


def _detect_ioc_type(value: str) -> str:
    """Map a raw IOC string to a MISP attribute type."""
    v = value.strip()
    if _IP_RE.match(v):     return "ip-dst"
    if _SHA256_RE.match(v): return "sha256"
    if _SHA1_RE.match(v):   return "sha1"
    if _MD5_RE.match(v):    return "md5"
    if _CVE_RE.match(v):    return "vulnerability"
    if _DOMAIN_RE.match(v): return "domain"
    return "text"


def push_to_misp(misp_cfg: dict, alert_data: dict) -> Optional[str]:
    """
    Create a MISP event from an alert and return the event UUID.

    alert_data keys:
        channel         str  — Telegram channel name
        category        str  — alert category (e.g. 'ransomware')
        matched_keyword str  — the keyword/IOC that triggered
        message_text    str  — original message text
        date            str  — message timestamp
        ioc_matches     list — list of raw IOC strings found (may be empty)
    """
    PyMISP, MISPEvent, MISPAttribute = _try_import_misp()
    if not PyMISP:
        return None

    try:
        misp = PyMISP(
            url=misp_cfg["url"],
            key=misp_cfg["auth_key"],
            ssl=misp_cfg.get("verify_ssl", False)
        )
    except Exception as e:
        logger.error(f"MISP connection failed: {e}")
        return None

    event = MISPEvent()

    # Event metadata
    category   = alert_data.get("category", "unknown")
    channel    = alert_data.get("channel", "unknown")
    keyword    = alert_data.get("matched_keyword", "")
    msg_text   = alert_data.get("message_text", "")
    msg_date   = alert_data.get("date", datetime.utcnow().isoformat())
    ioc_list   = alert_data.get("ioc_matches", [])

    event.info = (
        f"[TG-CTI] {category.replace('_', ' ').title()} "
        f"— {keyword[:60]} — {channel}"
    )
    event.threat_level_id = misp_cfg.get("threat_level", 2)
    event.distribution    = misp_cfg.get("distribution", 0)
    event.analysis        = 0   # initial

    # Tags
    event.add_tag("tlp:amber")
    event.add_tag("type:osint")
    event.add_tag(f"source:telegram")
    event.add_tag(f"cti-category:{category}")

    # Core attributes
    event.add_attribute(
        "text",
        f"Source channel: {channel} | Date: {msg_date}",
        comment="Telegram source metadata",
        to_ids=False
    )
    event.add_attribute(
        "text",
        msg_text[:2000],   # MISP attribute limit
        comment="Original Telegram message (truncated to 2000 chars)",
        to_ids=False
    )
    event.add_attribute(
        "text",
        keyword,
        comment="Triggering keyword",
        to_ids=False
    )

    # IOC attributes (IP, domain, hash, CVE etc.)
    seen = set()
    for ioc in ioc_list:
        ioc = ioc.strip()
        if not ioc or ioc in seen:
            continue
        seen.add(ioc)
        ioc_type = _detect_ioc_type(ioc)
        try:
            event.add_attribute(
                ioc_type,
                ioc,
                comment=f"Extracted from Telegram — {channel}",
                to_ids=(ioc_type != "text")
            )
        except Exception as e:
            logger.warning(f"Could not add IOC attribute '{ioc}': {e}")

    # Push
    try:
        result = misp.add_event(event)
        if isinstance(result, dict) and "Event" in result:
            event_id = result["Event"].get("uuid", "unknown")
            logger.info(f"MISP event created: {event_id} for '{keyword}'")
            return event_id
        else:
            logger.warning(f"Unexpected MISP response: {result}")
            return None
    except Exception as e:
        logger.error(f"Failed to push event to MISP: {e}")
        return None
