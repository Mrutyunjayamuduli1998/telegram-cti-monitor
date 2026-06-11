"""
alerter.py — Keyword and IOC matching engine
Scans message text against configured keyword categories and regex IOC patterns.
"""

import re
import logging
from dataclasses import dataclass, field
from typing import List, Optional

logger = logging.getLogger(__name__)


@dataclass
class Match:
    category: str
    keyword: str
    is_ioc: bool = False


@dataclass
class AlertResult:
    has_alert: bool
    matches: List[Match] = field(default_factory=list)

    @property
    def categories(self) -> List[str]:
        return list({m.category for m in self.matches})

    @property
    def top_match(self) -> Optional[Match]:
        return self.matches[0] if self.matches else None


class Alerter:
    # Category priority for MISP event naming
    PRIORITY = ["threat_actors", "ransomware", "malware",
                "vulnerabilities", "data_leaks", "ioc_patterns"]

    def __init__(self, keywords_config: dict):
        self.keywords = {}
        self.ioc_patterns = []
        self._load(keywords_config)

    def _load(self, config: dict):
        for category, items in config.items():
            if category == "ioc_patterns":
                for pattern in items:
                    try:
                        self.ioc_patterns.append(
                            (re.compile(pattern), pattern))
                    except re.error as e:
                        logger.warning(f"Bad IOC regex '{pattern}': {e}")
            else:
                self.keywords[category] = [k.lower() for k in items]
        logger.info(
            f"Alerter loaded: {sum(len(v) for v in self.keywords.values())} "
            f"keywords, {len(self.ioc_patterns)} IOC patterns"
        )

    def scan(self, text: str) -> AlertResult:
        if not text:
            return AlertResult(has_alert=False)

        text_lower = text.lower()
        matches = []

        # Keyword matching
        for category in self.PRIORITY:
            if category not in self.keywords:
                continue
            for kw in self.keywords[category]:
                if kw in text_lower:
                    matches.append(Match(
                        category=category,
                        keyword=kw,
                        is_ioc=False
                    ))

        # IOC regex matching
        for pattern, pattern_str in self.ioc_patterns:
            found = pattern.findall(text)
            for hit in found:
                matches.append(Match(
                    category="ioc_patterns",
                    keyword=hit,
                    is_ioc=True
                ))

        return AlertResult(has_alert=bool(matches), matches=matches)

    def format_alert_summary(self, result: AlertResult,
                              channel: str, text: str) -> str:
        """Build a human-readable alert summary."""
        cats = result.categories
        lines = [
            f"🚨 ALERT — {channel}",
            f"Categories: {', '.join(cats)}",
            f"Keywords: {', '.join(m.keyword for m in result.matches[:5])}",
            f"",
            f"Message preview:",
            f"{text[:400]}{'...' if len(text) > 400 else ''}"
        ]
        return "\n".join(lines)
