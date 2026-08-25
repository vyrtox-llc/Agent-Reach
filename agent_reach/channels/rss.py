# -*- coding: utf-8 -*-
"""RSS — check if feedparser is available."""

from urllib.parse import parse_qs, urlparse

from .base import Channel

_FEED_QUERY_VALUES = {"rss", "rss2", "atom", "atom10", "rdf"}


class RSSChannel(Channel):
    name = "rss"
    description = "RSS/Atom 订阅源"
    backends = ["feedparser"]
    tier = 0

    def can_handle(self, url: str) -> bool:
        try:
            parsed = urlparse(str(url or "").strip())
        except ValueError:
            return False
        path = (parsed.path or "").lower().rstrip("/")
        segments = [part for part in path.split("/") if part]
        last = segments[-1] if segments else ""
        if last in {"feed", "rss", "atom", "feed.xml", "rss.xml", "atom.xml"}:
            return True
        if last.endswith((".atom", ".rss")):
            return True
        if (
            len(segments) >= 2
            and segments[-2] in {"feed", "rss", "atom"}
            and last.endswith(".xml")
        ):
            return True
        if (
            len(segments) >= 3
            and segments[-3] == "feeds"
            and segments[-2] == "posts"
            and segments[-1] in {"default", "default.xml"}
        ):
            return True
        query_values = {
            value.lower()
            for key in ("feed", "format", "type")
            for value in parse_qs(parsed.query, keep_blank_values=True).get(key, [])
        }
        return bool(query_values & _FEED_QUERY_VALUES)

    def check(self, config=None):
        try:
            import feedparser  # noqa: F401
        except ImportError:
            self.active_backend = None
            return "off", "feedparser 未安装。安装：pip install feedparser"
        except Exception as e:
            # 已安装但导入期崩溃（半残安装/版本冲突）→ 重装处方
            self.active_backend = None
            return "error", f"feedparser 导入失败：{e}\n修复：pip install --force-reinstall feedparser"
        self.active_backend = self.backends[0]
        return "ok", "可读取 RSS/Atom 源"
