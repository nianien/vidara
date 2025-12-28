from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, List
from urllib.parse import urljoin, urlparse

from playwright.sync_api import Page, sync_playwright

__all__ = ["GoodShortCrawler", "CrawlResult"]


@dataclass(frozen=True)
class CrawlResult:
    series_id: str
    base_dir: Path
    episodes_file: Path
    m3u8_map: Dict[int, str]
    episode_urls: List[str]


class GoodShortCrawler:
    """
    工具类：GoodShort 抓每集第一个 m3u8（结果文件=断点状态文件）
    输入：任意一集URL
    输出：episodes.m3u8.txt（001\t<url>）
    """

    def __init__(
            self,
            work_root: Path | str = Path("./downloads"),
            base_url: str = "https://www.goodshort.com",
            ep_link_sel: str | None = None,
    ) -> None:
        self.work_root = Path(work_root)
        self.base_url = base_url.rstrip("/")
        # EP 链接 selector 作为实例策略，便于不同站点/页面复用
        self.ep_link_sel = ep_link_sel or 'a[href^="/episode/"], a[href^="episode/"]'

    @staticmethod
    def extract_series_id(start_url: str) -> str:
        path = urlparse(start_url).path
        parts = [p for p in path.split("/") if p]
        if len(parts) >= 2 and parts[0] == "episode":
            return parts[1]
        raise ValueError(f"Unrecognized GoodShort URL structure: {start_url}")

    @staticmethod
    def extract_namespace(start_url: str) -> str:
        host = (urlparse(start_url).hostname or "").lower().lstrip("www.")
        if not host:
            return "site"
        parts = host.split(".")
        ns = parts[-2] if len(parts) >= 2 else parts[0]
        ns = re.sub(r"[^a-z0-9._-]+", "_", ns)
        return ns or "site"

    def base_dir_for_url(self, start_url: str) -> Path:
        ns = self.extract_namespace(start_url)
        series_id = self.extract_series_id(start_url)
        base = self.work_root / ns / series_id
        base.mkdir(parents=True, exist_ok=True)
        return base

    def episodes_file_for_url(self, start_url: str) -> Path:
        return self.base_dir_for_url(start_url) / "episodes.m3u8.txt"

    @staticmethod
    def _load_done_from_episodes_file(episodes_file: Path) -> Dict[int, str]:
        done: Dict[int, str] = {}
        if not episodes_file.exists():
            return done
        for line in episodes_file.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip()
            if not line:
                continue
            m = re.match(r"^(\d{3})\t(.+)$", line)
            if not m:
                continue
            idx = int(m.group(1))
            url = m.group(2).strip()
            if idx not in done and url:
                done[idx] = url
        return done

    @staticmethod
    def _append_episode_line(episodes_file: Path, ep_index: int, m3u8_url: str) -> None:
        episodes_file.parent.mkdir(parents=True, exist_ok=True)
        with episodes_file.open("a", encoding="utf-8") as f:
            f.write(f"{ep_index:03d}\t{m3u8_url}\n")

    def _get_episode_urls(self, page: Page) -> List[str]:
        page.wait_for_timeout(800)
        hrefs: List[str] = page.eval_on_selector_all(
            self.ep_link_sel,
            "els => els.map(a => a.getAttribute('href')).filter(Boolean)",
        )
        seen = set()
        urls: List[str] = []
        for h in hrefs:
            u = urljoin(self.base_url + "/", h)
            if u in seen:
                continue
            seen.add(u)
            urls.append(u)
        return urls

    @staticmethod
    def _wait_first_m3u8_on_action(page: Page, action: Callable[[], None], timeout_ms: int) -> str | None:
        try:
            with page.expect_request(lambda r: ".m3u8" in r.url, timeout=timeout_ms) as reqinfo:
                action()
            return reqinfo.value.url
        except Exception:
            return None

    def _goto_and_capture_m3u8(self, page: Page, ep_url: str, timeout_ms: int) -> str | None:
        return self._wait_first_m3u8_on_action(
            page,
            action=lambda: page.goto(ep_url, wait_until="domcontentloaded", timeout=60_000),
            timeout_ms=timeout_ms,
        )

    def crawl(
            self,
            start_url: str,
            show: bool = False,
            timeout_ms: int = 10_000,
            max_limit: int = -1,
    ) -> CrawlResult:
        series_id = self.extract_series_id(start_url)
        base_dir = self.base_dir_for_url(start_url)
        episodes_file = self.episodes_file_for_url(start_url)
        done = self._load_done_from_episodes_file(episodes_file)

        with sync_playwright() as pwt:
            browser = pwt.chromium.launch(headless=not show)
            ctx = browser.new_context()
            page = ctx.new_page()

            # 先进入页面获取全集链接列表（不抓 m3u8）
            page.goto(start_url, wait_until="domcontentloaded", timeout=10_000)

            ep_urls = self._get_episode_urls(page)
            if not ep_urls:
                ctx.close()
                browser.close()
                raise RuntimeError("No episode urls found on page (selector mismatch or page not ready).")

            total = len(ep_urls)
            for i, ep_url in enumerate(ep_urls, start=1):
                if 0 < max_limit < i:
                    break
                if i in done:
                    continue
                print(f"[{i}/{total}] goto {i:03d}: {ep_url}")
                m3u8 = self._goto_and_capture_m3u8(page, ep_url, timeout_ms)
                if not m3u8:
                    print(f"[x] {i:03d} timeout/no m3u8, skip")
                    continue
                self._append_episode_line(episodes_file, i, m3u8)
                done[i] = m3u8
                print(f"{i:03d}\t{m3u8}")
            ctx.close()
            browser.close()

        return CrawlResult(
            series_id=series_id,
            base_dir=base_dir,
            episodes_file=episodes_file,
            m3u8_map=dict(done),
            episode_urls=list(ep_urls),
        )
