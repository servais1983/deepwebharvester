"""
Multi-format result persistence.

Supports simultaneous output to JSON, CSV, and SQLite so results are
immediately queryable and portable.  The SQLite backend also powers the
resume feature by tracking already-crawled URLs.
"""
from __future__ import annotations

import csv
import json
import logging
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set

from .crawler import CrawlResult

logger = logging.getLogger(__name__)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS crawl_results (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    url           TEXT    UNIQUE NOT NULL,
    title         TEXT,
    text          TEXT,
    content_hash  TEXT,
    depth         INTEGER,
    crawl_time    REAL,
    links_found   INTEGER,
    site          TEXT,
    crawled_at    TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
CREATE INDEX IF NOT EXISTS idx_site ON crawl_results(site);
CREATE INDEX IF NOT EXISTS idx_hash ON crawl_results(content_hash);
"""


class StorageManager:
    """
    Saves :class:`~deepwebharvester.crawler.CrawlResult` objects to disk in
    one or more formats.

    Args:
        output_dir:    Directory where all output files are written.
        db_name:       SQLite database filename (inside *output_dir*).
        json_output:   Enable JSON export.
        csv_output:    Enable CSV export.
        sqlite_output: Enable SQLite persistence (also required for resume).
    """

    def __init__(
        self,
        output_dir: str = "results",
        db_name: str = "deepwebharvester.db",
        json_output: bool = True,
        csv_output: bool = True,
        sqlite_output: bool = True,
    ) -> None:
        self._dir = Path(output_dir)
        self._dir.mkdir(parents=True, exist_ok=True)
        self._db_path = self._dir / db_name
        self.json_output = json_output
        self.csv_output = csv_output
        self.sqlite_output = sqlite_output

        if self.sqlite_output:
            self._init_db()

    # ── SQLite ────────────────────────────────────────────────────────────────

    def _init_db(self) -> None:
        with sqlite3.connect(self._db_path) as conn:
            conn.executescript(_SCHEMA)

    def get_known_urls(self) -> Set[str]:
        """
        Return the set of URLs already stored in the database.

        Used by the crawler to implement *resume* mode: previously crawled
        URLs are skipped on the next run.
        """
        if not self.sqlite_output or not self._db_path.exists():
            return set()
        with sqlite3.connect(self._db_path) as conn:
            rows = conn.execute("SELECT url FROM crawl_results").fetchall()
        return {row[0] for row in rows}

    def save_to_sqlite(self, results: List[CrawlResult]) -> int:
        """
        Persist *results* to SQLite, silently skipping duplicates.

        Returns:
            Number of newly inserted rows.
        """
        if not self.sqlite_output:
            return 0
        inserted = 0
        with sqlite3.connect(self._db_path) as conn:
            for r in results:
                try:
                    conn.execute(
                        """
                        INSERT OR IGNORE INTO crawl_results
                            (url, title, text, content_hash, depth,
                             crawl_time, links_found, site)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            r.url, r.title, r.text, r.content_hash,
                            r.depth, r.crawl_time, r.links_found, r.site,
                        ),
                    )
                    if conn.execute("SELECT changes()").fetchone()[0]:
                        inserted += 1
                except sqlite3.Error as exc:
                    logger.error("SQLite insert failed for %s: %s", r.url, exc)
            conn.commit()
        logger.info("SQLite: %d new row(s) saved → %s", inserted, self._db_path)
        return inserted

    # ── JSON ──────────────────────────────────────────────────────────────────

    def save_to_json(
        self,
        results: List[CrawlResult],
        filename: Optional[str] = None,
    ) -> Path:
        """
        Write *results* as a JSON array.

        Args:
            results:  List of :class:`CrawlResult` to serialise.
            filename: Override the auto-generated timestamped filename.

        Returns:
            Path to the written file.
        """
        ts = datetime.now(tz=timezone.utc).strftime("%Y%m%d_%H%M%S")
        path = self._dir / (filename or f"results_{ts}.json")
        payload = [
            {
                "url": r.url,
                "site": r.site,
                "title": r.title,
                "depth": r.depth,
                "crawl_time_s": round(r.crawl_time, 3),
                "links_found": r.links_found,
                "content_hash": r.content_hash,
                "text": r.text,
            }
            for r in results
        ]
        try:
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, indent=2, ensure_ascii=False)
            logger.info("JSON: %d result(s) → %s", len(payload), path)
        except OSError as exc:
            logger.error("Failed to write JSON output: %s", exc)
        return path

    # ── CSV ───────────────────────────────────────────────────────────────────

    def save_to_csv(
        self,
        results: List[CrawlResult],
        filename: Optional[str] = None,
    ) -> Path:
        """
        Write *results* as a CSV file.

        Args:
            results:  List of :class:`CrawlResult` to serialise.
            filename: Override the auto-generated timestamped filename.

        Returns:
            Path to the written file.
        """
        ts = datetime.now(tz=timezone.utc).strftime("%Y%m%d_%H%M%S")
        path = self._dir / (filename or f"results_{ts}.csv")
        try:
            with open(path, "w", newline="", encoding="utf-8") as fh:
                writer = csv.writer(fh)
                writer.writerow(
                    ["URL", "Site", "Title", "Depth",
                     "CrawlTime(s)", "LinksFound", "ContentHash", "Text"]
                )
                for r in results:
                    clean = r.text.replace("\n", " ").replace("\r", " ")
                    writer.writerow(
                        [r.url, r.site, r.title, r.depth,
                         round(r.crawl_time, 3), r.links_found,
                         r.content_hash, clean]
                    )
            logger.info("CSV: %d result(s) → %s", len(results), path)
        except OSError as exc:
            logger.error("Failed to write CSV output: %s", exc)
        return path

    # ── Combined ──────────────────────────────────────────────────────────────

    def save_all(self, results: List[CrawlResult]) -> Dict[str, Path]:
        """
        Save *results* in every enabled format.

        Returns:
            A mapping of format name → output path.
        """
        paths: Dict[str, Path] = {}
        if self.sqlite_output:
            self.save_to_sqlite(results)
            paths["sqlite"] = self._db_path
        if self.json_output:
            paths["json"] = self.save_to_json(results)
        if self.csv_output:
            paths["csv"] = self.save_to_csv(results)
        return paths
