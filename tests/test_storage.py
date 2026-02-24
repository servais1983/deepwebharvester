"""
Tests for StorageManager.

Covers SQLite persistence, JSON/CSV serialization, deduplication,
and resume support via get_known_urls().
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from deepwebharvester.crawler import CrawlResult
from deepwebharvester.storage import StorageManager
from tests.conftest import VALID_ONION


# ── Helpers ───────────────────────────────────────────────────────────────────


def make_result(
    url: str = VALID_ONION + "/page",
    title: str = "Test Page",
    text: str = "Sample intelligence content.",
    content_hash: str = "deadbeef" * 8,
    depth: int = 0,
    crawl_time: float = 1.23,
    links_found: int = 3,
    site: str = VALID_ONION,
) -> CrawlResult:
    return CrawlResult(
        url=url,
        title=title,
        text=text,
        content_hash=content_hash,
        depth=depth,
        crawl_time=crawl_time,
        links_found=links_found,
        site=site,
    )


# ── SQLite ────────────────────────────────────────────────────────────────────


class TestSQLite:
    def test_database_file_created(self, tmp_storage: StorageManager, tmp_path: Path) -> None:
        assert (tmp_path / "test.db").exists()

    def test_table_exists(self, tmp_storage: StorageManager, tmp_path: Path) -> None:
        with sqlite3.connect(tmp_path / "test.db") as conn:
            tables = {
                row[0]
                for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
            }
        assert "crawl_results" in tables

    def test_save_returns_inserted_count(self, tmp_storage: StorageManager) -> None:
        results = [make_result()]
        count = tmp_storage.save_to_sqlite(results)
        assert count == 1

    def test_save_multiple(self, tmp_storage: StorageManager) -> None:
        results = [
            make_result(url=VALID_ONION + f"/page{i}", content_hash=f"hash{i}" * 8)
            for i in range(3)
        ]
        count = tmp_storage.save_to_sqlite(results)
        assert count == 3

    def test_duplicate_not_inserted(self, tmp_storage: StorageManager) -> None:
        result = make_result()
        tmp_storage.save_to_sqlite([result])
        count = tmp_storage.save_to_sqlite([result])
        assert count == 0

    def test_get_known_urls_returns_saved(self, tmp_storage: StorageManager) -> None:
        result = make_result()
        tmp_storage.save_to_sqlite([result])
        known = tmp_storage.get_known_urls()
        assert result.url in known

    def test_get_known_urls_empty_initially(self, tmp_storage: StorageManager) -> None:
        known = tmp_storage.get_known_urls()
        assert len(known) == 0

    def test_get_known_urls_respects_all_rows(self, tmp_storage: StorageManager) -> None:
        results = [
            make_result(url=VALID_ONION + f"/p{i}", content_hash=f"h{i}" * 16)
            for i in range(5)
        ]
        tmp_storage.save_to_sqlite(results)
        known = tmp_storage.get_known_urls()
        assert len(known) == 5


# ── JSON ──────────────────────────────────────────────────────────────────────


class TestJSON:
    def test_file_is_created(self, tmp_storage: StorageManager) -> None:
        path = tmp_storage.save_to_json([make_result()])
        assert path.exists()

    def test_content_is_valid_json(self, tmp_storage: StorageManager) -> None:
        path = tmp_storage.save_to_json([make_result()])
        data = json.loads(path.read_text(encoding="utf-8"))
        assert isinstance(data, list)

    def test_result_fields_present(self, tmp_storage: StorageManager) -> None:
        path = tmp_storage.save_to_json([make_result()])
        item = json.loads(path.read_text(encoding="utf-8"))[0]
        for key in ("url", "site", "title", "depth", "crawl_time_s",
                    "links_found", "content_hash", "text"):
            assert key in item, f"Missing key: {key}"

    def test_title_preserved(self, tmp_storage: StorageManager) -> None:
        result = make_result(title="My Research Page")
        path = tmp_storage.save_to_json([result])
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data[0]["title"] == "My Research Page"

    def test_multiple_results(self, tmp_storage: StorageManager) -> None:
        results = [
            make_result(url=VALID_ONION + f"/p{i}", title=f"Page {i}")
            for i in range(4)
        ]
        path = tmp_storage.save_to_json(results)
        data = json.loads(path.read_text(encoding="utf-8"))
        assert len(data) == 4

    def test_custom_filename(self, tmp_storage: StorageManager, tmp_path: Path) -> None:
        path = tmp_storage.save_to_json([make_result()], filename="custom.json")
        assert path.name == "custom.json"


# ── CSV ───────────────────────────────────────────────────────────────────────


class TestCSV:
    def test_file_is_created(self, tmp_storage: StorageManager) -> None:
        path = tmp_storage.save_to_csv([make_result()])
        assert path.exists()

    def test_header_row_present(self, tmp_storage: StorageManager) -> None:
        path = tmp_storage.save_to_csv([make_result()])
        lines = path.read_text(encoding="utf-8").splitlines()
        assert "URL" in lines[0]
        assert "Title" in lines[0]

    def test_data_row_count(self, tmp_storage: StorageManager) -> None:
        results = [
            make_result(url=VALID_ONION + f"/p{i}", content_hash=f"c{i}" * 16)
            for i in range(3)
        ]
        path = tmp_storage.save_to_csv(results)
        lines = path.read_text(encoding="utf-8").splitlines()
        # 1 header + 3 data rows
        assert len(lines) == 4

    def test_newlines_stripped_from_text(self, tmp_storage: StorageManager) -> None:
        result = make_result(text="line one\nline two\nline three")
        path = tmp_storage.save_to_csv([result])
        content = path.read_text(encoding="utf-8")
        # Newlines in text field should be replaced with spaces
        assert "\nline two" not in content

    def test_custom_filename(self, tmp_storage: StorageManager) -> None:
        path = tmp_storage.save_to_csv([make_result()], filename="output.csv")
        assert path.name == "output.csv"


# ── Combined save_all ─────────────────────────────────────────────────────────


class TestSaveAll:
    def test_returns_all_format_keys(self, tmp_storage: StorageManager) -> None:
        paths = tmp_storage.save_all([make_result()])
        assert "json" in paths
        assert "csv" in paths
        assert "sqlite" in paths

    def test_all_files_exist(self, tmp_storage: StorageManager) -> None:
        paths = tmp_storage.save_all([make_result()])
        for path in paths.values():
            assert Path(path).exists()

    def test_disabled_formats_omitted(self, tmp_path: Path) -> None:
        storage = StorageManager(
            output_dir=str(tmp_path),
            json_output=False,
            csv_output=False,
            sqlite_output=True,
        )
        paths = storage.save_all([make_result()])
        assert "json" not in paths
        assert "csv" not in paths
        assert "sqlite" in paths


# ── Resume (get_known_urls with no DB) ────────────────────────────────────────


class TestResumeWithoutDB:
    def test_get_known_urls_returns_empty_when_no_sqlite(self, tmp_path: Path) -> None:
        storage = StorageManager(
            output_dir=str(tmp_path),
            sqlite_output=False,
        )
        known = storage.get_known_urls()
        assert known == set()
