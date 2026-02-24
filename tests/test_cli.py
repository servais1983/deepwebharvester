"""
Tests for the CLI entry point.

Uses mocks to avoid network calls or real Tor connections.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from deepwebharvester.cli import _build_parser, main


# ── Argument parser ───────────────────────────────────────────────────────────


class TestArgumentParser:
    @pytest.fixture
    def parser(self):
        return _build_parser()

    def test_version_flag_exists(self, parser) -> None:
        with pytest.raises(SystemExit) as exc_info:
            parser.parse_args(["--version"])
        assert exc_info.value.code == 0

    def test_url_flag_stored(self, parser) -> None:
        args = parser.parse_args(["--url", "http://test.onion/"])
        assert args.urls == ["http://test.onion/"]

    def test_multiple_urls(self, parser) -> None:
        args = parser.parse_args(["--url", "http://a.onion/", "--url", "http://b.onion/"])
        assert len(args.urls) == 2

    def test_depth_flag(self, parser) -> None:
        args = parser.parse_args(["--depth", "3"])
        assert args.depth == 3

    def test_pages_flag(self, parser) -> None:
        args = parser.parse_args(["--pages", "10"])
        assert args.pages == 10

    def test_workers_flag(self, parser) -> None:
        args = parser.parse_args(["--workers", "5"])
        assert args.workers == 5

    def test_output_flag(self, parser) -> None:
        args = parser.parse_args(["--output", "/tmp/results"])
        assert args.output == "/tmp/results"

    def test_no_json_flag(self, parser) -> None:
        args = parser.parse_args(["--no-json"])
        assert args.no_json is True

    def test_no_csv_flag(self, parser) -> None:
        args = parser.parse_args(["--no-csv"])
        assert args.no_csv is True

    def test_no_sqlite_flag(self, parser) -> None:
        args = parser.parse_args(["--no-sqlite"])
        assert args.no_sqlite is True

    def test_resume_flag(self, parser) -> None:
        args = parser.parse_args(["--resume"])
        assert args.resume is True

    def test_verify_tor_flag(self, parser) -> None:
        args = parser.parse_args(["--verify-tor"])
        assert args.verify_tor is True

    def test_log_level_flag(self, parser) -> None:
        args = parser.parse_args(["--log-level", "DEBUG"])
        assert args.log_level == "DEBUG"

    def test_config_default(self, parser) -> None:
        args = parser.parse_args([])
        assert args.config == "config.yaml"

    def test_defaults_are_none(self, parser) -> None:
        args = parser.parse_args([])
        assert args.depth is None
        assert args.pages is None
        assert args.workers is None
        assert args.urls is None


# ── main() exit codes ─────────────────────────────────────────────────────────


VALID_ONION = "http://" + "a" * 56 + ".onion"


def _make_mock_crawler(results=None):
    """Return a mock Crawler that produces *results* from crawl_all."""
    mock = MagicMock()
    mock.crawl_all.return_value = results or []
    mock.stats = MagicMock()
    mock.stats.sites_crawled = 1
    mock.stats.pages_crawled = len(results or [])
    mock.stats.pages_failed = 0
    mock.stats.pages_skipped = 0
    mock.stats.pages_deduplicated = 0
    mock.stats.elapsed = 1.0
    return mock


class TestMainExitCodes:
    def test_exits_1_with_no_urls(self, tmp_path) -> None:
        """No seed URLs → exit code 1."""
        code = main(["--output", str(tmp_path), "--no-sqlite"])
        assert code == 1

    @patch("deepwebharvester.cli.Crawler")
    @patch("deepwebharvester.cli.StorageManager")
    @patch("deepwebharvester.cli.TorManager")
    def test_exits_0_with_valid_url(
        self,
        mock_tor_cls: MagicMock,
        mock_storage_cls: MagicMock,
        mock_crawler_cls: MagicMock,
        tmp_path,
    ) -> None:
        """Valid URL + mocked dependencies → exit code 0."""
        mock_crawler = _make_mock_crawler()
        mock_crawler_cls.return_value = mock_crawler
        mock_storage = MagicMock()
        mock_storage.get_known_urls.return_value = set()
        mock_storage.save_all.return_value = {}
        mock_storage_cls.return_value = mock_storage

        code = main(["--url", VALID_ONION, "--output", str(tmp_path)])
        assert code == 0

    @patch("deepwebharvester.cli.Crawler")
    @patch("deepwebharvester.cli.StorageManager")
    @patch("deepwebharvester.cli.TorManager")
    def test_verify_tor_failure_exits_1(
        self,
        mock_tor_cls: MagicMock,
        mock_storage_cls: MagicMock,
        mock_crawler_cls: MagicMock,
        tmp_path,
    ) -> None:
        """When --verify-tor fails, exit code should be 1."""
        mock_tor = MagicMock()
        mock_tor.verify_connection.return_value = False
        mock_tor_cls.return_value = mock_tor

        code = main(["--url", VALID_ONION, "--verify-tor", "--output", str(tmp_path)])
        assert code == 1


class TestMainCliOverrides:
    @patch("deepwebharvester.cli.Crawler")
    @patch("deepwebharvester.cli.StorageManager")
    @patch("deepwebharvester.cli.TorManager")
    def test_depth_override_applied(
        self,
        mock_tor_cls: MagicMock,
        mock_storage_cls: MagicMock,
        mock_crawler_cls: MagicMock,
        tmp_path,
    ) -> None:
        mock_crawler = _make_mock_crawler()
        mock_crawler_cls.return_value = mock_crawler
        mock_storage_cls.return_value = MagicMock(
            get_known_urls=MagicMock(return_value=set()),
            save_all=MagicMock(return_value={}),
        )

        main(["--url", VALID_ONION, "--depth", "1", "--output", str(tmp_path)])
        # Verify Crawler was instantiated with max_depth=1
        _, kwargs = mock_crawler_cls.call_args
        assert kwargs.get("max_depth") == 1

    @patch("deepwebharvester.cli.Crawler")
    @patch("deepwebharvester.cli.StorageManager")
    @patch("deepwebharvester.cli.TorManager")
    def test_no_json_disables_json(
        self,
        mock_tor_cls: MagicMock,
        mock_storage_cls: MagicMock,
        mock_crawler_cls: MagicMock,
        tmp_path,
    ) -> None:
        mock_crawler_cls.return_value = _make_mock_crawler()
        mock_storage_cls.return_value = MagicMock(
            get_known_urls=MagicMock(return_value=set()),
            save_all=MagicMock(return_value={}),
        )

        main(["--url", VALID_ONION, "--no-json", "--output", str(tmp_path)])
        _, kwargs = mock_storage_cls.call_args
        assert kwargs.get("json_output") is False

    @patch("deepwebharvester.cli.Crawler")
    @patch("deepwebharvester.cli.StorageManager")
    @patch("deepwebharvester.cli.TorManager")
    def test_resume_loads_known_urls(
        self,
        mock_tor_cls: MagicMock,
        mock_storage_cls: MagicMock,
        mock_crawler_cls: MagicMock,
        tmp_path,
    ) -> None:
        mock_crawler = _make_mock_crawler()
        mock_crawler_cls.return_value = mock_crawler
        mock_storage = MagicMock()
        mock_storage.get_known_urls.return_value = {"http://already-crawled.onion/"}
        mock_storage.save_all.return_value = {}
        mock_storage_cls.return_value = mock_storage

        main(["--url", VALID_ONION, "--resume", "--output", str(tmp_path)])
        mock_storage.get_known_urls.assert_called_once()
