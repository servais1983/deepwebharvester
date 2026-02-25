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


# ── Edge cases ────────────────────────────────────────────────────────────────


class TestConfigFileNotFound:
    """When the config file does not exist the CLI should fall back gracefully."""

    @patch("deepwebharvester.cli.Crawler")
    @patch("deepwebharvester.cli.StorageManager")
    @patch("deepwebharvester.cli.TorManager")
    def test_missing_config_file_still_runs(
        self,
        mock_tor_cls: MagicMock,
        mock_storage_cls: MagicMock,
        mock_crawler_cls: MagicMock,
        tmp_path,
    ) -> None:
        """A nonexistent config path should not crash — load_config handles it."""
        mock_crawler_cls.return_value = _make_mock_crawler()
        mock_storage_cls.return_value = MagicMock(
            get_known_urls=MagicMock(return_value=set()),
            save_all=MagicMock(return_value={}),
        )
        code = main([
            "--config", "/nonexistent/path/config.yaml",
            "--url", VALID_ONION,
            "--output", str(tmp_path),
        ])
        # Should succeed — nonexistent config → load_config(None) defaults
        assert code == 0

    def test_missing_config_with_no_url_still_returns_1(self, tmp_path) -> None:
        """No URL + missing config → exit code 1 (no seeds)."""
        code = main([
            "--config", "/nonexistent/path/config.yaml",
            "--output", str(tmp_path),
        ])
        assert code == 1


class TestInvalidUrlHandling:
    """Invalid / non-.onion URLs are accepted by argparse but the crawl may yield nothing."""

    @patch("deepwebharvester.cli.Crawler")
    @patch("deepwebharvester.cli.StorageManager")
    @patch("deepwebharvester.cli.TorManager")
    def test_non_onion_url_does_not_crash(
        self,
        mock_tor_cls: MagicMock,
        mock_storage_cls: MagicMock,
        mock_crawler_cls: MagicMock,
        tmp_path,
    ) -> None:
        """The CLI accepts any URL string; crawling is delegated to Crawler."""
        mock_crawler_cls.return_value = _make_mock_crawler(results=[])
        mock_storage_cls.return_value = MagicMock(
            get_known_urls=MagicMock(return_value=set()),
            save_all=MagicMock(return_value={}),
        )
        code = main(["--url", "http://not-an-onion.example.com/",
                     "--output", str(tmp_path)])
        assert code == 0

    @patch("deepwebharvester.cli.Crawler")
    @patch("deepwebharvester.cli.StorageManager")
    @patch("deepwebharvester.cli.TorManager")
    def test_empty_string_url_still_accepted_as_seed(
        self,
        mock_tor_cls: MagicMock,
        mock_storage_cls: MagicMock,
        mock_crawler_cls: MagicMock,
        tmp_path,
    ) -> None:
        """CLI does not validate URL format — validation is left to Crawler."""
        mock_crawler_cls.return_value = _make_mock_crawler(results=[])
        mock_storage_cls.return_value = MagicMock(
            get_known_urls=MagicMock(return_value=set()),
            save_all=MagicMock(return_value={}),
        )
        code = main(["--url", "ftp://weird-scheme.onion/",
                     "--output", str(tmp_path)])
        assert code == 0


class TestOutputDirectoryCreationFailure:
    """Test behaviour when the output directory cannot be created."""

    @patch("deepwebharvester.cli.Crawler")
    @patch("deepwebharvester.cli.StorageManager")
    @patch("deepwebharvester.cli.TorManager")
    def test_storage_manager_receives_output_dir(
        self,
        mock_tor_cls: MagicMock,
        mock_storage_cls: MagicMock,
        mock_crawler_cls: MagicMock,
        tmp_path,
    ) -> None:
        """Verify the output dir is forwarded to StorageManager."""
        mock_crawler_cls.return_value = _make_mock_crawler()
        mock_storage_cls.return_value = MagicMock(
            get_known_urls=MagicMock(return_value=set()),
            save_all=MagicMock(return_value={}),
        )
        main(["--url", VALID_ONION, "--output", str(tmp_path)])
        _, kwargs = mock_storage_cls.call_args
        assert kwargs.get("output_dir") == str(tmp_path)

    @patch("deepwebharvester.cli.Crawler")
    @patch("deepwebharvester.cli.StorageManager",
           side_effect=OSError("Permission denied"))
    @patch("deepwebharvester.cli.TorManager")
    def test_storage_manager_oserror_propagates(
        self,
        mock_tor_cls: MagicMock,
        mock_storage_cls: MagicMock,
        mock_crawler_cls: MagicMock,
        tmp_path,
    ) -> None:
        """If StorageManager raises OSError (e.g. bad dir), the exception bubbles."""
        with pytest.raises(OSError, match="Permission denied"):
            main(["--url", VALID_ONION, "--output", "/root/no_perm_dir"])


class TestHtmlReportGeneration:
    """HTML report should be generated when crawl results exist."""

    @patch("deepwebharvester.cli.ReportGenerator")
    @patch("deepwebharvester.cli.Crawler")
    @patch("deepwebharvester.cli.StorageManager")
    @patch("deepwebharvester.cli.TorManager")
    def test_report_generator_called_when_results(
        self,
        mock_tor_cls: MagicMock,
        mock_storage_cls: MagicMock,
        mock_crawler_cls: MagicMock,
        mock_report_cls: MagicMock,
        tmp_path,
    ) -> None:
        """ReportGenerator.generate should be called when there are results."""
        mock_result = MagicMock()
        mock_result.url = VALID_ONION
        mock_result.text = "sample page text"
        mock_result.iocs = MagicMock(total=0, cves=[], btc_addresses=[], emails=[])
        mock_result.threat = MagicMock(risk_label="Low", categories=[])

        mock_crawler = _make_mock_crawler(results=[mock_result])
        mock_crawler_cls.return_value = mock_crawler

        mock_storage = MagicMock()
        mock_storage.get_known_urls.return_value = set()
        mock_storage.save_all.return_value = {}
        mock_storage_cls.return_value = mock_storage

        mock_report = MagicMock()
        mock_report.generate.return_value = str(tmp_path / "report.html")
        mock_report_cls.return_value = mock_report

        with patch("deepwebharvester.cli.IntelligenceExtractor") as mock_intel_cls:
            mock_intel = MagicMock()
            page_intel = MagicMock()
            page_intel.iocs = MagicMock(total=0, cves=[], btc_addresses=[], emails=[])
            page_intel.threat = MagicMock(risk_label="Low", categories=[])
            mock_intel.analyze.return_value = page_intel
            mock_intel_cls.return_value = mock_intel

            with patch("deepwebharvester.cli.GraphVisualizer") as mock_viz_cls:
                mock_viz = MagicMock()
                mock_viz.save_png.return_value = str(tmp_path / "graph.png")
                mock_viz_cls.return_value = mock_viz

                code = main(["--url", VALID_ONION, "--output", str(tmp_path)])

        assert code == 0
        mock_report.generate.assert_called_once()

    @patch("deepwebharvester.cli.ReportGenerator")
    @patch("deepwebharvester.cli.Crawler")
    @patch("deepwebharvester.cli.StorageManager")
    @patch("deepwebharvester.cli.TorManager")
    def test_report_generator_not_called_when_no_results(
        self,
        mock_tor_cls: MagicMock,
        mock_storage_cls: MagicMock,
        mock_crawler_cls: MagicMock,
        mock_report_cls: MagicMock,
        tmp_path,
    ) -> None:
        """ReportGenerator.generate should NOT be called when results are empty."""
        mock_crawler_cls.return_value = _make_mock_crawler(results=[])
        mock_storage_cls.return_value = MagicMock(
            get_known_urls=MagicMock(return_value=set()),
            save_all=MagicMock(return_value={}),
        )
        mock_report = MagicMock()
        mock_report_cls.return_value = mock_report

        code = main(["--url", VALID_ONION, "--output", str(tmp_path)])
        assert code == 0
        mock_report.generate.assert_not_called()

    @patch("deepwebharvester.cli.ReportGenerator")
    @patch("deepwebharvester.cli.Crawler")
    @patch("deepwebharvester.cli.StorageManager")
    @patch("deepwebharvester.cli.TorManager")
    def test_report_generation_exception_does_not_abort(
        self,
        mock_tor_cls: MagicMock,
        mock_storage_cls: MagicMock,
        mock_crawler_cls: MagicMock,
        mock_report_cls: MagicMock,
        tmp_path,
    ) -> None:
        """A ReportGenerator exception should be caught; exit code is still 0."""
        mock_result = MagicMock()
        mock_result.url = VALID_ONION
        mock_result.text = "text"
        mock_result.iocs = MagicMock(total=0, cves=[], btc_addresses=[], emails=[])
        mock_result.threat = MagicMock(risk_label="Low", categories=[])

        mock_crawler = _make_mock_crawler(results=[mock_result])
        mock_crawler_cls.return_value = mock_crawler

        mock_storage = MagicMock()
        mock_storage.get_known_urls.return_value = set()
        mock_storage.save_all.return_value = {}
        mock_storage_cls.return_value = mock_storage

        mock_report = MagicMock()
        mock_report.generate.side_effect = RuntimeError("report broken")
        mock_report_cls.return_value = mock_report

        with patch("deepwebharvester.cli.IntelligenceExtractor") as mock_intel_cls:
            mock_intel = MagicMock()
            page_intel = MagicMock()
            page_intel.iocs = MagicMock(total=0, cves=[], btc_addresses=[], emails=[])
            page_intel.threat = MagicMock(risk_label="Low", categories=[])
            mock_intel.analyze.return_value = page_intel
            mock_intel_cls.return_value = mock_intel

            with patch("deepwebharvester.cli.GraphVisualizer") as mock_viz_cls:
                mock_viz = MagicMock()
                mock_viz.save_png.side_effect = RuntimeError("viz broken")
                mock_viz_cls.return_value = mock_viz

                code = main(["--url", VALID_ONION, "--output", str(tmp_path)])

        assert code == 0


class TestGraphGeneration:
    """3D graph PNG should be generated when results exist."""

    @patch("deepwebharvester.cli.GraphVisualizer")
    @patch("deepwebharvester.cli.ReportGenerator")
    @patch("deepwebharvester.cli.Crawler")
    @patch("deepwebharvester.cli.StorageManager")
    @patch("deepwebharvester.cli.TorManager")
    def test_graph_visualizer_called_when_results(
        self,
        mock_tor_cls: MagicMock,
        mock_storage_cls: MagicMock,
        mock_crawler_cls: MagicMock,
        mock_report_cls: MagicMock,
        mock_viz_cls: MagicMock,
        tmp_path,
    ) -> None:
        """GraphVisualizer.save_png should be called when there are results."""
        mock_result = MagicMock()
        mock_result.url = VALID_ONION
        mock_result.text = "text"
        mock_result.iocs = MagicMock(total=0, cves=[], btc_addresses=[], emails=[])
        mock_result.threat = MagicMock(risk_label="Low", categories=[])

        mock_crawler = _make_mock_crawler(results=[mock_result])
        mock_crawler_cls.return_value = mock_crawler

        mock_storage = MagicMock()
        mock_storage.get_known_urls.return_value = set()
        mock_storage.save_all.return_value = {}
        mock_storage_cls.return_value = mock_storage

        mock_report = MagicMock()
        mock_report.generate.return_value = str(tmp_path / "report.html")
        mock_report_cls.return_value = mock_report

        mock_viz = MagicMock()
        mock_viz.save_png.return_value = str(tmp_path / "network_graph.png")
        mock_viz_cls.return_value = mock_viz

        with patch("deepwebharvester.cli.IntelligenceExtractor") as mock_intel_cls:
            mock_intel = MagicMock()
            page_intel = MagicMock()
            page_intel.iocs = MagicMock(total=0, cves=[], btc_addresses=[], emails=[])
            page_intel.threat = MagicMock(risk_label="Low", categories=[])
            mock_intel.analyze.return_value = page_intel
            mock_intel_cls.return_value = mock_intel

            code = main(["--url", VALID_ONION, "--output", str(tmp_path)])

        assert code == 0
        mock_viz.save_png.assert_called_once()

    @patch("deepwebharvester.cli.GraphVisualizer")
    @patch("deepwebharvester.cli.ReportGenerator")
    @patch("deepwebharvester.cli.Crawler")
    @patch("deepwebharvester.cli.StorageManager")
    @patch("deepwebharvester.cli.TorManager")
    def test_graph_output_path_uses_output_dir(
        self,
        mock_tor_cls: MagicMock,
        mock_storage_cls: MagicMock,
        mock_crawler_cls: MagicMock,
        mock_report_cls: MagicMock,
        mock_viz_cls: MagicMock,
        tmp_path,
    ) -> None:
        """The graph PNG path should be inside the configured output dir."""
        mock_result = MagicMock()
        mock_result.url = VALID_ONION
        mock_result.text = "text"
        mock_result.iocs = MagicMock(total=0, cves=[], btc_addresses=[], emails=[])
        mock_result.threat = MagicMock(risk_label="Low", categories=[])

        mock_crawler = _make_mock_crawler(results=[mock_result])
        mock_crawler_cls.return_value = mock_crawler

        mock_storage = MagicMock()
        mock_storage.get_known_urls.return_value = set()
        mock_storage.save_all.return_value = {}
        mock_storage_cls.return_value = mock_storage

        mock_report = MagicMock()
        mock_report.generate.return_value = str(tmp_path / "report.html")
        mock_report_cls.return_value = mock_report

        mock_viz = MagicMock()
        mock_viz.save_png.return_value = str(tmp_path / "network_graph.png")
        mock_viz_cls.return_value = mock_viz

        with patch("deepwebharvester.cli.IntelligenceExtractor") as mock_intel_cls:
            mock_intel = MagicMock()
            page_intel = MagicMock()
            page_intel.iocs = MagicMock(total=0, cves=[], btc_addresses=[], emails=[])
            page_intel.threat = MagicMock(risk_label="Low", categories=[])
            mock_intel.analyze.return_value = page_intel
            mock_intel_cls.return_value = mock_intel

            main(["--url", VALID_ONION, "--output", str(tmp_path)])

        call_kwargs = mock_viz.save_png.call_args
        output_path_arg = call_kwargs[1].get("output_path") or call_kwargs[0][2]
        assert str(tmp_path) in output_path_arg
        assert "network_graph.png" in output_path_arg
