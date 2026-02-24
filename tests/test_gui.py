"""
Tests for the GUI module.

All tests use mocks and a headless Tk root so they work in CI environments
without a display server (the tests are skipped if Tkinter is unavailable).
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

# Skip the entire module if Tkinter is not available (headless CI / no python3-tk)
try:
    import tkinter as tk
    _TK_AVAILABLE = True
except ImportError:
    _TK_AVAILABLE = False

if not _TK_AVAILABLE:
    pytest.skip("tkinter not installed (run: sudo apt install python3-tk)",
                allow_module_level=True)


@pytest.fixture(scope="module")
def tk_root():
    """Create a single Tk root for all GUI tests, then destroy it."""
    try:
        root = tk.Tk()
        root.withdraw()   # hide the window
        yield root
        root.destroy()
    except tk.TclError:
        pytest.skip("No display available for Tkinter tests")


# ---------------------------------------------------------------------------
# Import guard — skip if display is unavailable
# ---------------------------------------------------------------------------

try:
    from deepwebharvester.gui import App, _PALETTE, QueueHandler
    _GUI_IMPORTABLE = True
except tk.TclError:
    _GUI_IMPORTABLE = False

pytestmark = pytest.mark.skipif(
    not _GUI_IMPORTABLE,
    reason="GUI cannot be instantiated without a display",
)


# ---------------------------------------------------------------------------
# QueueHandler (no display needed)
# ---------------------------------------------------------------------------

class TestQueueHandler:
    import queue as _q

    def test_emit_puts_record_in_queue(self) -> None:
        import logging
        import queue

        q: queue.Queue = queue.Queue()
        handler = QueueHandler(q)
        handler.setFormatter(logging.Formatter("%(message)s"))

        record = logging.LogRecord(
            name="test", level=logging.INFO,
            pathname="", lineno=0,
            msg="hello world", args=(), exc_info=None,
        )
        handler.emit(record)
        assert not q.empty()
        retrieved = q.get_nowait()
        assert retrieved.getMessage() == "hello world"

    def test_multiple_records_queued(self) -> None:
        import logging
        import queue

        q: queue.Queue = queue.Queue()
        handler = QueueHandler(q)

        for i in range(5):
            record = logging.LogRecord(
                name="test", level=logging.DEBUG,
                pathname="", lineno=0,
                msg=f"msg {i}", args=(), exc_info=None,
            )
            handler.emit(record)

        assert q.qsize() == 5


# ---------------------------------------------------------------------------
# Palette sanity checks (no display needed)
# ---------------------------------------------------------------------------

class TestPalette:
    def test_all_keys_present(self) -> None:
        required = {"bg", "panel", "accent", "fg", "entry_bg", "error", "success"}
        assert required.issubset(_PALETTE.keys())

    def test_all_values_are_hex_colours(self) -> None:
        for key, value in _PALETTE.items():
            assert value.startswith("#"), f"{key!r} is not a hex colour: {value!r}"
            assert len(value) in (4, 7), f"{key!r} has unexpected length: {value!r}"


# ---------------------------------------------------------------------------
# App widget construction
# ---------------------------------------------------------------------------

class TestAppConstruction:
    @pytest.fixture
    def app(self):
        """Create App instance for each test then destroy."""
        try:
            instance = App()
            instance.withdraw()
            yield instance
            instance.destroy()
        except tk.TclError:
            pytest.skip("Cannot create App without display")

    def test_title_contains_version(self, app: App) -> None:
        from deepwebharvester import __version__
        assert __version__ in app.title()

    def test_url_text_widget_exists(self, app: App) -> None:
        assert isinstance(app._url_text, tk.Text)

    def test_start_button_exists(self, app: App) -> None:
        assert hasattr(app, "_start_btn")

    def test_stop_button_exists(self, app: App) -> None:
        assert hasattr(app, "_stop_btn")

    def test_stop_button_initially_disabled(self, app: App) -> None:
        assert str(app._stop_btn["state"]) == tk.DISABLED

    def test_start_button_initially_enabled(self, app: App) -> None:
        assert str(app._start_btn["state"]) == tk.NORMAL

    def test_log_text_widget_exists(self, app: App) -> None:
        assert hasattr(app, "_log_text")

    def test_progress_bar_exists(self, app: App) -> None:
        assert hasattr(app, "_progress")

    def test_notebook_has_two_tabs(self, app: App) -> None:
        assert app._notebook.index("end") == 2

    def test_stat_vars_exist(self, app: App) -> None:
        for attr in ("_stat_crawled", "_stat_failed", "_stat_skipped",
                     "_stat_dedup", "_stat_elapsed"):
            assert hasattr(app, attr)

    def test_status_var_default(self, app: App) -> None:
        assert app._status_var.get() == "Ready"


# ---------------------------------------------------------------------------
# _collect_config
# ---------------------------------------------------------------------------

class TestCollectConfig:
    @pytest.fixture
    def app(self):
        try:
            instance = App()
            instance.withdraw()
            yield instance
            instance.destroy()
        except tk.TclError:
            pytest.skip("Cannot create App without display")

    def test_returns_none_when_no_urls(self, app: App) -> None:
        app._url_text.delete("1.0", tk.END)
        with patch("deepwebharvester.gui.messagebox.showerror"):
            result = app._collect_config()
        assert result is None

    def test_returns_config_with_valid_url(self, app: App) -> None:
        url = "http://" + "a" * 56 + ".onion"
        app._url_text.delete("1.0", tk.END)
        app._url_text.insert("1.0", url)
        cfg = app._collect_config()
        assert cfg is not None
        assert url in cfg.seed_urls

    def test_multiple_urls_collected(self, app: App) -> None:
        urls = [
            "http://" + "a" * 56 + ".onion",
            "http://" + "b" * 56 + ".onion",
        ]
        app._url_text.delete("1.0", tk.END)
        app._url_text.insert("1.0", "\n".join(urls))
        cfg = app._collect_config()
        assert cfg is not None
        assert len(cfg.seed_urls) == 2

    def test_depth_applied_to_config(self, app: App) -> None:
        url = "http://" + "a" * 56 + ".onion"
        app._url_text.delete("1.0", tk.END)
        app._url_text.insert("1.0", url)
        app._depth_var.set("3")
        cfg = app._collect_config()
        assert cfg is not None
        assert cfg.crawler.max_depth == 3

    def test_output_dir_applied_to_config(self, app: App) -> None:
        url = "http://" + "a" * 56 + ".onion"
        app._url_text.delete("1.0", tk.END)
        app._url_text.insert("1.0", url)
        app._output_dir_var.set("/tmp/harvest")
        cfg = app._collect_config()
        assert cfg is not None
        assert cfg.storage.output_dir == "/tmp/harvest"

    def test_no_json_applied(self, app: App) -> None:
        url = "http://" + "a" * 56 + ".onion"
        app._url_text.delete("1.0", tk.END)
        app._url_text.insert("1.0", url)
        app._json_var.set(False)
        cfg = app._collect_config()
        assert cfg is not None
        assert cfg.storage.json_output is False


# ---------------------------------------------------------------------------
# UI state transitions
# ---------------------------------------------------------------------------

class TestUIState:
    @pytest.fixture
    def app(self):
        try:
            instance = App()
            instance.withdraw()
            yield instance
            instance.destroy()
        except tk.TclError:
            pytest.skip("Cannot create App without display")

    def test_set_running_disables_start(self, app: App) -> None:
        app._set_ui_running(True)
        assert str(app._start_btn["state"]) == tk.DISABLED

    def test_set_running_enables_stop(self, app: App) -> None:
        app._set_ui_running(True)
        assert str(app._stop_btn["state"]) == tk.NORMAL

    def test_set_not_running_enables_start(self, app: App) -> None:
        app._set_ui_running(True)
        app._set_ui_running(False)
        assert str(app._start_btn["state"]) == tk.NORMAL

    def test_set_not_running_disables_stop(self, app: App) -> None:
        app._set_ui_running(True)
        app._set_ui_running(False)
        assert str(app._stop_btn["state"]) == tk.DISABLED

    def test_clear_log(self, app: App) -> None:
        app._log_text.configure(state=tk.NORMAL)
        app._log_text.insert(tk.END, "test log entry\n")
        app._log_text.configure(state=tk.DISABLED)
        app._clear_log()
        content = app._log_text.get("1.0", tk.END).strip()
        assert content == ""

    def test_update_stats(self, app: App) -> None:
        mock_stats = MagicMock()
        mock_stats.pages_crawled    = 42
        mock_stats.pages_failed     = 3
        mock_stats.pages_skipped    = 1
        mock_stats.pages_deduplicated = 5
        mock_stats.elapsed          = 17.3
        app._update_stats(mock_stats)
        assert app._stat_crawled.get() == "42"
        assert app._stat_failed.get()  == "3"
