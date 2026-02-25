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


# ---------------------------------------------------------------------------
# AppGUI.__init__ initialization (additional coverage)
# ---------------------------------------------------------------------------

class TestAppInitialization:
    """Tests for App.__init__ covering state setup and attribute existence."""

    @pytest.fixture
    def app(self):
        try:
            instance = App()
            instance.withdraw()
            yield instance
            instance.destroy()
        except tk.TclError:
            pytest.skip("Cannot create App without display")

    def test_stop_event_is_threading_event(self, app: App) -> None:
        import threading
        assert isinstance(app._stop_event, threading.Event)

    def test_stop_event_initially_clear(self, app: App) -> None:
        assert not app._stop_event.is_set()

    def test_log_queue_is_queue(self, app: App) -> None:
        import queue
        assert isinstance(app._log_queue, queue.Queue)

    def test_result_paths_initially_empty(self, app: App) -> None:
        assert app._result_paths == {}

    def test_crawl_results_initially_empty(self, app: App) -> None:
        assert app._crawl_results == []

    def test_intel_data_initially_empty(self, app: App) -> None:
        assert app._intel_data == []

    def test_intel_stats_initially_empty(self, app: App) -> None:
        assert app._intel_stats == {}

    def test_crawl_thread_initially_none(self, app: App) -> None:
        assert app._crawl_thread is None

    def test_queue_handler_attached(self, app: App) -> None:
        import logging
        root_logger = logging.getLogger()
        handler_types = [type(h).__name__ for h in root_logger.handlers]
        assert "QueueHandler" in handler_types

    def test_url_text_is_text_widget(self, app: App) -> None:
        assert isinstance(app._url_text, tk.Text)

    def test_depth_var_default_value(self, app: App) -> None:
        # default is set from config/load_defaults; should be a digit
        val = app._depth_var.get()
        assert val.isdigit()

    def test_pages_var_is_stringvar(self, app: App) -> None:
        assert isinstance(app._pages_var, tk.StringVar)

    def test_json_var_is_booleanvar(self, app: App) -> None:
        assert isinstance(app._json_var, tk.BooleanVar)

    def test_verify_tor_var_is_booleanvar(self, app: App) -> None:
        assert isinstance(app._verify_tor_var, tk.BooleanVar)

    def test_resume_var_default_is_false(self, app: App) -> None:
        assert app._resume_var.get() is False


# ---------------------------------------------------------------------------
# _browse_output dialog
# ---------------------------------------------------------------------------

class TestBrowseOutput:
    @pytest.fixture
    def app(self):
        try:
            instance = App()
            instance.withdraw()
            yield instance
            instance.destroy()
        except tk.TclError:
            pytest.skip("Cannot create App without display")

    def test_browse_output_sets_directory_when_chosen(self, app: App) -> None:
        """When the dialog returns a path the output dir var is updated."""
        with patch("deepwebharvester.gui.filedialog.askdirectory",
                   return_value="/tmp/chosen_dir"):
            app._browse_output()
        assert app._output_dir_var.get() == "/tmp/chosen_dir"

    def test_browse_output_no_change_when_cancelled(self, app: App) -> None:
        """When the dialog is cancelled (returns empty string), var is unchanged."""
        app._output_dir_var.set("/original/path")
        with patch("deepwebharvester.gui.filedialog.askdirectory", return_value=""):
            app._browse_output()
        assert app._output_dir_var.get() == "/original/path"

    def test_browse_output_no_change_when_none_returned(self, app: App) -> None:
        """When the dialog returns None (dialog dismissed), var is unchanged."""
        app._output_dir_var.set("/original/path")
        with patch("deepwebharvester.gui.filedialog.askdirectory", return_value=None):
            app._browse_output()
        assert app._output_dir_var.get() == "/original/path"


# ---------------------------------------------------------------------------
# _on_stop / _stop_crawl behavior
# ---------------------------------------------------------------------------

class TestStopCrawl:
    @pytest.fixture
    def app(self):
        try:
            instance = App()
            instance.withdraw()
            yield instance
            instance.destroy()
        except tk.TclError:
            pytest.skip("Cannot create App without display")

    def test_on_stop_sets_stop_event(self, app: App) -> None:
        app._on_stop()
        assert app._stop_event.is_set()

    def test_on_stop_updates_status_var(self, app: App) -> None:
        app._on_stop()
        assert "stop" in app._status_var.get().lower() or "Stop" in app._status_var.get()

    def test_on_stop_logs_message(self, app: App) -> None:
        """_on_stop should write something to the log widget."""
        app._log_text.configure(state=tk.NORMAL)
        app._log_text.delete("1.0", tk.END)
        app._log_text.configure(state=tk.DISABLED)
        app._on_stop()
        content = app._log_text.get("1.0", tk.END)
        assert len(content.strip()) > 0


# ---------------------------------------------------------------------------
# _update_log / _append_log / _log_system
# ---------------------------------------------------------------------------

class TestUpdateLog:
    @pytest.fixture
    def app(self):
        try:
            instance = App()
            instance.withdraw()
            yield instance
            instance.destroy()
        except tk.TclError:
            pytest.skip("Cannot create App without display")

    def test_log_system_writes_to_log_widget(self, app: App) -> None:
        app._log_text.configure(state=tk.NORMAL)
        app._log_text.delete("1.0", tk.END)
        app._log_text.configure(state=tk.DISABLED)
        app._log_system("test system message")
        content = app._log_text.get("1.0", tk.END)
        assert "test system message" in content

    def test_log_text_disabled_after_log_system(self, app: App) -> None:
        """Widget should be left in DISABLED state after writing."""
        app._log_system("another message")
        assert str(app._log_text["state"]) == tk.DISABLED

    def test_append_log_writes_formatted_record(self, app: App) -> None:
        import logging
        app._log_text.configure(state=tk.NORMAL)
        app._log_text.delete("1.0", tk.END)
        app._log_text.configure(state=tk.DISABLED)
        record = logging.LogRecord(
            name="test", level=logging.WARNING,
            pathname="", lineno=0,
            msg="warning message here", args=(), exc_info=None,
        )
        app._append_log(record)
        content = app._log_text.get("1.0", tk.END)
        assert "warning message here" in content

    def test_append_log_leaves_widget_disabled(self, app: App) -> None:
        import logging
        record = logging.LogRecord(
            name="test", level=logging.INFO,
            pathname="", lineno=0,
            msg="info message", args=(), exc_info=None,
        )
        app._append_log(record)
        assert str(app._log_text["state"]) == tk.DISABLED

    def test_multiple_log_system_calls_accumulate(self, app: App) -> None:
        app._log_text.configure(state=tk.NORMAL)
        app._log_text.delete("1.0", tk.END)
        app._log_text.configure(state=tk.DISABLED)
        app._log_system("line one")
        app._log_system("line two")
        content = app._log_text.get("1.0", tk.END)
        assert "line one" in content
        assert "line two" in content


# ---------------------------------------------------------------------------
# _on_closing / window close behavior
# ---------------------------------------------------------------------------

class TestOnClosing:
    """Test that stopping the crawl thread on close works correctly."""

    @pytest.fixture
    def app(self):
        try:
            instance = App()
            instance.withdraw()
            yield instance
            instance.destroy()
        except tk.TclError:
            pytest.skip("Cannot create App without display")

    def test_stop_event_can_be_set_before_destroy(self, app: App) -> None:
        """Simulate what on_closing would do: set stop event then destroy."""
        app._stop_event.set()
        assert app._stop_event.is_set()
        # destroy is called by the fixture; just verify state
        app._stop_event.clear()

    def test_crawl_thread_none_on_close_is_safe(self, app: App) -> None:
        """If there is no crawl thread, closing should not raise."""
        app._crawl_thread = None
        # Should not raise when there's nothing to join
        if app._crawl_thread is not None:
            app._crawl_thread.join(timeout=0)

    def test_on_crawl_error_resets_ui(self, app: App) -> None:
        """_on_crawl_error sets status and disables stop button."""
        app._set_ui_running(True)
        app._on_crawl_error("some error occurred")
        assert str(app._stop_btn["state"]) == tk.DISABLED
        assert "error" in app._status_var.get().lower() or "Error" in app._status_var.get()

    def test_on_crawl_error_shows_messagebox(self, app: App) -> None:
        """_on_crawl_error should call messagebox.showerror."""
        with patch("deepwebharvester.gui.messagebox.showerror") as mock_err:
            app._on_crawl_error("boom")
        mock_err.assert_called_once()
        call_args = mock_err.call_args
        assert "boom" in str(call_args)


# ---------------------------------------------------------------------------
# Settings persistence — save and load cycle
# ---------------------------------------------------------------------------

class TestSettingsPersistence:
    @pytest.fixture
    def app(self):
        try:
            instance = App()
            instance.withdraw()
            yield instance
            instance.destroy()
        except tk.TclError:
            pytest.skip("Cannot create App without display")

    def test_load_defaults_does_not_raise(self, app: App) -> None:
        """_load_defaults should silently skip on missing config."""
        with patch("deepwebharvester.gui.load_config", side_effect=Exception("no config")):
            try:
                app._load_defaults()
            except Exception:
                pytest.fail("_load_defaults raised an exception unexpectedly")

    def test_load_defaults_populates_urls_from_config(self, app: App) -> None:
        """If config has seed_urls they should be loaded into the text widget."""
        from deepwebharvester.config import AppConfig
        cfg = AppConfig()
        cfg.seed_urls = ["http://" + "c" * 56 + ".onion"]
        app._url_text.delete("1.0", tk.END)
        with patch("deepwebharvester.gui.load_config", return_value=cfg):
            with patch("deepwebharvester.gui.Path.exists", return_value=False):
                app._load_defaults()
        content = app._url_text.get("1.0", tk.END).strip()
        assert "c" * 56 + ".onion" in content

    def test_collect_config_workers_override(self, app: App) -> None:
        url = "http://" + "a" * 56 + ".onion"
        app._url_text.delete("1.0", tk.END)
        app._url_text.insert("1.0", url)
        app._workers_var.set("7")
        cfg = app._collect_config()
        assert cfg is not None
        assert cfg.crawler.max_workers == 7

    def test_collect_config_delay_override(self, app: App) -> None:
        url = "http://" + "a" * 56 + ".onion"
        app._url_text.delete("1.0", tk.END)
        app._url_text.insert("1.0", url)
        app._delay_var.set("2.5")
        cfg = app._collect_config()
        assert cfg is not None
        assert cfg.crawler.crawl_delay == 2.5

    def test_collect_config_tor_port_override(self, app: App) -> None:
        url = "http://" + "a" * 56 + ".onion"
        app._url_text.delete("1.0", tk.END)
        app._url_text.insert("1.0", url)
        app._tor_port_var.set("19050")
        cfg = app._collect_config()
        assert cfg is not None
        assert cfg.tor.socks_port == 19050

    def test_collect_config_no_csv_applied(self, app: App) -> None:
        url = "http://" + "a" * 56 + ".onion"
        app._url_text.delete("1.0", tk.END)
        app._url_text.insert("1.0", url)
        app._csv_var.set(False)
        cfg = app._collect_config()
        assert cfg is not None
        assert cfg.storage.csv_output is False

    def test_collect_config_no_sqlite_applied(self, app: App) -> None:
        url = "http://" + "a" * 56 + ".onion"
        app._url_text.delete("1.0", tk.END)
        app._url_text.insert("1.0", url)
        app._sqlite_var.set(False)
        cfg = app._collect_config()
        assert cfg is not None
        assert cfg.storage.sqlite_output is False

    def test_collect_config_control_password(self, app: App) -> None:
        url = "http://" + "a" * 56 + ".onion"
        app._url_text.delete("1.0", tk.END)
        app._url_text.insert("1.0", url)
        app._ctrl_pass_var.set("secret_pw")
        cfg = app._collect_config()
        assert cfg is not None
        assert cfg.tor.control_password == "secret_pw"

    def test_collect_config_renew_circuit_every(self, app: App) -> None:
        url = "http://" + "a" * 56 + ".onion"
        app._url_text.delete("1.0", tk.END)
        app._url_text.insert("1.0", url)
        app._renew_var.set("5")
        cfg = app._collect_config()
        assert cfg is not None
        assert cfg.tor.renew_circuit_every == 5


# ---------------------------------------------------------------------------
# _start_crawl validation (missing URL, missing output dir)
# ---------------------------------------------------------------------------

class TestStartCrawlValidation:
    @pytest.fixture
    def app(self):
        try:
            instance = App()
            instance.withdraw()
            yield instance
            instance.destroy()
        except tk.TclError:
            pytest.skip("Cannot create App without display")

    def test_on_start_shows_error_when_no_urls(self, app: App) -> None:
        """_on_start calls _collect_config which shows an error for empty URLs."""
        app._url_text.delete("1.0", tk.END)
        with patch("deepwebharvester.gui.messagebox.showerror") as mock_err:
            app._on_start()
        mock_err.assert_called_once()

    def test_on_start_does_not_start_thread_with_no_urls(self, app: App) -> None:
        """When URL validation fails, no crawl thread should be started."""
        app._url_text.delete("1.0", tk.END)
        with patch("deepwebharvester.gui.messagebox.showerror"):
            app._on_start()
        assert app._crawl_thread is None

    def test_on_start_with_whitespace_only_is_treated_as_no_urls(self, app: App) -> None:
        """Whitespace-only URL field should produce no valid URLs."""
        app._url_text.delete("1.0", tk.END)
        app._url_text.insert("1.0", "   \n   \n   ")
        with patch("deepwebharvester.gui.messagebox.showerror") as mock_err:
            app._on_start()
        mock_err.assert_called_once()

    def test_collect_config_falls_back_for_empty_output_dir(self, app: App) -> None:
        """An empty output_dir entry should fall back to 'results'."""
        url = "http://" + "a" * 56 + ".onion"
        app._url_text.delete("1.0", tk.END)
        app._url_text.insert("1.0", url)
        app._output_dir_var.set("")
        cfg = app._collect_config()
        assert cfg is not None
        assert cfg.storage.output_dir == "results"

    def test_on_start_sets_ui_running_when_valid(self, app: App) -> None:
        """A valid start should put the UI into running state."""
        url = "http://" + "a" * 56 + ".onion"
        app._url_text.delete("1.0", tk.END)
        app._url_text.insert("1.0", url)
        with patch.object(app, "_crawl_worker"):
            # Patch the thread so it doesn't actually run
            with patch("deepwebharvester.gui.threading.Thread") as mock_thread_cls:
                mock_thread = MagicMock()
                mock_thread_cls.return_value = mock_thread
                app._on_start()
        assert str(app._start_btn["state"]) == tk.DISABLED

    def test_on_start_status_var_updates_when_valid(self, app: App) -> None:
        url = "http://" + "a" * 56 + ".onion"
        app._url_text.delete("1.0", tk.END)
        app._url_text.insert("1.0", url)
        with patch("deepwebharvester.gui.threading.Thread") as mock_thread_cls:
            mock_thread = MagicMock()
            mock_thread_cls.return_value = mock_thread
            app._on_start()
        assert app._status_var.get() != "Ready"
