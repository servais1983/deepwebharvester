"""
DeepWebHarvester — Desktop Graphical User Interface.

A fully-featured Tkinter application providing:
  - Settings panel (seed URLs, crawl parameters, Tor config, output options)
  - Real-time colour-coded log stream (non-blocking, thread-safe)
  - Live progress bar and per-metric counters
  - Start / Stop crawl controls
  - Results summary with quick-open file buttons

Launch with:
    deepwebharvester-gui
or:
    python -m deepwebharvester.gui
"""
from __future__ import annotations

import logging
import os
import queue
import subprocess
import sys
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, scrolledtext, ttk
from typing import Optional

from . import __version__
from .config import AppConfig, load_config
from .crawler import CrawlResult, Crawler
from .extractor import PageExtractor
from .intelligence import IntelligenceExtractor
from .report import ReportGenerator
from .storage import StorageManager
from .tor_manager import TorManager

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

APP_TITLE = f"DeepWebHarvester  v{__version__}"

_PALETTE = {
    "bg":         "#1a1d23",
    "panel":      "#22262f",
    "border":     "#2e3440",
    "accent":     "#4c9be8",
    "accent_dim": "#2a5a9a",
    "success":    "#57cc8a",
    "warning":    "#e8a74c",
    "error":      "#e85c5c",
    "fg":         "#d8dde6",
    "fg_dim":     "#8a91a8",
    "entry_bg":   "#181b21",
    "btn_active": "#3a7fd5",
}

_LOG_COLORS = {
    "DEBUG":   _PALETTE["fg_dim"],
    "INFO":    _PALETTE["fg"],
    "WARNING": _PALETTE["warning"],
    "ERROR":   _PALETTE["error"],
    "CRITICAL":_PALETTE["error"],
    "SYSTEM":  _PALETTE["success"],
}

_FONT_MONO  = ("Courier New", 10)
_FONT_LABEL = ("Segoe UI", 10)
_FONT_BOLD  = ("Segoe UI", 10, "bold")
_FONT_TITLE = ("Segoe UI", 13, "bold")
_FONT_SMALL = ("Segoe UI", 9)


# ---------------------------------------------------------------------------
# Thread-safe logging handler
# ---------------------------------------------------------------------------

class QueueHandler(logging.Handler):
    """Emit log records into a thread-safe queue for UI consumption."""

    def __init__(self, log_queue: queue.Queue) -> None:
        super().__init__()
        self._q = log_queue

    def emit(self, record: logging.LogRecord) -> None:
        self._q.put(record)


# ---------------------------------------------------------------------------
# Labelled entry helper
# ---------------------------------------------------------------------------

def _make_entry(
    parent: tk.Widget,
    label: str,
    default: str = "",
    show: str = "",
    tooltip: str = "",
    width: int = 38,
) -> tk.StringVar:
    row = tk.Frame(parent, bg=_PALETTE["panel"])
    row.pack(fill=tk.X, padx=12, pady=3)
    lbl = tk.Label(
        row, text=label, width=22, anchor="w",
        bg=_PALETTE["panel"], fg=_PALETTE["fg_dim"],
        font=_FONT_LABEL,
    )
    lbl.pack(side=tk.LEFT)
    var = tk.StringVar(value=default)
    ent = tk.Entry(
        row, textvariable=var, show=show, width=width,
        bg=_PALETTE["entry_bg"], fg=_PALETTE["fg"],
        insertbackground=_PALETTE["fg"],
        relief=tk.FLAT, font=_FONT_MONO,
        highlightthickness=1,
        highlightbackground=_PALETTE["border"],
        highlightcolor=_PALETTE["accent"],
    )
    ent.pack(side=tk.LEFT, fill=tk.X, expand=True)
    if tooltip:
        _Tooltip(ent, tooltip)
    return var


def _make_check(
    parent: tk.Widget, label: str, default: bool = True
) -> tk.BooleanVar:
    var = tk.BooleanVar(value=default)
    row = tk.Frame(parent, bg=_PALETTE["panel"])
    row.pack(fill=tk.X, padx=12, pady=2)
    tk.Checkbutton(
        row, text=label, variable=var,
        bg=_PALETTE["panel"], fg=_PALETTE["fg"],
        activebackground=_PALETTE["panel"],
        activeforeground=_PALETTE["accent"],
        selectcolor=_PALETTE["entry_bg"],
        font=_FONT_LABEL, anchor="w",
    ).pack(side=tk.LEFT)
    return var


class _Tooltip:
    """Simple hover tooltip."""

    def __init__(self, widget: tk.Widget, text: str) -> None:
        self._widget = widget
        self._text = text
        self._tip: Optional[tk.Toplevel] = None
        widget.bind("<Enter>", self._show)
        widget.bind("<Leave>", self._hide)

    def _show(self, _event=None) -> None:
        x, y, *_ = self._widget.bbox("insert")
        x += self._widget.winfo_rootx() + 25
        y += self._widget.winfo_rooty() + 20
        self._tip = tw = tk.Toplevel(self._widget)
        tw.wm_overrideredirect(True)
        tw.wm_geometry(f"+{x}+{y}")
        tk.Label(
            tw, text=self._text,
            bg="#2e3440", fg=_PALETTE["fg"],
            font=_FONT_SMALL, relief=tk.SOLID, borderwidth=1, padx=6, pady=3,
        ).pack()

    def _hide(self, _event=None) -> None:
        if self._tip:
            self._tip.destroy()
            self._tip = None


# ---------------------------------------------------------------------------
# Section header
# ---------------------------------------------------------------------------

def _section(parent: tk.Widget, title: str) -> tk.LabelFrame:
    frame = tk.LabelFrame(
        parent, text=f"  {title}  ",
        bg=_PALETTE["panel"], fg=_PALETTE["accent"],
        font=_FONT_BOLD, bd=1,
        relief=tk.GROOVE,
        highlightbackground=_PALETTE["border"],
        labelanchor="nw",
    )
    frame.pack(fill=tk.X, padx=10, pady=(8, 2))
    return frame


# ---------------------------------------------------------------------------
# Main application window
# ---------------------------------------------------------------------------

class App(tk.Tk):
    """DeepWebHarvester main window."""

    def __init__(self) -> None:
        super().__init__()

        self.title(APP_TITLE)
        self.configure(bg=_PALETTE["bg"])
        self.minsize(1050, 740)
        self._center_window(1150, 800)

        # State
        self._crawl_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._log_queue: queue.Queue = queue.Queue()
        self._result_paths: dict = {}
        self._crawl_results: list[CrawlResult] = []
        self._intel_stats: dict = {}

        # Logging
        self._setup_logging()

        # Layout
        self._build_menu()
        self._build_layout()

        # Load defaults from config file / env
        self._load_defaults()

        # Poll log queue
        self.after(100, self._poll_logs)

    # ── Window helpers ────────────────────────────────────────────────────────

    def _center_window(self, w: int, h: int) -> None:
        sw = self.winfo_screenwidth()
        sh = self.winfo_screenheight()
        x = (sw - w) // 2
        y = (sh - h) // 2
        self.geometry(f"{w}x{h}+{x}+{y}")

    # ── Logging ───────────────────────────────────────────────────────────────

    def _setup_logging(self) -> None:
        self._queue_handler = QueueHandler(self._log_queue)
        self._queue_handler.setFormatter(
            logging.Formatter("%(asctime)s [%(levelname)-8s]  %(message)s",
                              datefmt="%H:%M:%S")
        )
        root_logger = logging.getLogger()
        root_logger.setLevel(logging.DEBUG)
        # Remove any existing stream handlers to avoid double output
        root_logger.handlers = [h for h in root_logger.handlers
                                 if not isinstance(h, logging.StreamHandler)]
        root_logger.addHandler(self._queue_handler)

    def _poll_logs(self) -> None:
        try:
            while True:
                record = self._log_queue.get_nowait()
                self._append_log(record)
        except queue.Empty:
            pass
        self.after(100, self._poll_logs)

    def _append_log(self, record: logging.LogRecord) -> None:
        level = record.levelname
        color = _LOG_COLORS.get(level, _PALETTE["fg"])
        msg = self._queue_handler.format(record) + "\n"
        self._log_text.configure(state=tk.NORMAL)
        self._log_text.insert(tk.END, msg, level)
        self._log_text.tag_configure(level, foreground=color)
        self._log_text.see(tk.END)
        self._log_text.configure(state=tk.DISABLED)

    def _log_system(self, msg: str) -> None:
        self._log_text.configure(state=tk.NORMAL)
        self._log_text.insert(tk.END, msg + "\n", "SYSTEM")
        self._log_text.tag_configure("SYSTEM", foreground=_LOG_COLORS["SYSTEM"])
        self._log_text.see(tk.END)
        self._log_text.configure(state=tk.DISABLED)

    # ── Menu ──────────────────────────────────────────────────────────────────

    def _build_menu(self) -> None:
        menubar = tk.Menu(self, bg=_PALETTE["panel"], fg=_PALETTE["fg"],
                          activebackground=_PALETTE["accent"],
                          activeforeground="#ffffff")
        self.config(menu=menubar)

        file_menu = tk.Menu(menubar, tearoff=0,
                            bg=_PALETTE["panel"], fg=_PALETTE["fg"],
                            activebackground=_PALETTE["accent"],
                            activeforeground="#ffffff")
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Open results folder",
                              command=self._open_results_dir)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.destroy)

        help_menu = tk.Menu(menubar, tearoff=0,
                            bg=_PALETTE["panel"], fg=_PALETTE["fg"],
                            activebackground=_PALETTE["accent"],
                            activeforeground="#ffffff")
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About", command=self._show_about)

    # ── Main layout ───────────────────────────────────────────────────────────

    def _build_layout(self) -> None:
        # Title bar
        title_bar = tk.Frame(self, bg=_PALETTE["bg"], pady=6)
        title_bar.pack(fill=tk.X)
        tk.Label(
            title_bar, text="DEEPWEB HARVESTER",
            bg=_PALETTE["bg"], fg=_PALETTE["accent"],
            font=("Courier New", 16, "bold"),
        ).pack(side=tk.LEFT, padx=16)
        tk.Label(
            title_bar, text=f"v{__version__}  |  OSINT Intelligence Platform",
            bg=_PALETTE["bg"], fg=_PALETTE["fg_dim"],
            font=_FONT_SMALL,
        ).pack(side=tk.LEFT, padx=4, pady=6)

        separator = tk.Frame(self, bg=_PALETTE["border"], height=1)
        separator.pack(fill=tk.X)

        # Main pane: left (settings) + right (logs)
        main_pane = tk.PanedWindow(
            self, orient=tk.HORIZONTAL,
            bg=_PALETTE["bg"], sashwidth=4,
            sashrelief=tk.FLAT, sashpad=2,
        )
        main_pane.pack(fill=tk.BOTH, expand=True, padx=0, pady=0)

        # Left panel
        left = tk.Frame(main_pane, bg=_PALETTE["bg"], width=420)
        left.pack_propagate(False)
        main_pane.add(left, minsize=380)

        # Right panel
        right = tk.Frame(main_pane, bg=_PALETTE["bg"])
        main_pane.add(right, minsize=400)

        self._build_settings(left)
        self._build_log_panel(right)
        self._build_bottom_bar()

    # ── Settings panel ────────────────────────────────────────────────────────

    def _build_settings(self, parent: tk.Widget) -> None:
        canvas = tk.Canvas(parent, bg=_PALETTE["bg"], highlightthickness=0)
        scrollbar = ttk.Scrollbar(parent, orient=tk.VERTICAL,
                                  command=canvas.yview)
        scrollable = tk.Frame(canvas, bg=_PALETTE["bg"])
        scrollable.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all")),
        )
        canvas.create_window((0, 0), window=scrollable, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        canvas.bind_all("<MouseWheel>",
                        lambda e: canvas.yview_scroll(-1 * (e.delta // 120), "units"))

        # -- Seed URLs ---------------------------------------------------------
        sec = _section(scrollable, "Seed URLs")
        url_frame = tk.Frame(sec, bg=_PALETTE["panel"])
        url_frame.pack(fill=tk.BOTH, padx=8, pady=4)

        self._url_text = tk.Text(
            url_frame, height=4, width=38,
            bg=_PALETTE["entry_bg"], fg=_PALETTE["fg"],
            insertbackground=_PALETTE["fg"],
            relief=tk.FLAT, font=_FONT_MONO,
            highlightthickness=1,
            highlightbackground=_PALETTE["border"],
        )
        self._url_text.pack(fill=tk.X, padx=4, pady=4)
        tk.Label(
            url_frame,
            text="One .onion URL per line  (Tor v3: 56 base32 chars + .onion)",
            bg=_PALETTE["panel"], fg=_PALETTE["fg_dim"], font=_FONT_SMALL,
        ).pack(anchor="w", padx=4)

        # -- Crawl settings ----------------------------------------------------
        sec2 = _section(scrollable, "Crawl Settings")
        self._depth_var   = _make_entry(sec2, "Max depth",    "2",
                                        tooltip="0 = seed page only")
        self._pages_var   = _make_entry(sec2, "Max pages / site", "20")
        self._workers_var = _make_entry(sec2, "Concurrent workers", "3",
                                        tooltip="Parallel site threads")
        self._delay_var   = _make_entry(sec2, "Request delay (s)",  "7.0",
                                        tooltip="Seconds between requests")
        self._timeout_var = _make_entry(sec2, "Request timeout (s)", "30")
        self._retries_var = _make_entry(sec2, "Retry attempts",  "3")

        # -- Tor settings ------------------------------------------------------
        sec3 = _section(scrollable, "Tor Settings")
        self._tor_host_var    = _make_entry(sec3, "SOCKS host",     "127.0.0.1")
        self._tor_port_var    = _make_entry(sec3, "SOCKS port",     "9050")
        self._ctrl_host_var   = _make_entry(sec3, "Control host",   "127.0.0.1")
        self._ctrl_port_var   = _make_entry(sec3, "Control port",   "9051")
        self._ctrl_pass_var   = _make_entry(sec3, "Control password", "",
                                            show="*",
                                            tooltip="Matches TOR_CONTROL_PASSWORD env var")
        self._renew_var       = _make_entry(sec3, "Renew circuit every", "10",
                                            tooltip="Pages between circuit renewals")
        self._verify_tor_var  = _make_check(sec3, "Verify Tor before crawling", True)

        # -- Output settings ---------------------------------------------------
        sec4 = _section(scrollable, "Output")
        self._output_dir_var  = _make_entry(sec4, "Output directory", "results")
        btn_row = tk.Frame(sec4, bg=_PALETTE["panel"])
        btn_row.pack(fill=tk.X, padx=12, pady=(0, 4))
        tk.Button(
            btn_row, text="Browse...",
            bg=_PALETTE["border"], fg=_PALETTE["fg"],
            relief=tk.FLAT, font=_FONT_SMALL, padx=8,
            command=self._browse_output,
            activebackground=_PALETTE["accent_dim"],
            activeforeground="#ffffff",
            cursor="hand2",
        ).pack(side=tk.LEFT)

        self._json_var   = _make_check(sec4, "Save JSON",   True)
        self._csv_var    = _make_check(sec4, "Save CSV",    True)
        self._sqlite_var = _make_check(sec4, "Save SQLite (required for resume)", True)
        self._resume_var = _make_check(sec4, "Resume previous session", False)

        # -- Log level ---------------------------------------------------------
        sec5 = _section(scrollable, "Logging")
        log_row = tk.Frame(sec5, bg=_PALETTE["panel"])
        log_row.pack(fill=tk.X, padx=12, pady=4)
        tk.Label(log_row, text="Log level", width=22, anchor="w",
                 bg=_PALETTE["panel"], fg=_PALETTE["fg_dim"],
                 font=_FONT_LABEL).pack(side=tk.LEFT)
        self._log_level_var = tk.StringVar(value="INFO")
        combo = ttk.Combobox(
            log_row, textvariable=self._log_level_var,
            values=["DEBUG", "INFO", "WARNING", "ERROR"],
            state="readonly", width=12, font=_FONT_LABEL,
        )
        combo.pack(side=tk.LEFT)

    # ── Log panel (right side) ────────────────────────────────────────────────

    def _build_log_panel(self, parent: tk.Widget) -> None:
        # Tabs: Logs / Results
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TNotebook",          background=_PALETTE["bg"])
        style.configure("TNotebook.Tab",      background=_PALETTE["panel"],
                        foreground=_PALETTE["fg_dim"], padding=[12, 4])
        style.map("TNotebook.Tab",
                  background=[("selected", _PALETTE["border"])],
                  foreground=[("selected", _PALETTE["accent"])])

        self._notebook = ttk.Notebook(parent)
        self._notebook.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)

        # -- Log tab -----------------------------------------------------------
        log_tab = tk.Frame(self._notebook, bg=_PALETTE["bg"])
        self._notebook.add(log_tab, text="  Live Log  ")

        # Stats bar inside log tab
        stats_bar = tk.Frame(log_tab, bg=_PALETTE["border"], pady=4)
        stats_bar.pack(fill=tk.X)

        def _stat(label: str) -> tk.StringVar:
            tk.Label(stats_bar, text=label, bg=_PALETTE["border"],
                     fg=_PALETTE["fg_dim"], font=_FONT_SMALL).pack(
                side=tk.LEFT, padx=(12, 2))
            var = tk.StringVar(value="0")
            tk.Label(stats_bar, textvariable=var, bg=_PALETTE["border"],
                     fg=_PALETTE["accent"], font=_FONT_BOLD, width=5).pack(
                side=tk.LEFT, padx=(0, 8))
            return var

        self._stat_crawled  = _stat("Crawled")
        self._stat_failed   = _stat("Failed")
        self._stat_skipped  = _stat("Skipped")
        self._stat_dedup    = _stat("Deduped")
        self._stat_elapsed  = _stat("Elapsed (s)")

        # Progress bar
        self._progress = ttk.Progressbar(
            log_tab, mode="indeterminate", length=200,
        )
        self._progress.pack(fill=tk.X, padx=6, pady=2)

        # Log text widget
        self._log_text = scrolledtext.ScrolledText(
            log_tab,
            bg=_PALETTE["entry_bg"], fg=_PALETTE["fg"],
            font=_FONT_MONO, state=tk.DISABLED,
            relief=tk.FLAT, wrap=tk.WORD,
            insertbackground=_PALETTE["fg"],
        )
        self._log_text.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)

        # -- Results tab -------------------------------------------------------
        res_tab = tk.Frame(self._notebook, bg=_PALETTE["panel"])
        self._notebook.add(res_tab, text="  Results  ")
        self._results_frame = res_tab
        self._build_results_placeholder(res_tab)

    def _build_results_placeholder(self, parent: tk.Widget) -> None:
        tk.Label(
            parent,
            text="No crawl completed yet.\nStart a crawl to see results here.",
            bg=_PALETTE["panel"], fg=_PALETTE["fg_dim"],
            font=_FONT_LABEL, justify=tk.CENTER,
        ).pack(expand=True)

    def _build_results_panel(self) -> None:
        for widget in self._results_frame.winfo_children():
            widget.destroy()

        # Scrollable container
        canvas = tk.Canvas(self._results_frame, bg=_PALETTE["panel"],
                           highlightthickness=0)
        scrollbar = ttk.Scrollbar(self._results_frame, orient=tk.VERTICAL,
                                  command=canvas.yview)
        inner = tk.Frame(canvas, bg=_PALETTE["panel"])
        inner.bind("<Configure>",
                   lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=inner, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        tk.Label(
            inner, text="Crawl Summary",
            bg=_PALETTE["panel"], fg=_PALETTE["accent"],
            font=_FONT_TITLE,
        ).pack(pady=(20, 10))

        # Crawl stats grid
        grid = tk.Frame(inner, bg=_PALETTE["panel"])
        grid.pack(padx=20, pady=4)

        crawl_stats = [
            ("Pages crawled",   self._stat_crawled.get()),
            ("Failed",          self._stat_failed.get()),
            ("Skipped",         self._stat_skipped.get()),
            ("Deduplicated",    self._stat_dedup.get()),
            ("Elapsed (s)",     self._stat_elapsed.get()),
        ]
        for i, (label, val) in enumerate(crawl_stats):
            tk.Label(grid, text=label, bg=_PALETTE["panel"],
                     fg=_PALETTE["fg_dim"], font=_FONT_LABEL, width=18,
                     anchor="w").grid(row=i, column=0, sticky="w", pady=2)
            tk.Label(grid, text=val, bg=_PALETTE["panel"],
                     fg=_PALETTE["fg"], font=_FONT_BOLD).grid(
                row=i, column=1, sticky="w", padx=10)

        # Intelligence summary
        if self._intel_stats:
            tk.Frame(inner, bg=_PALETTE["border"],
                     height=1).pack(fill=tk.X, padx=20, pady=12)
            tk.Label(
                inner, text="Intelligence Summary",
                bg=_PALETTE["panel"], fg=_PALETTE["accent"],
                font=_FONT_BOLD,
            ).pack(anchor="w", padx=20, pady=(0, 6))

            intel_grid = tk.Frame(inner, bg=_PALETTE["panel"])
            intel_grid.pack(padx=20, pady=4)

            high_risk = self._intel_stats.get("high_risk", 0)
            high_color = _PALETTE["error"] if high_risk > 0 else _PALETTE["success"]
            intel_rows = [
                ("Total IOCs",       str(self._intel_stats.get("total_iocs", 0)),
                 _PALETTE["fg"]),
                ("High / Critical",  str(high_risk), high_color),
                ("CVEs found",       str(self._intel_stats.get("cves", 0)),
                 _PALETTE["warning"]),
                ("BTC addresses",    str(self._intel_stats.get("btc", 0)),
                 _PALETTE["fg"]),
                ("Emails",           str(self._intel_stats.get("emails", 0)),
                 _PALETTE["fg"]),
            ]
            for i, (label, val, color) in enumerate(intel_rows):
                tk.Label(intel_grid, text=label, bg=_PALETTE["panel"],
                         fg=_PALETTE["fg_dim"], font=_FONT_LABEL, width=18,
                         anchor="w").grid(row=i, column=0, sticky="w", pady=2)
                tk.Label(intel_grid, text=val, bg=_PALETTE["panel"],
                         fg=color, font=_FONT_BOLD).grid(
                    row=i, column=1, sticky="w", padx=10)

            cats = self._intel_stats.get("top_categories", [])
            if cats:
                tk.Label(intel_grid, text="Top categories",
                         bg=_PALETTE["panel"], fg=_PALETTE["fg_dim"],
                         font=_FONT_LABEL, width=18,
                         anchor="w").grid(row=len(intel_rows), column=0,
                                          sticky="w", pady=2)
                tk.Label(intel_grid, text=", ".join(cats),
                         bg=_PALETTE["panel"], fg=_PALETTE["fg"],
                         font=_FONT_LABEL).grid(
                    row=len(intel_rows), column=1, sticky="w", padx=10)

        tk.Frame(inner, bg=_PALETTE["border"],
                 height=1).pack(fill=tk.X, padx=20, pady=12)

        tk.Label(
            inner, text="Output Files",
            bg=_PALETTE["panel"], fg=_PALETTE["fg_dim"],
            font=_FONT_BOLD,
        ).pack(anchor="w", padx=20)

        for fmt, path in self._result_paths.items():
            row = tk.Frame(inner, bg=_PALETTE["panel"])
            row.pack(fill=tk.X, padx=20, pady=3)
            fmt_color = _PALETTE["warning"] if fmt == "html" else _PALETTE["accent"]
            tk.Label(
                row, text=fmt.upper(), width=8,
                bg=_PALETTE["panel"], fg=fmt_color,
                font=_FONT_BOLD, anchor="w",
            ).pack(side=tk.LEFT)
            tk.Label(
                row, text=str(path),
                bg=_PALETTE["panel"], fg=_PALETTE["fg"],
                font=_FONT_SMALL, anchor="w",
            ).pack(side=tk.LEFT, fill=tk.X, expand=True)
            tk.Button(
                row, text="Open",
                bg=_PALETTE["border"], fg=_PALETTE["fg"],
                font=_FONT_SMALL, relief=tk.FLAT, padx=8,
                command=lambda p=path: self._open_file(p),
                activebackground=_PALETTE["accent_dim"],
                activeforeground="#ffffff", cursor="hand2",
            ).pack(side=tk.RIGHT)

    # ── Bottom control bar ────────────────────────────────────────────────────

    def _build_bottom_bar(self) -> None:
        bar = tk.Frame(self, bg=_PALETTE["border"], pady=8)
        bar.pack(fill=tk.X, side=tk.BOTTOM)

        self._status_var = tk.StringVar(value="Ready")
        tk.Label(
            bar, textvariable=self._status_var,
            bg=_PALETTE["border"], fg=_PALETTE["fg_dim"],
            font=_FONT_SMALL,
        ).pack(side=tk.LEFT, padx=16)

        # Buttons (right-aligned)
        btn_defaults = dict(
            relief=tk.FLAT, font=_FONT_BOLD, padx=18, pady=6,
            cursor="hand2",
        )

        self._stop_btn = tk.Button(
            bar, text="STOP", state=tk.DISABLED,
            bg=_PALETTE["error"], fg="#ffffff",
            activebackground="#c04040", activeforeground="#ffffff",
            command=self._on_stop,
            **btn_defaults,
        )
        self._stop_btn.pack(side=tk.RIGHT, padx=6)

        self._start_btn = tk.Button(
            bar, text="START CRAWL",
            bg=_PALETTE["accent"], fg="#ffffff",
            activebackground=_PALETTE["btn_active"], activeforeground="#ffffff",
            command=self._on_start,
            **btn_defaults,
        )
        self._start_btn.pack(side=tk.RIGHT, padx=6)

        tk.Button(
            bar, text="Clear log",
            bg=_PALETTE["panel"], fg=_PALETTE["fg_dim"],
            activebackground=_PALETTE["border"], activeforeground=_PALETTE["fg"],
            command=self._clear_log,
            **btn_defaults,
        ).pack(side=tk.RIGHT, padx=6)

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _load_defaults(self) -> None:
        try:
            cfg = load_config("config.yaml" if Path("config.yaml").exists() else None)
            if cfg.seed_urls:
                self._url_text.insert("1.0", "\n".join(cfg.seed_urls))
            if cfg.tor.control_password:
                self._ctrl_pass_var.set(cfg.tor.control_password)
            self._depth_var.set(str(cfg.crawler.max_depth))
            self._pages_var.set(str(cfg.crawler.max_pages))
            self._delay_var.set(str(cfg.crawler.crawl_delay))
            self._workers_var.set(str(cfg.crawler.max_workers))
            self._output_dir_var.set(cfg.storage.output_dir)
            self._json_var.set(cfg.storage.json_output)
            self._csv_var.set(cfg.storage.csv_output)
            self._sqlite_var.set(cfg.storage.sqlite_output)
            self._log_level_var.set(cfg.log_level)
        except Exception:
            pass

    def _collect_config(self) -> Optional[AppConfig]:
        urls = [
            u.strip()
            for u in self._url_text.get("1.0", tk.END).splitlines()
            if u.strip()
        ]
        if not urls:
            messagebox.showerror("No URLs", "Please enter at least one .onion URL.")
            return None

        cfg = AppConfig()
        cfg.seed_urls = urls
        cfg.log_level = self._log_level_var.get()
        cfg.tor.socks_host     = self._tor_host_var.get()
        cfg.tor.socks_port     = int(self._tor_port_var.get() or 9050)
        cfg.tor.control_host   = self._ctrl_host_var.get()
        cfg.tor.control_port   = int(self._ctrl_port_var.get() or 9051)
        cfg.tor.control_password = self._ctrl_pass_var.get()
        cfg.tor.renew_circuit_every = int(self._renew_var.get() or 10)
        cfg.crawler.max_depth  = int(self._depth_var.get() or 2)
        cfg.crawler.max_pages  = int(self._pages_var.get() or 20)
        cfg.crawler.crawl_delay = float(self._delay_var.get() or 7.0)
        cfg.crawler.max_workers = int(self._workers_var.get() or 3)
        cfg.crawler.request_timeout = int(self._timeout_var.get() or 30)
        cfg.crawler.retry_count = int(self._retries_var.get() or 3)
        cfg.storage.output_dir = self._output_dir_var.get() or "results"
        cfg.storage.json_output   = self._json_var.get()
        cfg.storage.csv_output    = self._csv_var.get()
        cfg.storage.sqlite_output = self._sqlite_var.get()
        return cfg

    def _browse_output(self) -> None:
        directory = filedialog.askdirectory(title="Select output directory")
        if directory:
            self._output_dir_var.set(directory)

    def _open_results_dir(self) -> None:
        path = Path(self._output_dir_var.get())
        path.mkdir(parents=True, exist_ok=True)
        self._open_file(path)

    def _open_file(self, path) -> None:
        path = Path(path)
        try:
            if sys.platform == "win32":
                os.startfile(path)
            elif sys.platform == "darwin":
                subprocess.Popen(["open", str(path)])
            else:
                subprocess.Popen(["xdg-open", str(path)])
        except Exception as exc:
            messagebox.showerror("Open failed", str(exc))

    def _clear_log(self) -> None:
        self._log_text.configure(state=tk.NORMAL)
        self._log_text.delete("1.0", tk.END)
        self._log_text.configure(state=tk.DISABLED)

    def _set_ui_running(self, running: bool) -> None:
        self._start_btn.configure(
            state=tk.DISABLED if running else tk.NORMAL,
            bg=_PALETTE["accent_dim"] if running else _PALETTE["accent"],
        )
        self._stop_btn.configure(state=tk.NORMAL if running else tk.DISABLED)
        if running:
            self._progress.start(12)
        else:
            self._progress.stop()

    def _update_stats(self, stats) -> None:
        self._stat_crawled.set(str(stats.pages_crawled))
        self._stat_failed.set(str(stats.pages_failed))
        self._stat_skipped.set(str(stats.pages_skipped))
        self._stat_dedup.set(str(stats.pages_deduplicated))
        self._stat_elapsed.set(f"{stats.elapsed:.0f}")

    # ── Crawl orchestration ───────────────────────────────────────────────────

    def _on_start(self) -> None:
        cfg = self._collect_config()
        if cfg is None:
            return

        self._stop_event.clear()
        self._set_ui_running(True)
        self._status_var.set("Crawling...")
        self._notebook.select(0)

        # Adjust root logger level
        logging.getLogger().setLevel(
            getattr(logging, cfg.log_level.upper(), logging.INFO)
        )

        self._log_system(
            f"=== DeepWebHarvester v{__version__} — crawl started ==="
        )
        self._log_system(
            f"Seeds: {len(cfg.seed_urls)}  |  "
            f"Depth: {cfg.crawler.max_depth}  |  "
            f"Max pages: {cfg.crawler.max_pages}  |  "
            f"Workers: {cfg.crawler.max_workers}"
        )

        self._crawl_thread = threading.Thread(
            target=self._crawl_worker, args=(cfg,), daemon=True
        )
        self._crawl_thread.start()

        # Poll for stats updates
        self.after(500, self._poll_stats)

    def _on_stop(self) -> None:
        self._stop_event.set()
        self._status_var.set("Stopping...")
        self._log_system("Stop requested — finishing current page then saving...")

    def _poll_stats(self) -> None:
        if hasattr(self, "_active_crawler") and self._active_crawler:
            try:
                self._update_stats(self._active_crawler.stats)
            except Exception:
                pass
        if self._crawl_thread and self._crawl_thread.is_alive():
            self.after(500, self._poll_stats)

    def _crawl_worker(self, cfg: AppConfig) -> None:
        """Run in a background thread. All UI updates go via after()."""
        self._active_crawler: Optional[Crawler] = None
        try:
            tor_manager = TorManager(
                socks_host=cfg.tor.socks_host,
                socks_port=cfg.tor.socks_port,
                control_host=cfg.tor.control_host,
                control_port=cfg.tor.control_port,
                control_password=cfg.tor.control_password,
                user_agent=cfg.crawler.user_agent,
            )

            if self._verify_tor_var.get():
                logging.info("Verifying Tor connectivity...")
                if not tor_manager.verify_connection():
                    self.after(0, lambda: messagebox.showerror(
                        "Tor Error",
                        "Traffic is not routed through Tor.\n"
                        "Ensure the Tor service is running and retry.",
                    ))
                    return

            extractor = PageExtractor(blacklist_paths=cfg.crawler.blacklist_paths)
            storage = StorageManager(
                output_dir=cfg.storage.output_dir,
                db_name=cfg.storage.db_name,
                json_output=cfg.storage.json_output,
                csv_output=cfg.storage.csv_output,
                sqlite_output=cfg.storage.sqlite_output,
            )

            known_urls = (
                storage.get_known_urls()
                if self._resume_var.get()
                else None
            )
            if known_urls:
                logging.info(
                    "Resume mode: %d URL(s) will be skipped.", len(known_urls)
                )

            def _on_page(result: CrawlResult) -> None:
                self._crawl_results.append(result)
                logging.debug("  + [%s]  %s", result.title[:50], result.url)

            self._active_crawler = Crawler(
                tor_manager=tor_manager,
                extractor=extractor,
                max_depth=cfg.crawler.max_depth,
                max_pages=cfg.crawler.max_pages,
                crawl_delay=cfg.crawler.crawl_delay,
                request_timeout=cfg.crawler.request_timeout,
                retry_count=cfg.crawler.retry_count,
                backoff_factor=cfg.crawler.backoff_factor,
                renew_circuit_every=cfg.tor.renew_circuit_every,
                max_workers=cfg.crawler.max_workers,
                on_page_crawled=_on_page,
            )

            results = self._active_crawler.crawl_all(cfg.seed_urls, known_urls)

            if self._stop_event.is_set():
                logging.warning("Crawl stopped by user. Saving %d result(s).", len(results))

            # Intelligence extraction
            intel_data = []
            if results:
                try:
                    logging.info("Running intelligence extraction on %d page(s)…", len(results))
                    intel_extractor = IntelligenceExtractor()
                    intel_data = [intel_extractor.analyze(r.url, r.text) for r in results]
                    total_iocs = sum(p.iocs.total for p in intel_data)
                    high_risk  = sum(
                        1 for p in intel_data
                        if p.threat.risk_label in ("High", "Critical")
                    )
                    from collections import Counter
                    cat_counter: Counter = Counter(
                        cat for p in intel_data for cat in p.threat.categories
                    )
                    self._intel_stats = {
                        "total_iocs":     total_iocs,
                        "high_risk":      high_risk,
                        "cves":           sum(len(p.iocs.cves) for p in intel_data),
                        "btc":            sum(len(p.iocs.btc_addresses) for p in intel_data),
                        "emails":         sum(len(p.iocs.emails) for p in intel_data),
                        "top_categories": [cat for cat, _ in cat_counter.most_common(3)],
                    }
                    logging.info("Intelligence: %d IOC(s), %d High/Critical", total_iocs, high_risk)
                except Exception as exc:
                    logging.warning("Intelligence extraction failed: %s", exc)

            self._result_paths = storage.save_all(results, intel_data or None)

            # HTML report
            if results:
                try:
                    report_gen = ReportGenerator()
                    report_path = report_gen.generate(
                        results, output_dir=cfg.storage.output_dir
                    )
                    self._result_paths["html"] = report_path
                    logging.info("HTML report written → %s", report_path)
                except Exception as exc:
                    logging.warning("Could not generate HTML report: %s", exc)

            stats = self._active_crawler.stats
            self.after(0, lambda: self._on_crawl_complete(stats))

        except Exception as exc:  # noqa: BLE001
            logging.error("Unhandled error during crawl: %s", exc, exc_info=True)
            self.after(0, lambda: self._on_crawl_error(str(exc)))
        finally:
            self._active_crawler = None

    def _on_crawl_complete(self, stats) -> None:
        self._set_ui_running(False)
        self._update_stats(stats)
        self._status_var.set(
            f"Complete — {stats.pages_crawled} page(s) in {stats.elapsed:.1f}s"
        )
        self._log_system(
            f"=== Crawl complete: {stats.pages_crawled} pages | "
            f"{stats.pages_failed} failed | "
            f"{stats.pages_deduplicated} deduped | "
            f"{stats.elapsed:.1f}s elapsed ==="
        )
        self._build_results_panel()
        self._notebook.select(1)

    def _on_crawl_error(self, error: str) -> None:
        self._set_ui_running(False)
        self._status_var.set("Error — see log")
        messagebox.showerror("Crawl error", f"An error occurred:\n\n{error}")

    # ── Menu actions ──────────────────────────────────────────────────────────

    def _show_about(self) -> None:
        about = tk.Toplevel(self)
        about.title("About DeepWebHarvester")
        about.configure(bg=_PALETTE["bg"])
        about.resizable(False, False)
        about.grab_set()

        tk.Label(
            about, text="DEEPWEB HARVESTER",
            bg=_PALETTE["bg"], fg=_PALETTE["accent"],
            font=("Courier New", 16, "bold"),
        ).pack(pady=(20, 4))

        tk.Label(
            about, text=f"Version {__version__}",
            bg=_PALETTE["bg"], fg=_PALETTE["fg_dim"],
            font=_FONT_LABEL,
        ).pack()

        tk.Label(
            about,
            text=(
                "\nAdvanced OSINT dark web intelligence platform.\n"
                "For authorized cybersecurity research only.\n\n"
                "Author: Tech Enthusiast\n"
                "License: MIT"
            ),
            bg=_PALETTE["bg"], fg=_PALETTE["fg"],
            font=_FONT_LABEL, justify=tk.CENTER,
        ).pack(padx=30, pady=10)

        tk.Button(
            about, text="Close",
            bg=_PALETTE["accent"], fg="#ffffff",
            relief=tk.FLAT, font=_FONT_BOLD, padx=20, pady=6,
            command=about.destroy, cursor="hand2",
        ).pack(pady=(0, 20))


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    """Launch the DeepWebHarvester graphical interface."""
    try:
        app = App()
        app.mainloop()
    except tk.TclError as exc:
        print(
            f"ERROR: Cannot initialise GUI — {exc}\n"
            "Ensure python3-tk is installed:  sudo apt install python3-tk",
            file=sys.stderr,
        )
        sys.exit(1)


if __name__ == "__main__":
    main()
