"""
Command-line interface for DeepWebHarvester.

Usage examples::

    # Basic crawl from command line
    deepwebharvester --url http://<56-char-hash>.onion/

    # Use a YAML config file
    deepwebharvester --config config.yaml

    # Resume a previous crawl, writing only to JSON
    deepwebharvester --config config.yaml --resume --no-csv --no-sqlite

    # Verify Tor, limit depth and pages, high verbosity
    deepwebharvester --url http://<hash>.onion/ --verify-tor --depth 1 --pages 5 --log-level DEBUG
"""
from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path
from typing import List, Optional

from . import __version__
from .config import AppConfig, load_config
from .crawler import Crawler
from .extractor import PageExtractor
from .intelligence import IntelligenceExtractor
from .report import ReportGenerator
from .storage import StorageManager
from .tor_manager import TorManager
from .visualizer import GraphVisualizer

# ── Presentation ──────────────────────────────────────────────────────────────

_BANNER = r"""
 ____                   __        __   _     _   _
|  _ \  ___  ___ _ __  \ \      / /__| |__ | | | | __ _ _ ____   _____  ___| |_ ___ _ __
| | | |/ _ \/ _ \ '_ \  \ \ /\ / / _ \ '_ \| |_| |/ _` | '__\ \ / / _ \/ __| __/ _ \ '__|
| |_| |  __/  __/ |_) |  \ V  V /  __/ |_) |  _  | (_| | |   \ V /  __/\__ \ ||  __/ |
|____/ \___|\___| .__/    \_/\_/ \___|_.__/|_| |_|\__,_|_|    \_/ \___||___/\__\___|_|
                |_|
  v{version}  |  OSINT Intelligence Gathering Tool
  For authorized cybersecurity and OSINT research only.
"""


def _print_banner() -> None:
    print(_BANNER.format(version=__version__))


def _print_summary(stats, paths: dict, intel_stats: dict = {}) -> None:  # type: ignore[type-arg]
    sep = "=" * 60
    print(f"\n{sep}")
    print("  CRAWL COMPLETE")
    print(sep)
    print(f"  Sites crawled    : {stats.sites_crawled}")
    print(f"  Pages collected  : {stats.pages_crawled}")
    print(f"  Pages failed     : {stats.pages_failed}")
    print(f"  Pages skipped    : {stats.pages_skipped}")
    print(f"  Duplicates       : {stats.pages_deduplicated}")
    print(f"  Elapsed time     : {stats.elapsed:.1f}s")
    if intel_stats:
        print(sep)
        print("  INTELLIGENCE SUMMARY")
        print(f"  Total IOCs       : {intel_stats.get('total_iocs', 0)}")
        print(f"  High/Critical    : {intel_stats.get('high_risk', 0)} page(s)")
        print(f"  CVEs found       : {intel_stats.get('cves', 0)}")
        print(f"  BTC addresses    : {intel_stats.get('btc', 0)}")
        print(f"  Emails           : {intel_stats.get('emails', 0)}")
        cats = intel_stats.get("top_categories", [])
        if cats:
            print(f"  Top categories   : {', '.join(cats[:3])}")
    print(sep)
    if paths:
        print("  Output files:")
        for fmt, path in paths.items():
            print(f"    {fmt.upper():8s}: {path}")
    print(sep + "\n")


# ── CLI definition ────────────────────────────────────────────────────────────


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="deepwebharvester",
        description="Advanced OSINT dark web intelligence gathering tool.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "DISCLAIMER: For authorized cybersecurity and OSINT research only.\n"
            "Users must comply with all applicable laws and ethical standards.\n"
        ),
    )
    parser.add_argument(
        "--version", "-V",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    parser.add_argument(
        "--config", "-c",
        metavar="PATH",
        default="config.yaml",
        help="Path to YAML configuration file (default: config.yaml).",
    )

    # ── Seed URLs ──────────────────────────────────────────────────────────────
    parser.add_argument(
        "--url", "-u",
        metavar="ONION_URL",
        action="append",
        dest="urls",
        help=(
            "Seed .onion URL to crawl. "
            "May be specified multiple times to crawl several sites."
        ),
    )

    # ── Crawl behaviour ────────────────────────────────────────────────────────
    crawl = parser.add_argument_group("crawl settings")
    crawl.add_argument("--depth", "-d", type=int, metavar="N",
                       help="Maximum crawl depth (overrides config).")
    crawl.add_argument("--pages", "-p", type=int, metavar="N",
                       help="Maximum pages per site (overrides config).")
    crawl.add_argument("--workers", "-w", type=int, metavar="N",
                       help="Concurrent site-crawl threads (overrides config).")
    crawl.add_argument("--delay", type=float, metavar="SECS",
                       help="Delay in seconds between requests (overrides config).")

    # ── Output ─────────────────────────────────────────────────────────────────
    out = parser.add_argument_group("output settings")
    out.add_argument("--output", "-o", metavar="DIR",
                     help="Output directory for results (overrides config).")
    out.add_argument("--no-json", action="store_true", help="Disable JSON output.")
    out.add_argument("--no-csv",  action="store_true", help="Disable CSV output.")
    out.add_argument("--no-sqlite", action="store_true", help="Disable SQLite output.")

    # ── Misc ───────────────────────────────────────────────────────────────────
    misc = parser.add_argument_group("miscellaneous")
    misc.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging verbosity (overrides config).",
    )
    misc.add_argument(
        "--verify-tor",
        action="store_true",
        help="Confirm traffic is routed through Tor before starting.",
    )
    misc.add_argument(
        "--resume",
        action="store_true",
        help="Skip URLs already present in the SQLite database.",
    )

    return parser


# ── Logging setup ─────────────────────────────────────────────────────────────


def _setup_logging(level: str, log_file: Optional[str] = None) -> None:
    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stdout)]
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        handlers.append(
            logging.FileHandler(log_path, encoding="utf-8")
        )
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s [%(levelname)-8s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        handlers=handlers,
    )


# ── Entry point ───────────────────────────────────────────────────────────────


def main(argv: Optional[List[str]] = None) -> int:
    """
    CLI entry point.

    Returns:
        Exit code – ``0`` on success, ``1`` on configuration errors.
    """
    parser = _build_parser()
    args = parser.parse_args(argv)

    # ── Load and merge configuration ──────────────────────────────────────────
    cfg: AppConfig = load_config(args.config if Path(args.config).exists() else None)

    # CLI flags override config file values
    if args.depth is not None:
        cfg.crawler.max_depth = args.depth
    if args.pages is not None:
        cfg.crawler.max_pages = args.pages
    if args.workers is not None:
        cfg.crawler.max_workers = args.workers
    if getattr(args, "delay", None) is not None:
        cfg.crawler.crawl_delay = args.delay
    if args.output:
        cfg.storage.output_dir = args.output
    if args.log_level:
        cfg.log_level = args.log_level
    if args.no_json:
        cfg.storage.json_output = False
    if args.no_csv:
        cfg.storage.csv_output = False
    if args.no_sqlite:
        cfg.storage.sqlite_output = False
    if args.urls:
        cfg.seed_urls.extend(args.urls)

    # ── Logging ───────────────────────────────────────────────────────────────
    _setup_logging(cfg.log_level, cfg.log_file)
    logger = logging.getLogger(__name__)

    _print_banner()

    if not cfg.seed_urls:
        logger.error(
            "No seed URLs provided. "
            "Use --url or add seed_urls to your config file."
        )
        return 1

    # ── Component wiring ──────────────────────────────────────────────────────
    tor_manager = TorManager(
        socks_host=cfg.tor.socks_host,
        socks_port=cfg.tor.socks_port,
        control_host=cfg.tor.control_host,
        control_port=cfg.tor.control_port,
        control_password=cfg.tor.control_password,
        user_agent=cfg.crawler.user_agent,
    )

    if args.verify_tor:
        logger.info("Verifying Tor connectivity…")
        if not tor_manager.verify_connection():
            logger.error(
                "Tor verification failed. "
                "Ensure the Tor service is running on %s:%d.",
                cfg.tor.socks_host,
                cfg.tor.socks_port,
            )
            return 1

    extractor = PageExtractor(blacklist_paths=cfg.crawler.blacklist_paths)

    storage = StorageManager(
        output_dir=cfg.storage.output_dir,
        db_name=cfg.storage.db_name,
        json_output=cfg.storage.json_output,
        csv_output=cfg.storage.csv_output,
        sqlite_output=cfg.storage.sqlite_output,
    )

    # ── Resume support ────────────────────────────────────────────────────────
    known_urls = storage.get_known_urls() if args.resume else None
    if known_urls:
        logger.info(
            "Resume mode enabled: %d URL(s) will be skipped.", len(known_urls)
        )

    # ── Crawl ─────────────────────────────────────────────────────────────────
    def _on_crawled(result):  # type: ignore[return]
        logger.debug("Collected [%s]: %s", result.title[:60], result.url)

    crawler = Crawler(
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
        on_page_crawled=_on_crawled,
    )

    logger.info(
        "Starting DeepWebHarvester — crawling %d seed URL(s).", len(cfg.seed_urls)
    )

    results = []
    try:
        results = crawler.crawl_all(cfg.seed_urls, known_urls)
    except KeyboardInterrupt:
        logger.warning("Interrupted by user — saving collected data…")

    # ── Intelligence extraction ───────────────────────────────────────────────
    intel_data = []
    intel_stats: dict = {}
    if results:
        logger.info("Running intelligence extraction on %d page(s)…", len(results))
        extractor_intel = IntelligenceExtractor()
        intel_data = [extractor_intel.analyze(r.url, r.text) for r in results]

        total_iocs = sum(p.iocs.total for p in intel_data)
        high_risk  = sum(
            1 for p in intel_data if p.threat.risk_label in ("High", "Critical")
        )
        from collections import Counter
        cat_counter: Counter = Counter(
            cat for p in intel_data for cat in p.threat.categories
        )
        intel_stats = {
            "total_iocs":     total_iocs,
            "high_risk":      high_risk,
            "cves":           sum(len(p.iocs.cves)          for p in intel_data),
            "btc":            sum(len(p.iocs.btc_addresses) for p in intel_data),
            "emails":         sum(len(p.iocs.emails)        for p in intel_data),
            "top_categories": [cat for cat, _ in cat_counter.most_common(3)],
        }
        logger.info(
            "Intelligence: %d IOC(s) — %d High/Critical page(s)",
            total_iocs, high_risk,
        )

    # ── Persist results ───────────────────────────────────────────────────────
    paths = storage.save_all(results, intel_data or None) if results else {}

    # ── HTML report ───────────────────────────────────────────────────────────
    if results:
        try:
            report_gen = ReportGenerator()
            report_path = report_gen.generate(
                results, output_dir=cfg.storage.output_dir
            )
            paths["html"] = report_path
            logger.info("HTML report written → %s", report_path)
        except Exception as exc:
            logger.warning("Could not generate HTML report: %s", exc)

    # ── 3D network graph PNG ──────────────────────────────────────────────────
    if results:
        try:
            from pathlib import Path as _Path
            graph_path = str(
                _Path(cfg.storage.output_dir) / "network_graph.png"
            )
            viz = GraphVisualizer()
            saved = viz.save_png(results, intel_data or None,
                                 output_path=graph_path, dpi=150)
            paths["graph"] = saved
            logger.info("3D network graph saved → %s", saved)
        except Exception as exc:
            logger.warning("Could not save 3D graph: %s", exc)

    _print_summary(crawler.stats, paths, intel_stats)

    if not results:
        logger.warning("No results collected.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
