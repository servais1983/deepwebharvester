"""
Professional HTML report generator for DeepWebHarvester crawl sessions.

Produces a self-contained, single-file HTML report (no external CDN
dependencies) with:
  - Executive summary and session metadata
  - Global IOC table with type breakdown
  - Per-site threat assessment cards
  - Risk distribution chart (pure CSS, no JavaScript required)
  - Full crawled URL index

Usage::

    from deepwebharvester.report import ReportGenerator
    gen = ReportGenerator()
    path = gen.generate(results, intelligence_data, output_dir="results")
"""
from __future__ import annotations

import html
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from .crawler import CrawlResult
from .intelligence import IntelligenceExtractor, PageIntelligence

# ---------------------------------------------------------------------------
# CSS — embedded, no external dependencies
# ---------------------------------------------------------------------------

_CSS = """
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
    font-family: 'Segoe UI', system-ui, sans-serif;
    background: #0f1117;
    color: #c9d1d9;
    line-height: 1.6;
    font-size: 14px;
}
a { color: #58a6ff; text-decoration: none; }
a:hover { text-decoration: underline; }

/* Layout */
.container { max-width: 1200px; margin: 0 auto; padding: 0 24px 60px; }

/* Header */
.header {
    background: linear-gradient(135deg, #161b22 0%, #0d1117 100%);
    border-bottom: 1px solid #21262d;
    padding: 32px 0;
    margin-bottom: 32px;
}
.header-inner { max-width: 1200px; margin: 0 auto; padding: 0 24px; }
.header h1 {
    font-family: 'Courier New', monospace;
    font-size: 28px;
    color: #4c9be8;
    letter-spacing: 3px;
    text-transform: uppercase;
}
.header .subtitle {
    color: #8b949e;
    margin-top: 6px;
    font-size: 13px;
}
.header .meta {
    margin-top: 12px;
    display: flex;
    gap: 24px;
    flex-wrap: wrap;
}
.meta-item { font-size: 12px; color: #6e7681; }
.meta-item span { color: #c9d1d9; font-weight: 600; }

/* Section */
.section { margin: 32px 0; }
.section-title {
    font-size: 18px;
    font-weight: 700;
    color: #e6edf3;
    border-bottom: 2px solid #21262d;
    padding-bottom: 8px;
    margin-bottom: 20px;
}
.section-title .accent { color: #4c9be8; }

/* Stat cards */
.stat-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
    gap: 16px;
    margin-bottom: 24px;
}
.stat-card {
    background: #161b22;
    border: 1px solid #21262d;
    border-radius: 8px;
    padding: 20px;
    text-align: center;
    transition: border-color 0.2s;
}
.stat-card:hover { border-color: #4c9be8; }
.stat-card .value {
    font-size: 36px;
    font-weight: 700;
    color: #4c9be8;
    font-family: 'Courier New', monospace;
}
.stat-card .label {
    font-size: 11px;
    color: #6e7681;
    text-transform: uppercase;
    letter-spacing: 1px;
    margin-top: 4px;
}

/* Risk badges */
.risk { display: inline-block; padding: 2px 10px; border-radius: 12px;
        font-size: 11px; font-weight: 700; letter-spacing: 0.5px; }
.risk-Critical { background: #3d1515; color: #ff7b72; border: 1px solid #6e2020; }
.risk-High     { background: #3d2c1e; color: #ffa657; border: 1px solid #6e4c2e; }
.risk-Medium   { background: #2e2e00; color: #e3b341; border: 1px solid #5a5200; }
.risk-Low      { background: #12261e; color: #3fb950; border: 1px solid #1a4731; }

/* Tables */
.table-wrap { overflow-x: auto; }
table {
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
}
th {
    background: #161b22;
    color: #8b949e;
    font-weight: 600;
    text-transform: uppercase;
    font-size: 11px;
    letter-spacing: 0.8px;
    padding: 10px 14px;
    text-align: left;
    border-bottom: 1px solid #21262d;
}
td {
    padding: 10px 14px;
    border-bottom: 1px solid #161b22;
    vertical-align: top;
    word-break: break-all;
}
tr:hover td { background: #161b22; }
.mono { font-family: 'Courier New', monospace; font-size: 12px; }
.truncate { max-width: 360px; overflow: hidden; text-overflow: ellipsis;
            white-space: nowrap; }

/* Site cards */
.site-card {
    background: #161b22;
    border: 1px solid #21262d;
    border-radius: 8px;
    margin-bottom: 16px;
    overflow: hidden;
}
.site-card-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 14px 20px;
    background: #0d1117;
    border-bottom: 1px solid #21262d;
    flex-wrap: wrap;
    gap: 8px;
}
.site-card-header .site-url { font-family: 'Courier New', monospace; font-size: 13px; }
.site-card-body { padding: 16px 20px; }
.tag-list { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 8px; }
.tag {
    display: inline-block;
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 11px;
    background: #21262d;
    color: #8b949e;
    border: 1px solid #30363d;
}

/* IOC type pills */
.ioc-pill {
    display: inline-flex; align-items: center; gap: 4px;
    padding: 2px 8px; border-radius: 10px;
    font-size: 11px; font-weight: 600;
    margin: 2px;
}
.ioc-ipv4       { background:#1a2a3a; color:#58a6ff; border:1px solid #1f4068; }
.ioc-email      { background:#2a1a3a; color:#d2a8ff; border:1px solid #4e2a7a; }
.ioc-hash       { background:#1a2a1a; color:#56d364; border:1px solid #1a4a1a; }
.ioc-cve        { background:#3a2a1a; color:#ffa657; border:1px solid #6a4a1a; }
.ioc-btc        { background:#2a2a00; color:#e3b341; border:1px solid #5a5200; }
.ioc-onion      { background:#2a1a1a; color:#ff7b72; border:1px solid #6a2a2a; }
.ioc-pgp        { background:#1a2a2a; color:#39d3d3; border:1px solid #1a5a5a; }

/* Risk distribution bar */
.risk-bar { margin: 16px 0; }
.risk-bar-row { display:flex; align-items:center; margin:6px 0; gap:12px; }
.risk-bar-label { width:80px; font-size:12px; color:#8b949e; }
.risk-bar-track { flex:1; background:#21262d; border-radius:4px; height:12px; overflow:hidden; }
.risk-bar-fill { height:100%; border-radius:4px; transition:width 0.3s; }
.risk-bar-count { width:32px; font-size:12px; text-align:right; color:#6e7681; }

/* Footer */
.footer {
    margin-top: 60px;
    padding-top: 20px;
    border-top: 1px solid #21262d;
    text-align: center;
    font-size: 12px;
    color: #6e7681;
}
"""

# ---------------------------------------------------------------------------
# HTML template helpers
# ---------------------------------------------------------------------------

def _e(text: str) -> str:
    """HTML-escape a string."""
    return html.escape(str(text), quote=True)


def _risk_badge(label: str) -> str:
    return f'<span class="risk risk-{_e(label)}">{_e(label)}</span>'


def _ioc_pill(kind: str, value: str, css_class: str) -> str:
    return (
        f'<span class="ioc-pill {_e(css_class)}" title="{_e(kind)}">'
        f'{_e(kind)}: {_e(value)}</span>'
    )


def _stat_card(value: int | str, label: str) -> str:
    return (
        f'<div class="stat-card">'
        f'<div class="value">{_e(str(value))}</div>'
        f'<div class="label">{_e(label)}</div>'
        f'</div>'
    )


# ---------------------------------------------------------------------------
# Report generator
# ---------------------------------------------------------------------------

class ReportGenerator:
    """
    Generates a self-contained HTML threat intelligence report.

    The report is written to *output_dir* with a timestamped filename
    and contains no external dependencies (no CDN, no images, no JS).
    """

    def __init__(self) -> None:
        self._intel = IntelligenceExtractor()

    def generate(
        self,
        results: List[CrawlResult],
        output_dir: str = "results",
        filename: Optional[str] = None,
    ) -> Path:
        """
        Build the HTML report from crawl results.

        Intelligence extraction is run internally on each result's ``text``
        field, so this method requires no pre-computed intelligence data.

        Args:
            results:    List of :class:`~deepwebharvester.crawler.CrawlResult`.
            output_dir: Directory where the HTML file will be written.
            filename:   Override the auto-generated timestamped filename.

        Returns:
            :class:`~pathlib.Path` to the written HTML file.
        """
        out_dir = Path(output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)

        ts = datetime.now(tz=timezone.utc)
        ts_str = ts.strftime("%Y%m%d_%H%M%S")
        path = out_dir / (filename or f"report_{ts_str}.html")

        # Run intelligence on every result
        intel_data: List[PageIntelligence] = [
            self._intel.analyze(r.url, r.text) for r in results
        ]

        html_content = self._build_html(results, intel_data, ts)
        path.write_text(html_content, encoding="utf-8")
        return path

    # ── HTML construction ─────────────────────────────────────────────────────

    def _build_html(
        self,
        results: List[CrawlResult],
        intel: List[PageIntelligence],
        ts: datetime,
    ) -> str:
        from . import __version__

        # Aggregate stats
        total_iocs = sum(p.iocs.total for p in intel)
        sites = sorted({r.site for r in results})
        risk_dist: Dict[str, int] = {
            "Critical": 0, "High": 0, "Medium": 0, "Low": 0
        }
        for p in intel:
            lbl = p.threat.risk_label
            risk_dist[lbl] = risk_dist.get(lbl, 0) + 1

        high_risk_pages = [
            (r, p) for r, p in zip(results, intel)
            if p.threat.risk_label in ("High", "Critical")
        ]
        high_risk_pages.sort(key=lambda x: x[1].threat.risk_score, reverse=True)

        body = (
            self._header(ts, __version__, len(results), len(sites))
            + '<div class="container">'
            + self._summary_cards(results, intel, total_iocs)
            + self._risk_distribution(risk_dist, len(results))
            + self._ioc_summary(intel)
            + self._high_risk_section(high_risk_pages)
            + self._site_breakdown(results, intel, sites)
            + self._url_index(results, intel)
            + self._footer(__version__, ts)
            + "</div>"
        )

        return (
            "<!DOCTYPE html>\n"
            '<html lang="en">\n'
            "<head>\n"
            '<meta charset="UTF-8">\n'
            '<meta name="viewport" content="width=device-width,initial-scale=1">\n'
            f"<title>DeepWebHarvester Report — {_e(ts.strftime('%Y-%m-%d %H:%M UTC'))}</title>\n"
            f"<style>{_CSS}</style>\n"
            "</head>\n"
            f"<body>{body}</body>\n"
            "</html>"
        )

    def _header(
        self, ts: datetime, version: str, pages: int, sites: int
    ) -> str:
        return (
            '<div class="header">'
            '<div class="header-inner">'
            '<h1>DeepWebHarvester</h1>'
            '<div class="subtitle">OSINT Threat Intelligence Report</div>'
            '<div class="meta">'
            f'<div class="meta-item">Generated <span>{_e(ts.strftime("%Y-%m-%d %H:%M UTC"))}</span></div>'
            f'<div class="meta-item">Tool version <span>v{_e(version)}</span></div>'
            f'<div class="meta-item">Pages analysed <span>{pages}</span></div>'
            f'<div class="meta-item">Sites covered <span>{sites}</span></div>'
            "</div>"
            "</div>"
            "</div>"
        )

    def _summary_cards(
        self,
        results: List[CrawlResult],
        intel: List[PageIntelligence],
        total_iocs: int,
    ) -> str:
        cves    = sum(len(p.iocs.cves)          for p in intel)
        btc     = sum(len(p.iocs.btc_addresses) for p in intel)
        emails  = sum(len(p.iocs.emails)        for p in intel)
        hashes  = sum(len(p.iocs.md5) + len(p.iocs.sha1) + len(p.iocs.sha256)
                      for p in intel)
        high    = sum(1 for p in intel if p.threat.risk_label in ("High", "Critical"))
        onions  = sum(len(p.iocs.onion_addresses) for p in intel)

        cards = "".join([
            _stat_card(len(results),  "Pages Crawled"),
            _stat_card(total_iocs,    "Total IOCs"),
            _stat_card(high,          "High / Critical"),
            _stat_card(cves,          "CVEs Found"),
            _stat_card(hashes,        "Hash IOCs"),
            _stat_card(emails,        "Emails"),
            _stat_card(btc,           "BTC Addresses"),
            _stat_card(onions,        "Onion References"),
        ])
        return (
            '<div class="section">'
            '<div class="section-title"><span class="accent">01.</span> Executive Summary</div>'
            f'<div class="stat-grid">{cards}</div>'
            "</div>"
        )

    def _risk_distribution(self, dist: Dict[str, int], total: int) -> str:
        colors = {
            "Critical": "#ff7b72",
            "High":     "#ffa657",
            "Medium":   "#e3b341",
            "Low":      "#3fb950",
        }
        rows = ""
        for label in ("Critical", "High", "Medium", "Low"):
            count = dist.get(label, 0)
            pct   = int(count / max(total, 1) * 100)
            color = colors.get(label, "#8b949e")
            rows += (
                '<div class="risk-bar-row">'
                f'<div class="risk-bar-label">{_risk_badge(label)}</div>'
                '<div class="risk-bar-track">'
                f'<div class="risk-bar-fill" style="width:{pct}%;background:{color}"></div>'
                "</div>"
                f'<div class="risk-bar-count">{count}</div>'
                "</div>"
            )
        return (
            '<div class="section">'
            '<div class="section-title"><span class="accent">02.</span> Risk Distribution</div>'
            f'<div class="risk-bar">{rows}</div>'
            "</div>"
        )

    def _ioc_summary(self, intel: List[PageIntelligence]) -> str:
        # Aggregate unique IOCs across all pages
        all_ipv4   = sorted({ip  for p in intel for ip  in p.iocs.ipv4})
        all_emails = sorted({em  for p in intel for em  in p.iocs.emails})
        all_cves   = sorted({cv  for p in intel for cv  in p.iocs.cves})
        all_btc    = sorted({bt  for p in intel for bt  in p.iocs.btc_addresses})
        all_xmr    = sorted({xm  for p in intel for xm  in p.iocs.xmr_addresses})
        all_sha256 = sorted({sh  for p in intel for sh  in p.iocs.sha256})
        all_onions = sorted({on  for p in intel for on  in p.iocs.onion_addresses})

        def _table(title: str, items: list, css: str, cols=1) -> str:
            if not items:
                return ""
            rows = "".join(
                f"<tr><td class='mono'>{_e(item)}</td></tr>"
                for item in items[:100]
            )
            note = (
                f"<p style='font-size:11px;color:#6e7681;margin-top:8px'>"
                f"Showing first 100 of {len(items)}</p>"
                if len(items) > 100 else ""
            )
            return (
                f"<h4 style='color:#8b949e;margin:20px 0 8px;font-size:13px;"
                f"text-transform:uppercase;letter-spacing:0.8px'>"
                f'<span class="ioc-pill {css}">&nbsp;</span> {_e(title)} '
                f"({len(items)})</h4>"
                '<div class="table-wrap">'
                f"<table><tbody>{rows}</tbody></table>"
                "</div>"
                f"{note}"
            )

        content = (
            _table("IPv4 Addresses", all_ipv4,   "ioc-ipv4")
            + _table("Email Addresses", all_emails, "ioc-email")
            + _table("CVE References", all_cves,   "ioc-cve")
            + _table("Bitcoin Addresses", all_btc, "ioc-btc")
            + _table("Monero Addresses", all_xmr,  "ioc-btc")
            + _table("SHA-256 Hashes", all_sha256, "ioc-hash")
            + _table("Hidden Service References", all_onions, "ioc-onion")
        )

        return (
            '<div class="section">'
            '<div class="section-title"><span class="accent">03.</span> IOC Registry</div>'
            + (content or "<p style='color:#6e7681'>No IOCs extracted.</p>")
            + "</div>"
        )

    def _high_risk_section(
        self, pages: List[tuple]
    ) -> str:
        if not pages:
            return (
                '<div class="section">'
                '<div class="section-title"><span class="accent">04.</span> High-Risk Pages</div>'
                "<p style='color:#6e7681'>No high-risk pages detected.</p>"
                "</div>"
            )
        rows = ""
        for result, p in pages[:50]:
            cats = ", ".join(p.threat.categories[:3]) or "—"
            rows += (
                f"<tr>"
                f"<td class='mono truncate' title='{_e(result.url)}'>"
                f"<a href='{_e(result.url)}'>{_e(result.url[:70])}</a></td>"
                f"<td>{_e(result.title[:60])}</td>"
                f"<td>{_risk_badge(p.threat.risk_label)}</td>"
                f"<td class='mono'>{_e(str(p.threat.risk_score))}</td>"
                f"<td>{_e(cats)}</td>"
                f"<td class='mono'>{_e(str(p.iocs.total))}</td>"
                f"</tr>"
            )
        return (
            '<div class="section">'
            '<div class="section-title"><span class="accent">04.</span> High-Risk Pages</div>'
            '<div class="table-wrap">'
            "<table>"
            "<thead><tr>"
            "<th>URL</th><th>Title</th><th>Risk</th>"
            "<th>Score</th><th>Categories</th><th>IOCs</th>"
            "</tr></thead>"
            f"<tbody>{rows}</tbody>"
            "</table></div></div>"
        )

    def _site_breakdown(
        self,
        results: List[CrawlResult],
        intel: List[PageIntelligence],
        sites: List[str],
    ) -> str:
        # Group by site
        site_data: Dict[str, list] = {s: [] for s in sites}
        for r, p in zip(results, intel):
            site_data[r.site].append((r, p))

        cards = ""
        for site in sites:
            pages = site_data[site]
            if not pages:
                continue
            site_risk = max((p.threat.risk_score for _, p in pages), default=0)
            site_label = (
                "Critical" if site_risk >= 9 else
                "High" if site_risk >= 7 else
                "Medium" if site_risk >= 4 else "Low"
            )
            all_cats = sorted(
                {cat for _, p in pages for cat in p.threat.categories}
            )
            all_iocs = sum(p.iocs.total for _, p in pages)
            cards += (
                '<div class="site-card">'
                '<div class="site-card-header">'
                f'<span class="site-url">{_e(site)}</span>'
                f'<span>{_risk_badge(site_label)}</span>'
                "</div>"
                '<div class="site-card-body">'
                f"<b>{len(pages)}</b> page(s) &nbsp;|&nbsp; "
                f"<b>{all_iocs}</b> IOC(s) &nbsp;|&nbsp; "
                f"Risk score: <b>{site_risk:.1f}</b>"
                + (
                    '<div class="tag-list">'
                    + "".join(f'<span class="tag">{_e(c)}</span>' for c in all_cats)
                    + "</div>"
                    if all_cats else ""
                )
                + "</div></div>"
            )

        return (
            '<div class="section">'
            '<div class="section-title"><span class="accent">05.</span> Site Breakdown</div>'
            + cards
            + "</div>"
        )

    def _url_index(
        self, results: List[CrawlResult], intel: List[PageIntelligence]
    ) -> str:
        rows = ""
        for r, p in zip(results, intel):
            rows += (
                f"<tr>"
                f"<td class='mono' style='font-size:11px'>{_e(r.url[:80])}</td>"
                f"<td>{_e(r.title[:60])}</td>"
                f"<td>{r.depth}</td>"
                f"<td>{_risk_badge(p.threat.risk_label)}</td>"
                f"<td>{p.iocs.total}</td>"
                f"<td class='mono' style='font-size:11px'>{_e(r.content_hash[:16])}…</td>"
                f"</tr>"
            )
        return (
            '<div class="section">'
            '<div class="section-title"><span class="accent">06.</span> Crawled URL Index</div>'
            '<div class="table-wrap"><table>'
            "<thead><tr><th>URL</th><th>Title</th><th>Depth</th>"
            "<th>Risk</th><th>IOCs</th><th>Hash</th></tr></thead>"
            f"<tbody>{rows}</tbody>"
            "</table></div></div>"
        )

    def _footer(self, version: str, ts: datetime) -> str:
        return (
            '<div class="footer">'
            f"DeepWebHarvester v{_e(version)} &nbsp;|&nbsp; "
            f"Report generated {_e(ts.strftime('%Y-%m-%d %H:%M UTC'))} &nbsp;|&nbsp; "
            "For authorized cybersecurity and OSINT research only."
            "</div>"
        )
