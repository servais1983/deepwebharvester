"""
3D Network Graph Visualizer for DeepWebHarvester crawl results.

Renders a force-directed 3D graph using matplotlib (Axes3D) and networkx,
where:

  - Site hubs are large star-shaped nodes, sized by page count
  - Page nodes are spherical, sized by IOC count
  - All nodes are colour-coded by risk level (Low=green → Critical=red)
  - Edges connect each site hub to its crawled pages
  - Depth shading gives the scene genuine 3D perspective
  - Mouse-dragging rotates the scene interactively in the GUI

The visualizer uses matplotlib's object-oriented API so the Figure is
backend-agnostic: embed it in Tkinter via ``FigureCanvasTkAgg``, save it
directly to PNG, or export it as a base64 string for HTML embedding.

Usage::

    from deepwebharvester.visualizer import GraphVisualizer
    fig  = GraphVisualizer().build_figure(results, intel_data)
    path = GraphVisualizer().save_png(results, intel_data, "output/graph.png")
    b64  = GraphVisualizer().to_png_base64(results, intel_data)
"""
from __future__ import annotations

import base64
import io
import logging
import math
from pathlib import Path
from typing import TYPE_CHECKING, Dict, List, Optional, Tuple

if TYPE_CHECKING:
    from matplotlib.figure import Figure

    from .crawler import CrawlResult
    from .intelligence import PageIntelligence

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Visual constants
# ---------------------------------------------------------------------------

_RISK_ORDER = ["Low", "Medium", "High", "Critical"]
_RISK_COLORS: Dict[str, str] = {
    "Low":      "#3fb950",
    "Medium":   "#e3b341",
    "High":     "#ffa657",
    "Critical": "#ff7b72",
    "unknown":  "#8b949e",
}

_BG        = "#0f1117"
_GRID      = "#21262d"
_FG        = "#c9d1d9"
_EDGE_CLR  = "#30363d"


def _risk_rank(label: str) -> int:
    """Return numeric rank for a risk label (higher = worse)."""
    try:
        return _RISK_ORDER.index(label)
    except ValueError:
        return -1


# ---------------------------------------------------------------------------
# Main visualizer
# ---------------------------------------------------------------------------

class GraphVisualizer:
    """
    Builds a 3D network graph figure from :class:`~deepwebharvester.crawler.CrawlResult`
    objects and optional :class:`~deepwebharvester.intelligence.PageIntelligence` data.

    All public methods require ``matplotlib`` and ``networkx`` to be
    installed.  Import errors are raised lazily so the rest of the
    application keeps working when these optional dependencies are absent.
    """

    # ── Public API ────────────────────────────────────────────────────────────

    def build_figure(
        self,
        results: List["CrawlResult"],
        intel: Optional[List["PageIntelligence"]] = None,
        figsize: Tuple[float, float] = (11, 9),
        dark: bool = True,
    ) -> "Figure":
        """
        Build and return a matplotlib 3D Figure.

        The figure is backend-agnostic and can be embedded in Tkinter via
        ``FigureCanvasTkAgg`` or saved to any format via ``fig.savefig()``.

        Args:
            results:  Crawl results to visualise.
            intel:    Optional parallel list of :class:`PageIntelligence`.
            figsize:  Figure dimensions in inches.
            dark:     Use dark background matching the application theme.

        Returns:
            A :class:`matplotlib.figure.Figure` instance.

        Raises:
            ImportError: If ``matplotlib`` or ``networkx`` are not installed.
        """
        try:
            import networkx as nx
            from matplotlib.figure import Figure
            from mpl_toolkits.mplot3d import Axes3D  # noqa: F401 — registers '3d'
        except ImportError as exc:
            raise ImportError(
                "matplotlib and networkx are required for 3D visualisation. "
                "Install them with:  pip install matplotlib networkx"
            ) from exc

        intel_map: Dict[str, "PageIntelligence"] = (
            {p.url: p for p in intel} if intel else {}
        )

        G = self._build_graph(results, intel_map)
        pos3d = self._compute_layout(G)

        bg = _BG if dark else "#ffffff"
        fg = _FG if dark else "#333333"
        grid_col = _GRID if dark else "#e0e0e0"

        fig = Figure(figsize=figsize, facecolor=bg)
        ax = fig.add_subplot(111, projection="3d")
        ax.set_facecolor(bg)

        self._style_axes(ax, bg, fg, grid_col, dark)
        self._draw_edges(ax, G, pos3d)
        self._draw_site_nodes(ax, G, pos3d, results)
        self._draw_page_nodes(ax, G, pos3d)
        self._draw_site_labels(ax, G, pos3d, fg)
        self._add_legend(ax, fig, bg, fg, dark)
        self._set_title(ax, results, G, fg)

        fig.tight_layout(pad=1.5)
        return fig

    def to_png_base64(
        self,
        results: List["CrawlResult"],
        intel: Optional[List["PageIntelligence"]] = None,
        dpi: int = 120,
    ) -> str:
        """
        Render the graph and return it as a base64-encoded PNG string.

        Suitable for embedding in HTML ``<img src="data:image/png;base64,…">``.

        Args:
            results: Crawl results.
            intel:   Optional intelligence data.
            dpi:     Rendering resolution.

        Returns:
            Base64-encoded PNG string (no data-URI prefix).
        """
        fig = self.build_figure(results, intel)
        buf = io.BytesIO()
        fig.savefig(buf, format="png", dpi=dpi,
                    bbox_inches="tight", facecolor=_BG)
        buf.seek(0)
        encoded = base64.b64encode(buf.read()).decode("ascii")
        self._close(fig)
        return encoded

    def save_png(
        self,
        results: List["CrawlResult"],
        intel: Optional[List["PageIntelligence"]] = None,
        output_path: str = "network_graph.png",
        dpi: int = 150,
    ) -> Path:
        """
        Render the graph and save it as a PNG file.

        Args:
            results:     Crawl results.
            intel:       Optional intelligence data.
            output_path: Destination file path.
            dpi:         Rendering resolution.

        Returns:
            :class:`~pathlib.Path` to the written file.
        """
        fig = self.build_figure(results, intel)
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        fig.savefig(out, format="png", dpi=dpi,
                    bbox_inches="tight", facecolor=_BG)
        self._close(fig)
        logger.info("3D network graph saved → %s", out)
        return out

    # ── Graph construction ────────────────────────────────────────────────────

    def _build_graph(
        self,
        results: List["CrawlResult"],
        intel_map: Dict[str, "PageIntelligence"],
    ):
        """Build a directed graph: site hub → pages."""
        import networkx as nx
        G = nx.DiGraph()

        sites = sorted({r.site for r in results})

        # Add site hub nodes
        for site in sites:
            site_pages = [r for r in results if r.site == site]
            page_risks = [
                intel_map[r.url].threat.risk_label
                for r in site_pages
                if r.url in intel_map
            ]
            worst_risk = (
                max(page_risks, key=_risk_rank, default="unknown")
                if page_risks else "unknown"
            )
            total_iocs = sum(
                intel_map[r.url].iocs.total
                for r in site_pages
                if r.url in intel_map
            )
            G.add_node(site, kind="site", risk=worst_risk,
                       ioc_count=total_iocs, page_count=len(site_pages))

        # Add page nodes and site→page edges
        for r in results:
            p = intel_map.get(r.url)
            risk = p.threat.risk_label if p else "unknown"
            ioc_count = p.iocs.total if p else 0
            G.add_node(r.url, kind="page", risk=risk,
                       ioc_count=ioc_count, depth=r.depth)
            G.add_edge(r.site, r.url)

        return G

    def _compute_layout(self, G) -> Dict:
        """
        Compute 3D positions using networkx spring layout.

        Falls back to a deterministic ring layout for very small graphs
        or when spring_layout doesn't converge well.
        """
        import networkx as nx

        n = len(G.nodes)
        if n == 0:
            return {}
        if n == 1:
            return {list(G.nodes)[0]: [0.0, 0.0, 0.0]}

        # spring_layout with dim=3 gives a force-directed 3D arrangement
        k = 2.5 / math.sqrt(max(n, 1))
        try:
            pos3d = nx.spring_layout(
                G, dim=3, seed=42, k=k, iterations=80, weight=None
            )
        except Exception:
            # Fallback: uniform sphere distribution
            pos3d = {}
            for i, node in enumerate(G.nodes):
                theta = i * 2 * math.pi / n
                phi   = math.acos(1 - 2 * (i + 0.5) / n)
                pos3d[node] = [
                    math.sin(phi) * math.cos(theta),
                    math.sin(phi) * math.sin(theta),
                    math.cos(phi),
                ]

        # Convert numpy arrays to plain lists for compatibility
        return {node: list(xyz) for node, xyz in pos3d.items()}

    # ── Drawing helpers ───────────────────────────────────────────────────────

    def _style_axes(self, ax, bg, fg, grid_col, dark):
        ax.xaxis.pane.fill = False
        ax.yaxis.pane.fill = False
        ax.zaxis.pane.fill = False
        for pane in (ax.xaxis.pane, ax.yaxis.pane, ax.zaxis.pane):
            pane.set_edgecolor(grid_col)
        ax.grid(True, color=grid_col, linestyle="--", linewidth=0.4, alpha=0.4)
        for axis in (ax.xaxis, ax.yaxis, ax.zaxis):
            axis.label.set_color(fg)
            axis.set_tick_params(colors=fg, labelsize=6)
        ax.set_xlabel("X", color=fg, fontsize=7, labelpad=3)
        ax.set_ylabel("Y", color=fg, fontsize=7, labelpad=3)
        ax.set_zlabel("Z", color=fg, fontsize=7, labelpad=3)

    def _draw_edges(self, ax, G, pos3d):
        for u, v in G.edges():
            if u not in pos3d or v not in pos3d:
                continue
            xu, yu, zu = pos3d[u]
            xv, yv, zv = pos3d[v]
            risk = G.nodes[v].get("risk", "unknown")
            color = _RISK_COLORS.get(risk, _EDGE_CLR)
            ax.plot([xu, xv], [yu, yv], [zu, zv],
                    color=color, alpha=0.20, linewidth=0.7, zorder=1)

    def _draw_site_nodes(self, ax, G, pos3d, results):
        """Draw site hub nodes as gold/risk-coloured stars."""
        xs, ys, zs, colors, sizes = [], [], [], [], []
        for node, data in G.nodes(data=True):
            if data.get("kind") != "site":
                continue
            if node not in pos3d:
                continue
            xs.append(pos3d[node][0])
            ys.append(pos3d[node][1])
            zs.append(pos3d[node][2])
            colors.append(_RISK_COLORS.get(data.get("risk", "unknown"), _EDGE_CLR))
            page_count = data.get("page_count", 1)
            sizes.append(180 + min(page_count * 35, 400))

        if xs:
            ax.scatter(xs, ys, zs, c=colors, s=sizes, marker="*",
                       alpha=0.95, edgecolors="none",
                       depthshade=True, zorder=5)

    def _draw_page_nodes(self, ax, G, pos3d):
        """Draw page nodes grouped by risk level for efficient scatter calls."""
        for risk_label in _RISK_ORDER:
            color = _RISK_COLORS[risk_label]
            xs, ys, zs, sizes = [], [], [], []
            for node, data in G.nodes(data=True):
                if data.get("kind") != "page":
                    continue
                if data.get("risk", "unknown") != risk_label:
                    continue
                if node not in pos3d:
                    continue
                xs.append(pos3d[node][0])
                ys.append(pos3d[node][1])
                zs.append(pos3d[node][2])
                ioc_count = data.get("ioc_count", 0)
                sizes.append(35 + min(ioc_count * 10, 220))
            if xs:
                ax.scatter(xs, ys, zs, c=color, s=sizes, marker="o",
                           alpha=0.82, edgecolors="none",
                           depthshade=True, label=risk_label, zorder=4)

        # Draw "unknown" risk nodes (no intel data available)
        xs, ys, zs, sizes = [], [], [], []
        for node, data in G.nodes(data=True):
            if data.get("kind") != "page":
                continue
            if data.get("risk", "unknown") != "unknown":
                continue
            if node not in pos3d:
                continue
            xs.append(pos3d[node][0])
            ys.append(pos3d[node][1])
            zs.append(pos3d[node][2])
            sizes.append(40)
        if xs:
            ax.scatter(xs, ys, zs, c=_RISK_COLORS["unknown"], s=sizes,
                       marker="o", alpha=0.6, edgecolors="none",
                       depthshade=True, label="No data", zorder=3)

    def _draw_site_labels(self, ax, G, pos3d, fg):
        """Annotate site hub nodes with a truncated hostname label."""
        for node, data in G.nodes(data=True):
            if data.get("kind") != "site":
                continue
            if node not in pos3d:
                continue
            x, y, z = pos3d[node]
            raw = node.replace("http://", "").replace("https://", "")
            label = (raw[:20] + "…") if len(raw) > 21 else raw
            ax.text(x, y, z + 0.08, label,
                    color=fg, fontsize=6, ha="center", va="bottom",
                    alpha=0.80, zorder=6)

    def _add_legend(self, ax, fig, bg, fg, dark):
        """Add a risk-level legend and a size legend."""
        import matplotlib.patches as mpatches
        risk_patches = [
            mpatches.Patch(color=_RISK_COLORS[lbl], label=lbl)
            for lbl in _RISK_ORDER
        ]
        legend = ax.legend(
            handles=risk_patches,
            loc="upper left",
            framealpha=0.25,
            fontsize=8,
            title="Risk Level",
        )
        if dark:
            legend.get_frame().set_facecolor(bg)
            legend.get_frame().set_edgecolor(_GRID)
            legend.get_title().set_color(fg)
            for text in legend.get_texts():
                text.set_color(fg)

    def _set_title(self, ax, results, G, fg):
        sites = {data.get("kind") == "site" for _, data in G.nodes(data=True)}
        n_sites = sum(1 for _, d in G.nodes(data=True) if d.get("kind") == "site")
        ax.set_title(
            f"3D Crawl Network — {len(results)} page(s) | "
            f"{n_sites} site(s)  "
            f"[★ = site hub  ● = page  size ∝ IOC count]",
            color=fg, fontsize=10, pad=14,
        )

    @staticmethod
    def _close(fig) -> None:
        """Close a figure to free resources (no-op if matplotlib not loaded)."""
        try:
            import matplotlib.pyplot as plt
            plt.close(fig)
        except Exception:
            pass
