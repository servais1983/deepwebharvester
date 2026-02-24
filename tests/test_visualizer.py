"""
Tests for deepwebharvester.visualizer — 3D network graph rendering.
"""
from __future__ import annotations

import base64
from pathlib import Path

import pytest

from deepwebharvester.crawler import CrawlResult
from deepwebharvester.visualizer import GraphVisualizer, _RISK_COLORS, _RISK_ORDER

# ---------------------------------------------------------------------------
# Skip gracefully if matplotlib / networkx are not installed
# ---------------------------------------------------------------------------

try:
    import matplotlib  # noqa: F401
    import networkx    # noqa: F401
    _VIZ_AVAILABLE = True
except ImportError:
    _VIZ_AVAILABLE = False

pytestmark = pytest.mark.skipif(
    not _VIZ_AVAILABLE,
    reason="matplotlib and networkx required for visualizer tests",
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

SITE_A = "http://" + "a" * 56 + ".onion"
SITE_B = "http://" + "b" * 56 + ".onion"


def _result(
    url: str,
    site: str,
    depth: int = 0,
    title: str = "Test",
    text: str = "hello",
    ioc_count: int = 0,
) -> CrawlResult:
    return CrawlResult(
        url=url,
        site=site,
        title=title,
        text=text,
        depth=depth,
        crawl_time=0.5,
        links_found=3,
        content_hash="a" * 64,
    )


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

class TestConstants:
    def test_risk_colors_has_all_labels(self):
        for label in ("Low", "Medium", "High", "Critical", "unknown"):
            assert label in _RISK_COLORS

    def test_risk_colors_are_hex(self):
        for color in _RISK_COLORS.values():
            assert color.startswith("#")
            assert len(color) == 7

    def test_risk_order(self):
        assert _RISK_ORDER == ["Low", "Medium", "High", "Critical"]


# ---------------------------------------------------------------------------
# GraphVisualizer._build_graph()
# ---------------------------------------------------------------------------

class TestBuildGraph:
    def test_site_nodes_added(self):
        viz = GraphVisualizer()
        results = [_result(SITE_A + "/p1", SITE_A)]
        G = viz._build_graph(results, {})
        assert SITE_A in G.nodes

    def test_page_nodes_added(self):
        viz = GraphVisualizer()
        url = SITE_A + "/page1"
        results = [_result(url, SITE_A)]
        G = viz._build_graph(results, {})
        assert url in G.nodes

    def test_edge_from_site_to_page(self):
        viz = GraphVisualizer()
        url = SITE_A + "/page1"
        results = [_result(url, SITE_A)]
        G = viz._build_graph(results, {})
        assert G.has_edge(SITE_A, url)

    def test_site_kind_attribute(self):
        viz = GraphVisualizer()
        results = [_result(SITE_A + "/", SITE_A)]
        G = viz._build_graph(results, {})
        assert G.nodes[SITE_A]["kind"] == "site"

    def test_page_kind_attribute(self):
        viz = GraphVisualizer()
        url = SITE_A + "/p"
        results = [_result(url, SITE_A)]
        G = viz._build_graph(results, {})
        assert G.nodes[url]["kind"] == "page"

    def test_multiple_sites(self):
        viz = GraphVisualizer()
        results = [
            _result(SITE_A + "/p1", SITE_A),
            _result(SITE_B + "/p1", SITE_B),
        ]
        G = viz._build_graph(results, {})
        assert SITE_A in G.nodes
        assert SITE_B in G.nodes

    def test_site_page_count_stored(self):
        viz = GraphVisualizer()
        results = [
            _result(SITE_A + "/p1", SITE_A),
            _result(SITE_A + "/p2", SITE_A),
        ]
        G = viz._build_graph(results, {})
        assert G.nodes[SITE_A]["page_count"] == 2

    def test_no_intel_risk_is_unknown(self):
        viz = GraphVisualizer()
        url = SITE_A + "/p"
        results = [_result(url, SITE_A)]
        G = viz._build_graph(results, {})
        assert G.nodes[url]["risk"] == "unknown"

    def test_empty_results(self):
        viz = GraphVisualizer()
        G = viz._build_graph([], {})
        assert len(G.nodes) == 0


# ---------------------------------------------------------------------------
# GraphVisualizer._compute_layout()
# ---------------------------------------------------------------------------

class TestComputeLayout:
    def test_empty_graph_returns_empty(self):
        import networkx as nx
        viz = GraphVisualizer()
        G = nx.DiGraph()
        pos = viz._compute_layout(G)
        assert pos == {}

    def test_single_node(self):
        import networkx as nx
        viz = GraphVisualizer()
        G = nx.DiGraph()
        G.add_node("only")
        pos = viz._compute_layout(G)
        assert "only" in pos
        assert len(pos["only"]) == 3

    def test_all_nodes_have_3d_positions(self):
        import networkx as nx
        viz = GraphVisualizer()
        results = [
            _result(SITE_A + "/p1", SITE_A),
            _result(SITE_A + "/p2", SITE_A),
            _result(SITE_B + "/p1", SITE_B),
        ]
        G = viz._build_graph(results, {})
        pos = viz._compute_layout(G)
        for node in G.nodes:
            assert node in pos
            xyz = pos[node]
            assert len(xyz) == 3
            assert all(isinstance(v, float) for v in xyz)

    def test_positions_are_finite(self):
        import math
        import networkx as nx
        viz = GraphVisualizer()
        results = [_result(SITE_A + f"/p{i}", SITE_A) for i in range(5)]
        G = viz._build_graph(results, {})
        pos = viz._compute_layout(G)
        for node, xyz in pos.items():
            for v in xyz:
                assert math.isfinite(v), f"Non-finite position for {node}: {xyz}"


# ---------------------------------------------------------------------------
# GraphVisualizer.build_figure()
# ---------------------------------------------------------------------------

class TestBuildFigure:
    def test_returns_figure_object(self):
        from matplotlib.figure import Figure
        viz = GraphVisualizer()
        results = [_result(SITE_A + "/p1", SITE_A)]
        fig = viz.build_figure(results)
        assert isinstance(fig, Figure)

    def test_figure_has_3d_axes(self):
        from mpl_toolkits.mplot3d import Axes3D
        viz = GraphVisualizer()
        results = [_result(SITE_A + "/p1", SITE_A)]
        fig = viz.build_figure(results)
        ax = fig.axes[0]
        assert isinstance(ax, Axes3D)

    def test_empty_results(self):
        from matplotlib.figure import Figure
        viz = GraphVisualizer()
        fig = viz.build_figure([])
        assert isinstance(fig, Figure)

    def test_multiple_sites_and_pages(self):
        from matplotlib.figure import Figure
        viz = GraphVisualizer()
        results = [
            _result(SITE_A + "/p1", SITE_A, depth=0),
            _result(SITE_A + "/p2", SITE_A, depth=1),
            _result(SITE_B + "/p1", SITE_B, depth=0),
        ]
        fig = viz.build_figure(results)
        assert isinstance(fig, Figure)

    def test_light_theme(self):
        from matplotlib.figure import Figure
        viz = GraphVisualizer()
        results = [_result(SITE_A + "/p1", SITE_A)]
        fig = viz.build_figure(results, dark=False)
        assert isinstance(fig, Figure)

    def test_custom_figsize(self):
        viz = GraphVisualizer()
        results = [_result(SITE_A + "/p1", SITE_A)]
        fig = viz.build_figure(results, figsize=(8, 6))
        w, h = fig.get_size_inches()
        assert (w, h) == (8.0, 6.0)


# ---------------------------------------------------------------------------
# GraphVisualizer.to_png_base64()
# ---------------------------------------------------------------------------

class TestToPngBase64:
    def test_returns_string(self):
        viz = GraphVisualizer()
        results = [_result(SITE_A + "/p1", SITE_A)]
        b64 = viz.to_png_base64(results)
        assert isinstance(b64, str)
        assert len(b64) > 0

    def test_valid_base64(self):
        viz = GraphVisualizer()
        results = [_result(SITE_A + "/p1", SITE_A)]
        b64 = viz.to_png_base64(results)
        # Should decode without error
        data = base64.b64decode(b64)
        assert data[:8] == b"\x89PNG\r\n\x1a\n"  # PNG magic bytes

    def test_empty_results(self):
        viz = GraphVisualizer()
        b64 = viz.to_png_base64([])
        assert isinstance(b64, str)
        assert len(b64) > 0


# ---------------------------------------------------------------------------
# GraphVisualizer.save_png()
# ---------------------------------------------------------------------------

class TestSavePng:
    def test_creates_file(self, tmp_path):
        viz = GraphVisualizer()
        results = [_result(SITE_A + "/p1", SITE_A)]
        out = tmp_path / "graph.png"
        path = viz.save_png(results, output_path=str(out))
        assert path.exists()

    def test_returns_path_object(self, tmp_path):
        viz = GraphVisualizer()
        results = [_result(SITE_A + "/p1", SITE_A)]
        path = viz.save_png(results, output_path=str(tmp_path / "g.png"))
        assert isinstance(path, Path)

    def test_creates_parent_dirs(self, tmp_path):
        viz = GraphVisualizer()
        results = [_result(SITE_A + "/p1", SITE_A)]
        deep = tmp_path / "a" / "b" / "c" / "graph.png"
        viz.save_png(results, output_path=str(deep))
        assert deep.exists()

    def test_png_magic_bytes(self, tmp_path):
        viz = GraphVisualizer()
        results = [_result(SITE_A + "/p1", SITE_A)]
        out = tmp_path / "graph.png"
        viz.save_png(results, output_path=str(out))
        with open(out, "rb") as f:
            header = f.read(8)
        assert header == b"\x89PNG\r\n\x1a\n"

    def test_empty_results_still_saves(self, tmp_path):
        viz = GraphVisualizer()
        out = tmp_path / "empty.png"
        viz.save_png([], output_path=str(out))
        assert out.exists()
