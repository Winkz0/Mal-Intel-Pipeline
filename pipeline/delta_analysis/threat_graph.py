"""
threat_graph.py
Builds an interactive threat relationship graph from delta analysis data.
Nodes = samples, edges = overlap relationships above a score threshold.
Outputs a self-contained HTML file viewable in browser or embedded in Streamlit.
"""

import json
import logging
import argparse
from pathlib import Path
from collections import defaultdict

from pyvis.network import Network

logger = logging.getLogger(__name__)

REPO_ROOT = Path(__file__).resolve().parents[2]
REPORTS_DIR = REPO_ROOT / "output" / "reports"
OUTPUT_DIR = REPO_ROOT / "output" / "graphs"

# Color palette for families — extends automatically for unknown families
FAMILY_COLORS = {
    "smokeloader": "#e74c3c",
    "acrstealer": "#e67e22",
    "lumma": "#f1c40f",
    "redline": "#9b59b6",
    "asyncrat": "#2ecc71",
    "remcos": "#3498db",
    "amadey": "#1abc9c",
    "formbook": "#e91e63",
    "agent tesla": "#00bcd4",
    "raccoon": "#ff5722",
    "vidar": "#795548",
    "unknown": "#95a5a6",
}

# Fallback colors for families not in the palette
EXTRA_COLORS = [
    "#d35400", "#8e44ad", "#2c3e50", "#16a085",
    "#c0392b", "#27ae60", "#2980b9", "#f39c12",
]


def get_family_color(family: str, seen: dict) -> str:
    """Assign a consistent color to each family."""
    key = family.lower()
    if key in FAMILY_COLORS:
        return FAMILY_COLORS[key]
    if key not in seen:
        idx = len(seen) % len(EXTRA_COLORS)
        seen[key] = EXTRA_COLORS[idx]
    return seen[key]


def load_all_deltas() -> list[dict]:
    """Load all delta JSON files from the reports directory."""
    deltas = []
    if not REPORTS_DIR.exists():
        return deltas
    for path in REPORTS_DIR.glob("*.delta.json"):
        try:
            with open(path, "r", encoding="utf-8") as f:
                deltas.append(json.load(f))
        except Exception as e:
            logger.warning(f"Failed to load {path.name}: {e}")
    return deltas


def build_graph_data(deltas: list[dict], min_score: int = 5) -> dict:
    """
    Extract nodes and edges from delta data.
    Only creates edges where overlap_score >= min_score.
    Deduplicates bidirectional edges (A->B and B->A become one edge).
    """
    nodes = {}  # sha256 -> {family, label, connections}
    edges = {}  # frozenset(sha_a, sha_b) -> {score, shared_ttps, shared_caps, ...}

    for delta in deltas:
        sha = delta.get("sha256", "unknown")
        family = delta.get("family", "unknown")

        if sha not in nodes:
            nodes[sha] = {"family": family, "connections": 0}

        for comp in delta.get("comparisons", []):
            comp_sha = comp.get("compared_sha256", "unknown")
            comp_family = comp.get("compared_family", "unknown")
            score = comp.get("overlap_score", 0)

            if score < min_score:
                continue

            if comp_sha not in nodes:
                nodes[comp_sha] = {"family": comp_family, "connections": 0}

            # Deduplicate edges
            edge_key = frozenset([sha, comp_sha])
            if edge_key not in edges or edges[edge_key]["score"] < score:
                edges[edge_key] = {
                    "source": sha,
                    "target": comp_sha,
                    "score": score,
                    "same_family": comp.get("same_family", False),
                    "shared_ttps": comp.get("shared_attack_ttps", []),
                    "shared_capabilities": comp.get("shared_capabilities", []),
                    "shared_notable_strings": comp.get("shared_notable_strings", []),
                    "same_imphash": comp.get("same_imphash", False),
                    "shared_string_count": comp.get("shared_string_count", 0),
                }

            nodes[sha]["connections"] += 1
            nodes[comp_sha]["connections"] += 1

    return {"nodes": nodes, "edges": edges}


def render_graph(
    graph_data: dict,
    output_path: Path = None,
    height: str = "700px",
    width: str = "100%",
    title: str = "Mal-Intel Threat Graph",
) -> Path:
    """
    Render an interactive Pyvis network graph from the extracted data.
    Returns the path to the generated HTML file.
    """
    nodes = graph_data["nodes"]
    edges = graph_data["edges"]

    if not nodes:
        logger.warning("No nodes to graph — run delta analysis first")
        return None

    net = Network(
        height=height,
        width=width,
        bgcolor="#1a1a2e",
        font_color="#e0e0e0",
        directed=False,
        heading=title,
    )

    # Physics settings for readable layout
    net.set_options("""
    {
        "physics": {
            "forceAtlas2Based": {
                "gravitationalConstant": -80,
                "centralGravity": 0.01,
                "springLength": 150,
                "springConstant": 0.08,
                "damping": 0.4
            },
            "solver": "forceAtlas2Based",
            "stabilization": {
                "iterations": 200
            }
        },
        "interaction": {
            "hover": true,
            "tooltipDelay": 100,
            "zoomView": true,
            "dragView": true
        },
        "edges": {
            "smooth": {
                "type": "continuous"
            }
        }
    }
    """)

    color_tracker = {}

    # Add nodes
    for sha, info in nodes.items():
        family = info["family"]
        color = get_family_color(family, color_tracker)
        connections = info["connections"]

        # Scale node size by connection count (min 15, max 50)
        size = min(15 + connections * 3, 50)

        label = f"{family.title()}\n{sha[:12]}"
        hover_title = (
            f"<b>{family.title()}</b><br>"
            f"SHA256: {sha[:32]}...<br>"
            f"Connections: {connections}"
        )

        net.add_node(
            sha,
            label=label,
            title=hover_title,
            color=color,
            size=size,
            borderWidth=2,
            borderWidthSelected=4,
        )

    # Add edges
    for edge_key, info in edges.items():
        source = info["source"]
        target = info["target"]
        score = info["score"]

        # Scale edge width by score (min 1, max 8)
        width = min(1 + score / 15, 8)

        # Color: green if same family, orange if cross-family
        edge_color = "#2ecc71" if info["same_family"] else "#e67e22"

        # Build hover tooltip
        tooltip_parts = [f"<b>Overlap Score: {score}</b>"]
        if info["shared_ttps"]:
            tooltip_parts.append(f"Shared TTPs: {', '.join(info['shared_ttps'][:10])}")
        if info["shared_capabilities"]:
            tooltip_parts.append(f"Shared Capabilities: {', '.join(info['shared_capabilities'][:10])}")
        if info["same_imphash"]:
            tooltip_parts.append("Same Import Hash")
        if info["shared_string_count"] > 0:
            tooltip_parts.append(f"Shared Strings: {info['shared_string_count']}")

        net.add_edge(
            source,
            target,
            value=width,
            title="<br>".join(tooltip_parts),
            color=edge_color,
        )

    # Save
    if output_path is None:
        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        output_path = OUTPUT_DIR / "threat_graph.html"
    else:
        output_path.parent.mkdir(parents=True, exist_ok=True)

    net.save_graph(str(output_path))
    logger.info(f"Graph saved: {output_path}")
    return output_path


def generate_threat_graph(min_score: int = 5) -> Path:
    """Full pipeline: load deltas → build graph data → render HTML."""
    print(f"\n{'='*60}")
    print(f"  Threat Graph Generator")
    print(f"{'='*60}")

    deltas = load_all_deltas()
    if not deltas:
        print("  [!] No delta JSON files found. Run delta analysis first.")
        return None

    print(f"  [*] Loaded {len(deltas)} delta report(s)")

    graph_data = build_graph_data(deltas, min_score=min_score)
    node_count = len(graph_data["nodes"])
    edge_count = len(graph_data["edges"])

    print(f"  [*] Graph: {node_count} nodes, {edge_count} edges (min_score={min_score})")

    if node_count == 0:
        print("  [!] No relationships above threshold. Try lowering --min-score.")
        return None

    output_path = render_graph(graph_data)
    if output_path:
        print(f"  [+] Graph saved: {output_path}")
        print(f"  [+] Open in browser to interact")
    print(f"{'='*60}")
    return output_path


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )

    parser = argparse.ArgumentParser(description="Threat Relationship Graph Generator")
    parser.add_argument(
        "--min-score", type=int, default=5,
        help="Minimum overlap score to draw an edge (default: 5)"
    )
    args = parser.parse_args()

    generate_threat_graph(min_score=args.min_score)