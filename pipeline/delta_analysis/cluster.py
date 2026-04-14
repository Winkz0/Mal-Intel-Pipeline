"""
cluster.py
M10 Corpus Clustering Engine.
Uses TF-IDF and DBSCAN to naturally group malware samples based on 
their MITRE ATT&CK TTPs and notable static strings.
"""

import sys
import json
import logging
import argparse
from pathlib import Path
from collections import defaultdict
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.cluster import DBSCAN

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

ANALYSIS_DIR = REPO_ROOT / "output" / "analysis"
REPORTS_DIR = REPO_ROOT / "output" / "reports"

logger = logging.getLogger(__name__)

def load_corpus() -> list[dict]:
    """Loads all analyzed JSON samples from the output directory."""
    corpus = []
    if not ANALYSIS_DIR.exists():
        return corpus
        
    for path in ANALYSIS_DIR.glob("*.analysis.json"):
        try:
            with open(path, "r", encoding="utf-8") as f:
                corpus.append(json.load(f))
        except Exception as e:
            logger.error(f"Failed to load {path.name}: {e}")
    return corpus

def extract_features(sample: dict) -> str:
    """
    Extracts high-value features (TTPs and Strings) and flattens them 
    into a single 'document' string for TF-IDF vectorization.
    """
    features = []

    # 1. Extract MITRE ATT&CK TTPs
    capa = sample.get("capa_result", {})
    for ttp in capa.get("attack", []):
        features.append(ttp.get("id", ""))
        features.append(ttp.get("technique", "").replace(" ", "_"))

    # 2. Extract Notable Strings
    floss = sample.get("floss_result", {})
    notable = floss.get("summary", {}).get("notable", [])
    features.extend(notable)

    # 3. Combine into a space-separated document
    return " ".join(features)

def run_clustering(eps: float = 0.5, min_samples: int = 2):
    print(f"\n{'='*60}")
    print(f"  M10: DBSCAN Corpus Clustering")
    print(f"{'='*60}")

    corpus = load_corpus()
    if not corpus:
        print("  [!] No analysis files found. Run M6 (analyze.py) first.")
        return

    print(f"  [*] Loaded {len(corpus)} samples for clustering.")

    # 1. Feature Extraction
    documents = []
    metadata = []
    
    for sample in corpus:
        doc = extract_features(sample)
        documents.append(doc)
        
        meta = sample.get("meta", {})
        metadata.append({
            "sha256": meta.get("sha256", "unknown"),
            "family": meta.get("malware_family", "unknown"),
            "tags": meta.get("tags", [])
        })

    # 2. Vectorization (TF-IDF)
    # This converts our text 'documents' into a mathematical matrix
    print("  [*] Vectorizing features (TF-IDF)...")
    vectorizer = TfidfVectorizer(max_features=2000, stop_words='english')
    try:
        X = vectorizer.fit_transform(documents)
    except ValueError:
        print("  [!] Not enough feature diversity to cluster. Add more samples.")
        return

    # 3. DBSCAN Execution
    print(f"  [*] Running DBSCAN (eps={eps}, min_samples={min_samples})...")
    dbscan = DBSCAN(eps=eps, min_samples=min_samples)
    labels = dbscan.fit_predict(X)

    # 4. Grouping Results
    clusters = defaultdict(list)
    for idx, label in enumerate(labels):
        clusters[int(label)].append(metadata[idx])

    # 5. Output Formatting
    noise = clusters.pop(-1, []) # DBSCAN labels outliers/noise as -1
    
    report = {
        "parameters": {"eps": eps, "min_samples": min_samples},
        "total_samples": len(corpus),
        "total_clusters": len(clusters),
        "noise_samples": len(noise),
        "clusters": clusters,
        "noise": noise
    }

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    out_path = REPORTS_DIR / "corpus_clusters.json"
    
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    # 6. Console Summary
    print(f"\n  [+] Clustering Complete. Found {len(clusters)} distinct clusters.")
    
    for cluster_id, members in sorted(clusters.items()):
        families = set([m['family'] for m in members])
        print(f"      Cluster {cluster_id}: {len(members)} samples | Dominant Families: {', '.join(families)}")
    
    print(f"      Noise (Unique/Unclustered): {len(noise)} samples")
    print(f"\n  [+] Cluster report saved: {out_path.name}")
    print(f"{'='*60}")

if __name__ == "__main__":
    logging.basicConfig(level=logging.WARNING)

    parser = argparse.ArgumentParser(description="M10 DBSCAN Clustering Engine")
    parser.add_argument("--eps", type=float, default=0.6, 
                        help="DBSCAN epsilon (max distance between samples in a cluster). Higher = looser clusters.")
    parser.add_argument("--min-samples", type=int, default=2, 
                        help="Minimum samples required to form a cluster.")
    args = parser.parse_args()

    run_clustering(eps=args.eps, min_samples=args.min_samples)