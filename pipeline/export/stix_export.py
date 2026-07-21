"""
stix_export.py
Converts pipeline synthesis output into STIX 2.1 bundles.
Maps analysis data to standardized threat intelligence objects
for interoperability with MISP, OpenCTI, and enterprise TIP platforms.

Usage:
    python -m pipeline.export.stix_export <sha256>
    python -m pipeline.export.stix_export --all
"""

import sys
import json
import logging
import argparse
from pathlib import Path
from datetime import datetime, timezone

from stix2 import (
    Bundle,
    Malware,
    Indicator,
    AttackPattern,
    Relationship,
    Report,
    Identity,
    ExternalReference,
)
from stix2.exceptions import InvalidValueError

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

logger = logging.getLogger(__name__)

REPORTS_DIR = REPO_ROOT / "output" / "reports"
STIX_DIR = REPO_ROOT / "output" / "stix"

# Pipeline identity — the producer of this intelligence
PIPELINE_IDENTITY = Identity(
    name="Mal-Intel-Pipeline",
    identity_class="system",
    description="Automated malware analysis pipeline with human-in-the-loop review",
)


def load_synthesis(sha256: str) -> dict | None:
    """Load a synthesis JSON by SHA256 (exact or prefix match)."""
    path = REPORTS_DIR / f"{sha256}.synthesis.json"
    if not path.exists():
        matches = list(REPORTS_DIR.glob(f"{sha256}*.synthesis.json"))
        if not matches:
            return None
        path = matches[0]

    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def build_malware_object(sample: dict, synthesis: dict) -> Malware:
    """Create a STIX Malware SDO from sample metadata."""
    family = (sample.get("malware_family") or "unknown").lower()
    sha256 = sample.get("sha256", "unknown")
    file_name = sample.get("file_name", "unknown")
    file_type = sample.get("file_type", "unknown")
    tags = sample.get("tags", [])

    tech_report = synthesis.get("technical_report", {})
    description = tech_report.get("executive_summary", "No description available.")

    return Malware(
        name=family if family != "unknown" else f"malware-{sha256[:16]}",
        description=description,
        is_family=False,
        malware_types=_infer_malware_types(tags, family),
        created_by_ref=PIPELINE_IDENTITY.id,
        external_references=[
            ExternalReference(
                source_name="MalwareBazaar",
                url=f"https://bazaar.abuse.ch/sample/{sha256}/",
                description=f"Sample {sha256[:16]}",
            )
        ],
        labels=tags[:10] if tags else None,
    )


def _infer_malware_types(tags: list, family: str) -> list[str]:
    """Map pipeline tags to STIX malware-type-ov vocabulary."""
    type_map = {
        "stealer": "spyware",
        "infostealer": "spyware",
        "rat": "remote-access-trojan",
        "ransomware": "ransomware",
        "loader": "dropper",
        "dropper": "dropper",
        "backdoor": "backdoor",
        "worm": "worm",
        "trojan": "trojan",
        "botnet": "bot",
        "miner": "resource-exploitation",
        "wiper": "wiper",
        "keylogger": "keylogger",
        "rootkit": "rootkit",
        "downloader": "dropper",
        "banker": "spyware",
    }

    types = set()
    combined = [t.lower() for t in tags] + [family.lower()]
    for term in combined:
        for key, stix_type in type_map.items():
            if key in term:
                types.add(stix_type)

    return list(types) if types else ["unknown"]


def build_attack_patterns(ttp_mapping: dict) -> list[AttackPattern]:
    """Create STIX AttackPattern SDOs from TTP mapping."""
    patterns = []
    techniques = ttp_mapping.get("techniques", [])

    for tech in techniques:
        tech_id = tech.get("id", "")
        name = tech.get("name", "")
        tactic = tech.get("tactic", "")
        evidence = tech.get("evidence", "")

        if not tech_id or not name:
            continue

        ext_refs = []
        if tech_id.startswith("T"):
            ext_refs.append(ExternalReference(
                source_name="mitre-attack",
                external_id=tech_id,
                url=f"https://attack.mitre.org/techniques/{tech_id.replace('.', '/')}/",
            ))

        try:
            pattern = AttackPattern(
                name=name,
                description=f"Tactic: {tactic}. Evidence: {evidence}",
                created_by_ref=PIPELINE_IDENTITY.id,
                external_references=ext_refs if ext_refs else None,
            )
            patterns.append(pattern)
        except InvalidValueError as e:
            logger.warning(f"Skipped invalid AttackPattern {tech_id}: {e}")

    return patterns


def build_yara_indicator(sha256: str, yara_data: dict, malware_id: str) -> Indicator | None:
    """Create a STIX Indicator from a YARA rule."""
    rule = yara_data.get("rule", "")
    if not rule or rule == "[DRY RUN]":
        return None

    confidence_map = {"high": 85, "medium": 60, "low": 30}
    confidence_str = (yara_data.get("confidence") or "medium").lower()
    confidence = confidence_map.get(confidence_str, 50)

    return Indicator(
        name=f"YARA rule for {sha256[:16]}",
        description=yara_data.get("reasoning", ""),
        pattern=f"[file:hashes.'SHA-256' = '{sha256}']",
        pattern_type="stix",
        valid_from=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        confidence=confidence,
        created_by_ref=PIPELINE_IDENTITY.id,
        labels=["malicious-activity"],
        external_references=[
            ExternalReference(
                source_name="Mal-Intel-Pipeline",
                description=f"YARA rule confidence: {confidence_str}",
            )
        ],
    )


def build_sigma_indicator(sha256: str, sigma_data: dict) -> Indicator | None:
    """Create a STIX Indicator from a Sigma rule."""
    rule = sigma_data.get("rule", "")
    if not rule or rule == "[DRY RUN]":
        return None

    confidence_map = {"high": 85, "medium": 60, "low": 30}
    confidence_str = (sigma_data.get("confidence") or "medium").lower()
    confidence = confidence_map.get(confidence_str, 50)

    cs_notes = sigma_data.get("crowdstrike_notes", "")
    splunk_notes = sigma_data.get("splunk_notes", "")
    description = sigma_data.get("reasoning", "")
    if cs_notes:
        description += f"\n\nCrowdStrike: {cs_notes}"
    if splunk_notes:
        description += f"\n\nSplunk: {splunk_notes}"

    return Indicator(
        name=f"Sigma rule for {sha256[:16]}",
        description=description,
        pattern=f"[file:hashes.'SHA-256' = '{sha256}']",
        pattern_type="stix",
        valid_from=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        confidence=confidence,
        created_by_ref=PIPELINE_IDENTITY.id,
        labels=["malicious-activity"],
    )


def build_ioc_indicators(sha256: str, tech_report: dict) -> list[Indicator]:
    """Create STIX Indicators from key IOCs in the technical report."""
    indicators = []
    key_indicators = tech_report.get("key_indicators", [])

    for ioc in key_indicators:
        ioc_lower = ioc.lower()
        pattern = None
        indicator_type = None

        # Detect IOC type and build appropriate STIX pattern
        if ioc_lower.startswith("sha256:"):
            hash_val = ioc.split(":", 1)[1].strip()
            pattern = f"[file:hashes.'SHA-256' = '{hash_val}']"
            indicator_type = "file-hash"
        elif ioc_lower.startswith("import hash:"):
            hash_val = ioc.split(":", 1)[1].strip()
            pattern = f"[file:hashes.'IMPHASH' = '{hash_val}']"
            indicator_type = "file-hash"
        elif "://" in ioc:
            pattern = f"[url:value = '{ioc}']"
            indicator_type = "url"
        elif _is_ip(ioc):
            pattern = f"[ipv4-addr:value = '{ioc}']"
            indicator_type = "ipv4-addr"
        else:
            # Skip non-parseable indicators (registry keys, paths, etc.)
            continue

        if pattern:
            try:
                ind = Indicator(
                    name=f"IOC: {ioc[:60]}",
                    description=f"Key indicator from analysis of {sha256[:16]}",
                    pattern=pattern,
                    pattern_type="stix",
                    valid_from=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    created_by_ref=PIPELINE_IDENTITY.id,
                    labels=[indicator_type],
                )
                indicators.append(ind)
            except InvalidValueError as e:
                logger.warning(f"Skipped invalid IOC indicator '{ioc[:30]}': {e}")

    return indicators


def _is_ip(value: str) -> bool:
    """Simple check for IPv4 address format."""
    parts = value.strip().split(".")
    if len(parts) != 4:
        return False
    return all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


def build_relationships(
    malware_obj: Malware,
    attack_patterns: list[AttackPattern],
    indicators: list[Indicator],
) -> list[Relationship]:
    """Create STIX Relationships linking objects together."""
    relationships = []

    # Malware uses AttackPattern
    for ap in attack_patterns:
        relationships.append(Relationship(
            relationship_type="uses",
            source_ref=malware_obj.id,
            target_ref=ap.id,
            created_by_ref=PIPELINE_IDENTITY.id,
        ))

    # Indicator indicates Malware
    for ind in indicators:
        relationships.append(Relationship(
            relationship_type="indicates",
            source_ref=ind.id,
            target_ref=malware_obj.id,
            created_by_ref=PIPELINE_IDENTITY.id,
        ))

    return relationships


def export_stix(sha256: str) -> Path | None:
    """
    Full export pipeline: load synthesis → build STIX objects → save bundle.
    """
    print(f"\n{'='*60}")
    print(f"  STIX Export: {sha256[:32]}...")
    print(f"{'='*60}")

    synthesis = load_synthesis(sha256)
    if not synthesis:
        print(f"  [!] No synthesis found for {sha256[:16]}...")
        return None

    sample = synthesis.get("sample", {})
    syn = synthesis.get("synthesis", {})
    actual_sha256 = sample.get("sha256", sha256)

    if not syn:
        print("  [!] Synthesis data is empty")
        return None

    ttp_mapping = syn.get("ttp_mapping", {})
    yara_data = syn.get("yara_rule", {})
    sigma_data = syn.get("sigma_rule", {})
    tech_report = syn.get("technical_report", {})

    # Build all STIX objects
    objects = [PIPELINE_IDENTITY]

    # Malware SDO
    malware_obj = build_malware_object(sample, syn)
    objects.append(malware_obj)
    print(f"  [+] Malware object   : {malware_obj.name}")

    # Attack Patterns
    attack_patterns = build_attack_patterns(ttp_mapping)
    objects.extend(attack_patterns)
    print(f"  [+] Attack patterns  : {len(attack_patterns)}")

    # YARA Indicator
    yara_ind = build_yara_indicator(actual_sha256, yara_data, malware_obj.id)
    if yara_ind:
        objects.append(yara_ind)
        print(f"  [+] YARA indicator   : confidence {yara_data.get('confidence', 'unknown')}")

    # Sigma Indicator
    sigma_ind = build_sigma_indicator(actual_sha256, sigma_data)
    if sigma_ind:
        objects.append(sigma_ind)
        print(f"  [+] Sigma indicator  : confidence {sigma_data.get('confidence', 'unknown')}")

    # IOC Indicators
    ioc_indicators = build_ioc_indicators(actual_sha256, tech_report)
    objects.extend(ioc_indicators)
    print(f"  [+] IOC indicators   : {len(ioc_indicators)}")

    # Collect all indicators for relationships
    all_indicators = ioc_indicators[:]
    if yara_ind:
        all_indicators.append(yara_ind)
    if sigma_ind:
        all_indicators.append(sigma_ind)

    # Relationships
    relationships = build_relationships(malware_obj, attack_patterns, all_indicators)
    objects.extend(relationships)
    print(f"  [+] Relationships    : {len(relationships)}")

    # Wrap in Report
    object_refs = [obj.id for obj in objects if obj.id != PIPELINE_IDENTITY.id]
    family = (sample.get("malware_family") or "unknown").title()

    report = Report(
        name=f"Mal-Intel-Pipeline Analysis: {family} ({actual_sha256[:16]})",
        description=tech_report.get("executive_summary", "Automated malware analysis report."),
        published=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        object_refs=object_refs,
        created_by_ref=PIPELINE_IDENTITY.id,
        labels=["malware"],
    )
    objects.append(report)

    # Build and save bundle
    bundle = Bundle(objects=objects)

    STIX_DIR.mkdir(parents=True, exist_ok=True)
    out_path = STIX_DIR / f"{actual_sha256}.stix.json"
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(bundle.serialize(pretty=True))

    obj_count = len(objects)
    print(f"\n  [+] Bundle saved     : {out_path.name}")
    print(f"  [+] Total objects    : {obj_count}")
    print(f"  [+] Bundle ID        : {bundle.id}")
    print(f"{'='*60}")

    return out_path


def get_all_synthesis_hashes() -> list[str]:
    """Get SHA256 hashes for all synthesis files."""
    return [
        p.stem.replace(".synthesis", "")
        for p in REPORTS_DIR.glob("*.synthesis.json")
    ]


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.WARNING,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )

    parser = argparse.ArgumentParser(description="STIX 2.1 Export")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("sha256", nargs="?", help="SHA256 of sample to export")
    group.add_argument("--all", action="store_true", help="Export all synthesis files")
    args = parser.parse_args()

    if args.all:
        hashes = get_all_synthesis_hashes()
        print(f"Found {len(hashes)} synthesis file(s)")
        for h in hashes:
            export_stix(h)
    else:
        export_stix(args.sha256)