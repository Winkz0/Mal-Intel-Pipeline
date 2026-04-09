"""
cache.py
Simple file-based feed cache with TTL
Caches raw feed responses to avoid redundant API calls
during repeat ingestion runs within the same session
"""

import json
import logging
import os
from pathlib import Path
from datetime import datetime,timezone

logger = logging.getLogger(__name__)

REPO_ROOT = Path(__file__).resolve().parents[2]
CACHE_DIR = REPO_ROOT / "output" / "logs" / "cache"
DEFAULT_TTL_HOURS = 12


def _cache_path(feed_name: str) -> Path:
    return CACHE_DIR/ f"{feed_name}.cache.json"
    
    
def get_cached(feed_name: str, ttl_hours: int = DEFAULT_TTL_HOURS) -> list[dict] | None:
    """
    Return cached feed data if it exists and is within TTL.
    Returns None if cache is missing, expired, or corrupt.
    """
    path = _cache_path(feed_name)
    if not path.exists():
        return None
        
    try:
        with open(path, "r") as f:
            cached = json.load(f)
            
        cached_at = datetime.fromisoformat(cached["cached_at"])
        age_hours = (datetime.now(timezone.utc) - cached_at).total_seconds() / 3600
        
        if age_hours > ttl_hours:
            logger.info(f"Cache expired for {feed_name} ({age_hours:.1f}h old, TTL={ttl_hours}h)")
            return None
            
        logger.info(f"Cache hit for {feed_name} ({age_hours:.1f}h old, {len(cached['data'])} entries)")
        return cached["data"]
    
    except (json.JSONDecodeError, KeyError, ValueError) as e:
        logger.warning(f"Cache corrupt for {feed_name}: {e}")
        return None
        
        
def set_cache(feed_name: str, data: list[dict]):
    """Save feed data to cache."""
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    path = _cache_path(feed_name)
    
    cached = {
        "feed": feed_name,
        "cached_at": datetime.now(timezone.utc).isoformat(),
        "count": len(data),
        "data": data,
    }
    
    with open(path, "w") as f:
        json.dump(cached, f, indent=2)
        
    logger.info(f"Cached {len(data)} entries for {feed_name}")
    
    
def clear_cache(feed_name: str = None):
    """Clear cache for specific feed, or all feeds if no name given."""
    if feed_name:
        path = _cache_path(feed_name)
        if path.exists():
            path.unlink()
            logger.info(f"Cache cleared for {feed_name}")
    else:
        if CACHE_DIR.exists():
            for f in CACHE_DIR.glob("*.cache.json"):
                f.unlink()
            logger.info("ALL feed caches cleared")
            