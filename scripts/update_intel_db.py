"""
Threat Intelligence Database Update Script

Downloads and updates the local threat intelligence database from multiple free sources:
- Abuse.ch SSL Blacklist
- URLhaus
- Emerging Threats
- Blocklist.de
- Feodo Tracker
- MalwareBazaar
- CINSSCORE
- Talos Intelligence

Usage:
    python scripts/update_intel_db.py
    python scripts/update_intel_db.py --stats-only
"""

import sys
import sqlite3
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Set
import argparse

try:
    import requests
except ImportError:
    print("ERROR: 'requests' library not found.")
    print("Install it with: pip install requests")
    sys.exit(1)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Database path
ROOT = Path(__file__).parent.parent
DB_PATH = ROOT / "data" / "threat_intel.db"

# Threat intelligence feeds (all free)
FEEDS = {
    "abuse_ssl": {
        "url": "https://sslbl.abuse.ch/blacklist/sslipblacklist.txt",
        "type": "ip",
        "description": "SSL Blacklist - Malicious SSL certificates"
    },
    "urlhaus": {
        "url": "https://urlhaus.abuse.ch/downloads/text/",
        "type": "domain",
        "description": "URLhaus - Malware distribution sites"
    },
    "feodo_tracker": {
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
        "type": "ip",
        "description": "Feodo Tracker - Botnet C2 servers"
    },
    "blocklist_de": {
        "url": "https://lists.blocklist.de/lists/all.txt",
        "type": "ip",
        "description": "Blocklist.de - Attack sources"
    },
    "cinsscore": {
        "url": "https://cinsscore.com/list/ci-badguys.txt",
        "type": "ip",
        "description": "CINSSCORE - Bad actors"
    },
}


def init_database():
    """Initialize the threat intelligence database."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    
    conn = sqlite3.connect(str(DB_PATH))
    cursor = conn.cursor()
    
    # Create tables
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS threat_intel (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            indicator TEXT UNIQUE NOT NULL,
            type TEXT NOT NULL,
            source TEXT NOT NULL,
            first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            reputation TEXT DEFAULT 'malicious',
            confidence REAL DEFAULT 0.8,
            description TEXT
        )
    """)
    
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_indicator ON threat_intel(indicator)
    """)
    
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_type ON threat_intel(type)
    """)
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS update_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            feed_name TEXT NOT NULL,
            update_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            indicators_added INTEGER,
            status TEXT
        )
    """)
    
    conn.commit()
    conn.close()
    
    logger.info(f"✓ Database initialized: {DB_PATH}")


def download_feed(feed_name: str, feed_config: Dict) -> Set[str]:
    """Download and parse a threat intelligence feed."""
    try:
        logger.info(f"Downloading {feed_name}...")
        response = requests.get(feed_config["url"], timeout=30)
        response.raise_for_status()
        
        indicators = set()
        for line in response.text.splitlines():
            line = line.strip()
            
            # Skip comments and empty lines
            if not line or line.startswith('#') or line.startswith(';'):
                continue
            
            # Extract IP or domain
            if feed_config["type"] == "ip":
                # Remove CIDR notation if present
                indicator = line.split('/')[0].split()[0]
            elif feed_config["type"] == "domain":
                # Extract domain from URL
                indicator = line.replace('http://', '').replace('https://', '').split('/')[0]
            else:
                indicator = line
            
            if indicator:
                indicators.add(indicator)
        
        logger.info(f"  Downloaded {len(indicators)} indicators from {feed_name}")
        return indicators
        
    except Exception as e:
        logger.error(f"  Failed to download {feed_name}: {e}")
        return set()


def update_database(feed_name: str, indicators: Set[str], feed_type: str, description: str) -> int:
    """Update the database with new indicators."""
    if not indicators:
        return 0
    
    conn = sqlite3.connect(str(DB_PATH))
    cursor = conn.cursor()
    
    added = 0
    for indicator in indicators:
        try:
            cursor.execute("""
                INSERT INTO threat_intel (indicator, type, source, description, reputation, confidence)
                VALUES (?, ?, ?, ?, 'malicious', 0.8)
                ON CONFLICT(indicator) DO UPDATE SET
                    last_seen = CURRENT_TIMESTAMP,
                    source = source || ',' || ?
            """, (indicator, feed_type, feed_name, description, feed_name))
            
            if cursor.rowcount > 0:
                added += 1
                
        except Exception as e:
            logger.debug(f"Error inserting {indicator}: {e}")
            continue
    
    # Record update history
    cursor.execute("""
        INSERT INTO update_history (feed_name, indicators_added, status)
        VALUES (?, ?, 'success')
    """, (feed_name, added))
    
    conn.commit()
    conn.close()
    
    logger.info(f"  Added {added} new indicators to database")
    return added


def get_statistics() -> Dict:
    """Get database statistics."""
    conn = sqlite3.connect(str(DB_PATH))
    cursor = conn.cursor()
    
    # Total indicators
    cursor.execute("SELECT COUNT(*) FROM threat_intel")
    total = cursor.fetchone()[0]
    
    # By type
    cursor.execute("""
        SELECT type, COUNT(*) 
        FROM threat_intel 
        GROUP BY type
    """)
    by_type = dict(cursor.fetchall())
    
    # By source
    cursor.execute("""
        SELECT source, COUNT(*)
        FROM threat_intel
        GROUP BY source
        ORDER BY COUNT(*) DESC
        LIMIT 10
    """)
    by_source = cursor.fetchall()
    
    # Last update
    cursor.execute("""
        SELECT MAX(update_time)
        FROM update_history
    """)
    last_update = cursor.fetchone()[0]
    
    conn.close()
    
    return {
        "total": total,
        "by_type": by_type,
        "by_source": by_source,
        "last_update": last_update
    }


def print_statistics():
    """Print database statistics."""
    stats = get_statistics()
    
    print("\n" + "="*60)
    print("Threat Intelligence Database Statistics")
    print("="*60)
    print(f"\nTotal Indicators: {stats['total']:,}")
    
    print("\nBy Type:")
    for ioc_type, count in stats['by_type'].items():
        print(f"  {ioc_type:15s}: {count:,}")
    
    print("\nTop Sources:")
    for source, count in stats['by_source']:
        source_name = source.split(',')[0]  # Get first source
        print(f"  {source_name:20s}: {count:,}")
    
    if stats['last_update']:
        print(f"\nLast Update: {stats['last_update']}")
    
    print("="*60 + "\n")


def main(args):
    """Main function."""
    logger.info("="*60)
    logger.info("ThreatOps Threat Intelligence Database Updater")
    logger.info("="*60)
    
    # Initialize database
    init_database()
    
    # If stats only, just print and exit
    if args.stats_only:
        print_statistics()
        return 0
    
    # Download and update from each feed
    total_added = 0
    
    for feed_name, feed_config in FEEDS.items():
        logger.info(f"\nProcessing feed: {feed_config['description']}")
        
        indicators = download_feed(feed_name, feed_config)
        
        if indicators:
            added = update_database(
                feed_name,
                indicators,
                feed_config["type"],
                feed_config["description"]
            )
            total_added += added
    
    # Print final statistics
    logger.info("\n" + "="*60)
    logger.info(f"✓ Update complete! Added {total_added:,} new indicators")
    logger.info("="*60)
    
    print_statistics()
    
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Update threat intelligence database")
    parser.add_argument("--stats-only", action="store_true", help="Only show statistics, don't update")
    args = parser.parse_args()
    
    try:
        sys.exit(main(args))
    except KeyboardInterrupt:
        logger.info("\n\nUpdate interrupted by user")
        sys.exit(130)
    except Exception as e:
        logger.exception(f"\nFatal error during update: {e}")
        sys.exit(1)

