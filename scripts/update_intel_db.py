#!/usr/bin/env python3
"""
Threat Intelligence Feed Updater for ThreatOps SOC
This script downloads free threat intelligence feeds and updates the local database.
Run this daily via cron/task scheduler to keep threat intel fresh.
"""

import asyncio
import aiohttp
import logging
import sqlite3
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any
import re

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class ThreatFeedUpdater:
    """Download and update threat intelligence feeds"""
    
    def __init__(self, db_path: str = "data/threat_intel.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.session = None
        
        # Free threat intelligence feed URLs
        self.feeds = {
            'abuse_ch_malware_ips': {
                'url': 'https://sslbl.abuse.ch/blacklist/sslipblacklist.txt',
                'type': 'ip',
                'format': 'plain',
                'reputation': 'malicious',
                'source': 'abuse.ch'
            },
            'abuse_ch_malware_domains': {
                'url': 'https://urlhaus.abuse.ch/downloads/text/',
                'type': 'domain',
                'format': 'plain',
                'reputation': 'malicious',
                'source': 'abuse.ch'
            },
            'emergingthreats_compromised': {
                'url': 'https://rules.emergingthreats.net/blockrules/compromised-ips.txt',
                'type': 'ip',
                'format': 'plain',
                'reputation': 'malicious',
                'source': 'emerging_threats'
            },
            'blocklist_de_all': {
                'url': 'https://lists.blocklist.de/lists/all.txt',
                'type': 'ip',
                'format': 'plain',
                'reputation': 'malicious',
                'source': 'blocklist.de'
            },
            'feodotracker_ips': {
                'url': 'https://feodotracker.abuse.ch/downloads/ipblocklist.txt',
                'type': 'ip',
                'format': 'plain',
                'reputation': 'malicious',
                'source': 'feodo_tracker'
            },
            'malware_bazaar_hashes': {
                'url': 'https://bazaar.abuse.ch/export/txt/md5/recent/',
                'type': 'hash',
                'format': 'plain',
                'reputation': 'malicious',
                'source': 'malware_bazaar'
            },
            'cinsscore_badguys': {
                'url': 'https://cinsscore.com/list/ci-badguys.txt',
                'type': 'ip',
                'format': 'plain',
                'reputation': 'malicious',
                'source': 'cinsscore'
            },
            'talos_ip_blacklist': {
                'url': 'https://www.talosintelligence.com/documents/ip-blacklist',
                'type': 'ip',
                'format': 'plain',
                'reputation': 'malicious',
                'source': 'talos'
            }
        }
    
    async def initialize(self):
        """Initialize HTTP session"""
        timeout = aiohttp.ClientTimeout(total=60)
        self.session = aiohttp.ClientSession(timeout=timeout)
    
    async def close(self):
        """Close HTTP session"""
        if self.session:
            await self.session.close()
    
    async def download_feed(self, feed_name: str, feed_config: Dict[str, Any]) -> List[str]:
        """Download a threat intelligence feed"""
        try:
            logger.info(f"Downloading {feed_name} from {feed_config['url']}...")
            
            headers = {
                'User-Agent': 'ThreatOps-SOC/1.0 (Threat Intelligence Research)'
            }
            
            async with self.session.get(feed_config['url'], headers=headers) as response:
                if response.status == 200:
                    content = await response.text()
                    
                    # Parse based on format
                    if feed_config['format'] == 'plain':
                        iocs = self._parse_plain_feed(content, feed_config['type'])
                    else:
                        logger.warning(f"Unknown format: {feed_config['format']}")
                        iocs = []
                    
                    logger.info(f"✓ Downloaded {len(iocs)} IOCs from {feed_name}")
                    return iocs
                else:
                    logger.error(f"✗ Failed to download {feed_name}: HTTP {response.status}")
                    return []
                    
        except asyncio.TimeoutError:
            logger.error(f"✗ Timeout downloading {feed_name}")
            return []
        except Exception as e:
            logger.error(f"✗ Error downloading {feed_name}: {e}")
            return []
    
    def _parse_plain_feed(self, content: str, ioc_type: str) -> List[str]:
        """Parse plain text feed (one IOC per line)"""
        iocs = []
        
        for line in content.split('\n'):
            line = line.strip()
            
            # Skip comments and empty lines
            if not line or line.startswith('#') or line.startswith(';'):
                continue
            
            # Extract IOC based on type
            if ioc_type == 'ip':
                # Match IP addresses
                ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line)
                if ip_match:
                    ip = ip_match.group(0)
                    # Validate IP
                    if self._is_valid_ip(ip):
                        iocs.append(ip)
            
            elif ioc_type == 'domain':
                # Match domains (more permissive extraction)
                # Remove http:// or https://
                line = re.sub(r'https?://', '', line)
                # Extract domain
                domain_match = re.search(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b', line)
                if domain_match:
                    domain = domain_match.group(0)
                    iocs.append(domain.lower())
            
            elif ioc_type == 'hash':
                # Match MD5, SHA1, SHA256 hashes
                hash_match = re.search(r'\b[a-fA-F0-9]{32,64}\b', line)
                if hash_match:
                    iocs.append(hash_match.group(0).lower())
        
        return iocs
    
    def _is_valid_ip(self, ip: str) -> bool:
        """Validate IP address"""
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(part) <= 255 for part in parts)
        except ValueError:
            return False
    
    def store_iocs(self, iocs: List[str], feed_config: Dict[str, Any]):
        """Store IOCs in local database"""
        if not iocs:
            return
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        inserted = 0
        updated = 0
        
        for ioc in iocs:
            # Check if IOC exists
            cursor.execute('SELECT ioc FROM iocs WHERE ioc = ?', (ioc,))
            exists = cursor.fetchone()
            
            details = {
                'feed': feed_config['source'],
                'added': datetime.now(timezone.utc).isoformat(),
                'type': feed_config['type']
            }
            
            if exists:
                # Update existing
                cursor.execute('''
                    UPDATE iocs 
                    SET last_updated = ?, source = ?, reputation = ?
                    WHERE ioc = ?
                ''', (
                    datetime.now(timezone.utc).isoformat(),
                    feed_config['source'],
                    feed_config['reputation'],
                    ioc
                ))
                updated += 1
            else:
                # Insert new
                cursor.execute('''
                    INSERT INTO iocs 
                    (ioc, ioc_type, reputation, confidence, source, details, last_updated)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    ioc,
                    feed_config['type'],
                    feed_config['reputation'],
                    0.8,  # Default confidence for feed data
                    feed_config['source'],
                    json.dumps(details),
                    datetime.now(timezone.utc).isoformat()
                ))
                inserted += 1
        
        conn.commit()
        conn.close()
        
        logger.info(f"  Stored: {inserted} new, {updated} updated IOCs")
    
    def cleanup_old_iocs(self, days: int = 90):
        """Remove IOCs older than specified days"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            DELETE FROM iocs 
            WHERE last_updated < datetime('now', ? || ' days')
        ''', (f'-{days}',))
        
        deleted = cursor.rowcount
        conn.commit()
        conn.close()
        
        if deleted > 0:
            logger.info(f"Cleaned up {deleted} old IOCs (>{days} days)")
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get database statistics"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Total IOCs
        cursor.execute('SELECT COUNT(*) FROM iocs')
        total = cursor.fetchone()[0]
        
        # By type
        cursor.execute('SELECT ioc_type, COUNT(*) FROM iocs GROUP BY ioc_type')
        by_type = dict(cursor.fetchall())
        
        # By source
        cursor.execute('SELECT source, COUNT(*) FROM iocs GROUP BY source')
        by_source = dict(cursor.fetchall())
        
        # By reputation
        cursor.execute('SELECT reputation, COUNT(*) FROM iocs GROUP BY reputation')
        by_reputation = dict(cursor.fetchall())
        
        conn.close()
        
        return {
            'total_iocs': total,
            'by_type': by_type,
            'by_source': by_source,
            'by_reputation': by_reputation
        }
    
    async def update_all_feeds(self):
        """Download and update all threat intelligence feeds"""
        logger.info("=" * 60)
        logger.info("ThreatOps Threat Intelligence Feed Updater")
        logger.info("=" * 60)
        
        await self.initialize()
        
        total_iocs = 0
        
        for feed_name, feed_config in self.feeds.items():
            try:
                iocs = await self.download_feed(feed_name, feed_config)
                self.store_iocs(iocs, feed_config)
                total_iocs += len(iocs)
            except Exception as e:
                logger.error(f"Error processing {feed_name}: {e}")
        
        await self.close()
        
        # Cleanup old entries
        logger.info("\nCleaning up old IOCs...")
        self.cleanup_old_iocs(days=90)
        
        # Print statistics
        logger.info("\n" + "=" * 60)
        logger.info("Update Summary")
        logger.info("=" * 60)
        stats = self.get_statistics()
        logger.info(f"Total IOCs in database: {stats['total_iocs']}")
        logger.info(f"Downloaded this run: {total_iocs}")
        logger.info("\nBreakdown by type:")
        for ioc_type, count in stats['by_type'].items():
            logger.info(f"  {ioc_type}: {count}")
        logger.info("\nBreakdown by source:")
        for source, count in sorted(stats['by_source'].items(), key=lambda x: x[1], reverse=True):
            logger.info(f"  {source}: {count}")
        logger.info("=" * 60)
        logger.info("✓ Update completed successfully!")
        logger.info("\nSchedule this script to run daily for fresh threat intel.")
        logger.info("=" * 60)

def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Update ThreatOps threat intelligence database")
    parser.add_argument("--db", default="data/threat_intel.db", help="Database path")
    parser.add_argument("--cleanup-days", type=int, default=90, help="Remove IOCs older than N days")
    parser.add_argument("--stats-only", action="store_true", help="Show statistics only")
    
    args = parser.parse_args()
    
    updater = ThreatFeedUpdater(args.db)
    
    if args.stats_only:
        stats = updater.get_statistics()
        print(json.dumps(stats, indent=2))
    else:
        asyncio.run(updater.update_all_feeds())

if __name__ == "__main__":
    main()

