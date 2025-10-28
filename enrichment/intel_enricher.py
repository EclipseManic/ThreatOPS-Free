# Threat Intelligence Enrichment Module for ThreatOps SOC

import asyncio
import aiohttp
import logging
import json
import hashlib
import time
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path
import sqlite3
from urllib.parse import quote
from functools import wraps

from detection.threat_detector import Alert

logger = logging.getLogger(__name__)

def retry_on_failure(max_retries: int = 3, delay: float = 1.0):
    """Decorator for retrying failed API calls"""
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            last_exception = None
            for attempt in range(max_retries):
                try:
                    return await func(*args, **kwargs)
                except aiohttp.ClientError as e:
                    last_exception = e
                    if attempt < max_retries - 1:
                        wait_time = delay * (2 ** attempt)  # Exponential backoff
                        logger.warning(f"API call failed (attempt {attempt + 1}/{max_retries}), retrying in {wait_time}s: {e}")
                        await asyncio.sleep(wait_time)
                except Exception as e:
                    logger.error(f"Unexpected error in {func.__name__}: {e}")
                    return None
            
            logger.error(f"API call failed after {max_retries} attempts: {last_exception}")
            return None
        return wrapper
    return decorator

class ThreatIntelResult:
    """Threat intelligence enrichment result"""
    
    def __init__(self, **kwargs):
        self.ioc = kwargs.get('ioc', '')  # Indicator of Compromise
        self.ioc_type = kwargs.get('ioc_type', '')  # ip, domain, hash, url
        self.reputation = kwargs.get('reputation', 'unknown')  # clean, suspicious, malicious
        self.confidence = kwargs.get('confidence', 0.0)
        self.source = kwargs.get('source', '')
        self.details = kwargs.get('details', {})
        self.last_updated = kwargs.get('last_updated', datetime.now(timezone.utc))
        
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'ioc': self.ioc,
            'ioc_type': self.ioc_type,
            'reputation': self.reputation,
            'confidence': self.confidence,
            'source': self.source,
            'details': self.details,
            'last_updated': self.last_updated.isoformat()
        }

class LocalIntelDB:
    """Local threat intelligence database"""
    
    def __init__(self, db_path: str = "data/threat_intel.db"):
        self.db_path = db_path
        self._init_db()
    
    def _init_db(self):
        """Initialize SQLite database"""
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create tables
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS iocs (
                ioc TEXT PRIMARY KEY,
                ioc_type TEXT,
                reputation TEXT,
                confidence REAL,
                source TEXT,
                details TEXT,
                last_updated TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS api_cache (
                query TEXT PRIMARY KEY,
                response TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        conn.commit()
        conn.close()
        
        # Load sample threat intelligence
        self._load_sample_intel()
    
    def _load_sample_intel(self):
        """Load sample threat intelligence data"""
        sample_iocs = [
            {
                'ioc': '192.168.1.100',
                'ioc_type': 'ip',
                'reputation': 'malicious',
                'confidence': 0.9,
                'source': 'sample_data',
                'details': {'reason': 'Known malicious IP from sample dataset'}
            },
            {
                'ioc': 'malicious-domain.com',
                'ioc_type': 'domain',
                'reputation': 'malicious',
                'confidence': 0.8,
                'source': 'sample_data',
                'details': {'reason': 'Known malicious domain from sample dataset'}
            },
            {
                'ioc': '5d41402abc4b2a76b9719d911017c592',
                'ioc_type': 'hash',
                'reputation': 'malicious',
                'confidence': 0.95,
                'source': 'sample_data',
                'details': {'reason': 'Known malicious file hash from sample dataset'}
            }
        ]
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        for ioc_data in sample_iocs:
            cursor.execute('''
                INSERT OR REPLACE INTO iocs 
                (ioc, ioc_type, reputation, confidence, source, details, last_updated)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                ioc_data['ioc'],
                ioc_data['ioc_type'],
                ioc_data['reputation'],
                ioc_data['confidence'],
                ioc_data['source'],
                json.dumps(ioc_data['details']),
                datetime.now(timezone.utc).isoformat()
            ))
        
        conn.commit()
        conn.close()
    
    def get_ioc_info(self, ioc: str, ioc_type: str) -> Optional[ThreatIntelResult]:
        """Get IOC information from local database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT ioc, ioc_type, reputation, confidence, source, details, last_updated
            FROM iocs WHERE ioc = ? AND ioc_type = ?
        ''', (ioc, ioc_type))
        
        row = cursor.fetchone()
        conn.close()
        
        if row:
            return ThreatIntelResult(
                ioc=row[0],
                ioc_type=row[1],
                reputation=row[2],
                confidence=row[3],
                source=row[4],
                details=json.loads(row[5]) if row[5] else {},
                last_updated=datetime.fromisoformat(row[6])
            )
        
        return None
    
    def store_ioc_info(self, intel_result: ThreatIntelResult):
        """Store IOC information in local database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO iocs 
            (ioc, ioc_type, reputation, confidence, source, details, last_updated)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            intel_result.ioc,
            intel_result.ioc_type,
            intel_result.reputation,
            intel_result.confidence,
            intel_result.source,
            json.dumps(intel_result.details),
            intel_result.last_updated.isoformat()
        ))
        
        conn.commit()
        conn.close()
    
    def cache_api_response(self, query: str, response: str):
        """Cache API response"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO api_cache (query, response)
            VALUES (?, ?)
        ''', (query, response))
        
        conn.commit()
        conn.close()
    
    def get_cached_response(self, query: str) -> Optional[str]:
        """Get cached API response"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT response FROM api_cache 
            WHERE query = ? AND timestamp > datetime('now', '-1 hour')
        ''', (query,))
        
        row = cursor.fetchone()
        conn.close()
        
        return row[0] if row else None

class VirusTotalAPI:
    """VirusTotal API integration"""
    
    def __init__(self, api_key: str, rate_limit: int = 4):
        self.api_key = api_key
        self.rate_limit = rate_limit
        self.base_url = "https://www.virustotal.com/api/v3"
        self.last_request_time = 0
    
    @retry_on_failure(max_retries=3, delay=1.0)
    async def check_ip(self, ip: str) -> Optional[ThreatIntelResult]:
        """Check IP reputation with VirusTotal"""
        if not self.api_key:
            logger.warning("VirusTotal API key not configured")
            return None
        
        await self._rate_limit()
        
        try:
            timeout = aiohttp.ClientTimeout(total=30)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                headers = {"x-apikey": self.api_key}
                url = f"{self.base_url}/ip_addresses/{ip}"
                
                async with session.get(url, headers=headers) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        # Parse response
                        stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                        malicious = stats.get('malicious', 0)
                        suspicious = stats.get('suspicious', 0)
                        total = sum(stats.values())
                        
                        if total > 0:
                            reputation = 'malicious' if malicious > 0 else 'suspicious' if suspicious > 0 else 'clean'
                            confidence = malicious / total if malicious > 0 else suspicious / total if suspicious > 0 else 0.1
                            
                            return ThreatIntelResult(
                                ioc=ip,
                                ioc_type='ip',
                                reputation=reputation,
                                confidence=confidence,
                                source='virustotal',
                                details={
                                    'malicious': malicious,
                                    'suspicious': suspicious,
                                    'total': total,
                                    'last_analysis': data.get('data', {}).get('attributes', {}).get('last_analysis_date')
                                }
                            )
                    
        except Exception as e:
            logger.error(f"VirusTotal API error for IP {ip}: {e}")
        
        return None
    
    @retry_on_failure(max_retries=3, delay=1.0)
    async def check_domain(self, domain: str) -> Optional[ThreatIntelResult]:
        """Check domain reputation with VirusTotal"""
        if not self.api_key:
            logger.warning("VirusTotal API key not configured")
            return None
        
        await self._rate_limit()
        
        try:
            timeout = aiohttp.ClientTimeout(total=30)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                headers = {"x-apikey": self.api_key}
                url = f"{self.base_url}/domains/{domain}"
                
                async with session.get(url, headers=headers) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                        malicious = stats.get('malicious', 0)
                        suspicious = stats.get('suspicious', 0)
                        total = sum(stats.values())
                        
                        if total > 0:
                            reputation = 'malicious' if malicious > 0 else 'suspicious' if suspicious > 0 else 'clean'
                            confidence = malicious / total if malicious > 0 else suspicious / total if suspicious > 0 else 0.1
                            
                            return ThreatIntelResult(
                                ioc=domain,
                                ioc_type='domain',
                                reputation=reputation,
                                confidence=confidence,
                                source='virustotal',
                                details={
                                    'malicious': malicious,
                                    'suspicious': suspicious,
                                    'total': total
                                }
                            )
                    
        except Exception as e:
            logger.error(f"VirusTotal API error for domain {domain}: {e}")
        
        return None
    
    @retry_on_failure(max_retries=3, delay=1.0)
    async def check_hash(self, file_hash: str) -> Optional[ThreatIntelResult]:
        """Check file hash with VirusTotal"""
        if not self.api_key:
            logger.warning("VirusTotal API key not configured")
            return None
        
        await self._rate_limit()
        
        try:
            timeout = aiohttp.ClientTimeout(total=30)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                headers = {"x-apikey": self.api_key}
                url = f"{self.base_url}/files/{file_hash}"
                
                async with session.get(url, headers=headers) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                        malicious = stats.get('malicious', 0)
                        suspicious = stats.get('suspicious', 0)
                        total = sum(stats.values())
                        
                        if total > 0:
                            reputation = 'malicious' if malicious > 0 else 'suspicious' if suspicious > 0 else 'clean'
                            confidence = malicious / total if malicious > 0 else suspicious / total if suspicious > 0 else 0.1
                            
                            return ThreatIntelResult(
                                ioc=file_hash,
                                ioc_type='hash',
                                reputation=reputation,
                                confidence=confidence,
                                source='virustotal',
                                details={
                                    'malicious': malicious,
                                    'suspicious': suspicious,
                                    'total': total
                                }
                            )
                    
        except Exception as e:
            logger.error(f"VirusTotal API error for hash {file_hash}: {e}")
        
        return None
    
    async def _rate_limit(self):
        """Implement rate limiting"""
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        
        if time_since_last < (60 / self.rate_limit):  # Convert to seconds per request
            await asyncio.sleep((60 / self.rate_limit) - time_since_last)
        
        self.last_request_time = time.time()

class AbuseIPDBAPI:
    """AbuseIPDB API integration"""
    
    def __init__(self, api_key: str, rate_limit: int = 1000):
        self.api_key = api_key
        self.rate_limit = rate_limit
        self.base_url = "https://api.abuseipdb.com/api/v2"
        self.last_request_time = 0
    
    @retry_on_failure(max_retries=3, delay=1.0)
    async def check_ip(self, ip: str) -> Optional[ThreatIntelResult]:
        """Check IP reputation with AbuseIPDB"""
        if not self.api_key:
            logger.warning("AbuseIPDB API key not configured")
            return None
        
        await self._rate_limit()
        
        try:
            timeout = aiohttp.ClientTimeout(total=30)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                headers = {"Key": self.api_key, "Accept": "application/json"}
                params = {"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""}
                
                async with session.get(f"{self.base_url}/check", headers=headers, params=params) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        abuse_confidence = data.get('data', {}).get('abuseConfidencePercentage', 0)
                        usage_type = data.get('data', {}).get('usageType', '')
                        country = data.get('data', {}).get('countryCode', '')
                        
                        reputation = 'malicious' if abuse_confidence > 75 else 'suspicious' if abuse_confidence > 25 else 'clean'
                        confidence = abuse_confidence / 100.0
                        
                        return ThreatIntelResult(
                            ioc=ip,
                            ioc_type='ip',
                            reputation=reputation,
                            confidence=confidence,
                            source='abuseipdb',
                            details={
                                'abuse_confidence': abuse_confidence,
                                'usage_type': usage_type,
                                'country': country,
                                'total_reports': data.get('data', {}).get('totalReports', 0)
                            }
                        )
                    
        except Exception as e:
            logger.error(f"AbuseIPDB API error for IP {ip}: {e}")
        
        return None
    
    async def _rate_limit(self):
        """Implement rate limiting"""
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        
        if time_since_last < (60 / self.rate_limit):
            await asyncio.sleep((60 / self.rate_limit) - time_since_last)
        
        self.last_request_time = time.time()

class AlienVaultOTXAPI:
    """AlienVault OTX API integration"""
    
    def __init__(self, api_key: str, rate_limit: int = 100):
        self.api_key = api_key
        self.rate_limit = rate_limit
        self.base_url = "https://otx.alienvault.com/api/v1"
        self.last_request_time = 0
    
    @retry_on_failure(max_retries=3, delay=1.0)
    async def check_ip(self, ip: str) -> Optional[ThreatIntelResult]:
        """Check IP reputation with OTX"""
        if not self.api_key:
            logger.warning("AlienVault OTX API key not configured")
            return None
        
        await self._rate_limit()
        
        try:
            timeout = aiohttp.ClientTimeout(total=30)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                headers = {"X-OTX-API-KEY": self.api_key}
                url = f"{self.base_url}/indicators/IPv4/{ip}"
                
                async with session.get(url, headers=headers) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        pulse_count = data.get('pulse_info', {}).get('count', 0)
                        pulses = data.get('pulse_info', {}).get('pulses', [])
                        
                        if pulse_count > 0:
                            # Calculate reputation based on pulse count and references
                            reputation = 'malicious' if pulse_count > 5 else 'suspicious' if pulse_count > 0 else 'clean'
                            confidence = min(pulse_count / 10.0, 1.0)
                            
                            # Extract pulse details
                            pulse_details = []
                            for pulse in pulses[:5]:  # Limit to first 5 pulses
                                pulse_details.append({
                                    'name': pulse.get('name', ''),
                                    'tags': pulse.get('tags', []),
                                    'references': pulse.get('references', [])
                                })
                            
                            return ThreatIntelResult(
                                ioc=ip,
                                ioc_type='ip',
                                reputation=reputation,
                                confidence=confidence,
                                source='otx',
                                details={
                                    'pulse_count': pulse_count,
                                    'pulses': pulse_details
                                }
                            )
                    
        except Exception as e:
            logger.error(f"OTX API error for IP {ip}: {e}")
        
        return None
    
    @retry_on_failure(max_retries=3, delay=1.0)
    async def check_domain(self, domain: str) -> Optional[ThreatIntelResult]:
        """Check domain reputation with OTX"""
        if not self.api_key:
            logger.warning("AlienVault OTX API key not configured")
            return None
        
        await self._rate_limit()
        
        try:
            timeout = aiohttp.ClientTimeout(total=30)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                headers = {"X-OTX-API-KEY": self.api_key}
                url = f"{self.base_url}/indicators/domain/{domain}"
                
                async with session.get(url, headers=headers) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        pulse_count = data.get('pulse_info', {}).get('count', 0)
                        
                        if pulse_count > 0:
                            reputation = 'malicious' if pulse_count > 5 else 'suspicious' if pulse_count > 0 else 'clean'
                            confidence = min(pulse_count / 10.0, 1.0)
                            
                            return ThreatIntelResult(
                                ioc=domain,
                                ioc_type='domain',
                                reputation=reputation,
                                confidence=confidence,
                                source='otx',
                                details={'pulse_count': pulse_count}
                            )
                    
        except Exception as e:
            logger.error(f"OTX API error for domain {domain}: {e}")
        
        return None
    
    async def _rate_limit(self):
        """Implement rate limiting"""
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        
        if time_since_last < (60 / self.rate_limit):
            await asyncio.sleep((60 / self.rate_limit) - time_since_last)
        
        self.last_request_time = time.time()

class IntelEnricher:
    """Main threat intelligence enrichment engine"""
    
    def __init__(self, settings):
        self.settings = settings
        self.local_db = LocalIntelDB()
        self.apis = {}
        
    async def initialize(self):
        """Initialize threat intelligence enricher"""
        logger.info("Initializing threat intelligence enricher...")
        
        # Initialize APIs
        for api_config in self.settings.get_enabled_apis():
            if api_config.name == "virustotal":
                self.apis['virustotal'] = VirusTotalAPI(api_config.api_key, api_config.rate_limit)
            elif api_config.name == "abuseipdb":
                self.apis['abuseipdb'] = AbuseIPDBAPI(api_config.api_key, api_config.rate_limit)
            elif api_config.name == "otx":
                self.apis['otx'] = AlienVaultOTXAPI(api_config.api_key, api_config.rate_limit)
        
        logger.info(f"Initialized {len(self.apis)} threat intelligence APIs")
    
    async def enrich_alerts(self, alerts: List[Alert]) -> List[Alert]:
        """Enrich alerts with threat intelligence"""
        logger.info(f"Enriching {len(alerts)} alerts with threat intelligence...")
        
        enriched_alerts = []
        
        for alert in alerts:
            enriched_alert = await self._enrich_single_alert(alert)
            enriched_alerts.append(enriched_alert)
        
        logger.info(f"Enriched {len(enriched_alerts)} alerts")
        return enriched_alerts
    
    async def _enrich_single_alert(self, alert: Alert) -> Alert:
        """Enrich a single alert with threat intelligence"""
        intel_results = []
        
        # Extract IOCs from alert
        iocs = self._extract_iocs(alert)
        
        # Check each IOC
        for ioc, ioc_type in iocs:
            intel_result = await self._check_ioc(ioc, ioc_type)
            if intel_result:
                intel_results.append(intel_result)
        
        # Update alert with intelligence
        if intel_results:
            alert.tags.extend(['threat_intel_enriched'])
            
            # Determine overall reputation
            malicious_count = sum(1 for r in intel_results if r.reputation == 'malicious')
            suspicious_count = sum(1 for r in intel_results if r.reputation == 'suspicious')
            
            if malicious_count > 0:
                alert.tags.append('malicious_ioc')
                # Increase severity if malicious IOCs found
                if alert.severity == 'Low':
                    alert.severity = 'Medium'
                elif alert.severity == 'Medium':
                    alert.severity = 'High'
            elif suspicious_count > 0:
                alert.tags.append('suspicious_ioc')
            
            # Add intelligence details to raw_events
            for event in alert.raw_events:
                if hasattr(event, 'raw_data'):
                    event.raw_data['threat_intel'] = [r.to_dict() for r in intel_results]
        
        return alert
    
    def _extract_iocs(self, alert: Alert) -> List[Tuple[str, str]]:
        """Extract IOCs from alert"""
        iocs = []
        
        # Extract IP addresses
        if alert.ip and alert.ip != 'unknown':
            iocs.append((alert.ip, 'ip'))
        
        # Extract IOCs from raw events
        for event in alert.raw_events:
            if hasattr(event, 'raw_data'):
                raw_data = event.raw_data
                
                # Extract IPs from raw data
                for key, value in raw_data.items():
                    if 'ip' in key.lower() and isinstance(value, str) and value != 'unknown':
                        iocs.append((value, 'ip'))
                
                # Extract domains from command lines
                if 'command_line' in raw_data:
                    domains = self._extract_domains(raw_data['command_line'])
                    for domain in domains:
                        iocs.append((domain, 'domain'))
                
                # Extract file hashes
                if 'process_name' in raw_data:
                    # Simple hash extraction (in real implementation, use proper hash detection)
                    process_name = raw_data['process_name']
                    if len(process_name) == 32 and all(c in '0123456789abcdef' for c in process_name.lower()):
                        iocs.append((process_name, 'hash'))
        
        return list(set(iocs))  # Remove duplicates
    
    def _extract_domains(self, text: str) -> List[str]:
        """Extract domain names from text"""
        import re
        domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
        domains = re.findall(domain_pattern, text)
        
        # Filter out common false positives
        filtered_domains = []
        for domain in domains:
            if not any(common in domain.lower() for common in ['localhost', '127.0.0.1', 'example.com']):
                filtered_domains.append(domain)
        
        return filtered_domains
    
    async def _check_ioc(self, ioc: str, ioc_type: str) -> Optional[ThreatIntelResult]:
        """Check IOC against all available sources (local DB first, then APIs)"""
        # EFFICIENCY FIX: First check local database (includes free feeds)
        local_result = self.local_db.get_ioc_info(ioc, ioc_type)
        if local_result:
            logger.debug(f"Found {ioc} in local database (source: {local_result.source})")
            return local_result
        
        # Only query external APIs if not found locally (saves rate limits)
        logger.debug(f"IOC {ioc} not in local DB, checking external APIs...")
        intel_result = None
        
        if ioc_type == 'ip':
            # Check IP with multiple APIs
            for api_name, api in self.apis.items():
                if hasattr(api, 'check_ip'):
                    try:
                        result = await api.check_ip(ioc)
                        if result:
                            intel_result = result
                            logger.info(f"Found {ioc} via {api_name} API")
                            break
                    except Exception as e:
                        logger.error(f"Error checking IP {ioc} with {api_name}: {e}")
        
        elif ioc_type == 'domain':
            # Check domain with multiple APIs
            for api_name, api in self.apis.items():
                if hasattr(api, 'check_domain'):
                    try:
                        result = await api.check_domain(ioc)
                        if result:
                            intel_result = result
                            logger.info(f"Found {ioc} via {api_name} API")
                            break
                    except Exception as e:
                        logger.error(f"Error checking domain {ioc} with {api_name}: {e}")
        
        elif ioc_type == 'hash':
            # Check hash with VirusTotal (only API that supports hashes)
            if 'virustotal' in self.apis:
                try:
                    result = await self.apis['virustotal'].check_hash(ioc)
                    if result:
                        intel_result = result
                        logger.info(f"Found {ioc} via VirusTotal API")
                except Exception as e:
                    logger.error(f"Error checking hash {ioc} with VirusTotal: {e}")
        
        # Store API result in local database for future lookups (caching)
        if intel_result:
            self.local_db.store_ioc_info(intel_result)
            logger.debug(f"Cached {ioc} in local database")
        
        return intel_result
    
    async def get_ioc_statistics(self) -> Dict[str, Any]:
        """Get threat intelligence statistics"""
        conn = sqlite3.connect(self.local_db.db_path)
        cursor = conn.cursor()
        
        # Get IOC counts by type
        cursor.execute('SELECT ioc_type, COUNT(*) FROM iocs GROUP BY ioc_type')
        ioc_counts = dict(cursor.fetchall())
        
        # Get reputation distribution
        cursor.execute('SELECT reputation, COUNT(*) FROM iocs GROUP BY reputation')
        reputation_counts = dict(cursor.fetchall())
        
        # Get source distribution
        cursor.execute('SELECT source, COUNT(*) FROM iocs GROUP BY source')
        source_counts = dict(cursor.fetchall())
        
        conn.close()
        
        return {
            'total_iocs': sum(ioc_counts.values()),
            'ioc_counts_by_type': ioc_counts,
            'reputation_distribution': reputation_counts,
            'source_distribution': source_counts
        }
