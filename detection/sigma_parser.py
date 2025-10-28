"""
Sigma Rule Parser for ThreatOps SOC
Implements parsing and evaluation of Sigma detection rules (industry standard).
Reference: https://github.com/SigmaHQ/sigma
"""

import yaml
import re
import logging
from typing import Dict, List, Any, Optional
from pathlib import Path
from datetime import datetime, timezone
from collections import defaultdict

logger = logging.getLogger(__name__)

class SigmaRule:
    """Represents a parsed Sigma detection rule"""
    
    def __init__(self, rule_dict: Dict[str, Any]):
        self.title = rule_dict.get('title', 'Unknown')
        self.id = rule_dict.get('id', '')
        self.description = rule_dict.get('description', '')
        self.author = rule_dict.get('author', '')
        self.date = rule_dict.get('date', '')
        self.status = rule_dict.get('status', 'experimental')
        self.level = rule_dict.get('level', 'medium')
        self.tags = rule_dict.get('tags', [])
        self.references = rule_dict.get('references', [])
        
        # Detection logic
        self.logsource = rule_dict.get('logsource', {})
        self.detection = rule_dict.get('detection', {})
        
        # False positives
        self.falsepositives = rule_dict.get('falsepositives', [])
        
    def get_mitre_techniques(self) -> List[str]:
        """Extract MITRE ATT&CK techniques from tags"""
        techniques = []
        for tag in self.tags:
            if tag.startswith('attack.t') or tag.startswith('attack.T'):
                # Extract technique ID (e.g., attack.t1110 -> T1110)
                technique = tag.replace('attack.', '').upper()
                techniques.append(technique)
        return techniques
    
    def get_severity(self) -> str:
        """Convert Sigma level to ThreatOps severity"""
        level_map = {
            'informational': 'Low',
            'low': 'Low',
            'medium': 'Medium',
            'high': 'High',
            'critical': 'Critical'
        }
        return level_map.get(self.level.lower(), 'Medium')

class SigmaParser:
    """Parse and evaluate Sigma detection rules"""
    
    def __init__(self):
        self.rules = []
        
    def load_rule(self, rule_path: Path) -> Optional[SigmaRule]:
        """Load a single Sigma rule from YAML file"""
        try:
            with open(rule_path, 'r', encoding='utf-8') as f:
                rule_dict = yaml.safe_load(f)
            
            if not rule_dict:
                logger.warning(f"Empty rule file: {rule_path}")
                return None
            
            sigma_rule = SigmaRule(rule_dict)
            logger.info(f"Loaded Sigma rule: {sigma_rule.title}")
            return sigma_rule
            
        except Exception as e:
            logger.error(f"Error loading rule {rule_path}: {e}")
            return None
    
    def load_rules_directory(self, rules_dir: Path) -> int:
        """Load all Sigma rules from a directory"""
        if not rules_dir.exists():
            logger.warning(f"Rules directory not found: {rules_dir}")
            return 0
        
        count = 0
        for rule_file in rules_dir.glob('**/*.yml'):
            rule = self.load_rule(rule_file)
            if rule:
                self.rules.append(rule)
                count += 1
        
        logger.info(f"Loaded {count} Sigma rules from {rules_dir}")
        return count
    
    def evaluate_rule(self, rule: SigmaRule, log_entry) -> bool:
        """Evaluate a Sigma rule against a log entry"""
        try:
            # Get detection logic
            detection = rule.detection
            
            # The 'condition' defines how to combine the detection selectors
            condition = detection.get('condition', '')
            
            # Evaluate each selector
            selector_results = {}
            for key, value in detection.items():
                if key == 'condition':
                    continue
                    
                # Evaluate selector
                result = self._evaluate_selector(key, value, log_entry)
                selector_results[key] = result
            
            # Evaluate condition
            return self._evaluate_condition(condition, selector_results)
            
        except Exception as e:
            logger.error(f"Error evaluating rule {rule.title}: {e}")
            return False
    
    def _evaluate_selector(self, selector_name: str, selector_def: Any, log_entry) -> bool:
        """Evaluate a detection selector"""
        if not isinstance(selector_def, dict):
            return False
        
        # All conditions in a selector must match (AND logic)
        for field, patterns in selector_def.items():
            if not self._match_field(field, patterns, log_entry):
                return False
        
        return True
    
    def _match_field(self, field: str, patterns: Any, log_entry) -> bool:
        """Match a field against patterns"""
        # Get field value from log entry
        log_value = self._get_log_field(field, log_entry)
        if log_value is None:
            return False
        
        # Convert to string for comparison
        log_value_str = str(log_value).lower()
        
        # Handle different pattern types
        if isinstance(patterns, str):
            # Single pattern
            return self._match_pattern(patterns, log_value_str)
        elif isinstance(patterns, list):
            # Multiple patterns (OR logic)
            return any(self._match_pattern(p, log_value_str) for p in patterns)
        elif isinstance(patterns, dict):
            # Modifiers (e.g., contains, startswith, endswith, all, etc.)
            return self._match_with_modifiers(patterns, log_value_str)
        
        return False
    
    def _match_pattern(self, pattern: str, value: str) -> bool:
        """Match a single pattern against a value"""
        pattern_lower = str(pattern).lower()
        
        # Wildcard matching
        if '*' in pattern_lower or '?' in pattern_lower:
            # Convert wildcard to regex
            regex_pattern = pattern_lower.replace('*', '.*').replace('?', '.')
            regex_pattern = f'^{regex_pattern}$'
            return bool(re.search(regex_pattern, value))
        else:
            # Exact match
            return pattern_lower in value
    
    def _match_with_modifiers(self, pattern_dict: Dict, value: str) -> bool:
        """Match with Sigma modifiers"""
        # Handle common modifiers
        if 'contains' in pattern_dict:
            patterns = pattern_dict['contains']
            if isinstance(patterns, list):
                return any(str(p).lower() in value for p in patterns)
            return str(patterns).lower() in value
        
        if 'startswith' in pattern_dict:
            pattern = str(pattern_dict['startswith']).lower()
            return value.startswith(pattern)
        
        if 'endswith' in pattern_dict:
            pattern = str(pattern_dict['endswith']).lower()
            return value.endswith(pattern)
        
        if 'all' in pattern_dict:
            patterns = pattern_dict['all']
            if isinstance(patterns, list):
                return all(str(p).lower() in value for p in patterns)
            return str(patterns).lower() in value
        
        return False
    
    def _get_log_field(self, field: str, log_entry) -> Optional[Any]:
        """Get field value from log entry (handles nested fields)"""
        # Map Sigma fields to LogEntry attributes
        field_map = {
            'EventID': 'event_id',
            'EventType': 'event_type',
            'User': 'user',
            'Computer': 'host',
            'Hostname': 'host',
            'SourceIP': 'ip',
            'DestinationIP': 'ip',
            'ProcessName': 'process_name',
            'CommandLine': 'command_line',
            'Image': 'process_name',
            'ParentImage': 'parent_process',
            'Message': 'message',
        }
        
        # Get mapped field name
        mapped_field = field_map.get(field, field.lower())
        
        # Try to get from log entry attributes
        if hasattr(log_entry, mapped_field):
            return getattr(log_entry, mapped_field)
        
        # Try to get from raw_data
        if hasattr(log_entry, 'raw_data') and isinstance(log_entry.raw_data, dict):
            # Try exact match
            if field in log_entry.raw_data:
                return log_entry.raw_data[field]
            # Try case-insensitive match
            for key, value in log_entry.raw_data.items():
                if key.lower() == field.lower():
                    return value
        
        return None
    
    def _evaluate_condition(self, condition: str, selector_results: Dict[str, bool]) -> bool:
        """Evaluate the Sigma condition expression"""
        if not condition:
            return False
        
        # Simple condition evaluation
        # Replace selector names with their boolean results
        expression = condition
        
        for selector_name, result in selector_results.items():
            # Replace selector name with True/False
            expression = expression.replace(selector_name, str(result))
        
        # Handle common operators
        expression = expression.replace(' and ', ' and ')
        expression = expression.replace(' or ', ' or ')
        expression = expression.replace(' not ', ' not ')
        expression = expression.replace('1 of', 'any')  # Simplified
        expression = expression.replace('all of', 'all')  # Simplified
        
        try:
            # Evaluate the boolean expression
            # Note: This is simplified. Full Sigma condition evaluation is more complex
            result = eval(expression)
            return bool(result)
        except Exception as e:
            logger.debug(f"Error evaluating condition '{condition}': {e}")
            # Fallback: if any selector is True, return True
            return any(selector_results.values())
    
    def match_logsource(self, rule: SigmaRule, log_entry) -> bool:
        """Check if log entry matches rule's logsource"""
        logsource = rule.logsource
        
        # Check product
        if 'product' in logsource:
            product = logsource['product'].lower()
            if product == 'windows':
                if not (hasattr(log_entry, 'source') and 'windows' in log_entry.source.lower()):
                    if not (hasattr(log_entry, 'event_id') and log_entry.event_id > 0):
                        return False
            elif product == 'linux':
                if not (hasattr(log_entry, 'source') and 'linux' in log_entry.source.lower()):
                    return False
        
        # Check service
        if 'service' in logsource:
            service = logsource['service'].lower()
            if service == 'security':
                if not (hasattr(log_entry, 'event_type') and 'security' in log_entry.event_type.lower()):
                    return False
        
        # Check category
        if 'category' in logsource:
            category = logsource['category'].lower()
            if hasattr(log_entry, 'event_type'):
                if category not in log_entry.event_type.lower():
                    return False
        
        return True

class SigmaDetectionEngine:
    """Sigma-based detection engine"""
    
    def __init__(self, rules_directory: Optional[Path] = None):
        self.parser = SigmaParser()
        self.rules_directory = rules_directory or Path(__file__).parent.parent / "config" / "sigma_rules"
        self.load_rules()
    
    def load_rules(self):
        """Load all Sigma rules"""
        logger.info("Loading Sigma rules...")
        count = self.parser.load_rules_directory(self.rules_directory)
        logger.info(f"Loaded {count} Sigma rules")
    
    def detect(self, log_entries: List) -> List[Dict[str, Any]]:
        """Run Sigma detection on log entries"""
        detections = []
        
        for log_entry in log_entries:
            for rule in self.parser.rules:
                try:
                    # Check logsource match
                    if not self.parser.match_logsource(rule, log_entry):
                        continue
                    
                    # Evaluate rule
                    if self.parser.evaluate_rule(rule, log_entry):
                        detection = {
                            'rule_name': rule.title,
                            'rule_id': rule.id,
                            'severity': rule.get_severity(),
                            'description': rule.description,
                            'mitre_techniques': rule.get_mitre_techniques(),
                            'log_entry': log_entry,
                            'timestamp': datetime.now(timezone.utc),
                            'tags': ['sigma_detection'] + rule.tags,
                            'confidence': 0.9  # High confidence for Sigma rules
                        }
                        detections.append(detection)
                        logger.info(f"Sigma detection: {rule.title} on {log_entry.host}")
                
                except Exception as e:
                    logger.error(f"Error evaluating rule {rule.title}: {e}")
        
        return detections

