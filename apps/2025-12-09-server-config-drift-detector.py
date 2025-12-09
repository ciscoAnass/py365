```python
#!/usr/bin/env python3
"""
Server Configuration Drift Detector
A comprehensive SysAdmin tool for detecting unauthorized changes in server configurations.
This tool compares a 'golden' configuration file against live configurations on multiple servers.
"""

import os
import sys
import json
import hashlib
import difflib
import argparse
import logging
import re
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Tuple, Optional, Set
from dataclasses import dataclass, asdict
from enum import Enum
import subprocess
import socket
import time


class DriftSeverity(Enum):
    """Enumeration for drift severity levels"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class ConfigLine:
    """Represents a single line in a configuration file"""
    line_number: int
    content: str
    is_comment: bool
    is_empty: bool
    
    def __hash__(self):
        return hash((self.line_number, self.content))


@dataclass
class DriftFinding:
    """Represents a single drift finding"""
    server_name: str
    config_file: str
    severity: DriftSeverity
    line_number: int
    golden_content: str
    actual_content: str
    drift_type: str
    timestamp: str
    
    def to_dict(self):
        return {
            'server_name': self.server_name,
            'config_file': self.config_file,
            'severity': self.severity.value,
            'line_number': self.line_number,
            'golden_content': self.golden_content,
            'actual_content': self.actual_content,
            'drift_type': self.drift_type,
            'timestamp': self.timestamp
        }


class ConfigParser:
    """Parses and normalizes configuration files"""
    
    def __init__(self, ignore_comments: bool = True, ignore_whitespace: bool = True):
        """
        Initialize the configuration parser.
        
        Args:
            ignore_comments: Whether to ignore comment lines during comparison
            ignore_whitespace: Whether to normalize whitespace
        """
        self.ignore_comments = ignore_comments
        self.ignore_whitespace = ignore_whitespace
        self.logger = logging.getLogger(__name__)
    
    def parse_file(self, file_path: str) -> List[ConfigLine]:
        """
        Parse a configuration file into ConfigLine objects.
        
        Args:
            file_path: Path to the configuration file
            
        Returns:
            List of ConfigLine objects
        """
        config_lines = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    content = line.rstrip('\n\r')
                    is_comment = self._is_comment_line(content)
                    is_empty = self._is_empty_line(content)
                    
                    config_lines.append(ConfigLine(
                        line_number=line_num,
                        content=content,
                        is_comment=is_comment,
                        is_empty=is_empty
                    ))
        except FileNotFoundError:
            self.logger.error(f"Configuration file not found: {file_path}")
            raise
        except IOError as e:
            self.logger.error(f"Error reading configuration file {file_path}: {e}")
            raise
        
        return config_lines
    
    def _is_comment_line(self, line: str) -> bool:
        """
        Determine if a line is a comment.
        
        Args:
            line: The line to check
            
        Returns:
            True if the line is a comment, False otherwise
        """
        stripped = line.lstrip()
        return stripped.startswith('#') or stripped.startswith(';')
    
    def _is_empty_line(self, line: str) -> bool:
        """
        Determine if a line is empty or contains only whitespace.
        
        Args:
            line: The line to check
            
        Returns:
            True if the line is empty, False otherwise
        """
        return len(line.strip()) == 0
    
    def normalize_line(self, line: str) -> str:
        """
        Normalize a configuration line for comparison.
        
        Args:
            line: The line to normalize
            
        Returns:
            Normalized line content
        """
        if self.ignore_whitespace:
            line = ' '.join(line.split())
        return line.lower()
    
    def get_effective_config(self, config_lines: List[ConfigLine]) -> List[str]:
        """
        Get the effective configuration (excluding comments and empty lines if configured).
        
        Args:
            config_lines: List of ConfigLine objects
            
        Returns:
            List of effective configuration lines
        """
        effective = []
        for line in config_lines:
            if self.ignore_comments and line.is_comment:
                continue
            if line.is_empty:
                continue
            effective.append(line.content)
        return effective


class DriftDetector:
    """Main class for detecting configuration drift"""
    
    def __init__(self, golden_config_path: str, ignore_comments: bool = True,
                 ignore_whitespace: bool = True, severity_rules: Optional[Dict] = None):
        """
        Initialize the drift detector.
        
        Args:
            golden_config_path: Path to the golden configuration file
            ignore_comments: Whether to ignore comments during comparison
            ignore_whitespace: Whether to normalize whitespace
            severity_rules: Dictionary of regex patterns to severity levels
        """
        self.golden_config_path = golden_config_path
        self.parser = ConfigParser(ignore_comments, ignore_whitespace)
        self.logger = logging.getLogger(__name__)
        self.severity_rules = severity_rules or self._get_default_severity_rules()
        self.golden_lines = []
        self.golden_effective = []
        self._load_golden_config()
    
    def _load_golden_config(self):
        """Load and parse the golden configuration file"""
        self.logger.info(f"Loading golden configuration from {self.golden_config_path}")
        self.golden_lines = self.parser.parse_file(self.golden_config_path)
        self.golden_effective = self.parser.get_effective_config(self.golden_lines)
        self.logger.info(f"Golden configuration loaded with {len(self.golden_lines)} total lines")
    
    def _get_default_severity_rules(self) -> Dict[str, DriftSeverity]:
        """
        Get default severity rules for common configuration parameters.
        
        Returns:
            Dictionary mapping parameter patterns to severity levels
        """
        return {
            r'(?i)(permit.*root|permitrootlogin)': DriftSeverity.CRITICAL,
            r'(?i)(password.*auth|pubkey.*auth)': DriftSeverity.CRITICAL,
            r'(?i)(port\s+\d+)': DriftSeverity.HIGH,
            r'(?i)(ssl|tls)': DriftSeverity.HIGH,
            r'(?i)(log|debug)': DriftSeverity.MEDIUM,
            r'(?i)(timeout|keepalive)': DriftSeverity.LOW,
        }
    
    def _determine_severity(self, line: str) -> DriftSeverity:
        """
        Determine the severity of a drift based on the configuration line.
        
        Args:
            line: The configuration line
            
        Returns:
            DriftSeverity level
        """
        for pattern, severity in self.severity_rules.items():
            if re.search(pattern, line):
                return severity
        return DriftSeverity.INFO
    
    def detect_drift(self, actual_config_path: str, server_name: str,
                     config_file_name: str) -> List[DriftFinding]:
        """
        Detect drift between golden and actual configuration.
        
        Args:
            actual_config_path: Path to the actual configuration file
            server_name: Name of the server being checked
            config_file_name: Name of the configuration file (for reporting)
            
        Returns:
            List of DriftFinding objects
        """
        findings = []
        
        try:
            actual_lines = self.parser.parse_file(actual_config_path)
            actual_effective = self.parser.get_effective_config(actual_lines)
        except Exception as e:
            self.logger.error(f"Error reading actual config on {server_name}: {e}")
            return findings
        
        # Perform line-by-line comparison
        findings.extend(self._compare_line_by_line(
            self.golden_effective, actual_effective, server_name, config_file_name
        ))
        
        # Perform structural comparison
        findings.extend(self._compare_structure(
            self.golden_lines, actual_lines, server_name, config_file_name
        ))
        
        return findings
    
    def _compare_line_by_line(self, golden: List[str], actual: List[str],
                              server_name: str, config_file_name: str) -> List[DriftFinding]:
        """
        Perform line-by-line comparison between configurations.
        
        Args:
            golden: Golden configuration lines
            actual: Actual configuration lines
            server_name: Name of the server
            config_file_name: Name of the configuration file
            
        Returns:
            List of DriftFinding objects
        """
        findings = []
        timestamp = datetime.now().isoformat()
        
        # Use difflib to find differences
        differ = difflib.unified_diff(golden, actual, lineterm='')
        diff_lines = list(differ)
        
        if not diff_lines:
            self.logger.info(f"No drift detected in {config_file_name} on {server_name}")
            return findings
        
        # Parse diff output to identify specific changes
        for i, line in enumerate(diff_lines):
            if line.startswith('-') and not line.startswith('---'):
                golden_line = line[1:]
                severity = self._determine_severity(golden_line)
                
                # Find corresponding actual line
                actual_line = ""
                if i + 1 < len(diff_lines) and diff_lines[i + 1].startswith('+'):
                    actual_line = diff_lines[i + 1][1:]
                
                finding = DriftFinding(
                    server_name=server_name,
                    config_file=config_file_name,
                    severity=severity,
                    line_number=i,
                    golden_content=golden_line,
                    actual_content=actual_line,
                    drift_type="MODIFIED" if actual_line else "REMOVED",
                    timestamp=timestamp
                )
                findings.append(finding)
            elif line.startswith('+') and not line.startswith('+++'):
                if i == 0 or not diff_lines[i - 1].startswith('-'):
                    actual_line = line[1:]
                    severity = self._determine_severity(actual_line)
                    
                    finding = DriftFinding(
                        server_name=server_name,
                        config_file=config_file_name,
                        severity=severity,
                        line_number=i,
                        golden_content="",
                        actual_content=actual_line,
                        drift_type="ADDED",
                        timestamp=timestamp
                    )
                    findings.append(finding)
        
        return findings
    
    def _compare_structure(self, golden_lines: List[ConfigLine],
                          actual_lines: List[ConfigLine],
                          server_name: str, config_file_name: str) -> List[DriftFinding]:
        """
        Perform structural comparison (e.g., missing sections, reordered blocks).
        
        Args:
            golden_lines: Golden configuration lines
            actual_lines: Actual configuration lines
            server_name: Name of the server
            config_file_name: Name of the configuration file
            
        Returns:
            List of DriftFinding objects
        """
        findings = []
        timestamp = datetime.now().isoformat()
        
        # Check for missing sections
        golden_sections = self._extract_sections(golden_lines)
        actual_sections = self._extract_sections(actual_lines)
        
        for section_name in golden_sections:
            if section_name not in actual_sections:
                finding = DriftFinding(
                    server_name=server_name,
                    config_file=config_file_name,
                    severity=DriftSeverity.HIGH,
                    line_number=0,
                    golden_content=f"Section: {section_name}",
                    actual_content="",
                    drift_type="MISSING_SECTION",
                    timestamp=timestamp
                )
                findings.append(finding)
        
        return findings
    
    def _extract_sections(self, config_lines: List[ConfigLine]) -> Set[str]:
        """
        Extract section names from configuration lines.
        
        Args:
            config_lines: List of ConfigLine objects
            
        Returns:
            Set of section names
        """
        sections = set()
        section_pattern = re.compile(r'^\s*<?\s*(\w+)\s*[>\{]?')
        
        for line in config_lines:
            if line.is_comment or line.is_empty:
                continue
            match = section_pattern.match(line.content)
            if match:
                sections.add(match.group(1).lower())
        
        return sections
    
    def generate_report(self, findings: List[DriftFinding], output_format: str = 'text') -> str:
        """
        Generate a report of drift findings.
        
        Args:
            findings: List of DriftFinding objects
            output_format: Format for the report ('text', 'json', 'csv')
            
        Returns:
            Formatted report string
        """
        if output_format == 'json':
            return self._generate_json_report(findings)
        elif output_format == 'csv':
            return self._generate_csv_report(findings)
        else:
            return self._generate_text_report(findings)
    
    def _generate_text_report(self, findings: List[DriftFinding]) -> str:
        """Generate a text format report"""
        if not findings:
            return "No drift detected.\n"
        
        report = []
        report.append("=" * 80)
        report.append("CONFIGURATION DRIFT DETECTION REPORT")
        report.append("=" * 80)
        report.append(f"Generated: {datetime.now().isoformat()}")
        report.append(f"Total Findings: {len(findings)}")
        report.append("")
        
        # Group findings by severity
        by_severity = {}
        for finding in findings:
            severity = finding.severity.value
            if severity not in by_severity:
                by_severity[severity] = []
            by_severity[severity].append(finding)
        
        # Sort by severity
        severity_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
        for severity in severity_order:
            if severity in by_severity:
                report.append(f"\n{severity} FINDINGS ({len(by_severity[severity])}):")
                report.append("-" * 80)
                for finding in by_severity[severity]:
                    report.append(f"Server: {finding.server_name}")
                    report.append(f"Config: {finding.config_file}")
                    report.append(f"Type: {finding.drift_type}")
                    report.append(f"Line: {finding.line_number}")
                    report.append(f"Golden: {finding.golden_content