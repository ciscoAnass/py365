import json
import hashlib
import time
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict, field
from enum import Enum
import threading
import logging
from abc import ABC, abstractmethod
import random
import re

# Third-party: flask (pip install flask)
from flask import Flask, request, jsonify, Response
from functools import wraps
import sqlite3
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class FeatureFlagStatus(Enum):
    """Enumeration for feature flag statuses"""
    ENABLED = "enabled"
    DISABLED = "disabled"
    ROLLOUT = "rollout"
    SCHEDULED = "scheduled"


class RolloutStrategy(Enum):
    """Enumeration for rollout strategies"""
    PERCENTAGE = "percentage"
    USER_ID = "user_id"
    CUSTOM = "custom"
    GRADUAL = "gradual"


@dataclass
class RolloutConfig:
    """Configuration for gradual rollout of features"""
    strategy: RolloutStrategy
    percentage: int = 0
    user_ids: List[str] = field(default_factory=list)
    custom_rules: Dict[str, Any] = field(default_factory=dict)
    start_percentage: int = 0
    end_percentage: int = 100
    duration_days: int = 7
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert rollout config to dictionary"""
        return {
            'strategy': self.strategy.value,
            'percentage': self.percentage,
            'user_ids': self.user_ids,
            'custom_rules': self.custom_rules,
            'start_percentage': self.start_percentage,
            'end_percentage': self.end_percentage,
            'duration_days': self.duration_days
        }


@dataclass
class FeatureFlag:
    """Represents a feature flag with all its properties"""
    name: str
    status: FeatureFlagStatus
    description: str = ""
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    updated_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    created_by: str = ""
    rollout_config: Optional[RolloutConfig] = None
    scheduled_enable_at: Optional[str] = None
    scheduled_disable_at: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert feature flag to dictionary"""
        result = {
            'name': self.name,
            'status': self.status.value,
            'description': self.description,
            'created_at': self.created_at,
            'updated_at': self.updated_at,
            'created_by': self.created_by,
            'tags': self.tags,
            'metadata': self.metadata,
            'scheduled_enable_at': self.scheduled_enable_at,
            'scheduled_disable_at': self.scheduled_disable_at
        }
        if self.rollout_config:
            result['rollout_config'] = self.rollout_config.to_dict()
        return result


class FeatureFlagEvaluator:
    """Evaluates whether a feature flag should be enabled for a given context"""
    
    def __init__(self):
        """Initialize the evaluator"""
        self.logger = logging.getLogger(__name__)
    
    def evaluate(self, flag: FeatureFlag, user_id: Optional[str] = None, 
                 context: Optional[Dict[str, Any]] = None) -> bool:
        """
        Evaluate if a feature flag should be enabled
        
        Args:
            flag: The feature flag to evaluate
            user_id: Optional user ID for user-based rollouts
            context: Optional context dictionary for custom rules
            
        Returns:
            Boolean indicating if the feature should be enabled
        """
        # Check scheduled enable/disable times
        now = datetime.utcnow()
        
        if flag.scheduled_disable_at:
            disable_time = datetime.fromisoformat(flag.scheduled_disable_at)
            if now >= disable_time:
                self.logger.info(f"Flag {flag.name} is scheduled to be disabled")
                return False
        
        if flag.scheduled_enable_at:
            enable_time = datetime.fromisoformat(flag.scheduled_enable_at)
            if now < enable_time:
                self.logger.info(f"Flag {flag.name} is not yet scheduled to be enabled")
                return False
        
        # Check basic status
        if flag.status == FeatureFlagStatus.DISABLED:
            return False
        
        if flag.status == FeatureFlagStatus.ENABLED:
            return True
        
        # Handle rollout strategies
        if flag.status == FeatureFlagStatus.ROLLOUT and flag.rollout_config:
            return self._evaluate_rollout(flag, user_id, context)
        
        return False
    
    def _evaluate_rollout(self, flag: FeatureFlag, user_id: Optional[str] = None,
                         context: Optional[Dict[str, Any]] = None) -> bool:
        """
        Evaluate rollout strategy
        
        Args:
            flag: The feature flag with rollout config
            user_id: Optional user ID
            context: Optional context dictionary
            
        Returns:
            Boolean indicating if feature should be enabled
        """
        if not flag.rollout_config:
            return False
        
        config = flag.rollout_config
        
        # User ID based rollout
        if config.strategy == RolloutStrategy.USER_ID:
            if user_id and user_id in config.user_ids:
                return True
            return False
        
        # Percentage based rollout
        if config.strategy == RolloutStrategy.PERCENTAGE:
            if user_id:
                return self._hash_user_to_percentage(user_id, flag.name) < config.percentage
            return random.randint(0, 100) < config.percentage
        
        # Gradual rollout
        if config.strategy == RolloutStrategy.GRADUAL:
            return self._evaluate_gradual_rollout(flag, user_id)
        
        # Custom rules
        if config.strategy == RolloutStrategy.CUSTOM:
            return self._evaluate_custom_rules(config.custom_rules, context)
        
        return False
    
    def _hash_user_to_percentage(self, user_id: str, flag_name: str) -> int:
        """
        Hash user ID and flag name to a consistent percentage
        
        Args:
            user_id: The user ID
            flag_name: The flag name
            
        Returns:
            Integer between 0 and 100
        """
        combined = f"{user_id}:{flag_name}"
        hash_obj = hashlib.md5(combined.encode())
        hash_int = int(hash_obj.hexdigest(), 16)
        return hash_int % 100
    
    def _evaluate_gradual_rollout(self, flag: FeatureFlag, user_id: Optional[str] = None) -> bool:
        """
        Evaluate gradual rollout based on time
        
        Args:
            flag: The feature flag
            user_id: Optional user ID
            
        Returns:
            Boolean indicating if feature should be enabled
        """
        if not flag.rollout_config:
            return False
        
        config = flag.rollout_config
        created = datetime.fromisoformat(flag.created_at)
        now = datetime.utcnow()
        elapsed_days = (now - created).days
        
        if elapsed_days >= config.duration_days:
            return True
        
        # Calculate current percentage based on elapsed time
        progress = elapsed_days / config.duration_days
        current_percentage = int(config.start_percentage + 
                                (config.end_percentage - config.start_percentage) * progress)
        
        if user_id:
            return self._hash_user_to_percentage(user_id, flag.name) < current_percentage
        
        return random.randint(0, 100) < current_percentage
    
    def _evaluate_custom_rules(self, rules: Dict[str, Any], 
                              context: Optional[Dict[str, Any]] = None) -> bool:
        """
        Evaluate custom rules based on context
        
        Args:
            rules: Dictionary of custom rules
            context: Context dictionary for evaluation
            
        Returns:
            Boolean indicating if feature should be enabled
        """
        if not context:
            return False
        
        # Simple rule evaluation - can be extended
        for rule_key, rule_value in rules.items():
            if rule_key not in context:
                return False
            if context[rule_key] != rule_value:
                return False
        
        return True


class FeatureFlagStore:
    """Persistent storage for feature flags using SQLite"""
    
    def __init__(self, db_path: str = "feature_flags.db"):
        """
        Initialize the feature flag store
        
        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = db_path
        self.lock = threading.RLock()
        self._initialize_db()
    
    def _initialize_db(self):
        """Initialize the database schema"""
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS feature_flags (
                    name TEXT PRIMARY KEY,
                    status TEXT NOT NULL,
                    description TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    created_by TEXT,
                    rollout_config TEXT,
                    scheduled_enable_at TEXT,
                    scheduled_disable_at TEXT,
                    tags TEXT,
                    metadata TEXT
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS flag_audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    flag_name TEXT NOT NULL,
                    action TEXT NOT NULL,
                    changed_by TEXT,
                    timestamp TEXT NOT NULL,
                    old_value TEXT,
                    new_value TEXT,
                    FOREIGN KEY (flag_name) REFERENCES feature_flags(name)
                )
            ''')
            
            conn.commit()
            conn.close()
    
    def save_flag(self, flag: FeatureFlag, changed_by: str = "system") -> bool:
        """
        Save a feature flag to the database
        
        Args:
            flag: The feature flag to save
            changed_by: User who made the change
            
        Returns:
            Boolean indicating success
        """
        with self.lock:
            try:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                
                rollout_config_json = json.dumps(flag.rollout_config.to_dict()) if flag.rollout_config else None
                tags_json = json.dumps(flag.tags)
                metadata_json = json.dumps(flag.metadata)
                
                # Check if flag exists
                cursor.execute('SELECT * FROM feature_flags WHERE name = ?', (flag.name,))
                existing = cursor.fetchone()
                
                if existing:
                    # Update existing flag
                    cursor.execute('''
                        UPDATE feature_flags 
                        SET status = ?, description = ?, updated_at = ?, 
                            rollout_config = ?, scheduled_enable_at = ?, 
                            scheduled_disable_at = ?, tags = ?, metadata = ?
                        WHERE name = ?
                    ''', (
                        flag.status.value,
                        flag.description,
                        flag.updated_at,
                        rollout_config_json,
                        flag.scheduled_enable_at,
                        flag.scheduled_disable_at,
                        tags_json,
                        metadata_json,
                        flag.name
                    ))
                    
                    # Log the change
                    self._log_audit(cursor, flag.name, 'UPDATE', changed_by, 
                                   json.dumps(asdict(existing)), json.dumps(flag.to_dict()))
                else:
                    # Insert new flag
                    cursor.execute('''
                        INSERT INTO feature_flags 
                        (name, status, description, created_at, updated_at, created_by,
                         rollout_config, scheduled_enable_at, scheduled_disable_at, tags, metadata)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        flag.name,
                        flag.status.value,
                        flag.description,
                        flag.created_at,
                        flag.updated_at,
                        flag.created_by,
                        rollout_config_json,
                        flag.scheduled_enable_at,
                        flag.scheduled_disable_at,
                        tags_json,
                        metadata_json
                    ))
                    
                    # Log the creation
                    self._log_audit(cursor, flag.name, 'CREATE', changed_by, None, 
                                   json.dumps(flag.to_dict()))
                
                conn.commit()
                conn.close()
                logger.info(f"Flag {flag.name} saved successfully")
                return True
            except Exception as e:
                logger.error(f"Error saving flag {flag.name}: {str(e)}")
                return False
    
    def get_flag(self, name: str) -> Optional[FeatureFlag]:
        """
        Retrieve a feature flag by name
        
        Args:
            name: The flag name
            
        Returns:
            FeatureFlag object or None if not found
        """
        with self.lock:
            try:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                
                cursor.execute('SELECT * FROM feature_flags WHERE name = ?', (name,))
                row = cursor.fetchone()
                conn.close()
                
                if not row:
                    return None
                
                return self._row_to_flag(row)
            except Exception as e:
                logger.error(f"Error retrieving flag {name}: {str(e)}")
                return None
    
    def get_all_flags(self) -> List[FeatureFlag]:
        """
        Retrieve all feature flags
        
        Returns:
            List of FeatureFlag objects
        """
        with self.lock:
            try:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                
                cursor.execute('SELECT * FROM feature_flags')
                rows = cursor.fetchall()
                conn.close()
                
                return [self._row_to_flag(row) for row in rows]
            except Exception as e:
                logger.error(f"Error retrieving all flags: {str(e)}")
                return []
    
    def delete_flag(self, name: str, deleted_by: str = "system") -> bool:
        """
        Delete a feature flag
        
        Args:
            name: The flag name
            deleted_by: User who deleted the flag
            
        Returns:
            Boolean indicating success
        """
        with self.lock:
            try:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                
                # Get the flag before deletion for audit log
                cursor.execute('SELECT * FROM feature_flags WHERE name = ?', (name,))
                row = cursor.fetchone()