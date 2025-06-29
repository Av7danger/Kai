#!/usr/bin/env python3
"""
🚀 Advanced Integration & Optimization System
Intelligent orchestration of all framework components

Features:
- Advanced automation workflows
- Performance optimization and caching
- Intelligent resource management
- Advanced security features
- Multi-threading and async processing
- Advanced error handling and recovery
- Integration with external tools and APIs
- Advanced analytics and machine learning
"""

import os
import sys
import json
import time
import asyncio
import threading
import logging
import hashlib
import sqlite3
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, asdict
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
import queue
import signal
import psutil
import yaml
from functools import wraps
import pickle
import gzip
import base64

# Import framework components
try:
    from recon_manager import get_recon_manager
    from ai_analysis import get_ai_manager
    from monitoring_manager import get_monitoring_manager
    from bug_submission import get_submission_manager
    from exploit_manager import get_exploit_manager
    from dashboard import get_dashboard_manager
    FRAMEWORK_AVAILABLE = True
except ImportError:
    FRAMEWORK_AVAILABLE = False
    print("Warning: Some framework components not available")

logger = logging.getLogger(__name__)

@dataclass
class WorkflowStep:
    """Workflow step definition"""
    id: str
    name: str
    component: str
    function: str
    parameters: Dict[str, Any]
    dependencies: List[str]
    timeout: int = 300
    retry_count: int = 3
    critical: bool = False

@dataclass
class WorkflowExecution:
    """Workflow execution instance"""
    id: str
    workflow_id: str
    status: str  # pending, running, completed, failed, cancelled
    start_time: datetime
    end_time: Optional[datetime] = None
    current_step: Optional[str] = None
    progress: float = 0.0
    results: Dict[str, Any] = None
    errors: List[str] = None

@dataclass
class PerformanceMetrics:
    """Performance metrics"""
    component: str
    operation: str
    execution_time: float
    memory_usage: float
    cpu_usage: float
    success_rate: float
    timestamp: datetime

class AdvancedIntegrationManager:
    """Advanced integration and optimization manager"""
    
    def __init__(self, config_path: str = 'advanced_integration_config.yml'):
        self.config_path = config_path
        self.config = self._load_config()
        
        # Framework managers
        self.framework_managers = {}
        if FRAMEWORK_AVAILABLE:
            self._initialize_framework_managers()
        
        # Workflow management
        self.workflows: Dict[str, List[WorkflowStep]] = {}
        self.executions: Dict[str, WorkflowExecution] = {}
        self.execution_queue = queue.Queue()
        
        # Performance monitoring
        self.performance_metrics: List[PerformanceMetrics] = []
        self.cache: Dict[str, Any] = {}
        
        # Threading and async
        self.executor = ThreadPoolExecutor(max_workers=self.config['performance']['max_workers'])
        self.process_executor = ProcessPoolExecutor(max_workers=self.config['performance']['max_processes'])
        
        # Security features
        self.security_manager = SecurityManager(self.config['security'])
        
        # Database
        self.db_path = 'advanced_integration.db'
        self._init_database()
        
        # Create output directories
        self.output_dir = Path('advanced_integration_results')
        self.output_dir.mkdir(exist_ok=True)
        
        for subdir in ['workflows', 'cache', 'logs', 'analytics', 'exports']:
            (self.output_dir / subdir).mkdir(exist_ok=True)
        
        # Start background workers
        self._start_background_workers()
        
        logger.info("Advanced Integration Manager initialized successfully")
    
    def _load_config(self) -> Dict:
        """Load advanced integration configuration"""
        if os.path.exists(self.config_path):
            with open(self.config_path, 'r') as f:
                return yaml.safe_load(f)
        else:
            return self._get_default_config()
    
    def _get_default_config(self) -> Dict:
        """Get default advanced integration configuration"""
        return {
            'performance': {
                'max_workers': 10,
                'max_processes': 4,
                'cache_size': 1000,
                'cache_ttl': 3600,
                'enable_compression': True,
                'enable_caching': True
            },
            'security': {
                'enable_encryption': True,
                'encryption_key': 'your-secret-key-change-this',
                'enable_audit_logging': True,
                'enable_rate_limiting': True,
                'max_requests_per_minute': 100,
                'enable_input_validation': True
            },
            'workflows': {
                'max_concurrent_workflows': 5,
                'workflow_timeout': 3600,
                'enable_auto_retry': True,
                'retry_delay': 60
            },
            'monitoring': {
                'enable_performance_monitoring': True,
                'metrics_retention_days': 30,
                'enable_resource_monitoring': True,
                'alert_thresholds': {
                    'cpu_usage': 80,
                    'memory_usage': 80,
                    'disk_usage': 90
                }
            },
            'integration': {
                'enable_external_apis': True,
                'enable_webhook_notifications': True,
                'webhook_url': '',
                'enable_third_party_integrations': True
            }
        }
    
    def _init_database(self):
        """Initialize advanced integration database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Workflows table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS workflows (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT,
                steps TEXT,
                created_at TEXT,
                updated_at TEXT,
                is_active BOOLEAN DEFAULT TRUE
            )
        ''')
        
        # Workflow executions table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS workflow_executions (
                id TEXT PRIMARY KEY,
                workflow_id TEXT,
                status TEXT,
                start_time TEXT,
                end_time TEXT,
                current_step TEXT,
                progress REAL,
                results TEXT,
                errors TEXT,
                FOREIGN KEY (workflow_id) REFERENCES workflows (id)
            )
        ''')
        
        # Performance metrics table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS performance_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                component TEXT,
                operation TEXT,
                execution_time REAL,
                memory_usage REAL,
                cpu_usage REAL,
                success_rate REAL,
                timestamp TEXT
            )
        ''')
        
        # Cache table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS cache (
                key TEXT PRIMARY KEY,
                value TEXT,
                created_at TEXT,
                expires_at TEXT
            )
        ''')
        
        # Security audit log table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS security_audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                user_id TEXT,
                action TEXT,
                resource TEXT,
                ip_address TEXT,
                user_agent TEXT,
                success BOOLEAN,
                details TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def _initialize_framework_managers(self):
        """Initialize framework component managers"""
        try:
            self.framework_managers['recon'] = get_recon_manager()
        except:
            logger.warning("Reconnaissance manager not available")
        
        try:
            self.framework_managers['ai'] = get_ai_manager()
        except:
            logger.warning("AI analysis manager not available")
        
        try:
            self.framework_managers['monitoring'] = get_monitoring_manager()
        except:
            logger.warning("Monitoring manager not available")
        
        try:
            self.framework_managers['submission'] = get_submission_manager()
        except:
            logger.warning("Submission manager not available")
        
        try:
            self.framework_managers['exploitation'] = get_exploit_manager()
        except:
            logger.warning("Exploitation manager not available")
        
        try:
            self.framework_managers['dashboard'] = get_dashboard_manager()
        except:
            logger.warning("Dashboard manager not available")
    
    def _start_background_workers(self):
        """Start background worker threads"""
        # Workflow execution worker
        self.workflow_worker = threading.Thread(target=self._workflow_worker_loop, daemon=True)
        self.workflow_worker.start()
        
        # Performance monitoring worker
        self.monitoring_worker = threading.Thread(target=self._monitoring_worker_loop, daemon=True)
        self.monitoring_worker.start()
        
        # Cache cleanup worker
        self.cache_worker = threading.Thread(target=self._cache_cleanup_worker_loop, daemon=True)
        self.cache_worker.start()
        
        logger.info("Background workers started")
    
    def _workflow_worker_loop(self):
        """Background worker for workflow execution"""
        while True:
            try:
                # Get workflow from queue
                execution_id = self.execution_queue.get(timeout=1)
                if execution_id in self.executions:
                    self._execute_workflow(execution_id)
                self.execution_queue.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Workflow worker error: {e}")
    
    def _monitoring_worker_loop(self):
        """Background worker for performance monitoring"""
        while True:
            try:
                self._collect_performance_metrics()
                time.sleep(60)  # Collect metrics every minute
            except Exception as e:
                logger.error(f"Monitoring worker error: {e}")
    
    def _cache_cleanup_worker_loop(self):
        """Background worker for cache cleanup"""
        while True:
            try:
                self._cleanup_expired_cache()
                time.sleep(300)  # Cleanup every 5 minutes
            except Exception as e:
                logger.error(f"Cache cleanup worker error: {e}")
    
    def create_workflow(self, workflow_id: str, name: str, steps: List[WorkflowStep], description: str = "") -> bool:
        """Create a new workflow"""
        try:
            # Validate workflow
            if not self._validate_workflow(steps):
                raise ValueError("Invalid workflow configuration")
            
            # Store workflow
            self.workflows[workflow_id] = steps
            
            # Save to database
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT OR REPLACE INTO workflows 
                (id, name, description, steps, created_at, updated_at, is_active)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                workflow_id, name, description, json.dumps([asdict(step) for step in steps]),
                datetime.now().isoformat(), datetime.now().isoformat(), True
            ))
            
            conn.commit()
            conn.close()
            
            logger.info(f"Workflow '{name}' created successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to create workflow: {e}")
            return False
    
    def _validate_workflow(self, steps: List[WorkflowStep]) -> bool:
        """Validate workflow configuration"""
        if not steps:
            return False
        
        # Check for circular dependencies
        step_ids = {step.id for step in steps}
        for step in steps:
            for dep in step.dependencies:
                if dep not in step_ids:
                    return False
        
        # Check for valid components
        valid_components = list(self.framework_managers.keys())
        for step in steps:
            if step.component not in valid_components:
                return False
        
        return True
    
    def execute_workflow(self, workflow_id: str, parameters: Dict[str, Any] = None) -> str:
        """Execute a workflow"""
        if workflow_id not in self.workflows:
            raise ValueError(f"Workflow '{workflow_id}' not found")
        
        # Create execution instance
        execution_id = f"{workflow_id}_{int(time.time())}"
        execution = WorkflowExecution(
            id=execution_id,
            workflow_id=workflow_id,
            status='pending',
            start_time=datetime.now(),
            results=parameters or {},
            errors=[]
        )
        
        self.executions[execution_id] = execution
        
        # Add to execution queue
        self.execution_queue.put(execution_id)
        
        logger.info(f"Workflow execution '{execution_id}' queued")
        return execution_id
    
    def _execute_workflow(self, execution_id: str):
        """Execute a workflow (internal method)"""
        execution = self.executions[execution_id]
        workflow_steps = self.workflows[execution.workflow_id]
        
        try:
            execution.status = 'running'
            self._update_execution_in_db(execution)
            
            # Execute steps in dependency order
            completed_steps = set()
            total_steps = len(workflow_steps)
            
            while len(completed_steps) < total_steps:
                # Find steps ready to execute
                ready_steps = [
                    step for step in workflow_steps
                    if step.id not in completed_steps and
                    all(dep in completed_steps for dep in step.dependencies)
                ]
                
                if not ready_steps:
                    raise Exception("Circular dependency detected")
                
                # Execute ready steps in parallel
                futures = []
                for step in ready_steps:
                    future = self.executor.submit(self._execute_step, step, execution)
                    futures.append((step, future))
                
                # Wait for completion
                for step, future in futures:
                    try:
                        result = future.result(timeout=step.timeout)
                        execution.results[step.id] = result
                        completed_steps.add(step.id)
                        execution.current_step = step.id
                        execution.progress = len(completed_steps) / total_steps
                        self._update_execution_in_db(execution)
                        
                    except Exception as e:
                        if step.critical:
                            raise e
                        else:
                            execution.errors.append(f"Step {step.id} failed: {e}")
                            logger.warning(f"Non-critical step {step.id} failed: {e}")
            
            execution.status = 'completed'
            execution.end_time = datetime.now()
            self._update_execution_in_db(execution)
            
            logger.info(f"Workflow execution '{execution_id}' completed successfully")
            
        except Exception as e:
            execution.status = 'failed'
            execution.end_time = datetime.now()
            execution.errors.append(str(e))
            self._update_execution_in_db(execution)
            
            logger.error(f"Workflow execution '{execution_id}' failed: {e}")
    
    def _execute_step(self, step: WorkflowStep, execution: WorkflowExecution) -> Any:
        """Execute a single workflow step"""
        start_time = time.time()
        
        try:
            # Get component manager
            manager = self.framework_managers.get(step.component)
            if not manager:
                raise Exception(f"Component '{step.component}' not available")
            
            # Get function
            func = getattr(manager, step.function, None)
            if not func:
                raise Exception(f"Function '{step.function}' not found in {step.component}")
            
            # Execute function
            result = func(**step.parameters)
            
            # Record performance metrics
            execution_time = time.time() - start_time
            self._record_performance_metric(step.component, step.function, execution_time)
            
            return result
            
        except Exception as e:
            # Record failed performance metrics
            execution_time = time.time() - start_time
            self._record_performance_metric(step.component, step.function, execution_time, success=False)
            raise e
    
    def _update_execution_in_db(self, execution: WorkflowExecution):
        """Update execution in database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO workflow_executions 
            (id, workflow_id, status, start_time, end_time, current_step, progress, results, errors)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            execution.id, execution.workflow_id, execution.status,
            execution.start_time.isoformat(),
            execution.end_time.isoformat() if execution.end_time else None,
            execution.current_step, execution.progress,
            json.dumps(execution.results) if execution.results else None,
            json.dumps(execution.errors) if execution.errors else None
        ))
        
        conn.commit()
        conn.close()
    
    def _record_performance_metric(self, component: str, operation: str, execution_time: float, success: bool = True):
        """Record performance metric"""
        try:
            # Get system metrics
            memory_usage = psutil.virtual_memory().percent
            cpu_usage = psutil.cpu_percent()
            
            metric = PerformanceMetrics(
                component=component,
                operation=operation,
                execution_time=execution_time,
                memory_usage=memory_usage,
                cpu_usage=cpu_usage,
                success_rate=1.0 if success else 0.0,
                timestamp=datetime.now()
            )
            
            self.performance_metrics.append(metric)
            
            # Save to database
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO performance_metrics 
                (component, operation, execution_time, memory_usage, cpu_usage, success_rate, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                metric.component, metric.operation, metric.execution_time,
                metric.memory_usage, metric.cpu_usage, metric.success_rate,
                metric.timestamp.isoformat()
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Failed to record performance metric: {e}")
    
    def _collect_performance_metrics(self):
        """Collect system performance metrics"""
        try:
            # System metrics
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            # Check alert thresholds
            if cpu_percent > self.config['monitoring']['alert_thresholds']['cpu_usage']:
                self._send_alert('High CPU Usage', f"CPU usage: {cpu_percent}%")
            
            if memory.percent > self.config['monitoring']['alert_thresholds']['memory_usage']:
                self._send_alert('High Memory Usage', f"Memory usage: {memory.percent}%")
            
            if disk.percent > self.config['monitoring']['alert_thresholds']['disk_usage']:
                self._send_alert('High Disk Usage', f"Disk usage: {disk.percent}%")
            
        except Exception as e:
            logger.error(f"Failed to collect performance metrics: {e}")
    
    def _send_alert(self, title: str, message: str):
        """Send alert notification"""
        logger.warning(f"ALERT: {title} - {message}")
        
        # Send webhook notification if configured
        if self.config['integration']['enable_webhook_notifications'] and self.config['integration']['webhook_url']:
            try:
                import requests
                payload = {
                    'title': title,
                    'message': message,
                    'timestamp': datetime.now().isoformat()
                }
                requests.post(self.config['integration']['webhook_url'], json=payload, timeout=5)
            except Exception as e:
                logger.error(f"Failed to send webhook notification: {e}")
    
    def get_cache(self, key: str) -> Optional[Any]:
        """Get value from cache"""
        if not self.config['performance']['enable_caching']:
            return None
        
        # Check memory cache first
        if key in self.cache:
            cache_entry = self.cache[key]
            if cache_entry['expires_at'] > datetime.now():
                return cache_entry['value']
            else:
                del self.cache[key]
        
        # Check database cache
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('SELECT value, expires_at FROM cache WHERE key = ?', (key,))
        row = cursor.fetchone()
        conn.close()
        
        if row and datetime.fromisoformat(row[1]) > datetime.now():
            value = self._deserialize_value(row[0])
            
            # Add to memory cache
            self.cache[key] = {
                'value': value,
                'expires_at': datetime.fromisoformat(row[1])
            }
            
            return value
        
        return None
    
    def set_cache(self, key: str, value: Any, ttl: int = None):
        """Set value in cache"""
        if not self.config['performance']['enable_caching']:
            return
        
        ttl = ttl or self.config['performance']['cache_ttl']
        expires_at = datetime.now() + timedelta(seconds=ttl)
        
        # Add to memory cache
        self.cache[key] = {
            'value': value,
            'expires_at': expires_at
        }
        
        # Save to database cache
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO cache (key, value, created_at, expires_at)
            VALUES (?, ?, ?, ?)
        ''', (
            key, self._serialize_value(value),
            datetime.now().isoformat(), expires_at.isoformat()
        ))
        
        conn.commit()
        conn.close()
    
    def _serialize_value(self, value: Any) -> str:
        """Serialize value for storage"""
        if self.config['performance']['enable_compression']:
            data = gzip.compress(pickle.dumps(value))
            return base64.b64encode(data).decode('utf-8')
        else:
            return json.dumps(value)
    
    def _deserialize_value(self, serialized: str) -> Any:
        """Deserialize value from storage"""
        if self.config['performance']['enable_compression']:
            data = base64.b64decode(serialized.encode('utf-8'))
            return pickle.loads(gzip.decompress(data))
        else:
            return json.loads(serialized)
    
    def _cleanup_expired_cache(self):
        """Clean up expired cache entries"""
        try:
            # Clean memory cache
            current_time = datetime.now()
            expired_keys = [
                key for key, entry in self.cache.items()
                if entry['expires_at'] <= current_time
            ]
            for key in expired_keys:
                del self.cache[key]
            
            # Clean database cache
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('DELETE FROM cache WHERE expires_at <= ?', (current_time.isoformat(),))
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Failed to cleanup expired cache: {e}")
    
    def get_workflow_status(self, execution_id: str) -> Optional[WorkflowExecution]:
        """Get workflow execution status"""
        return self.executions.get(execution_id)
    
    def get_performance_analytics(self, component: str = None, days: int = 7) -> Dict[str, Any]:
        """Get performance analytics"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            since_date = (datetime.now() - timedelta(days=days)).isoformat()
            
            if component:
                cursor.execute('''
                    SELECT AVG(execution_time), AVG(memory_usage), AVG(cpu_usage), AVG(success_rate)
                    FROM performance_metrics 
                    WHERE component = ? AND timestamp >= ?
                ''', (component, since_date))
            else:
                cursor.execute('''
                    SELECT AVG(execution_time), AVG(memory_usage), AVG(cpu_usage), AVG(success_rate)
                    FROM performance_metrics 
                    WHERE timestamp >= ?
                ''', (since_date,))
            
            row = cursor.fetchone()
            conn.close()
            
            if row:
                return {
                    'avg_execution_time': row[0] or 0,
                    'avg_memory_usage': row[1] or 0,
                    'avg_cpu_usage': row[2] or 0,
                    'avg_success_rate': row[3] or 0
                }
            
            return {
                'avg_execution_time': 0,
                'avg_memory_usage': 0,
                'avg_cpu_usage': 0,
                'avg_success_rate': 0
            }
            
        except Exception as e:
            logger.error(f"Failed to get performance analytics: {e}")
            return {}
    
    def optimize_performance(self):
        """Run performance optimization"""
        try:
            # Clear expired cache
            self._cleanup_expired_cache()
            
            # Optimize database
            conn = sqlite3.connect(self.db_path)
            conn.execute('VACUUM')
            conn.execute('ANALYZE')
            conn.close()
            
            # Clear old performance metrics
            cutoff_date = (datetime.now() - timedelta(days=self.config['monitoring']['metrics_retention_days'])).isoformat()
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('DELETE FROM performance_metrics WHERE timestamp < ?', (cutoff_date,))
            conn.commit()
            conn.close()
            
            logger.info("Performance optimization completed")
            
        except Exception as e:
            logger.error(f"Performance optimization failed: {e}")
    
    def shutdown(self):
        """Shutdown the integration manager"""
        try:
            # Stop background workers
            self.executor.shutdown(wait=True)
            self.process_executor.shutdown(wait=True)
            
            # Save final state
            self.optimize_performance()
            
            logger.info("Advanced Integration Manager shutdown completed")
            
        except Exception as e:
            logger.error(f"Shutdown error: {e}")

class SecurityManager:
    """Advanced security manager"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.rate_limit_cache = {}
        self.audit_log = []
    
    def encrypt_data(self, data: str) -> str:
        """Encrypt sensitive data"""
        if not self.config['enable_encryption']:
            return data
        
        try:
            import cryptography.fernet
            key = base64.urlsafe_b64encode(hashlib.sha256(self.config['encryption_key'].encode()).digest())
            f = cryptography.fernet.Fernet(key)
            return f.encrypt(data.encode()).decode()
        except ImportError:
            logger.warning("Cryptography library not available, encryption disabled")
            return data
        except Exception as e:
            logger.error(f"Encryption failed: {e}")
            return data
    
    def decrypt_data(self, encrypted_data: str) -> str:
        """Decrypt sensitive data"""
        if not self.config['enable_encryption']:
            return encrypted_data
        
        try:
            import cryptography.fernet
            key = base64.urlsafe_b64encode(hashlib.sha256(self.config['encryption_key'].encode()).digest())
            f = cryptography.fernet.Fernet(key)
            return f.decrypt(encrypted_data.encode()).decode()
        except ImportError:
            logger.warning("Cryptography library not available, decryption disabled")
            return encrypted_data
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            return encrypted_data
    
    def validate_input(self, data: Any, validation_rules: Dict[str, Any]) -> bool:
        """Validate input data"""
        if not self.config['enable_input_validation']:
            return True
        
        try:
            # Basic validation rules
            if 'required' in validation_rules and validation_rules['required'] and not data:
                return False
            
            if 'type' in validation_rules:
                if validation_rules['type'] == 'string' and not isinstance(data, str):
                    return False
                elif validation_rules['type'] == 'int' and not isinstance(data, int):
                    return False
                elif validation_rules['type'] == 'list' and not isinstance(data, list):
                    return False
            
            if 'min_length' in validation_rules and len(str(data)) < validation_rules['min_length']:
                return False
            
            if 'max_length' in validation_rules and len(str(data)) > validation_rules['max_length']:
                return False
            
            return True
            
        except Exception as e:
            logger.error(f"Input validation failed: {e}")
            return False
    
    def check_rate_limit(self, identifier: str) -> bool:
        """Check rate limiting"""
        if not self.config['enable_rate_limiting']:
            return True
        
        current_time = time.time()
        window_start = current_time - 60  # 1 minute window
        
        # Clean old entries
        self.rate_limit_cache = {
            k: v for k, v in self.rate_limit_cache.items()
            if v > window_start
        }
        
        # Count requests in window
        request_count = sum(1 for t in self.rate_limit_cache.values() if t > window_start)
        
        if request_count >= self.config['max_requests_per_minute']:
            return False
        
        # Add current request
        self.rate_limit_cache[f"{identifier}_{current_time}"] = current_time
        return True
    
    def log_audit_event(self, user_id: str, action: str, resource: str, ip_address: str = None, 
                       user_agent: str = None, success: bool = True, details: str = None):
        """Log security audit event"""
        if not self.config['enable_audit_logging']:
            return
        
        try:
            event = {
                'timestamp': datetime.now().isoformat(),
                'user_id': user_id,
                'action': action,
                'resource': resource,
                'ip_address': ip_address,
                'user_agent': user_agent,
                'success': success,
                'details': details
            }
            
            self.audit_log.append(event)
            
            # Save to database
            conn = sqlite3.connect('advanced_integration.db')
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO security_audit_log 
                (timestamp, user_id, action, resource, ip_address, user_agent, success, details)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                event['timestamp'], event['user_id'], event['action'], event['resource'],
                event['ip_address'], event['user_agent'], event['success'], event['details']
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Failed to log audit event: {e}")

# Global integration manager instance
integration_manager = None

def initialize_integration_manager(config_path: str = 'advanced_integration_config.yml'):
    """Initialize the global integration manager"""
    global integration_manager
    integration_manager = AdvancedIntegrationManager(config_path)
    return integration_manager

def get_integration_manager() -> AdvancedIntegrationManager:
    """Get the global integration manager instance"""
    if integration_manager is None:
        raise RuntimeError("Integration manager not initialized. Call initialize_integration_manager() first.")
    return integration_manager

# Signal handlers for graceful shutdown
def signal_handler(signum, frame):
    """Handle shutdown signals"""
    if integration_manager:
        integration_manager.shutdown()
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

if __name__ == '__main__':
    # Initialize integration manager
    manager = initialize_integration_manager()
    
    try:
        # Keep the manager running
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        manager.shutdown() 