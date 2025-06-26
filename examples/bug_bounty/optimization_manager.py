"""
Enhanced Optimization Manager for Bug Bounty Framework
Advanced optimization, error handling, and fallback mechanisms
"""

import asyncio
import json
import logging
import time
import traceback
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple, Callable
from dataclasses import dataclass, field
from enum import Enum
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import sqlite3
import pickle
import yaml
from contextlib import asynccontextmanager

class OptimizationLevel(Enum):
    """Optimization levels for different operations"""
    MINIMAL = "minimal"
    BALANCED = "balanced"
    AGGRESSIVE = "aggressive"
    MAXIMUM = "maximum"

class ErrorSeverity(Enum):
    """Error severity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class PerformanceMetrics:
    """Performance tracking metrics"""
    operation_name: str
    start_time: float
    end_time: float
    duration: float
    memory_start: float
    memory_end: float
    memory_used: float
    success: bool
    error_message: Optional[str] = None
    retry_count: int = 0
    optimization_level: OptimizationLevel = OptimizationLevel.BALANCED

@dataclass
class ErrorContext:
    """Comprehensive error context"""
    error_type: str
    severity: ErrorSeverity
    message: str
    traceback: str
    timestamp: datetime
    operation: str
    data_context: Dict[str, Any]
    recovery_attempts: int = 0
    resolved: bool = False

class CacheManager:
    """Advanced caching with TTL, size limits, and intelligent eviction"""
    
    def __init__(self, max_size: int = 1000, default_ttl: int = 3600):
        self.max_size = max_size
        self.default_ttl = default_ttl
        self.cache: Dict[str, Dict] = {}
        self.access_times: Dict[str, float] = {}
        self.lock = threading.RLock()
        
    def get(self, key: str) -> Optional[Any]:
        """Get cached value with TTL check"""
        with self.lock:
            if key not in self.cache:
                return None
                
            entry = self.cache[key]
            if time.time() - entry['timestamp'] > entry.get('ttl', self.default_ttl):
                self._remove(key)
                return None
                
            self.access_times[key] = time.time()
            entry['access_count'] += 1
            return entry['value']
    
    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        """Set cached value with optional TTL"""
        with self.lock:
            if len(self.cache) >= self.max_size:
                self._evict_lru()
            
            self.cache[key] = {
                'value': value,
                'timestamp': time.time(),
                'ttl': ttl or self.default_ttl,
                'access_count': 1
            }
            self.access_times[key] = time.time()
    
    def _evict_lru(self) -> None:
        """Evict least recently used items"""
        if not self.access_times:
            return
            
        # Remove 20% of items based on LRU
        items_to_remove = max(1, len(self.cache) // 5)
        sorted_items = sorted(self.access_times.items(), key=lambda x: x[1])
        
        for key, _ in sorted_items[:items_to_remove]:
            self._remove(key)
    
    def _remove(self, key: str) -> None:
        """Remove item from cache"""
        self.cache.pop(key, None)
        self.access_times.pop(key, None)
    
    def clear(self) -> None:
        """Clear all cached items"""
        with self.lock:
            self.cache.clear()
            self.access_times.clear()
    
    def stats(self) -> Dict:
        """Get cache statistics"""
        with self.lock:
            total_access = sum(entry['access_count'] for entry in self.cache.values())
            return {
                'size': len(self.cache),
                'max_size': self.max_size,
                'hit_ratio': 0 if not hasattr(self, '_hit_count') else 
                           getattr(self, '_hit_count', 0) / max(getattr(self, '_total_requests', 1), 1),
                'total_access': total_access,
                'avg_access_per_item': total_access / max(len(self.cache), 1)
            }

class DatabaseManager:
    """SQLite database manager for persistent storage"""
    
    def __init__(self, db_path: str = "bug_bounty_optimization.db"):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Initialize database tables"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Performance metrics table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS performance_metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    operation_name TEXT,
                    duration REAL,
                    memory_used REAL,
                    success BOOLEAN,
                    error_message TEXT,
                    retry_count INTEGER,
                    timestamp DATETIME,
                    optimization_level TEXT
                )
            """)
            
            # Error tracking table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS error_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    error_type TEXT,
                    severity TEXT,
                    message TEXT,
                    traceback TEXT,
                    operation TEXT,
                    timestamp DATETIME,
                    recovery_attempts INTEGER,
                    resolved BOOLEAN
                )
            """)
            
            # Configuration table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS configuration (
                    key TEXT PRIMARY KEY,
                    value TEXT,
                    updated_at DATETIME
                )
            """)
            
            conn.commit()
    
    def save_performance_metric(self, metric: PerformanceMetrics):
        """Save performance metric to database"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO performance_metrics 
                (operation_name, duration, memory_used, success, error_message, 
                 retry_count, timestamp, optimization_level)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                metric.operation_name, metric.duration, metric.memory_used,
                metric.success, metric.error_message, metric.retry_count,
                datetime.now(), metric.optimization_level.value
            ))
            conn.commit()
    
    def save_error(self, error: ErrorContext):
        """Save error to database"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO error_log 
                (error_type, severity, message, traceback, operation, 
                 timestamp, recovery_attempts, resolved)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                error.error_type, error.severity.value, error.message,
                error.traceback, error.operation, error.timestamp,
                error.recovery_attempts, error.resolved
            ))
            conn.commit()
    
    def get_performance_stats(self, operation_name: Optional[str] = None, 
                            hours: int = 24) -> Dict:
        """Get performance statistics"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            where_clause = "WHERE timestamp > datetime('now', '-{} hours')".format(hours)
            if operation_name:
                where_clause += f" AND operation_name = '{operation_name}'"
            
            cursor.execute(f"""
                SELECT 
                    operation_name,
                    AVG(duration) as avg_duration,
                    MIN(duration) as min_duration,
                    MAX(duration) as max_duration,
                    AVG(memory_used) as avg_memory,
                    SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) as success_count,
                    COUNT(*) as total_count,
                    AVG(retry_count) as avg_retries
                FROM performance_metrics 
                {where_clause}
                GROUP BY operation_name
            """)
            
            results = {}
            for row in cursor.fetchall():
                op_name = row[0]
                results[op_name] = {
                    'avg_duration': row[1],
                    'min_duration': row[2], 
                    'max_duration': row[3],
                    'avg_memory': row[4],
                    'success_rate': row[5] / row[6] if row[6] > 0 else 0,
                    'total_executions': row[6],
                    'avg_retries': row[7]
                }
            
            return results

class SmartRetryManager:
    """Intelligent retry mechanism with exponential backoff and circuit breaker"""
    
    def __init__(self):
        self.retry_configs: Dict[str, Dict] = {}
        self.circuit_breakers: Dict[str, Dict] = {}
        self.failure_patterns: Dict[str, List] = {}
    
    def configure_retry(self, operation: str, max_retries: int = 3,
                       base_delay: float = 1.0, max_delay: float = 60.0,
                       backoff_factor: float = 2.0, jitter: bool = True):
        """Configure retry behavior for operation"""
        self.retry_configs[operation] = {
            'max_retries': max_retries,
            'base_delay': base_delay,
            'max_delay': max_delay,
            'backoff_factor': backoff_factor,
            'jitter': jitter
        }
        
        self.circuit_breakers[operation] = {
            'state': 'closed',  # closed, open, half-open
            'failure_count': 0,
            'failure_threshold': 5,
            'recovery_timeout': 60,
            'last_failure_time': None
        }
    
    async def execute_with_retry(self, operation: str, func: Callable, 
                               *args, **kwargs) -> Tuple[Any, PerformanceMetrics]:
        """Execute function with intelligent retry logic"""
        config = self.retry_configs.get(operation, {
            'max_retries': 3, 'base_delay': 1.0, 'max_delay': 60.0,
            'backoff_factor': 2.0, 'jitter': True
        })
        
        metric = PerformanceMetrics(
            operation_name=operation,
            start_time=time.time(),
            end_time=0,
            duration=0,
            memory_start=0,
            memory_end=0,
            memory_used=0,
            success=False
        )
        
        retry_count = 0
        last_exception = None
        
        # Check circuit breaker
        if self._is_circuit_open(operation):
            raise Exception(f"Circuit breaker open for operation: {operation}")
        
        while retry_count <= config['max_retries']:
            try:
                metric.retry_count = retry_count
                
                if asyncio.iscoroutinefunction(func):
                    result = await func(*args, **kwargs)
                else:
                    result = func(*args, **kwargs)
                
                metric.success = True
                metric.end_time = time.time()
                metric.duration = metric.end_time - metric.start_time
                
                # Reset circuit breaker on success
                self._reset_circuit_breaker(operation)
                
                return result, metric
                
            except Exception as e:
                last_exception = e
                retry_count += 1
                
                # Track failure pattern
                self._track_failure(operation, str(e))
                
                if retry_count <= config['max_retries']:
                    delay = self._calculate_delay(config, retry_count)
                    await asyncio.sleep(delay)
                else:
                    # Update circuit breaker on final failure
                    self._update_circuit_breaker(operation)
        
        metric.success = False
        metric.end_time = time.time()
        metric.duration = metric.end_time - metric.start_time
        metric.error_message = str(last_exception)
        
        if last_exception:
            raise last_exception
        else:
            raise Exception(f"Operation {operation} failed after {config['max_retries']} retries")
    
    def _calculate_delay(self, config: Dict, retry_count: int) -> float:
        """Calculate delay for retry with exponential backoff"""
        delay = min(
            config['base_delay'] * (config['backoff_factor'] ** (retry_count - 1)),
            config['max_delay']
        )
        
        if config['jitter']:
            import random
            delay *= (0.5 + random.random() * 0.5)  # 50-100% of calculated delay
        
        return delay
    
    def _is_circuit_open(self, operation: str) -> bool:
        """Check if circuit breaker is open"""
        breaker = self.circuit_breakers.get(operation, {})
        
        if breaker.get('state') == 'open':
            if (time.time() - breaker.get('last_failure_time', 0)) > breaker.get('recovery_timeout', 60):
                breaker['state'] = 'half-open'
                return False
            return True
        return False
    
    def _update_circuit_breaker(self, operation: str):
        """Update circuit breaker on failure"""
        breaker = self.circuit_breakers.get(operation, {})
        breaker['failure_count'] = breaker.get('failure_count', 0) + 1
        breaker['last_failure_time'] = time.time()
        
        if breaker['failure_count'] >= breaker.get('failure_threshold', 5):
            breaker['state'] = 'open'
    
    def _reset_circuit_breaker(self, operation: str):
        """Reset circuit breaker on success"""
        breaker = self.circuit_breakers.get(operation, {})
        breaker['failure_count'] = 0
        breaker['state'] = 'closed'
    
    def _track_failure(self, operation: str, error_message: str):
        """Track failure patterns for analysis"""
        if operation not in self.failure_patterns:
            self.failure_patterns[operation] = []
        
        self.failure_patterns[operation].append({
            'timestamp': time.time(),
            'error': error_message
        })
        
        # Keep only recent failures (last 100)
        if len(self.failure_patterns[operation]) > 100:
            self.failure_patterns[operation] = self.failure_patterns[operation][-100:]

class ResourceMonitor:
    """Monitor system resources and adjust optimization accordingly"""
    
    def __init__(self):
        self.cpu_threshold = 80.0
        self.memory_threshold = 85.0
        self.monitoring_active = True
        self.resource_history: List[Dict] = []
    
    def get_system_resources(self) -> Dict:
        """Get current system resource usage"""
        try:
            import psutil
            
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            return {
                'cpu_percent': cpu_percent,
                'memory_percent': memory.percent,
                'memory_available': memory.available,
                'disk_percent': disk.percent,
                'timestamp': time.time()
            }
        except (ImportError, Exception):
            # Fallback without psutil or on error
            return {
                'cpu_percent': 50.0,  # Assume moderate usage
                'memory_percent': 60.0,
                'memory_available': 1024 * 1024 * 1024,  # 1GB
                'disk_percent': 50.0,
                'timestamp': time.time()
            }
    
    def should_throttle(self) -> bool:
        """Determine if operations should be throttled"""
        resources = self.get_system_resources()
        
        return (resources['cpu_percent'] > self.cpu_threshold or 
                resources['memory_percent'] > self.memory_threshold)
    
    def get_optimization_level(self) -> OptimizationLevel:
        """Get recommended optimization level based on resources"""
        resources = self.get_system_resources()
        
        if resources['memory_percent'] > 90 or resources['cpu_percent'] > 90:
            return OptimizationLevel.MINIMAL
        elif resources['memory_percent'] > 75 or resources['cpu_percent'] > 75:
            return OptimizationLevel.BALANCED
        elif resources['memory_percent'] < 50 and resources['cpu_percent'] < 50:
            return OptimizationLevel.MAXIMUM
        else:
            return OptimizationLevel.AGGRESSIVE

class EnhancedOptimizationManager:
    """Main optimization manager coordinating all enhancement systems"""
    
    def __init__(self, config_path: Optional[str] = None):
        self.config_path = config_path
        self.cache_manager = CacheManager()
        self.db_manager = DatabaseManager()
        self.retry_manager = SmartRetryManager()
        self.resource_monitor = ResourceMonitor()
        
        # Setup logging
        self.logger = logging.getLogger('optimization_manager')
        self.logger.setLevel(logging.INFO)
        
        # Load configuration
        self.config = self._load_config()
        
        # Initialize components
        self._initialize_retry_configs()
        
        # Performance tracking
        self.operation_metrics: Dict[str, List[PerformanceMetrics]] = {}
        self.error_contexts: List[ErrorContext] = []
        
    def _load_config(self) -> Dict:
        """Load optimization configuration"""
        default_config = {
            'cache': {
                'max_size': 1000,
                'default_ttl': 3600
            },
            'retry': {
                'max_retries': 3,
                'base_delay': 1.0,
                'max_delay': 60.0
            },
            'resource_monitoring': {
                'cpu_threshold': 80.0,
                'memory_threshold': 85.0
            },
            'optimization': {
                'auto_adjust': True,
                'aggressive_mode': False
            }
        }
        
        if self.config_path and Path(self.config_path).exists():
            try:
                with open(self.config_path, 'r') as f:
                    user_config = yaml.safe_load(f)
                    default_config.update(user_config)
            except Exception as e:
                self.logger.warning(f"Failed to load config: {e}")
        
        return default_config
    
    def _initialize_retry_configs(self):
        """Initialize retry configurations for common operations"""
        operations = [
            'vulnerability_scan', 'network_scan', 'exploit_attempt',
            'report_generation', 'data_processing', 'ml_analysis'
        ]
        
        for operation in operations:
            self.retry_manager.configure_retry(
                operation,
                max_retries=self.config['retry']['max_retries'],
                base_delay=self.config['retry']['base_delay'],
                max_delay=self.config['retry']['max_delay']
            )
    
    @asynccontextmanager
    async def optimized_execution(self, operation_name: str, 
                                enable_cache: bool = True,
                                enable_retry: bool = True):
        """Context manager for optimized operation execution"""
        start_time = time.time()
        success = False
        error_message = None
        
        try:
            # Check resource constraints
            if self.resource_monitor.should_throttle():
                await asyncio.sleep(0.1)  # Brief throttle
            
            yield self
            success = True
            
        except Exception as e:
            error_message = str(e)
            
            # Create error context
            error_context = ErrorContext(
                error_type=type(e).__name__,
                severity=self._classify_error_severity(e),
                message=str(e),
                traceback=traceback.format_exc(),
                timestamp=datetime.now(),
                operation=operation_name,
                data_context={}
            )
            
            self.error_contexts.append(error_context)
            self.db_manager.save_error(error_context)
            raise
            
        finally:
            # Record performance metrics
            end_time = time.time()
            duration = end_time - start_time
            
            metric = PerformanceMetrics(
                operation_name=operation_name,
                start_time=start_time,
                end_time=end_time,
                duration=duration,
                memory_start=0,
                memory_end=0,
                memory_used=0,
                success=success,
                error_message=error_message,
                optimization_level=self.resource_monitor.get_optimization_level()
            )
            
            if operation_name not in self.operation_metrics:
                self.operation_metrics[operation_name] = []
            
            self.operation_metrics[operation_name].append(metric)
            self.db_manager.save_performance_metric(metric)
    
    async def execute_optimized(self, operation_name: str, func: Callable,
                              *args, use_cache: bool = True, 
                              use_retry: bool = True, **kwargs) -> Any:
        """Execute function with full optimization stack"""
        
        # Generate cache key if caching enabled
        cache_key = None
        if use_cache:
            cache_data = {
                'operation': operation_name,
                'args': str(args),
                'kwargs': str(sorted(kwargs.items()))
            }
            cache_key = hashlib.md5(str(cache_data).encode()).hexdigest()
            
            # Check cache first
            cached_result = self.cache_manager.get(cache_key)
            if cached_result is not None:
                return cached_result
        
        # Execute with retry if enabled
        if use_retry:
            result, metric = await self.retry_manager.execute_with_retry(
                operation_name, func, *args, **kwargs
            )
        else:
            async with self.optimized_execution(operation_name):
                if asyncio.iscoroutinefunction(func):
                    result = await func(*args, **kwargs)
                else:
                    result = func(*args, **kwargs)
        
        # Cache result if caching enabled
        if use_cache and cache_key:
            self.cache_manager.set(cache_key, result)
        
        return result
    
    def _classify_error_severity(self, exception: Exception) -> ErrorSeverity:
        """Classify error severity based on exception type"""
        if isinstance(exception, (MemoryError, SystemError)):
            return ErrorSeverity.CRITICAL
        elif isinstance(exception, (ConnectionError, TimeoutError)):
            return ErrorSeverity.HIGH
        elif isinstance(exception, (ValueError, KeyError, AttributeError)):
            return ErrorSeverity.MEDIUM
        else:
            return ErrorSeverity.LOW
    
    def get_comprehensive_stats(self) -> Dict:
        """Get comprehensive optimization statistics"""
        return {
            'cache_stats': self.cache_manager.stats(),
            'performance_stats': self.db_manager.get_performance_stats(),
            'circuit_breaker_states': {
                op: breaker['state'] 
                for op, breaker in self.retry_manager.circuit_breakers.items()
            },
            'resource_usage': self.resource_monitor.get_system_resources(),
            'error_summary': {
                'total_errors': len(self.error_contexts),
                'critical_errors': sum(1 for e in self.error_contexts 
                                     if e.severity == ErrorSeverity.CRITICAL),
                'high_errors': sum(1 for e in self.error_contexts 
                                 if e.severity == ErrorSeverity.HIGH),
                'recent_errors': len([e for e in self.error_contexts 
                                    if (datetime.now() - e.timestamp).total_seconds() < 3600])
            },
            'optimization_level': self.resource_monitor.get_optimization_level().value
        }
    
    def optimize_configuration(self) -> Dict:
        """Automatically optimize configuration based on performance data"""
        stats = self.get_comprehensive_stats()
        recommendations = {}
        
        # Cache optimization
        cache_stats = stats['cache_stats']
        if cache_stats['hit_ratio'] < 0.3:
            recommendations['cache'] = {
                'action': 'increase_size',
                'current_size': cache_stats['size'],
                'recommended_size': min(cache_stats['max_size'] * 2, 5000)
            }
        
        # Retry optimization
        perf_stats = stats['performance_stats']
        for operation, data in perf_stats.items():
            if data['success_rate'] < 0.8 and data['avg_retries'] < 2:
                recommendations[f'retry_{operation}'] = {
                    'action': 'increase_retries',
                    'current_retries': self.retry_manager.retry_configs.get(operation, {}).get('max_retries', 3),
                    'recommended_retries': min(5, data['avg_retries'] + 2)
                }
        
        # Resource optimization
        if stats['resource_usage']['memory_percent'] > 85:
            recommendations['memory'] = {
                'action': 'reduce_cache_size',
                'recommendation': 'Consider reducing cache size or enabling more aggressive eviction'
            }
        
        return recommendations

# Global optimization manager instance
optimization_manager = EnhancedOptimizationManager()

# Utility decorators for easy integration
def optimized_operation(operation_name: str, use_cache: bool = True, 
                       use_retry: bool = True):
    """Decorator for optimized operation execution"""
    def decorator(func):
        async def wrapper(*args, **kwargs):
            return await optimization_manager.execute_optimized(
                operation_name, func, *args, 
                use_cache=use_cache, use_retry=use_retry, **kwargs
            )
        return wrapper
    return decorator

async def get_optimization_stats() -> Dict:
    """Get comprehensive optimization statistics"""
    return optimization_manager.get_comprehensive_stats()

if __name__ == "__main__":
    # Demo functionality
    async def demo():
        print("🚀 Enhanced Optimization Manager Demo")
        print("=" * 50)
        
        # Test optimized execution
        @optimized_operation("demo_operation")
        async def demo_function(x: int, y: int) -> int:
            await asyncio.sleep(0.1)  # Simulate work
            if x < 0:
                raise ValueError("Negative input not allowed")
            return x + y
        
        # Test with various inputs
        test_cases = [(1, 2), (3, 4), (-1, 2), (1, 2)]  # Last one should hit cache
        
        for i, (x, y) in enumerate(test_cases):
            try:
                start_time = time.time()
                result = await demo_function(x, y)
                duration = time.time() - start_time
                print(f"Test {i+1}: demo_function({x}, {y}) = {result} (Duration: {duration:.3f}s)")
            except Exception as e:
                print(f"Test {i+1}: demo_function({x}, {y}) failed: {e}")
        
        # Show optimization stats
        stats = await get_optimization_stats()
        print(f"\nOptimization Statistics:")
        print(json.dumps(stats, indent=2, default=str))
        
        # Show recommendations
        recommendations = optimization_manager.optimize_configuration()
        print(f"\nOptimization Recommendations:")
        print(json.dumps(recommendations, indent=2))
    
    asyncio.run(demo())
