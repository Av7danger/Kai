#!/usr/bin/env python3
"""
⚡ Performance Optimization System
Advanced performance optimization and resource management

Features:
- Intelligent caching with multiple strategies
- Resource monitoring and optimization
- Database query optimization
- Memory management and garbage collection
- CPU and I/O optimization
- Load balancing and scaling
- Performance profiling and analysis
- Automated optimization recommendations
"""

import os
import sys
import time
import json
import psutil
import sqlite3
import threading
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, asdict
from pathlib import Path
from collections import defaultdict, OrderedDict
import gc
import pickle
import gzip
import hashlib
import asyncio
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
import queue

logger = logging.getLogger(__name__)

@dataclass
class CacheEntry:
    """Cache entry with metadata"""
    key: str
    value: Any
    created_at: datetime
    accessed_at: datetime
    access_count: int
    size: int
    ttl: int
    priority: int = 1

@dataclass
class PerformanceMetric:
    """Performance metric data"""
    timestamp: datetime
    component: str
    operation: str
    execution_time: float
    memory_usage: float
    cpu_usage: float
    success: bool
    metadata: Dict[str, Any] = None

@dataclass
class OptimizationRecommendation:
    """Performance optimization recommendation"""
    type: str
    priority: int
    description: str
    impact: str
    implementation: str
    estimated_improvement: float

class CacheManager:
    """Advanced caching system with multiple strategies"""
    
    def __init__(self, max_size: int = 1000, ttl: int = 3600):
        self.max_size = max_size
        self.default_ttl = ttl
        self.cache: OrderedDict[str, CacheEntry] = OrderedDict()
        self.stats = {
            'hits': 0,
            'misses': 0,
            'evictions': 0,
            'size': 0
        }
        self.lock = threading.RLock()
        
        # Start cleanup thread
        self.cleanup_thread = threading.Thread(target=self._cleanup_worker, daemon=True)
        self.cleanup_thread.start()
    
    def get(self, key: str) -> Optional[Any]:
        """Get value from cache"""
        with self.lock:
            if key in self.cache:
                entry = self.cache[key]
                
                # Check if expired
                if datetime.now() > entry.created_at + timedelta(seconds=entry.ttl):
                    del self.cache[key]
                    self.stats['misses'] += 1
                    return None
                
                # Update access info
                entry.accessed_at = datetime.now()
                entry.access_count += 1
                
                # Move to end (LRU)
                self.cache.move_to_end(key)
                
                self.stats['hits'] += 1
                return entry.value
            
            self.stats['misses'] += 1
            return None
    
    def set(self, key: str, value: Any, ttl: int = None, priority: int = 1) -> bool:
        """Set value in cache"""
        with self.lock:
            # Calculate size
            size = self._calculate_size(value)
            
            # Check if key exists
            if key in self.cache:
                old_entry = self.cache[key]
                self.stats['size'] -= old_entry.size
            
            # Create new entry
            entry = CacheEntry(
                key=key,
                value=value,
                created_at=datetime.now(),
                accessed_at=datetime.now(),
                access_count=1,
                size=size,
                ttl=ttl or self.default_ttl,
                priority=priority
            )
            
            # Check if we need to evict
            while len(self.cache) >= self.max_size:
                self._evict_entry()
            
            # Add entry
            self.cache[key] = entry
            self.stats['size'] += size
            
            return True
    
    def _evict_entry(self):
        """Evict an entry using LRU with priority"""
        if not self.cache:
            return
        
        # Find entry to evict (lowest priority, then oldest access)
        evict_key = min(
            self.cache.keys(),
            key=lambda k: (self.cache[k].priority, self.cache[k].accessed_at)
        )
        
        entry = self.cache[evict_key]
        self.stats['size'] -= entry.size
        self.stats['evictions'] += 1
        
        del self.cache[evict_key]
    
    def _calculate_size(self, value: Any) -> int:
        """Calculate approximate size of value"""
        try:
            return len(pickle.dumps(value))
        except:
            return 1024  # Default size
    
    def _cleanup_worker(self):
        """Background worker for cache cleanup"""
        while True:
            try:
                time.sleep(60)  # Cleanup every minute
                self._cleanup_expired()
            except Exception as e:
                logger.error(f"Cache cleanup error: {e}")
    
    def _cleanup_expired(self):
        """Remove expired entries"""
        with self.lock:
            current_time = datetime.now()
            expired_keys = [
                key for key, entry in self.cache.items()
                if current_time > entry.created_at + timedelta(seconds=entry.ttl)
            ]
            
            for key in expired_keys:
                entry = self.cache[key]
                self.stats['size'] -= entry.size
                del self.cache[key]
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        with self.lock:
            hit_rate = self.stats['hits'] / (self.stats['hits'] + self.stats['misses']) if (self.stats['hits'] + self.stats['misses']) > 0 else 0
            
            return {
                'hits': self.stats['hits'],
                'misses': self.stats['misses'],
                'evictions': self.stats['evictions'],
                'size': self.stats['size'],
                'entries': len(self.cache),
                'hit_rate': hit_rate,
                'max_size': self.max_size
            }

class DatabaseOptimizer:
    """Database optimization and query optimization"""
    
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.query_stats = defaultdict(lambda: {'count': 0, 'total_time': 0, 'avg_time': 0})
        self.slow_queries = []
        self.lock = threading.Lock()
    
    def optimize_database(self):
        """Run database optimization"""
        try:
            conn = sqlite3.connect(self.db_path)
            
            # Analyze tables
            conn.execute('ANALYZE')
            
            # Vacuum database
            conn.execute('VACUUM')
            
            # Reindex
            conn.execute('REINDEX')
            
            conn.close()
            logger.info("Database optimization completed")
            
        except Exception as e:
            logger.error(f"Database optimization failed: {e}")
    
    def track_query(self, query: str, execution_time: float):
        """Track query performance"""
        with self.lock:
            # Update query statistics
            stats = self.query_stats[query]
            stats['count'] += 1
            stats['total_time'] += execution_time
            stats['avg_time'] = stats['total_time'] / stats['count']
            
            # Track slow queries
            if execution_time > 1.0:  # Queries taking more than 1 second
                self.slow_queries.append({
                    'query': query,
                    'execution_time': execution_time,
                    'timestamp': datetime.now()
                })
                
                # Keep only last 100 slow queries
                if len(self.slow_queries) > 100:
                    self.slow_queries = self.slow_queries[-100:]
    
    def get_query_recommendations(self) -> List[OptimizationRecommendation]:
        """Get database optimization recommendations"""
        recommendations = []
        
        with self.lock:
            # Analyze slow queries
            for query, stats in self.query_stats.items():
                if stats['avg_time'] > 0.5:  # Average time > 500ms
                    recommendations.append(OptimizationRecommendation(
                        type='database',
                        priority=2,
                        description=f"Optimize slow query: {query[:100]}...",
                        impact='high',
                        implementation='Add indexes or rewrite query',
                        estimated_improvement=0.7
                    ))
            
            # Check for missing indexes
            if len(self.slow_queries) > 10:
                recommendations.append(OptimizationRecommendation(
                    type='database',
                    priority=1,
                    description='Multiple slow queries detected',
                    impact='high',
                    implementation='Review and add missing indexes',
                    estimated_improvement=0.8
                ))
        
        return recommendations

class MemoryManager:
    """Memory management and optimization"""
    
    def __init__(self, memory_limit: int = 1024 * 1024 * 1024):  # 1GB default
        self.memory_limit = memory_limit
        self.memory_usage = []
        self.gc_stats = {}
        self.lock = threading.Lock()
        
        # Start monitoring thread
        self.monitor_thread = threading.Thread(target=self._monitor_memory, daemon=True)
        self.monitor_thread.start()
    
    def _monitor_memory(self):
        """Monitor memory usage"""
        while True:
            try:
                memory_info = psutil.virtual_memory()
                
                with self.lock:
                    self.memory_usage.append({
                        'timestamp': datetime.now(),
                        'used': memory_info.used,
                        'available': memory_info.available,
                        'percent': memory_info.percent
                    })
                    
                    # Keep only last 1000 measurements
                    if len(self.memory_usage) > 1000:
                        self.memory_usage = self.memory_usage[-1000:]
                
                # Check if memory usage is high
                if memory_info.percent > 80:
                    self._optimize_memory()
                
                time.sleep(30)  # Check every 30 seconds
                
            except Exception as e:
                logger.error(f"Memory monitoring error: {e}")
    
    def _optimize_memory(self):
        """Optimize memory usage"""
        try:
            # Force garbage collection
            collected = gc.collect()
            
            # Clear caches if available
            if hasattr(self, 'cache_manager'):
                self.cache_manager._cleanup_expired()
            
            logger.info(f"Memory optimization completed, collected {collected} objects")
            
        except Exception as e:
            logger.error(f"Memory optimization failed: {e}")
    
    def get_memory_stats(self) -> Dict[str, Any]:
        """Get memory statistics"""
        memory_info = psutil.virtual_memory()
        
        with self.lock:
            recent_usage = self.memory_usage[-10:] if self.memory_usage else []
            avg_usage = sum(u['percent'] for u in recent_usage) / len(recent_usage) if recent_usage else 0
        
        return {
            'total': memory_info.total,
            'used': memory_info.used,
            'available': memory_info.available,
            'percent': memory_info.percent,
            'average_usage': avg_usage,
            'limit': self.memory_limit
        }

class PerformanceProfiler:
    """Performance profiling and analysis"""
    
    def __init__(self):
        self.metrics: List[PerformanceMetric] = []
        self.profiles = {}
        self.lock = threading.Lock()
    
    def profile_function(self, func: Callable, *args, **kwargs):
        """Profile a function execution"""
        start_time = time.time()
        start_memory = psutil.Process().memory_info().rss
        start_cpu = psutil.cpu_percent()
        
        try:
            result = func(*args, **kwargs)
            success = True
        except Exception as e:
            result = None
            success = False
            raise e
        finally:
            end_time = time.time()
            end_memory = psutil.Process().memory_info().rss
            end_cpu = psutil.cpu_percent()
            
            execution_time = end_time - start_time
            memory_usage = end_memory - start_memory
            cpu_usage = (start_cpu + end_cpu) / 2
            
            metric = PerformanceMetric(
                timestamp=datetime.now(),
                component=func.__module__,
                operation=func.__name__,
                execution_time=execution_time,
                memory_usage=memory_usage,
                cpu_usage=cpu_usage,
                success=success
            )
            
            with self.lock:
                self.metrics.append(metric)
                
                # Keep only last 10000 metrics
                if len(self.metrics) > 10000:
                    self.metrics = self.metrics[-10000:]
    
    def get_performance_analysis(self, component: str = None, days: int = 7) -> Dict[str, Any]:
        """Get performance analysis"""
        cutoff_time = datetime.now() - timedelta(days=days)
        
        with self.lock:
            filtered_metrics = [
                m for m in self.metrics
                if m.timestamp > cutoff_time and (component is None or m.component == component)
            ]
        
        if not filtered_metrics:
            return {}
        
        # Calculate statistics
        execution_times = [m.execution_time for m in filtered_metrics]
        memory_usage = [m.memory_usage for m in filtered_metrics]
        cpu_usage = [m.cpu_usage for m in filtered_metrics]
        success_rate = sum(1 for m in filtered_metrics if m.success) / len(filtered_metrics)
        
        return {
            'total_operations': len(filtered_metrics),
            'avg_execution_time': sum(execution_times) / len(execution_times),
            'max_execution_time': max(execution_times),
            'min_execution_time': min(execution_times),
            'avg_memory_usage': sum(memory_usage) / len(memory_usage),
            'avg_cpu_usage': sum(cpu_usage) / len(cpu_usage),
            'success_rate': success_rate,
            'slow_operations': len([t for t in execution_times if t > 1.0])
        }
    
    def get_optimization_recommendations(self) -> List[OptimizationRecommendation]:
        """Get performance optimization recommendations"""
        recommendations = []
        
        analysis = self.get_performance_analysis()
        
        if analysis.get('avg_execution_time', 0) > 0.5:
            recommendations.append(OptimizationRecommendation(
                type='performance',
                priority=1,
                description='High average execution time detected',
                impact='high',
                implementation='Optimize slow operations or add caching',
                estimated_improvement=0.6
            ))
        
        if analysis.get('success_rate', 1.0) < 0.95:
            recommendations.append(OptimizationRecommendation(
                type='reliability',
                priority=2,
                description='Low success rate detected',
                impact='high',
                implementation='Review error handling and retry logic',
                estimated_improvement=0.3
            ))
        
        if analysis.get('slow_operations', 0) > 10:
            recommendations.append(OptimizationRecommendation(
                type='performance',
                priority=2,
                description='Multiple slow operations detected',
                impact='medium',
                implementation='Profile and optimize slow operations',
                estimated_improvement=0.5
            ))
        
        return recommendations

class PerformanceOptimizer:
    """Main performance optimization system"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.cache_manager = CacheManager(
            max_size=config['performance']['cache_size'],
            ttl=config['performance']['cache_ttl']
        )
        self.db_optimizer = DatabaseOptimizer('advanced_integration.db')
        self.memory_manager = MemoryManager(
            memory_limit=self._parse_memory_limit(config['performance']['memory_limit'])
        )
        self.profiler = PerformanceProfiler()
        
        # Optimization workers
        self.optimization_queue = queue.Queue()
        self.optimization_worker = threading.Thread(target=self._optimization_worker, daemon=True)
        self.optimization_worker.start()
        
        logger.info("Performance Optimizer initialized")
    
    def _parse_memory_limit(self, limit_str: str) -> int:
        """Parse memory limit string"""
        if isinstance(limit_str, int):
            return limit_str
        
        limit_str = str(limit_str).upper()
        if 'GB' in limit_str:
            return int(limit_str.replace('GB', '')) * 1024 * 1024 * 1024
        elif 'MB' in limit_str:
            return int(limit_str.replace('MB', '')) * 1024 * 1024
        elif 'KB' in limit_str:
            return int(limit_str.replace('KB', '')) * 1024
        else:
            return int(limit_str)
    
    def _optimization_worker(self):
        """Background optimization worker"""
        while True:
            try:
                optimization_task = self.optimization_queue.get(timeout=1)
                self._run_optimization(optimization_task)
                self.optimization_queue.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Optimization worker error: {e}")
    
    def _run_optimization(self, task: str):
        """Run specific optimization task"""
        if task == 'database':
            self.db_optimizer.optimize_database()
        elif task == 'memory':
            self.memory_manager._optimize_memory()
        elif task == 'cache':
            self.cache_manager._cleanup_expired()
        elif task == 'gc':
            gc.collect()
    
    def schedule_optimization(self, task: str):
        """Schedule optimization task"""
        self.optimization_queue.put(task)
    
    def get_performance_report(self) -> Dict[str, Any]:
        """Get comprehensive performance report"""
        return {
            'cache_stats': self.cache_manager.get_stats(),
            'memory_stats': self.memory_manager.get_memory_stats(),
            'performance_analysis': self.profiler.get_performance_analysis(),
            'recommendations': self.get_optimization_recommendations(),
            'system_info': self._get_system_info()
        }
    
    def get_optimization_recommendations(self) -> List[OptimizationRecommendation]:
        """Get all optimization recommendations"""
        recommendations = []
        
        # Database recommendations
        recommendations.extend(self.db_optimizer.get_query_recommendations())
        
        # Performance recommendations
        recommendations.extend(self.profiler.get_optimization_recommendations())
        
        # Cache recommendations
        cache_stats = self.cache_manager.get_stats()
        if cache_stats['hit_rate'] < 0.7:
            recommendations.append(OptimizationRecommendation(
                type='cache',
                priority=2,
                description='Low cache hit rate detected',
                impact='medium',
                implementation='Review cache strategy and increase cache size',
                estimated_improvement=0.4
            ))
        
        # Memory recommendations
        memory_stats = self.memory_manager.get_memory_stats()
        if memory_stats['percent'] > 80:
            recommendations.append(OptimizationRecommendation(
                type='memory',
                priority=1,
                description='High memory usage detected',
                impact='high',
                implementation='Optimize memory usage or increase memory limit',
                estimated_improvement=0.3
            ))
        
        return sorted(recommendations, key=lambda r: r.priority)
    
    def _get_system_info(self) -> Dict[str, Any]:
        """Get system information"""
        return {
            'cpu_count': psutil.cpu_count(),
            'memory_total': psutil.virtual_memory().total,
            'disk_usage': psutil.disk_usage('/').percent,
            'load_average': psutil.getloadavg() if hasattr(psutil, 'getloadavg') else None,
            'python_version': sys.version,
            'platform': sys.platform
        }
    
    def optimize_all(self):
        """Run all optimizations"""
        logger.info("Starting comprehensive optimization")
        
        # Schedule all optimization tasks
        self.schedule_optimization('database')
        self.schedule_optimization('memory')
        self.schedule_optimization('cache')
        self.schedule_optimization('gc')
        
        # Wait for completion
        self.optimization_queue.join()
        
        logger.info("Comprehensive optimization completed")
    
    def profile_function(self, func: Callable):
        """Decorator to profile a function"""
        def wrapper(*args, **kwargs):
            return self.profiler.profile_function(func, *args, **kwargs)
        return wrapper

# Global performance optimizer instance
performance_optimizer = None

def initialize_performance_optimizer(config: Dict[str, Any]):
    """Initialize the global performance optimizer"""
    global performance_optimizer
    performance_optimizer = PerformanceOptimizer(config)
    return performance_optimizer

def get_performance_optimizer() -> PerformanceOptimizer:
    """Get the global performance optimizer instance"""
    if performance_optimizer is None:
        raise RuntimeError("Performance optimizer not initialized. Call initialize_performance_optimizer() first.")
    return performance_optimizer

if __name__ == '__main__':
    # Example usage
    config = {
        'performance': {
            'cache_size': 1000,
            'cache_ttl': 3600,
            'memory_limit': '1GB'
        }
    }
    
    optimizer = initialize_performance_optimizer(config)
    
    # Example profiling
    @optimizer.profile_function
    def example_function():
        time.sleep(0.1)
        return "example"
    
    # Run example
    for _ in range(10):
        example_function()
    
    # Get performance report
    report = optimizer.get_performance_report()
    print(json.dumps(report, indent=2, default=str)) 