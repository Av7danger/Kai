#!/usr/bin/env python3
"""
Performance Monitoring System
Provides comprehensive metrics collection, analysis, and reporting
"""

import time
import psutil
import threading
import json
import logging
import functools
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import deque, defaultdict
import asyncio

logger = logging.getLogger(__name__)

@dataclass
class PerformanceMetric:
    """Individual performance metric"""
    name: str
    value: float
    timestamp: float
    category: str
    unit: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class SystemMetrics:
    """System-wide performance metrics"""
    cpu_percent: float
    memory_percent: float
    memory_used_mb: float
    disk_usage_percent: float
    network_io: Dict[str, float]
    timestamp: float

@dataclass
class ApplicationMetrics:
    """Application-specific performance metrics"""
    request_count: int
    error_count: int
    avg_response_time: float
    active_connections: int
    cache_hit_rate: float
    database_queries: int
    timestamp: float

class PerformanceMonitor:
    """Comprehensive performance monitoring system"""
    
    def __init__(self, 
                 metrics_history_size: int = 1000,
                 collection_interval: float = 1.0,
                 enable_alerts: bool = True):
        """
        Initialize performance monitor
        
        Args:
            metrics_history_size: Number of historical metrics to keep
            collection_interval: Interval between metric collections (seconds)
            enable_alerts: Enable performance alerts
        """
        self.metrics_history_size = metrics_history_size
        self.collection_interval = collection_interval
        self.enable_alerts = enable_alerts
        
        # Metrics storage
        self.system_metrics: deque = deque(maxlen=metrics_history_size)
        self.application_metrics: deque = deque(maxlen=metrics_history_size)
        self.custom_metrics: Dict[str, deque] = defaultdict(lambda: deque(maxlen=metrics_history_size))
        
        # Performance counters
        self.request_count = 0
        self.error_count = 0
        self.response_times: deque = deque(maxlen=100)
        self.start_time = time.time()
        
        # Alert thresholds
        self.alert_thresholds = {
            'cpu_percent': 80.0,
            'memory_percent': 85.0,
            'disk_usage_percent': 90.0,
            'response_time_ms': 5000.0,
            'error_rate_percent': 5.0
        }
        
        # Alert callbacks
        self.alert_callbacks: List[Callable] = []
        
        # Thread safety
        self.lock = threading.RLock()
        
        # Start monitoring
        self.monitoring = False
        self.monitor_thread = None
    
    def start_monitoring(self) -> None:
        """Start performance monitoring"""
        if not self.monitoring:
            self.monitoring = True
            self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
            self.monitor_thread.start()
            logger.info("Performance monitoring started")
    
    def stop_monitoring(self) -> None:
        """Stop performance monitoring"""
        self.monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        logger.info("Performance monitoring stopped")
    
    def _monitor_loop(self) -> None:
        """Main monitoring loop"""
        while self.monitoring:
            try:
                # Collect system metrics
                system_metrics = self._collect_system_metrics()
                self.system_metrics.append(system_metrics)
                
                # Collect application metrics
                app_metrics = self._collect_application_metrics()
                self.application_metrics.append(app_metrics)
                
                # Check for alerts
                if self.enable_alerts:
                    self._check_alerts(system_metrics, app_metrics)
                
                # Wait for next collection
                time.sleep(self.collection_interval)
                
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}")
                time.sleep(self.collection_interval)
    
    def _collect_system_metrics(self) -> SystemMetrics:
        """Collect system-wide performance metrics"""
        try:
            # CPU usage
            cpu_percent = psutil.cpu_percent(interval=0.1)
            
            # Memory usage
            memory = psutil.virtual_memory()
            memory_percent = memory.percent
            memory_used_mb = memory.used / (1024 * 1024)
            
            # Disk usage
            disk_usage_percent = 0
            try:
                disk = psutil.disk_usage('/')
                disk_usage_percent = disk.percent
            except (OSError, FileNotFoundError):
                # Handle Windows or permission issues
                pass
            
            # Network I/O
            network_io = {'bytes_sent': 0.0, 'bytes_recv': 0.0}
            try:
                network = psutil.net_io_counters()
                network_io = {
                    'bytes_sent': float(network.bytes_sent),
                    'bytes_recv': float(network.bytes_recv)
                }
            except Exception:
                pass
            
            return SystemMetrics(
                cpu_percent=cpu_percent,
                memory_percent=memory_percent,
                memory_used_mb=memory_used_mb,
                disk_usage_percent=disk_usage_percent,
                network_io=network_io,
                timestamp=time.time()
            )
            
        except Exception as e:
            logger.error(f"Error collecting system metrics: {e}")
            return SystemMetrics(
                cpu_percent=0.0,
                memory_percent=0.0,
                memory_used_mb=0.0,
                disk_usage_percent=0.0,
                network_io={'bytes_sent': 0.0, 'bytes_recv': 0.0},
                timestamp=time.time()
            )
    
    def _collect_application_metrics(self) -> ApplicationMetrics:
        """Collect application-specific performance metrics"""
        with self.lock:
            # Calculate average response time
            avg_response_time = 0.0
            if self.response_times:
                avg_response_time = sum(self.response_times) / len(self.response_times)
            
            # Calculate error rate
            error_rate = 0.0
            if self.request_count > 0:
                error_rate = (self.error_count / self.request_count) * 100
            
            return ApplicationMetrics(
                request_count=self.request_count,
                error_count=self.error_count,
                avg_response_time=avg_response_time,
                active_connections=0,  # TODO: Implement connection tracking
                cache_hit_rate=0.0,   # TODO: Implement cache tracking
                database_queries=0,   # TODO: Implement DB tracking
                timestamp=time.time()
            )
    
    def _check_alerts(self, system_metrics: SystemMetrics, app_metrics: ApplicationMetrics) -> None:
        """Check for performance alerts"""
        alerts = []
        
        # System alerts
        if system_metrics.cpu_percent > self.alert_thresholds['cpu_percent']:
            alerts.append({
                'type': 'high_cpu',
                'severity': 'warning',
                'message': f"High CPU usage: {system_metrics.cpu_percent:.1f}%",
                'value': system_metrics.cpu_percent,
                'threshold': self.alert_thresholds['cpu_percent']
            })
        
        if system_metrics.memory_percent > self.alert_thresholds['memory_percent']:
            alerts.append({
                'type': 'high_memory',
                'severity': 'warning',
                'message': f"High memory usage: {system_metrics.memory_percent:.1f}%",
                'value': system_metrics.memory_percent,
                'threshold': self.alert_thresholds['memory_percent']
            })
        
        if system_metrics.disk_usage_percent > self.alert_thresholds['disk_usage_percent']:
            alerts.append({
                'type': 'high_disk',
                'severity': 'warning',
                'message': f"High disk usage: {system_metrics.disk_usage_percent:.1f}%",
                'value': system_metrics.disk_usage_percent,
                'threshold': self.alert_thresholds['disk_usage_percent']
            })
        
        # Application alerts
        if app_metrics.avg_response_time > self.alert_thresholds['response_time_ms']:
            alerts.append({
                'type': 'slow_response',
                'severity': 'warning',
                'message': f"Slow response time: {app_metrics.avg_response_time:.1f}ms",
                'value': app_metrics.avg_response_time,
                'threshold': self.alert_thresholds['response_time_ms']
            })
        
        if app_metrics.error_count > 0 and app_metrics.request_count > 0:
            error_rate = (app_metrics.error_count / app_metrics.request_count) * 100
            if error_rate > self.alert_thresholds['error_rate_percent']:
                alerts.append({
                    'type': 'high_error_rate',
                    'severity': 'error',
                    'message': f"High error rate: {error_rate:.1f}%",
                    'value': error_rate,
                    'threshold': self.alert_thresholds['error_rate_percent']
                })
        
        # Trigger alert callbacks
        for alert in alerts:
            for callback in self.alert_callbacks:
                try:
                    callback(alert)
                except Exception as e:
                    logger.error(f"Error in alert callback: {e}")
    
    def record_request(self, response_time: float, success: bool = True) -> None:
        """Record a request metric"""
        with self.lock:
            self.request_count += 1
            if not success:
                self.error_count += 1
            
            self.response_times.append(response_time)
    
    def add_custom_metric(self, name: str, value: float, category: str = "custom", unit: str = "") -> None:
        """Add a custom performance metric"""
        metric = PerformanceMetric(
            name=name,
            value=value,
            timestamp=time.time(),
            category=category,
            unit=unit
        )
        
        self.custom_metrics[name].append(metric)
    
    def add_alert_callback(self, callback: Callable) -> None:
        """Add an alert callback function"""
        self.alert_callbacks.append(callback)
    
    def get_current_metrics(self) -> Dict[str, Any]:
        """Get current performance metrics"""
        with self.lock:
            # Get latest system metrics
            system_metrics = None
            if self.system_metrics:
                system_metrics = self.system_metrics[-1]
            
            # Get latest application metrics
            app_metrics = None
            if self.application_metrics:
                app_metrics = self.application_metrics[-1]
            
            # Calculate uptime
            uptime = time.time() - self.start_time
            
            return {
                'uptime_seconds': uptime,
                'uptime_formatted': str(timedelta(seconds=int(uptime))),
                'system': {
                    'cpu_percent': system_metrics.cpu_percent if system_metrics else 0.0,
                    'memory_percent': system_metrics.memory_percent if system_metrics else 0.0,
                    'memory_used_mb': system_metrics.memory_used_mb if system_metrics else 0.0,
                    'disk_usage_percent': system_metrics.disk_usage_percent if system_metrics else 0.0,
                    'network_io': system_metrics.network_io if system_metrics else {'bytes_sent': 0.0, 'bytes_recv': 0.0}
                },
                'application': {
                    'request_count': app_metrics.request_count if app_metrics else 0,
                    'error_count': app_metrics.error_count if app_metrics else 0,
                    'avg_response_time_ms': (app_metrics.avg_response_time * 1000) if app_metrics else 0.0,
                    'active_connections': app_metrics.active_connections if app_metrics else 0,
                    'cache_hit_rate': app_metrics.cache_hit_rate if app_metrics else 0.0,
                    'database_queries': app_metrics.database_queries if app_metrics else 0
                },
                'calculated': {
                    'requests_per_second': self.request_count / uptime if uptime > 0 else 0,
                    'error_rate_percent': (self.error_count / self.request_count * 100) if self.request_count > 0 else 0,
                    'success_rate_percent': ((self.request_count - self.error_count) / self.request_count * 100) if self.request_count > 0 else 0
                }
            }
    
    def get_metrics_history(self, 
                          metric_type: str = "system", 
                          duration_minutes: int = 60) -> List[Dict[str, Any]]:
        """Get historical metrics for the specified duration"""
        with self.lock:
            cutoff_time = time.time() - (duration_minutes * 60)
            
            if metric_type == "system":
                metrics = self.system_metrics
            elif metric_type == "application":
                metrics = self.application_metrics
            else:
                metrics = self.custom_metrics.get(metric_type, deque())
            
            # Filter metrics by time
            filtered_metrics = [
                metric for metric in metrics
                if metric.timestamp >= cutoff_time
            ]
            
            # Convert to dictionary format
            result = []
            for metric in filtered_metrics:
                d = {
                    'timestamp': metric.timestamp,
                    'datetime': datetime.fromtimestamp(metric.timestamp).isoformat(),
                }
                if hasattr(metric, '__dict__'):
                    d.update(metric.__dict__)
                else:
                    d['value'] = metric
                result.append(d)
            return result
    
    def get_performance_summary(self, duration_minutes: int = 60) -> Dict[str, Any]:
        """Get performance summary for the specified duration"""
        with self.lock:
            cutoff_time = time.time() - (duration_minutes * 60)
            
            # Filter metrics by time
            system_metrics = [
                m for m in self.system_metrics
                if m.timestamp >= cutoff_time
            ]
            
            app_metrics = [
                m for m in self.application_metrics
                if m.timestamp >= cutoff_time
            ]
            
            if not system_metrics or not app_metrics:
                return {
                    'duration_minutes': duration_minutes,
                    'data_points': 0,
                    'summary': 'No data available'
                }
            
            # Calculate statistics
            cpu_values = [m.cpu_percent for m in system_metrics]
            memory_values = [m.memory_percent for m in system_metrics]
            response_times = [m.avg_response_time for m in app_metrics]
            
            return {
                'duration_minutes': duration_minutes,
                'data_points': len(system_metrics),
                'system': {
                    'cpu_avg': sum(cpu_values) / len(cpu_values),
                    'cpu_max': max(cpu_values),
                    'cpu_min': min(cpu_values),
                    'memory_avg': sum(memory_values) / len(memory_values),
                    'memory_max': max(memory_values),
                    'memory_min': min(memory_values)
                },
                'application': {
                    'response_time_avg': sum(response_times) / len(response_times),
                    'response_time_max': max(response_times),
                    'response_time_min': min(response_times),
                    'total_requests': sum(m.request_count for m in app_metrics),
                    'total_errors': sum(m.error_count for m in app_metrics)
                }
            }
    
    def export_metrics(self, filepath: str, duration_minutes: int = 60) -> None:
        """Export metrics to JSON file"""
        try:
            data = {
                'export_timestamp': datetime.now().isoformat(),
                'duration_minutes': duration_minutes,
                'system_metrics': self.get_metrics_history('system', duration_minutes),
                'application_metrics': self.get_metrics_history('application', duration_minutes),
                'custom_metrics': {
                    name: list(metrics) for name, metrics in self.custom_metrics.items()
                },
                'summary': self.get_performance_summary(duration_minutes)
            }
            
            with open(filepath, 'w') as f:
                json.dump(data, f, indent=2, default=str)
            
            logger.info(f"Metrics exported to {filepath}")
            
        except Exception as e:
            logger.error(f"Error exporting metrics: {e}")

# Global performance monitor instance
performance_monitor = PerformanceMonitor()

# Decorator for monitoring function performance
def monitor_performance(func_name: Optional[str] = None):
    """Decorator to monitor function performance"""
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            start_time = time.time()
            success = True
            
            try:
                result = func(*args, **kwargs)
                return result
            except Exception as e:
                success = False
                raise
            finally:
                response_time = time.time() - start_time
                performance_monitor.record_request(response_time, success)
                
                # Add custom metric
                metric_name = func_name or func.__name__
                performance_monitor.add_custom_metric(
                    f"function_{metric_name}",
                    response_time,
                    "function_performance",
                    "seconds"
                )
        
        return wrapper
    return decorator

if __name__ == "__main__":
    # Test the performance monitor
    print("Testing Performance Monitor...")
    
    # Start monitoring
    performance_monitor.start_monitoring()
    
    # Simulate some activity
    for i in range(10):
        performance_monitor.record_request(0.1 + (i * 0.05), success=True)
        performance_monitor.add_custom_metric("test_metric", i * 10, "test")
        time.sleep(1)
    
    # Get current metrics
    current_metrics = performance_monitor.get_current_metrics()
    print(f"Current metrics: {json.dumps(current_metrics, indent=2)}")
    
    # Get performance summary
    summary = performance_monitor.get_performance_summary(5)
    print(f"Performance summary: {json.dumps(summary, indent=2)}")
    
    # Stop monitoring
    performance_monitor.stop_monitoring() 