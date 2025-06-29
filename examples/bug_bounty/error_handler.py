#!/usr/bin/env python3
"""
Comprehensive Error Handling and Logging System
Provides structured error reporting, recovery mechanisms, and monitoring
"""

import logging
import traceback
import sys
import time
import json
from typing import Dict, List, Optional, Any, Callable, Union
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import threading
from contextlib import contextmanager
import functools

class ErrorSeverity(Enum):
    """Error severity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class ErrorCategory(Enum):
    """Error categories for classification"""
    NETWORK = "network"
    DATABASE = "database"
    SUBPROCESS = "subprocess"
    AI_API = "ai_api"
    VALIDATION = "validation"
    SYSTEM = "system"
    WORKFLOW = "workflow"
    UNKNOWN = "unknown"

@dataclass
class ErrorInfo:
    """Structured error information"""
    error_id: str
    timestamp: float
    severity: ErrorSeverity
    category: ErrorCategory
    error_type: str
    message: str
    details: Dict[str, Any] = field(default_factory=dict)
    stack_trace: str = ""
    context: Dict[str, Any] = field(default_factory=dict)
    resolved: bool = False
    resolution_time: Optional[float] = None
    retry_count: int = 0

class ErrorRecoveryStrategy(Enum):
    """Error recovery strategies"""
    RETRY = "retry"
    FALLBACK = "fallback"
    IGNORE = "ignore"
    TERMINATE = "terminate"
    MANUAL_INTERVENTION = "manual_intervention"

class ErrorHandler:
    """Comprehensive error handling and logging system"""
    
    def __init__(self, 
                 log_file: str = "error_log.json",
                 max_errors: int = 1000,
                 enable_recovery: bool = True):
        """
        Initialize error handler
        
        Args:
            log_file: File to store error logs
            max_errors: Maximum number of errors to keep in memory
            enable_recovery: Enable automatic error recovery
        """
        self.log_file = Path(log_file)
        self.max_errors = max_errors
        self.enable_recovery = enable_recovery
        
        # Error storage
        self.errors: List[ErrorInfo] = []
        self.error_counts: Dict[str, int] = {}
        self.recovery_strategies: Dict[ErrorCategory, ErrorRecoveryStrategy] = {}
        
        # Setup logging
        self._setup_logging()
        
        # Setup default recovery strategies
        self._setup_default_strategies()
        
        # Thread safety
        self.lock = threading.RLock()
    
    def _setup_logging(self) -> None:
        """Setup structured logging"""
        # Create logs directory if it doesn't exist
        self.log_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Setup JSON logging
        self.logger = logging.getLogger('error_handler')
        self.logger.setLevel(logging.INFO)
        
        # File handler for JSON logs
        file_handler = logging.FileHandler(self.log_file)
        file_handler.setLevel(logging.INFO)
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.WARNING)
        
        # Custom formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)
        
        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)
    
    def _setup_default_strategies(self) -> None:
        """Setup default error recovery strategies"""
        self.recovery_strategies = {
            ErrorCategory.NETWORK: ErrorRecoveryStrategy.RETRY,
            ErrorCategory.DATABASE: ErrorRecoveryStrategy.RETRY,
            ErrorCategory.SUBPROCESS: ErrorRecoveryStrategy.RETRY,
            ErrorCategory.AI_API: ErrorRecoveryStrategy.FALLBACK,
            ErrorCategory.VALIDATION: ErrorRecoveryStrategy.IGNORE,
            ErrorCategory.SYSTEM: ErrorRecoveryStrategy.MANUAL_INTERVENTION,
            ErrorCategory.WORKFLOW: ErrorRecoveryStrategy.FALLBACK,
            ErrorCategory.UNKNOWN: ErrorRecoveryStrategy.IGNORE
        }
    
    def handle_error(self, 
                    error: Exception,
                    severity: ErrorSeverity = ErrorSeverity.MEDIUM,
                    category: ErrorCategory = ErrorCategory.UNKNOWN,
                    context: Optional[Dict[str, Any]] = None,
                    retry_func: Optional[Callable] = None,
                    max_retries: int = 3) -> ErrorInfo:
        """
        Handle an error with structured logging and recovery
        
        Args:
            error: The exception that occurred
            severity: Error severity level
            category: Error category for classification
            context: Additional context information
            retry_func: Function to retry (if applicable)
            max_retries: Maximum number of retries
            
        Returns:
            ErrorInfo object with error details
        """
        with self.lock:
            # Create error info
            error_info = ErrorInfo(
                error_id=f"err_{int(time.time())}_{len(self.errors)}",
                timestamp=time.time(),
                severity=severity,
                category=category,
                error_type=type(error).__name__,
                message=str(error),
                details=self._extract_error_details(error),
                stack_trace=traceback.format_exc(),
                context=context or {}
            )
            
            # Add to error list
            self.errors.append(error_info)
            
            # Update error counts
            error_key = f"{category.value}:{error_info.error_type}"
            self.error_counts[error_key] = self.error_counts.get(error_key, 0) + 1
            
            # Log the error
            self._log_error(error_info)
            
            # Attempt recovery
            if self.enable_recovery and retry_func:
                self._attempt_recovery(error_info, retry_func, max_retries)
            
            # Cleanup old errors
            self._cleanup_old_errors()
            
            return error_info
    
    def _extract_error_details(self, error: Exception) -> Dict[str, Any]:
        """Extract detailed information from an error"""
        details = {
            'error_type': type(error).__name__,
            'error_message': str(error),
            'error_args': getattr(error, 'args', []),
            'error_code': getattr(error, 'code', None),
            'error_errno': getattr(error, 'errno', None),
        }
        
        # Add specific details for common error types
        if isinstance(error, (ConnectionError, TimeoutError)):
            details['connection_type'] = 'network'
        elif isinstance(error, (ValueError, TypeError)):
            details['validation_type'] = 'data'
        elif isinstance(error, PermissionError):
            details['permission_type'] = 'access'
        
        return details
    
    def _log_error(self, error_info: ErrorInfo) -> None:
        """Log error with structured format"""
        log_entry = {
            'error_id': error_info.error_id,
            'timestamp': error_info.timestamp,
            'severity': error_info.severity.value,
            'category': error_info.category.value,
            'error_type': error_info.error_type,
            'message': error_info.message,
            'details': error_info.details,
            'context': error_info.context
        }
        
        # Log to file
        self.logger.error(json.dumps(log_entry))
        
        # Log to console for high severity errors
        if error_info.severity in [ErrorSeverity.HIGH, ErrorSeverity.CRITICAL]:
            print(f"🚨 CRITICAL ERROR: {error_info.message}")
            print(f"   Category: {error_info.category.value}")
            print(f"   Error ID: {error_info.error_id}")
    
    def _attempt_recovery(self, 
                         error_info: ErrorInfo, 
                         retry_func: Callable, 
                         max_retries: int) -> None:
        """Attempt to recover from error"""
        strategy = self.recovery_strategies.get(error_info.category, ErrorRecoveryStrategy.IGNORE)
        
        if strategy == ErrorRecoveryStrategy.RETRY and error_info.retry_count < max_retries:
            try:
                error_info.retry_count += 1
                retry_func()
                error_info.resolved = True
                error_info.resolution_time = time.time()
                self.logger.info(f"Error {error_info.error_id} resolved after {error_info.retry_count} retries")
            except Exception as retry_error:
                self.logger.warning(f"Retry failed for error {error_info.error_id}: {retry_error}")
        
        elif strategy == ErrorRecoveryStrategy.FALLBACK:
            # Implement fallback logic here
            self.logger.info(f"Using fallback strategy for error {error_info.error_id}")
        
        elif strategy == ErrorRecoveryStrategy.TERMINATE:
            self.logger.critical(f"Terminating due to critical error: {error_info.error_id}")
            sys.exit(1)
    
    def _cleanup_old_errors(self) -> None:
        """Remove old errors to prevent memory bloat"""
        if len(self.errors) > self.max_errors:
            # Keep only the most recent errors
            self.errors = self.errors[-self.max_errors:]
    
    def get_error_summary(self) -> Dict[str, Any]:
        """Get summary of all errors"""
        with self.lock:
            total_errors = len(self.errors)
            critical_errors = len([e for e in self.errors if e.severity == ErrorSeverity.CRITICAL])
            resolved_errors = len([e for e in self.errors if e.resolved])
            
            return {
                'total_errors': total_errors,
                'critical_errors': critical_errors,
                'resolved_errors': resolved_errors,
                'resolution_rate': (resolved_errors / total_errors * 100) if total_errors > 0 else 0,
                'error_counts': self.error_counts,
                'recent_errors': [
                    {
                        'id': e.error_id,
                        'timestamp': e.timestamp,
                        'severity': e.severity.value,
                        'category': e.category.value,
                        'message': e.message,
                        'resolved': e.resolved
                    }
                    for e in self.errors[-10:]  # Last 10 errors
                ]
            }
    
    def get_errors_by_category(self, category: ErrorCategory) -> List[ErrorInfo]:
        """Get all errors for a specific category"""
        with self.lock:
            return [e for e in self.errors if e.category == category]
    
    def get_errors_by_severity(self, severity: ErrorSeverity) -> List[ErrorInfo]:
        """Get all errors for a specific severity"""
        with self.lock:
            return [e for e in self.errors if e.severity == severity]
    
    def mark_error_resolved(self, error_id: str) -> bool:
        """Mark an error as resolved"""
        with self.lock:
            for error in self.errors:
                if error.error_id == error_id:
                    error.resolved = True
                    error.resolution_time = time.time()
                    return True
            return False
    
    def clear_resolved_errors(self) -> int:
        """Clear all resolved errors and return count"""
        with self.lock:
            original_count = len(self.errors)
            self.errors = [e for e in self.errors if not e.resolved]
            return original_count - len(self.errors)

# Global error handler instance
error_handler = ErrorHandler()

@contextmanager
def error_context(category: ErrorCategory = ErrorCategory.UNKNOWN,
                 severity: ErrorSeverity = ErrorSeverity.MEDIUM,
                 context: Optional[Dict[str, Any]] = None):
    """
    Context manager for error handling
    
    Usage:
        with error_context(ErrorCategory.NETWORK, ErrorSeverity.HIGH):
            # Code that might raise an error
            pass
    """
    try:
        yield
    except Exception as e:
        error_handler.handle_error(
            error=e,
            severity=severity,
            category=category,
            context=context
        )
        raise

def handle_errors(category: ErrorCategory = ErrorCategory.UNKNOWN,
                 severity: ErrorSeverity = ErrorSeverity.MEDIUM,
                 retry_count: int = 0):
    """
    Decorator for error handling
    
    Usage:
        @handle_errors(ErrorCategory.NETWORK, ErrorSeverity.HIGH, retry_count=3)
        def network_function():
            pass
    """
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            for attempt in range(retry_count + 1):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    if attempt == retry_count:
                        error_handler.handle_error(
                            error=e,
                            severity=severity,
                            category=category,
                            context={'function': func.__name__, 'attempt': attempt + 1}
                        )
                        raise
                    else:
                        # Wait before retry
                        time.sleep(2 ** attempt)
            return None
        return wrapper
    return decorator

class ErrorMonitor:
    """Monitor for error patterns and trends"""
    
    def __init__(self, error_handler: ErrorHandler):
        self.error_handler = error_handler
        self.patterns: Dict[str, Dict[str, Any]] = {}
        self.alerts: List[Dict[str, Any]] = []
    
    def analyze_patterns(self) -> Dict[str, Any]:
        """Analyze error patterns and trends"""
        summary = self.error_handler.get_error_summary()
        
        # Analyze error frequency
        high_frequency_errors = [
            error_type for error_type, count in summary['error_counts'].items()
            if count > 5  # More than 5 occurrences
        ]
        
        # Analyze severity distribution
        severity_distribution = {}
        for error in self.error_handler.errors:
            severity = error.severity.value
            severity_distribution[severity] = severity_distribution.get(severity, 0) + 1
        
        # Check for critical error spikes
        recent_errors = summary['recent_errors']
        critical_recent = len([e for e in recent_errors if e['severity'] == 'critical'])
        
        analysis = {
            'high_frequency_errors': high_frequency_errors,
            'severity_distribution': severity_distribution,
            'critical_error_spike': critical_recent > 2,  # More than 2 critical errors recently
            'overall_health': self._calculate_health_score(summary),
            'recommendations': self._generate_recommendations(summary)
        }
        
        return analysis
    
    def _calculate_health_score(self, summary: Dict[str, Any]) -> float:
        """Calculate system health score (0-100)"""
        total_errors = summary['total_errors']
        if total_errors == 0:
            return 100.0
        
        critical_errors = summary['critical_errors']
        resolution_rate = summary['resolution_rate']
        
        # Penalize critical errors heavily
        critical_penalty = critical_errors * 20
        
        # Reward high resolution rate
        resolution_bonus = resolution_rate * 0.5
        
        score = 100 - critical_penalty + resolution_bonus
        return max(0.0, min(100.0, score))
    
    def _generate_recommendations(self, summary: Dict[str, Any]) -> List[str]:
        """Generate recommendations based on error analysis"""
        recommendations = []
        
        if summary['critical_errors'] > 0:
            recommendations.append("Investigate critical errors immediately")
        
        if summary['resolution_rate'] < 50:
            recommendations.append("Improve error recovery mechanisms")
        
        high_freq_errors = summary.get('high_frequency_errors', [])
        if high_freq_errors:
            recommendations.append(f"Address recurring errors: {', '.join(high_freq_errors[:3])}")
        
        return recommendations

if __name__ == "__main__":
    # Test the error handler
    print("Testing Error Handler...")
    
    # Test basic error handling
    try:
        with error_context(ErrorCategory.NETWORK, ErrorSeverity.HIGH):
            raise ConnectionError("Test network error")
    except ConnectionError:
        print("Network error handled successfully")
    
    # Test error summary
    summary = error_handler.get_error_summary()
    print(f"Error summary: {summary}")
    
    # Test error monitor
    monitor = ErrorMonitor(error_handler)
    analysis = monitor.analyze_patterns()
    print(f"Error analysis: {analysis}") 