#!/usr/bin/env python3
"""
Security Enhancement Module for Bug Bounty Dashboard
Provides rate limiting, input sanitization, CSRF protection, and security monitoring
"""

import hashlib
import hmac
import secrets
import time
import logging
import re
import json
from typing import Dict, List, Optional, Any, Callable
from datetime import datetime, timedelta
from dataclasses import dataclass
from functools import wraps
import threading
from collections import defaultdict, deque
import ipaddress
import requests

logger = logging.getLogger(__name__)

@dataclass
class SecurityEvent:
    """Security event data structure"""
    event_type: str
    timestamp: datetime
    ip_address: str
    user_agent: str
    endpoint: str
    severity: str
    details: Dict
    blocked: bool = False

class RateLimiter:
    """Advanced rate limiting with IP-based and user-based limits"""
    
    def __init__(self):
        self.ip_limits = defaultdict(lambda: deque(maxlen=1000))
        self.user_limits = defaultdict(lambda: deque(maxlen=1000))
        self.blocked_ips = set()
        self.blocked_users = set()
        self.lock = threading.Lock()
        
        # Rate limit configurations
        self.limits = {
            'default': {'requests': 100, 'window': 60},  # 100 requests per minute
            'api': {'requests': 50, 'window': 60},       # 50 API requests per minute
            'auth': {'requests': 5, 'window': 300},      # 5 auth attempts per 5 minutes
            'scan': {'requests': 10, 'window': 3600},    # 10 scans per hour
        }
    
    def is_allowed(self, identifier: str, limit_type: str = 'default', 
                  user_id: Optional[str] = None) -> bool:
        """Check if request is allowed based on rate limits"""
        current_time = time.time()
        
        with self.lock:
            # Check if IP is blocked
            if identifier in self.blocked_ips:
                return False
            
            # Check if user is blocked
            if user_id and user_id in self.blocked_users:
                return False
            
            # Get limit configuration
            limit_config = self.limits.get(limit_type, self.limits['default'])
            window = limit_config['window']
            max_requests = limit_config['requests']
            
            # Clean old requests
            cutoff_time = current_time - window
            
            # Check IP-based limits
            ip_requests = self.ip_limits[identifier]
            while ip_requests and ip_requests[0] < cutoff_time:
                ip_requests.popleft()
            
            if len(ip_requests) >= max_requests:
                self.blocked_ips.add(identifier)
                logger.warning(f"IP {identifier} blocked due to rate limit violation")
                return False
            
            # Add current request
            ip_requests.append(current_time)
            
            # Check user-based limits if user_id provided
            if user_id:
                user_requests = self.user_limits[user_id]
                while user_requests and user_requests[0] < cutoff_time:
                    user_requests.popleft()
                
                if len(user_requests) >= max_requests:
                    self.blocked_users.add(user_id)
                    logger.warning(f"User {user_id} blocked due to rate limit violation")
                    return False
                
                user_requests.append(current_time)
            
            return True
    
    def unblock_ip(self, ip: str):
        """Unblock an IP address"""
        with self.lock:
            self.blocked_ips.discard(ip)
            self.ip_limits[ip].clear()
    
    def unblock_user(self, user_id: str):
        """Unblock a user"""
        with self.lock:
            self.blocked_users.discard(user_id)
            self.user_limits[user_id].clear()
    
    def get_stats(self) -> Dict:
        """Get rate limiter statistics"""
        with self.lock:
            return {
                'blocked_ips': len(self.blocked_ips),
                'blocked_users': len(self.blocked_users),
                'active_ips': len(self.ip_limits),
                'active_users': len(self.user_limits),
                'limits': self.limits
            }

class InputSanitizer:
    """Input sanitization and validation utilities"""
    
    def __init__(self):
        # SQL injection patterns
        self.sql_patterns = [
            r'(\b(union|select|insert|update|delete|drop|create|alter)\b)',
            r'(\b(and|or)\b\s+\d+\s*[=<>])',
            r'(\b(exec|execute|script)\b)',
            r'(\b(xp_|sp_)\w+)',
            r'(\b(declare|cast|convert)\b)',
        ]
        
        # XSS patterns
        self.xss_patterns = [
            r'<script[^>]*>.*?</script>',
            r'<iframe[^>]*>.*?</iframe>',
            r'<object[^>]*>.*?</object>',
            r'<embed[^>]*>.*?</embed>',
            r'javascript:',
            r'vbscript:',
            r'on\w+\s*=',
            r'<img[^>]*on\w+\s*=',
        ]
        
        # Command injection patterns
        self.command_patterns = [
            r'[;&|`$(){}[\]]',
            r'\b(cat|ls|pwd|whoami|id|uname|ps|netstat)\b',
            r'\b(rm|del|mkdir|touch|chmod|chown)\b',
            r'\b(wget|curl|nc|telnet|ssh|ftp)\b',
        ]
        
        # Compile patterns
        self.sql_regex = re.compile('|'.join(self.sql_patterns), re.IGNORECASE)
        self.xss_regex = re.compile('|'.join(self.xss_patterns), re.IGNORECASE)
        self.command_regex = re.compile('|'.join(self.command_patterns), re.IGNORECASE)
    
    def sanitize_string(self, value: str, max_length: int = 1000) -> str:
        """Sanitize a string input"""
        if not isinstance(value, str):
            return str(value)
        
        # Truncate if too long
        if len(value) > max_length:
            value = value[:max_length]
        
        # Remove null bytes
        value = value.replace('\x00', '')
        
        # Normalize whitespace
        value = ' '.join(value.split())
        
        return value
    
    def validate_url(self, url: str) -> bool:
        """Validate URL format and security"""
        try:
            # Basic URL validation
            if not url.startswith(('http://', 'https://')):
                return False
            
            # Check for suspicious patterns
            suspicious_patterns = [
                'javascript:',
                'data:',
                'file:',
                'ftp:',
                'telnet:',
            ]
            
            for pattern in suspicious_patterns:
                if pattern in url.lower():
                    return False
            
            # Validate IP addresses
            parsed = requests.utils.urlparse(url)
            if parsed.hostname:
                try:
                    ipaddress.ip_address(parsed.hostname)
                    # Allow localhost for testing
                    if parsed.hostname not in ['localhost', '127.0.0.1']:
                        return False
                except ValueError:
                    pass  # Not an IP address
            
            return True
        except Exception:
            return False
    
    def detect_sql_injection(self, value: str) -> bool:
        """Detect potential SQL injection attempts"""
        return bool(self.sql_regex.search(value))
    
    def detect_xss(self, value: str) -> bool:
        """Detect potential XSS attempts"""
        return bool(self.xss_regex.search(value))
    
    def detect_command_injection(self, value: str) -> bool:
        """Detect potential command injection attempts"""
        return bool(self.command_regex.search(value))
    
    def sanitize_json(self, data: Any) -> Any:
        """Recursively sanitize JSON data"""
        if isinstance(data, dict):
            return {k: self.sanitize_json(v) for k, v in data.items()}
        elif isinstance(data, list):
            return [self.sanitize_json(item) for item in data]
        elif isinstance(data, str):
            return self.sanitize_string(data)
        else:
            return data

class CSRFProtector:
    """CSRF protection utilities"""
    
    def __init__(self, secret_key: str):
        self.secret_key = secret_key.encode('utf-8')
        self.tokens = {}  # Store valid tokens
        self.lock = threading.Lock()
    
    def generate_token(self, user_id: str, session_id: str) -> str:
        """Generate a CSRF token for a user session"""
        data = f"{user_id}:{session_id}:{int(time.time())}"
        token = hmac.new(self.secret_key, data.encode('utf-8'), hashlib.sha256).hexdigest()
        
        with self.lock:
            self.tokens[token] = {
                'user_id': user_id,
                'session_id': session_id,
                'created_at': time.time(),
                'expires_at': time.time() + 3600  # 1 hour expiry
            }
        
        return token
    
    def validate_token(self, token: str, user_id: str, session_id: str) -> bool:
        """Validate a CSRF token"""
        with self.lock:
            if token not in self.tokens:
                return False
            
            token_data = self.tokens[token]
            
            # Check if token is expired
            if time.time() > token_data['expires_at']:
                del self.tokens[token]
                return False
            
            # Check if token matches user and session
            if (token_data['user_id'] != user_id or 
                token_data['session_id'] != session_id):
                return False
            
            return True
    
    def invalidate_token(self, token: str):
        """Invalidate a CSRF token"""
        with self.lock:
            self.tokens.pop(token, None)
    
    def cleanup_expired_tokens(self):
        """Remove expired tokens"""
        current_time = time.time()
        with self.lock:
            expired_tokens = [
                token for token, data in self.tokens.items()
                if current_time > data['expires_at']
            ]
            for token in expired_tokens:
                del self.tokens[token]

class SecurityMonitor:
    """Security monitoring and alerting"""
    
    def __init__(self):
        self.events: List[SecurityEvent] = []
        self.lock = threading.Lock()
        self.alert_thresholds = {
            'rate_limit_violations': 10,
            'sql_injection_attempts': 5,
            'xss_attempts': 5,
            'command_injection_attempts': 3,
            'failed_auth_attempts': 20,
        }
        self.alert_callbacks: List[Callable] = []
    
    def log_event(self, event: SecurityEvent):
        """Log a security event"""
        with self.lock:
            self.events.append(event)
            
            # Keep only last 1000 events
            if len(self.events) > 1000:
                self.events = self.events[-1000:]
        
        # Check for alert conditions
        self._check_alerts(event)
        
        # Log the event
        log_level = logging.WARNING if event.severity in ['high', 'critical'] else logging.INFO
        logger.log(log_level, f"Security event: {event.event_type} from {event.ip_address} - {event.severity}")
    
    def _check_alerts(self, event: SecurityEvent):
        """Check if alert conditions are met"""
        current_time = time.time()
        window = 3600  # 1 hour window
        
        # Count recent events by type and IP
        recent_events = [
            e for e in self.events
            if e.timestamp.timestamp() > current_time - window
            and e.ip_address == event.ip_address
            and e.event_type == event.event_type
        ]
        
        threshold = self.alert_thresholds.get(event.event_type, 10)
        
        if len(recent_events) >= threshold:
            self._trigger_alert(event, recent_events)
    
    def _trigger_alert(self, event: SecurityEvent, recent_events: List[SecurityEvent]):
        """Trigger security alert"""
        alert_data = {
            'type': 'security_alert',
            'timestamp': datetime.now().isoformat(),
            'event_type': event.event_type,
            'ip_address': event.ip_address,
            'severity': event.severity,
            'count': len(recent_events),
            'threshold': self.alert_thresholds.get(event.event_type, 10),
            'recent_events': [
                {
                    'timestamp': e.timestamp.isoformat(),
                    'endpoint': e.endpoint,
                    'details': e.details
                }
                for e in recent_events[-5:]  # Last 5 events
            ]
        }
        
        # Call alert callbacks
        for callback in self.alert_callbacks:
            try:
                callback(alert_data)
            except Exception as e:
                logger.error(f"Alert callback failed: {e}")
    
    def add_alert_callback(self, callback: Callable):
        """Add a callback for security alerts"""
        self.alert_callbacks.append(callback)
    
    def get_security_stats(self, hours: int = 24) -> Dict:
        """Get security statistics"""
        cutoff_time = datetime.now() - timedelta(hours=hours)
        
        with self.lock:
            recent_events = [
                e for e in self.events
                if e.timestamp > cutoff_time
            ]
        
        # Group events by type
        event_counts = defaultdict(int)
        blocked_events = 0
        ip_addresses = set()
        
        for event in recent_events:
            event_counts[event.event_type] += 1
            if event.blocked:
                blocked_events += 1
            ip_addresses.add(event.ip_address)
        
        return {
            'total_events': len(recent_events),
            'blocked_events': blocked_events,
            'unique_ips': len(ip_addresses),
            'events_by_type': dict(event_counts),
            'time_period_hours': hours
        }

class SecurityEnhancer:
    """Main security enhancement class"""
    
    def __init__(self, secret_key: str):
        self.rate_limiter = RateLimiter()
        self.input_sanitizer = InputSanitizer()
        self.csrf_protector = CSRFProtector(secret_key)
        self.security_monitor = SecurityMonitor()
        
        # Start cleanup threads
        self._start_cleanup_threads()
    
    def _start_cleanup_threads(self):
        """Start background cleanup threads"""
        def csrf_cleanup():
            while True:
                time.sleep(300)  # Every 5 minutes
                self.csrf_protector.cleanup_expired_tokens()
        
        csrf_thread = threading.Thread(target=csrf_cleanup, daemon=True)
        csrf_thread.start()
    
    def rate_limit(self, limit_type: str = 'default'):
        """Decorator for rate limiting"""
        def decorator(func):
            @wraps(func)
            def wrapper(*args, **kwargs):
                # Extract IP from request (assuming Flask request object)
                from flask import request
                ip = request.remote_addr
                
                if not self.rate_limiter.is_allowed(ip, limit_type):
                    # Log security event
                    self.security_monitor.log_event(SecurityEvent(
                        event_type='rate_limit_violation',
                        timestamp=datetime.now(),
                        ip_address=ip,
                        user_agent=request.headers.get('User-Agent', ''),
                        endpoint=request.endpoint or '',
                        severity='medium',
                        details={'limit_type': limit_type}
                    ))
                    
                    return {'error': 'Rate limit exceeded'}, 429
                
                return func(*args, **kwargs)
            return wrapper
        return decorator
    
    def sanitize_input(self, fields: List[str]):
        """Decorator for input sanitization"""
        def decorator(func):
            @wraps(func)
            def wrapper(*args, **kwargs):
                from flask import request
                
                # Sanitize form data
                if request.form:
                    for field in fields:
                        if field in request.form:
                            value = request.form[field]
                            sanitized = self.input_sanitizer.sanitize_string(value)
                            
                            # Check for security threats
                            if self.input_sanitizer.detect_sql_injection(sanitized):
                                self._log_security_threat('sql_injection_attempt', field, sanitized)
                                return {'error': 'Invalid input'}, 400
                            
                            if self.input_sanitizer.detect_xss(sanitized):
                                self._log_security_threat('xss_attempt', field, sanitized)
                                return {'error': 'Invalid input'}, 400
                            
                            if self.input_sanitizer.detect_command_injection(sanitized):
                                self._log_security_threat('command_injection_attempt', field, sanitized)
                                return {'error': 'Invalid input'}, 400
                            
                            request.form[field] = sanitized
                
                # Sanitize JSON data
                if request.is_json:
                    data = request.get_json()
                    if data:
                        sanitized_data = self.input_sanitizer.sanitize_json(data)
                        request._cached_json = sanitized_data
                
                return func(*args, **kwargs)
            return wrapper
        return decorator
    
    def require_csrf(self):
        """Decorator for CSRF protection"""
        def decorator(func):
            @wraps(func)
            def wrapper(*args, **kwargs):
                from flask import request, session
                
                if request.method in ['POST', 'PUT', 'DELETE', 'PATCH']:
                    token = request.headers.get('X-CSRF-Token') or request.form.get('csrf_token')
                    
                    if not token:
                        return {'error': 'CSRF token missing'}, 403
                    
                    user_id = session.get('user_id', 'anonymous')
                    session_id = session.get('session_id', '')
                    
                    if not self.csrf_protector.validate_token(token, user_id, session_id):
                        self._log_security_threat('csrf_attempt', 'token', token)
                        return {'error': 'Invalid CSRF token'}, 403
                
                return func(*args, **kwargs)
            return wrapper
        return decorator
    
    def _log_security_threat(self, threat_type: str, field: str, value: str):
        """Log a security threat"""
        from flask import request
        
        self.security_monitor.log_event(SecurityEvent(
            event_type=threat_type,
            timestamp=datetime.now(),
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent', ''),
            endpoint=request.endpoint or '',
            severity='high',
            details={'field': field, 'value': value[:100]}  # Truncate value for logging
        ))
    
    def get_security_report(self) -> Dict:
        """Get comprehensive security report"""
        return {
            'rate_limiter': self.rate_limiter.get_stats(),
            'security_monitor': self.security_monitor.get_security_stats(),
            'csrf_tokens': len(self.csrf_protector.tokens),
            'timestamp': datetime.now().isoformat()
        }

# Global security enhancer instance
security_enhancer = None

def initialize_security_enhancer(secret_key: str):
    """Initialize the global security enhancer"""
    global security_enhancer
    security_enhancer = SecurityEnhancer(secret_key)
    return security_enhancer

def get_security_enhancer() -> SecurityEnhancer:
    """Get the global security enhancer instance"""
    if security_enhancer is None:
        raise RuntimeError("Security enhancer not initialized. Call initialize_security_enhancer() first.")
    return security_enhancer 