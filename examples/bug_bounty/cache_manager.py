#!/usr/bin/env python3
"""
Advanced Caching System with TTL, LRU eviction, and multiple storage backends
"""

import time
import json
import hashlib
import pickle
import sqlite3
from typing import Any, Optional, Dict, List, Union
from dataclasses import dataclass, asdict
from enum import Enum
from pathlib import Path
import logging
from collections import OrderedDict
import threading

logger = logging.getLogger(__name__)

class CacheBackend(Enum):
    """Available cache backends"""
    MEMORY = "memory"
    SQLITE = "sqlite"
    FILE = "file"

@dataclass
class CacheEntry:
    """Cache entry with metadata"""
    key: str
    value: Any
    timestamp: float
    ttl: Optional[float] = None
    access_count: int = 0
    last_accessed: float = 0.0

class MemoryCache:
    """In-memory cache with LRU eviction"""
    
    def __init__(self, max_size: int = 1000):
        self.max_size = max_size
        self.cache: OrderedDict[str, CacheEntry] = OrderedDict()
        self.lock = threading.RLock()
    
    def get(self, key: str) -> Optional[Any]:
        """Get value from cache"""
        with self.lock:
            if key in self.cache:
                entry = self.cache[key]
                
                # Check TTL
                if entry.ttl and time.time() - entry.timestamp > entry.ttl:
                    del self.cache[key]
                    return None
                
                # Update access info
                entry.access_count += 1
                entry.last_accessed = time.time()
                
                # Move to end (LRU)
                self.cache.move_to_end(key)
                return entry.value
            
            return None
    
    def set(self, key: str, value: Any, ttl: Optional[float] = None) -> None:
        """Set value in cache"""
        with self.lock:
            # Remove if exists
            if key in self.cache:
                del self.cache[key]
            
            # Add new entry
            entry = CacheEntry(
                key=key,
                value=value,
                timestamp=time.time(),
                ttl=ttl,
                access_count=1,
                last_accessed=time.time()
            )
            self.cache[key] = entry
            
            # Evict if needed
            if len(self.cache) > self.max_size:
                self.cache.popitem(last=False)
    
    def delete(self, key: str) -> bool:
        """Delete key from cache"""
        with self.lock:
            if key in self.cache:
                del self.cache[key]
                return True
            return False
    
    def clear(self) -> None:
        """Clear all cache entries"""
        with self.lock:
            self.cache.clear()
    
    def cleanup_expired(self) -> int:
        """Remove expired entries and return count"""
        with self.lock:
            current_time = time.time()
            expired_keys = [
                key for key, entry in self.cache.items()
                if entry.ttl and current_time - entry.timestamp > entry.ttl
            ]
            
            for key in expired_keys:
                del self.cache[key]
            
            return len(expired_keys)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        with self.lock:
            current_time = time.time()
            total_entries = len(self.cache)
            expired_count = sum(
                1 for entry in self.cache.values()
                if entry.ttl and current_time - entry.timestamp > entry.ttl
            )
            
            return {
                'total_entries': total_entries,
                'expired_entries': expired_count,
                'max_size': self.max_size,
                'usage_percent': (total_entries / self.max_size) * 100 if self.max_size > 0 else 0
            }

class SQLiteCache:
    """SQLite-based persistent cache"""
    
    def __init__(self, db_path: str = "cache.db"):
        self.db_path = db_path
        self.lock = threading.RLock()
        self._init_db()
    
    def _init_db(self) -> None:
        """Initialize database schema"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS cache (
                    key TEXT PRIMARY KEY,
                    value BLOB,
                    timestamp REAL,
                    ttl REAL,
                    access_count INTEGER DEFAULT 0,
                    last_accessed REAL
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON cache(timestamp)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_last_accessed ON cache(last_accessed)")
    
    def get(self, key: str) -> Optional[Any]:
        """Get value from cache"""
        with self.lock:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute(
                    "SELECT value, timestamp, ttl FROM cache WHERE key = ?",
                    (key,)
                )
                row = cursor.fetchone()
                
                if row:
                    value_blob, timestamp, ttl = row
                    
                    # Check TTL
                    if ttl and time.time() - timestamp > ttl:
                        self.delete(key)
                        return None
                    
                    # Update access info
                    conn.execute(
                        "UPDATE cache SET access_count = access_count + 1, last_accessed = ? WHERE key = ?",
                        (time.time(), key)
                    )
                    
                    # Deserialize value
                    try:
                        value = pickle.loads(value_blob)
                        return value
                    except (pickle.PickleError, EOFError):
                        logger.error(f"Failed to deserialize cached value for key: {key}")
                        self.delete(key)
                        return None
                
                return None
    
    def set(self, key: str, value: Any, ttl: Optional[float] = None) -> None:
        """Set value in cache"""
        with self.lock:
            try:
                value_blob = pickle.dumps(value)
                current_time = time.time()
                
                with sqlite3.connect(self.db_path) as conn:
                    conn.execute("""
                        INSERT OR REPLACE INTO cache 
                        (key, value, timestamp, ttl, access_count, last_accessed)
                        VALUES (?, ?, ?, ?, 1, ?)
                    """, (key, value_blob, current_time, ttl, current_time))
            except Exception as e:
                logger.error(f"Failed to cache value for key {key}: {e}")
    
    def delete(self, key: str) -> bool:
        """Delete key from cache"""
        with self.lock:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute("DELETE FROM cache WHERE key = ?", (key,))
                return cursor.rowcount > 0
    
    def clear(self) -> None:
        """Clear all cache entries"""
        with self.lock:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("DELETE FROM cache")
    
    def cleanup_expired(self) -> int:
        """Remove expired entries and return count"""
        with self.lock:
            current_time = time.time()
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute(
                    "DELETE FROM cache WHERE ttl IS NOT NULL AND ? - timestamp > ttl",
                    (current_time,)
                )
                return cursor.rowcount
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        with self.lock:
            with sqlite3.connect(self.db_path) as conn:
                total_entries = conn.execute("SELECT COUNT(*) FROM cache").fetchone()[0]
                expired_count = conn.execute("""
                    SELECT COUNT(*) FROM cache 
                    WHERE ttl IS NOT NULL AND ? - timestamp > ttl
                """, (time.time(),)).fetchone()[0]
                
                return {
                    'total_entries': total_entries,
                    'expired_entries': expired_count,
                    'db_size_mb': Path(self.db_path).stat().st_size / (1024 * 1024) if Path(self.db_path).exists() else 0
                }

class CacheManager:
    """Main cache manager with multiple backends"""
    
    def __init__(self, backend: CacheBackend = CacheBackend.MEMORY, **kwargs):
        self.backend = backend
        
        if backend == CacheBackend.MEMORY:
            self.cache = MemoryCache(**kwargs)
        elif backend == CacheBackend.SQLITE:
            self.cache = SQLiteCache(**kwargs)
        else:
            raise ValueError(f"Unsupported backend: {backend}")
        
        # Start cleanup thread
        self.cleanup_thread = threading.Thread(target=self._cleanup_worker, daemon=True)
        self.cleanup_thread.start()
    
    def _cleanup_worker(self) -> None:
        """Background worker for cache cleanup"""
        while True:
            try:
                time.sleep(300)  # Cleanup every 5 minutes
                expired_count = self.cache.cleanup_expired()
                if expired_count > 0:
                    logger.info(f"Cleaned up {expired_count} expired cache entries")
            except Exception as e:
                logger.error(f"Cache cleanup error: {e}")
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get value from cache"""
        value = self.cache.get(key)
        return value if value is not None else default
    
    def set(self, key: str, value: Any, ttl: Optional[float] = None) -> None:
        """Set value in cache"""
        self.cache.set(key, value, ttl)
    
    def delete(self, key: str) -> bool:
        """Delete key from cache"""
        return self.cache.delete(key)
    
    def clear(self) -> None:
        """Clear all cache entries"""
        self.cache.clear()
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        stats = self.cache.get_stats()
        stats['backend'] = self.backend.value
        return stats
    
    def generate_key(self, *args, **kwargs) -> str:
        """Generate cache key from arguments"""
        key_data = {
            'args': args,
            'kwargs': sorted(kwargs.items())
        }
        key_str = json.dumps(key_data, sort_keys=True)
        return hashlib.md5(key_str.encode()).hexdigest()

# Global cache instance
cache_manager = CacheManager()

def cached(ttl: Optional[float] = None, key_prefix: str = ""):
    """Decorator for caching function results"""
    def decorator(func):
        def wrapper(*args, **kwargs):
            # Generate cache key
            cache_key = f"{key_prefix}:{func.__name__}:{cache_manager.generate_key(*args, **kwargs)}"
            
            # Try to get from cache
            cached_result = cache_manager.get(cache_key)
            if cached_result is not None:
                return cached_result
            
            # Execute function and cache result
            result = func(*args, **kwargs)
            cache_manager.set(cache_key, result, ttl)
            return result
        
        return wrapper
    return decorator

if __name__ == "__main__":
    # Test the cache manager
    print("Testing Cache Manager...")
    
    # Test memory cache
    mem_cache = CacheManager(CacheBackend.MEMORY, max_size=100)
    mem_cache.set("test_key", "test_value", ttl=60)
    print(f"Memory cache get: {mem_cache.get('test_key')}")
    print(f"Memory cache stats: {mem_cache.get_stats()}")
    
    # Test SQLite cache
    sqlite_cache = CacheManager(CacheBackend.SQLITE, db_path="test_cache.db")
    sqlite_cache.set("test_key2", {"data": "test"}, ttl=60)
    print(f"SQLite cache get: {sqlite_cache.get('test_key2')}")
    print(f"SQLite cache stats: {sqlite_cache.get_stats()}")
    
    # Test decorator
    @cached(ttl=30, key_prefix="test")
    def expensive_function(x: int) -> int:
        print(f"Computing expensive function for {x}")
        return x * x
    
    print(f"First call: {expensive_function(5)}")
    print(f"Second call (cached): {expensive_function(5)}") 