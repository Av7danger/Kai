#!/usr/bin/env python3
"""
Database Optimization Module for Bug Bounty Dashboard
Handles connection pooling, query optimization, indexing, and performance monitoring
"""

import sqlite3
import threading
import time
import logging
from typing import Dict, List, Optional, Any, Tuple
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta
import json
import queue
import statistics

logger = logging.getLogger(__name__)

@dataclass
class QueryMetrics:
    """Query performance metrics"""
    query: str
    execution_time: float
    timestamp: datetime
    success: bool
    error_message: Optional[str] = None
    rows_returned: int = 0
    parameters: Optional[Dict] = None

class ConnectionPool:
    """SQLite connection pool with performance monitoring"""
    
    def __init__(self, db_path: str, max_connections: int = 10, timeout: int = 30):
        self.db_path = db_path
        self.max_connections = max_connections
        self.timeout = timeout
        self._connections = queue.Queue(maxsize=max_connections)
        self._lock = threading.Lock()
        self._active_connections = 0
        self._query_metrics: List[QueryMetrics] = []
        self._metrics_lock = threading.Lock()
        
        # Initialize connections
        self._initialize_connections()
        
        # Start metrics cleanup thread
        self._start_cleanup_thread()
    
    def _initialize_connections(self):
        """Initialize connection pool"""
        for _ in range(self.max_connections):
            conn = self._create_connection()
            if conn:
                self._connections.put(conn)
    
    def _create_connection(self) -> Optional[sqlite3.Connection]:
        """Create a new database connection"""
        try:
            conn = sqlite3.connect(
                self.db_path,
                timeout=self.timeout,
                check_same_thread=False
            )
            conn.row_factory = sqlite3.Row
            
            # Enable WAL mode for better concurrency
            conn.execute("PRAGMA journal_mode=WAL")
            
            # Set reasonable cache size
            conn.execute("PRAGMA cache_size=10000")
            
            # Enable foreign keys
            conn.execute("PRAGMA foreign_keys=ON")
            
            return conn
        except Exception as e:
            logger.error(f"Failed to create database connection: {e}")
            return None
    
    @contextmanager
    def get_connection(self):
        """Get a connection from the pool"""
        conn = None
        try:
            conn = self._connections.get(timeout=self.timeout)
            with self._lock:
                self._active_connections += 1
            
            yield conn
        except queue.Empty:
            logger.error("No available connections in pool")
            raise
        except Exception as e:
            logger.error(f"Database connection error: {e}")
            raise
        finally:
            if conn:
                try:
                    # Reset connection state
                    conn.rollback()
                    self._connections.put(conn)
                except:
                    # If connection is broken, create a new one
                    new_conn = self._create_connection()
                    if new_conn:
                        self._connections.put(new_conn)
                
                with self._lock:
                    self._active_connections -= 1
    
    def execute_query(self, query: str, parameters: Optional[Dict] = None, 
                     fetch: bool = True) -> Tuple[Any, float]:
        """Execute a query with performance monitoring"""
        start_time = time.time()
        success = False
        error_message = None
        rows_returned = 0
        
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                if parameters:
                    cursor.execute(query, parameters)
                else:
                    cursor.execute(query)
                
                if fetch:
                    result = cursor.fetchall()
                    rows_returned = len(result)
                else:
                    conn.commit()
                    result = cursor.rowcount
                    rows_returned = result
                
                success = True
                
        except Exception as e:
            error_message = str(e)
            logger.error(f"Query execution failed: {e}")
            logger.error(f"Query: {query}")
            if parameters:
                logger.error(f"Parameters: {parameters}")
            raise
        
        finally:
            execution_time = time.time() - start_time
            
            # Record metrics
            with self._metrics_lock:
                self._query_metrics.append(QueryMetrics(
                    query=query,
                    execution_time=execution_time,
                    timestamp=datetime.now(),
                    success=success,
                    error_message=error_message,
                    rows_returned=rows_returned,
                    parameters=parameters
                ))
        
        return result, execution_time
    
    def _start_cleanup_thread(self):
        """Start thread to clean up old metrics"""
        def cleanup():
            while True:
                time.sleep(3600)  # Clean up every hour
                self._cleanup_old_metrics()
        
        thread = threading.Thread(target=cleanup, daemon=True)
        thread.start()
    
    def _cleanup_old_metrics(self):
        """Remove metrics older than 24 hours"""
        cutoff_time = datetime.now() - timedelta(hours=24)
        
        with self._metrics_lock:
            self._query_metrics = [
                metric for metric in self._query_metrics
                if metric.timestamp > cutoff_time
            ]
    
    def get_performance_stats(self, hours: int = 24) -> Dict:
        """Get database performance statistics"""
        cutoff_time = datetime.now() - timedelta(hours=hours)
        
        with self._metrics_lock:
            recent_metrics = [
                metric for metric in self._query_metrics
                if metric.timestamp > cutoff_time
            ]
        
        if not recent_metrics:
            return {"error": "No metrics available"}
        
        execution_times = [m.execution_time for m in recent_metrics]
        success_count = sum(1 for m in recent_metrics if m.success)
        
        stats = {
            "total_queries": len(recent_metrics),
            "successful_queries": success_count,
            "failed_queries": len(recent_metrics) - success_count,
            "success_rate": success_count / len(recent_metrics) * 100,
            "execution_time_stats": {
                "min": min(execution_times),
                "max": max(execution_times),
                "mean": statistics.mean(execution_times),
                "median": statistics.median(execution_times),
                "p95": sorted(execution_times)[int(len(execution_times) * 0.95)],
                "p99": sorted(execution_times)[int(len(execution_times) * 0.99)]
            },
            "pool_stats": {
                "active_connections": self._active_connections,
                "available_connections": self._connections.qsize(),
                "max_connections": self.max_connections
            },
            "slow_queries": [
                {
                    "query": m.query,
                    "execution_time": m.execution_time,
                    "timestamp": m.timestamp.isoformat()
                }
                for m in sorted(recent_metrics, key=lambda x: x.execution_time, reverse=True)[:10]
            ]
        }
        
        return stats

class DatabaseOptimizer:
    """Database optimization and maintenance utilities"""
    
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.pool = ConnectionPool(db_path)
    
    def create_indexes(self):
        """Create performance indexes for common queries"""
        indexes = [
            # Vulnerabilities table indexes
            "CREATE INDEX IF NOT EXISTS idx_vulnerabilities_severity ON vulnerabilities(severity)",
            "CREATE INDEX IF NOT EXISTS idx_vulnerabilities_discovered_at ON vulnerabilities(discovered_at)",
            "CREATE INDEX IF NOT EXISTS idx_vulnerabilities_target_id ON vulnerabilities(target_id)",
            "CREATE INDEX IF NOT EXISTS idx_vulnerabilities_vulnerability_type ON vulnerabilities(vulnerability_type)",
            
            # Targets table indexes
            "CREATE INDEX IF NOT EXISTS idx_targets_status ON targets(status)",
            "CREATE INDEX IF NOT EXISTS idx_targets_created_at ON targets(created_at)",
            "CREATE INDEX IF NOT EXISTS idx_targets_domain ON targets(domain)",
            
            # Performance metrics indexes
            "CREATE INDEX IF NOT EXISTS idx_performance_metrics_timestamp ON performance_metrics(timestamp)",
            "CREATE INDEX IF NOT EXISTS idx_performance_metrics_operation ON performance_metrics(operation_name)",
            
            # Error log indexes
            "CREATE INDEX IF NOT EXISTS idx_error_log_timestamp ON error_log(timestamp)",
            "CREATE INDEX IF NOT EXISTS idx_error_log_severity ON error_log(severity)",
        ]
        
        for index_sql in indexes:
            try:
                self.pool.execute_query(index_sql, fetch=False)
                logger.info(f"Created index: {index_sql}")
            except Exception as e:
                logger.error(f"Failed to create index: {e}")
    
    def analyze_tables(self):
        """Analyze table statistics for query optimization"""
        try:
            self.pool.execute_query("ANALYZE", fetch=False)
            logger.info("Database analysis completed")
        except Exception as e:
            logger.error(f"Database analysis failed: {e}")
    
    def vacuum_database(self):
        """Vacuum database to reclaim space and optimize performance"""
        try:
            self.pool.execute_query("VACUUM", fetch=False)
            logger.info("Database vacuum completed")
        except Exception as e:
            logger.error(f"Database vacuum failed: {e}")
    
    def optimize_queries(self) -> Dict:
        """Analyze and suggest query optimizations"""
        suggestions = []
        
        # Get slow queries
        stats = self.pool.get_performance_stats(hours=24)
        slow_queries = stats.get("slow_queries", [])
        
        for query_info in slow_queries:
            query = query_info["query"]
            execution_time = query_info["execution_time"]
            
            if execution_time > 1.0:  # Queries taking more than 1 second
                suggestion = self._analyze_query(query)
                if suggestion:
                    suggestions.append({
                        "query": query,
                        "execution_time": execution_time,
                        "suggestion": suggestion
                    })
        
        return {
            "total_suggestions": len(suggestions),
            "suggestions": suggestions
        }
    
    def _analyze_query(self, query: str) -> Optional[str]:
        """Analyze a single query for optimization opportunities"""
        query_lower = query.lower()
        
        # Check for missing indexes
        if "where" in query_lower:
            if "vulnerabilities.severity" in query and "idx_vulnerabilities_severity" not in query:
                return "Consider adding index on vulnerabilities.severity"
            if "vulnerabilities.discovered_at" in query and "idx_vulnerabilities_discovered_at" not in query:
                return "Consider adding index on vulnerabilities.discovered_at"
            if "targets.status" in query and "idx_targets_status" not in query:
                return "Consider adding index on targets.status"
        
        # Check for inefficient patterns
        if "select *" in query_lower:
            return "Consider selecting only needed columns instead of SELECT *"
        
        if "order by" in query_lower and "limit" not in query_lower:
            return "Consider adding LIMIT clause to ORDER BY queries"
        
        if "like '%" in query_lower:
            return "Consider using indexed columns or full-text search instead of LIKE with leading wildcard"
        
        return None
    
    def get_database_info(self) -> Dict:
        """Get comprehensive database information"""
        try:
            # Get table sizes
            size_query = """
                SELECT 
                    name as table_name,
                    sqlite_compileoption_used('ENABLE_FTS5') as fts5_enabled,
                    (SELECT COUNT(*) FROM sqlite_master WHERE type='table') as total_tables
                FROM sqlite_master 
                WHERE type='table' AND name NOT LIKE 'sqlite_%'
            """
            
            tables, _ = self.pool.execute_query(size_query)
            
            # Get index information
            index_query = """
                SELECT 
                    name as index_name,
                    tbl_name as table_name,
                    sql as index_sql
                FROM sqlite_master 
                WHERE type='index' AND name NOT LIKE 'sqlite_%'
            """
            
            indexes, _ = self.pool.execute_query(index_query)
            
            # Get database file size
            import os
            file_size = os.path.getsize(self.db_path)
            
            return {
                "file_size_mb": file_size / (1024 * 1024),
                "total_tables": len(tables),
                "total_indexes": len(indexes),
                "tables": [dict(table) for table in tables],
                "indexes": [dict(index) for index in indexes],
                "performance_stats": self.pool.get_performance_stats()
            }
            
        except Exception as e:
            logger.error(f"Failed to get database info: {e}")
            return {"error": str(e)}
    
    def backup_database(self, backup_path: str):
        """Create a backup of the database"""
        try:
            import shutil
            shutil.copy2(self.db_path, backup_path)
            logger.info(f"Database backed up to {backup_path}")
        except Exception as e:
            logger.error(f"Database backup failed: {e}")
            raise

# Global database optimizer instance
db_optimizer = None

def initialize_database_optimizer(db_path: str):
    """Initialize the global database optimizer"""
    global db_optimizer
    db_optimizer = DatabaseOptimizer(db_path)
    
    # Create indexes on startup
    db_optimizer.create_indexes()
    
    # Analyze tables
    db_optimizer.analyze_tables()
    
    return db_optimizer

def get_db_optimizer() -> DatabaseOptimizer:
    """Get the global database optimizer instance"""
    if db_optimizer is None:
        raise RuntimeError("Database optimizer not initialized. Call initialize_database_optimizer() first.")
    return db_optimizer 