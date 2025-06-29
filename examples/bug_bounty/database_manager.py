#!/usr/bin/env python3
"""
Database Manager with Connection Pooling and Efficient Queries
Provides optimized database operations for the bug hunter system
"""

import sqlite3
import json
import logging
import asyncio
import time
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass
from pathlib import Path
import threading
from contextlib import asynccontextmanager

logger = logging.getLogger(__name__)

@dataclass
class DatabaseStats:
    """Database statistics"""
    total_workflows: int
    total_vulnerabilities: int
    avg_workflow_duration: float
    success_rate: float
    last_updated: float

class DatabaseManager:
    """Database manager with connection pooling and optimizations"""
    
    def __init__(self, db_path: str = "kali_bug_hunter.db", max_connections: int = 10):
        """
        Initialize database manager
        
        Args:
            db_path: Path to SQLite database file
            max_connections: Maximum number of connections in pool
        """
        self.db_path = Path(db_path)
        self.max_connections = max_connections
        self.connection_pool = []
        self.pool_lock = threading.Lock()
        self.initialized = False
        
        # Create database directory if needed
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
    
    async def initialize(self) -> None:
        """Initialize database and create tables"""
        try:
            # Create tables
            await self._create_tables()
            self.initialized = True
            logger.info("Database initialized successfully")
        except Exception as e:
            logger.error(f"Database initialization failed: {e}")
            raise
    
    async def _create_tables(self) -> None:
        """Create database tables with optimized schema"""
        async with self._get_connection() as conn:
            # Workflows table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS workflows (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    workflow_id TEXT UNIQUE NOT NULL,
                    target TEXT NOT NULL,
                    scope TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'running',
                    start_time REAL NOT NULL,
                    end_time REAL,
                    ai_provider TEXT,
                    workflow_type TEXT,
                    steps TEXT,  -- JSON array
                    logs TEXT,   -- JSON array
                    vulnerabilities TEXT,  -- JSON array
                    performance_metrics TEXT,  -- JSON object
                    created_at REAL DEFAULT (strftime('%s', 'now')),
                    updated_at REAL DEFAULT (strftime('%s', 'now'))
                )
            """)
            
            # Vulnerabilities table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS vulnerabilities (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    workflow_id TEXT NOT NULL,
                    vulnerability_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT,
                    proof_of_concept TEXT,
                    affected_url TEXT,
                    payload TEXT,
                    created_at REAL DEFAULT (strftime('%s', 'now')),
                    FOREIGN KEY (workflow_id) REFERENCES workflows (workflow_id)
                )
            """)
            
            # Performance metrics table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS performance_metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    workflow_id TEXT NOT NULL,
                    metric_name TEXT NOT NULL,
                    metric_value REAL NOT NULL,
                    timestamp REAL NOT NULL,
                    metadata TEXT,  -- JSON object
                    FOREIGN KEY (workflow_id) REFERENCES workflows (workflow_id)
                )
            """)
            
            # Create indexes for better performance
            conn.execute("CREATE INDEX IF NOT EXISTS idx_workflows_status ON workflows(status)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_workflows_target ON workflows(target)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_workflows_start_time ON workflows(start_time)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_vulnerabilities_workflow ON vulnerabilities(workflow_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_vulnerabilities_type ON vulnerabilities(vulnerability_type)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_vulnerabilities_severity ON vulnerabilities(severity)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_performance_workflow ON performance_metrics(workflow_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_performance_timestamp ON performance_metrics(timestamp)")
            
            conn.commit()
    
    @asynccontextmanager
    async def _get_connection(self):
        """Get database connection from pool"""
        conn = None
        try:
            # Try to get connection from pool
            with self.pool_lock:
                if self.connection_pool:
                    conn = self.connection_pool.pop()
                else:
                    # Create new connection
                    conn = sqlite3.connect(self.db_path, check_same_thread=False)
                    conn.row_factory = sqlite3.Row  # Enable dict-like access
            
            yield conn
            
        except Exception as e:
            logger.error(f"Database connection error: {e}")
            raise
        finally:
            # Return connection to pool
            if conn:
                try:
                    with self.pool_lock:
                        if len(self.connection_pool) < self.max_connections:
                            self.connection_pool.append(conn)
                        else:
                            conn.close()
                except Exception as e:
                    logger.error(f"Error returning connection to pool: {e}")
                    conn.close()
    
    async def save_workflow(self, workflow_data: Dict[str, Any]) -> bool:
        """
        Save workflow data efficiently
        
        Args:
            workflow_data: Workflow data dictionary
            
        Returns:
            True if saved successfully
        """
        try:
            async with self._get_connection() as conn:
                # Prepare data
                workflow_id = workflow_data.get('workflow_id', f"workflow_{int(time.time())}")
                
                # Check if workflow exists
                cursor = conn.execute(
                    "SELECT id FROM workflows WHERE workflow_id = ?",
                    (workflow_id,)
                )
                existing = cursor.fetchone()
                
                if existing:
                    # Update existing workflow
                    conn.execute("""
                        UPDATE workflows SET
                            target = ?, scope = ?, status = ?, end_time = ?,
                            steps = ?, logs = ?, vulnerabilities = ?, performance_metrics = ?,
                            updated_at = (strftime('%s', 'now'))
                        WHERE workflow_id = ?
                    """, (
                        workflow_data.get('target', ''),
                        workflow_data.get('scope', ''),
                        workflow_data.get('status', 'running'),
                        workflow_data.get('end_time'),
                        json.dumps(workflow_data.get('steps', [])),
                        json.dumps(workflow_data.get('logs', [])),
                        json.dumps(workflow_data.get('vulnerabilities', [])),
                        json.dumps(workflow_data.get('performance_metrics', {})),
                        workflow_id
                    ))
                else:
                    # Insert new workflow
                    conn.execute("""
                        INSERT INTO workflows (
                            workflow_id, target, scope, status, start_time, end_time,
                            ai_provider, workflow_type, steps, logs, vulnerabilities, performance_metrics
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        workflow_id,
                        workflow_data.get('target', ''),
                        workflow_data.get('scope', ''),
                        workflow_data.get('status', 'running'),
                        workflow_data.get('start_time', time.time()),
                        workflow_data.get('end_time'),
                        workflow_data.get('ai_provider', ''),
                        workflow_data.get('workflow_type', ''),
                        json.dumps(workflow_data.get('steps', [])),
                        json.dumps(workflow_data.get('logs', [])),
                        json.dumps(workflow_data.get('vulnerabilities', [])),
                        json.dumps(workflow_data.get('performance_metrics', {}))
                    ))
                
                conn.commit()
                return True
                
        except Exception as e:
            logger.error(f"Error saving workflow: {e}")
            return False
    
    async def get_workflows(self, 
                          limit: int = 50, 
                          offset: int = 0,
                          status: Optional[str] = None,
                          target: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Get workflows with efficient filtering and pagination
        
        Args:
            limit: Maximum number of workflows to return
            offset: Number of workflows to skip
            status: Filter by status
            target: Filter by target
            
        Returns:
            List of workflow dictionaries
        """
        try:
            async with self._get_connection() as conn:
                # Build query with conditions
                query = "SELECT * FROM workflows WHERE 1=1"
                params = []
                
                if status:
                    query += " AND status = ?"
                    params.append(status)
                
                if target:
                    query += " AND target LIKE ?"
                    params.append(f"%{target}%")
                
                query += " ORDER BY start_time DESC LIMIT ? OFFSET ?"
                params.extend([limit, offset])
                
                cursor = conn.execute(query, params)
                rows = cursor.fetchall()
                
                # Convert to dictionaries
                workflows = []
                for row in rows:
                    workflow = dict(row)
                    
                    # Parse JSON fields
                    for field in ['steps', 'logs', 'vulnerabilities', 'performance_metrics']:
                        if workflow[field]:
                            try:
                                workflow[field] = json.loads(workflow[field])
                            except json.JSONDecodeError:
                                workflow[field] = []
                    
                    workflows.append(workflow)
                
                return workflows
                
        except Exception as e:
            logger.error(f"Error getting workflows: {e}")
            return []
    
    async def get_workflow(self, workflow_id: str) -> Optional[Dict[str, Any]]:
        """
        Get specific workflow by ID
        
        Args:
            workflow_id: Workflow ID
            
        Returns:
            Workflow dictionary or None
        """
        try:
            async with self._get_connection() as conn:
                cursor = conn.execute(
                    "SELECT * FROM workflows WHERE workflow_id = ?",
                    (workflow_id,)
                )
                row = cursor.fetchone()
                
                if row:
                    workflow = dict(row)
                    
                    # Parse JSON fields
                    for field in ['steps', 'logs', 'vulnerabilities', 'performance_metrics']:
                        if workflow[field]:
                            try:
                                workflow[field] = json.loads(workflow[field])
                            except json.JSONDecodeError:
                                workflow[field] = []
                    
                    return workflow
                
                return None
                
        except Exception as e:
            logger.error(f"Error getting workflow {workflow_id}: {e}")
            return None
    
    async def save_vulnerability(self, workflow_id: str, vulnerability_data: Dict[str, Any]) -> bool:
        """
        Save vulnerability data
        
        Args:
            workflow_id: Associated workflow ID
            vulnerability_data: Vulnerability data dictionary
            
        Returns:
            True if saved successfully
        """
        try:
            async with self._get_connection() as conn:
                conn.execute("""
                    INSERT INTO vulnerabilities (
                        workflow_id, vulnerability_type, severity, title, description,
                        proof_of_concept, affected_url, payload
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    workflow_id,
                    vulnerability_data.get('type', ''),
                    vulnerability_data.get('severity', 'medium'),
                    vulnerability_data.get('title', ''),
                    vulnerability_data.get('description', ''),
                    vulnerability_data.get('proof_of_concept', ''),
                    vulnerability_data.get('affected_url', ''),
                    vulnerability_data.get('payload', '')
                ))
                
                conn.commit()
                return True
                
        except Exception as e:
            logger.error(f"Error saving vulnerability: {e}")
            return False
    
    async def get_vulnerabilities(self, 
                                workflow_id: Optional[str] = None,
                                severity: Optional[str] = None,
                                limit: int = 100) -> List[Dict[str, Any]]:
        """
        Get vulnerabilities with filtering
        
        Args:
            workflow_id: Filter by workflow ID
            severity: Filter by severity
            limit: Maximum number to return
            
        Returns:
            List of vulnerability dictionaries
        """
        try:
            async with self._get_connection() as conn:
                query = "SELECT * FROM vulnerabilities WHERE 1=1"
                params = []
                
                if workflow_id:
                    query += " AND workflow_id = ?"
                    params.append(workflow_id)
                
                if severity:
                    query += " AND severity = ?"
                    params.append(severity)
                
                query += " ORDER BY created_at DESC LIMIT ?"
                params.append(limit)
                
                cursor = conn.execute(query, params)
                rows = cursor.fetchall()
                
                return [dict(row) for row in rows]
                
        except Exception as e:
            logger.error(f"Error getting vulnerabilities: {e}")
            return []
    
    async def save_performance_metric(self, 
                                    workflow_id: str, 
                                    metric_name: str, 
                                    metric_value: float,
                                    metadata: Optional[Dict[str, Any]] = None) -> bool:
        """
        Save performance metric
        
        Args:
            workflow_id: Associated workflow ID
            metric_name: Name of the metric
            metric_value: Metric value
            metadata: Additional metadata
            
        Returns:
            True if saved successfully
        """
        try:
            async with self._get_connection() as conn:
                conn.execute("""
                    INSERT INTO performance_metrics (
                        workflow_id, metric_name, metric_value, timestamp, metadata
                    ) VALUES (?, ?, ?, ?, ?)
                """, (
                    workflow_id,
                    metric_name,
                    metric_value,
                    time.time(),
                    json.dumps(metadata) if metadata else None
                ))
                
                conn.commit()
                return True
                
        except Exception as e:
            logger.error(f"Error saving performance metric: {e}")
            return False
    
    async def get_stats(self) -> DatabaseStats:
        """
        Get database statistics
        
        Returns:
            DatabaseStats object
        """
        try:
            async with self._get_connection() as conn:
                # Get workflow stats
                cursor = conn.execute("SELECT COUNT(*) as total FROM workflows")
                total_workflows = cursor.fetchone()['total']
                
                cursor = conn.execute("SELECT COUNT(*) as total FROM vulnerabilities")
                total_vulnerabilities = cursor.fetchone()['total']
                
                # Calculate average workflow duration
                cursor = conn.execute("""
                    SELECT AVG(end_time - start_time) as avg_duration 
                    FROM workflows 
                    WHERE end_time IS NOT NULL AND start_time IS NOT NULL
                """)
                avg_duration = cursor.fetchone()['avg_duration'] or 0.0
                
                # Calculate success rate
                cursor = conn.execute("""
                    SELECT 
                        COUNT(*) as total,
                        SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) as completed
                    FROM workflows
                """)
                row = cursor.fetchone()
                success_rate = (row['completed'] / row['total'] * 100) if row['total'] > 0 else 0.0
                
                return DatabaseStats(
                    total_workflows=total_workflows,
                    total_vulnerabilities=total_vulnerabilities,
                    avg_workflow_duration=avg_duration,
                    success_rate=success_rate,
                    last_updated=time.time()
                )
                
        except Exception as e:
            logger.error(f"Error getting database stats: {e}")
            return DatabaseStats(
                total_workflows=0,
                total_vulnerabilities=0,
                avg_workflow_duration=0.0,
                success_rate=0.0,
                last_updated=time.time()
            )
    
    async def cleanup_old_data(self, days: int = 30) -> int:
        """
        Clean up old data to maintain performance
        
        Args:
            days: Number of days to keep data
            
        Returns:
            Number of records deleted
        """
        try:
            cutoff_time = time.time() - (days * 24 * 3600)
            
            async with self._get_connection() as conn:
                # Delete old workflows
                cursor = conn.execute(
                    "DELETE FROM workflows WHERE start_time < ?",
                    (cutoff_time,)
                )
                workflows_deleted = cursor.rowcount
                
                # Delete old performance metrics
                cursor = conn.execute(
                    "DELETE FROM performance_metrics WHERE timestamp < ?",
                    (cutoff_time,)
                )
                metrics_deleted = cursor.rowcount
                
                conn.commit()
                
                total_deleted = workflows_deleted + metrics_deleted
                logger.info(f"Cleaned up {total_deleted} old records")
                
                return total_deleted
                
        except Exception as e:
            logger.error(f"Error cleaning up old data: {e}")
            return 0
    
    async def close(self) -> None:
        """Close all database connections"""
        try:
            with self.pool_lock:
                for conn in self.connection_pool:
                    conn.close()
                self.connection_pool.clear()
            
            logger.info("Database connections closed")
            
        except Exception as e:
            logger.error(f"Error closing database connections: {e}")

# Global database manager instance
db_manager = DatabaseManager()

if __name__ == "__main__":
    # Test the database manager
    async def test_database():
        print("Testing Database Manager...")
        
        # Initialize database
        await db_manager.initialize()
        
        # Test saving workflow
        workflow_data = {
            'workflow_id': 'test_workflow',
            'target': 'test.com',
            'scope': '*.test.com',
            'status': 'completed',
            'start_time': time.time() - 3600,
            'end_time': time.time(),
            'steps': [{'name': 'test', 'status': 'completed'}],
            'logs': [{'message': 'test log'}],
            'vulnerabilities': []
        }
        
        success = await db_manager.save_workflow(workflow_data)
        print(f"Save workflow: {'SUCCESS' if success else 'FAILED'}")
        
        # Test getting workflows
        workflows = await db_manager.get_workflows(limit=10)
        print(f"Get workflows: {len(workflows)} found")
        
        # Test getting stats
        stats = await db_manager.get_stats()
        print(f"Database stats: {stats}")
        
        # Cleanup
        await db_manager.close()
    
    asyncio.run(test_database()) 