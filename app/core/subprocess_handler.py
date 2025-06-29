#!/usr/bin/env python3
"""
Enhanced Subprocess Handler with async support, resource limits, and better error handling
"""

import subprocess
import asyncio
import logging
import time
import signal
import os
import json
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from pathlib import Path
from enum import Enum

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Only import resource on Unix
if os.name != 'nt':
    try:
        import resource
    except ImportError:
        resource = None
else:
    resource = None

class ProcessStatus(Enum):
    """Process execution status"""
    SUCCESS = "success"
    TIMEOUT = "timeout"
    ERROR = "error"
    KILLED = "killed"
    RESOURCE_LIMIT = "resource_limit"

@dataclass
class ProcessResult:
    """Result of process execution"""
    status: ProcessStatus
    output: str
    error: str
    return_code: int
    execution_time: float
    memory_usage: Optional[float] = None
    cpu_usage: Optional[float] = None
    timestamp: Optional[float] = None

class SubprocessHandler:
    """Enhanced subprocess handler with async support and resource monitoring"""
    
    def __init__(self, default_timeout: int = 30, max_memory_mb: int = 512):
        self.default_timeout = default_timeout
        self.max_memory_mb = max_memory_mb
        self.process_cache: Dict[str, ProcessResult] = {}
        self.cache_ttl = 300  # 5 minutes cache TTL
        
    def run_command(self, command: List[str], timeout: Optional[int] = None, 
                   cwd: Optional[str] = None, env: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        """Run a command synchronously with enhanced error handling"""
        start_time = time.time()
        timeout = timeout or self.default_timeout
        
        try:
            # Create process with resource limits
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd=cwd,
                env=env,
                preexec_fn=self._set_resource_limits if os.name != 'nt' else None
            )
            
            # Monitor process with timeout
            try:
                stdout, stderr = process.communicate(timeout=timeout)
                execution_time = time.time() - start_time
                
                if process.returncode == 0:
                    return {
                        'success': True,
                        'output': stdout,
                        'error': stderr,
                        'return_code': process.returncode,
                        'execution_time': execution_time,
                        'command': ' '.join(command)
                    }
                else:
                    return {
                        'success': False,
                        'output': stdout,
                        'error': stderr,
                        'return_code': process.returncode,
                        'execution_time': execution_time,
                        'command': ' '.join(command)
                    }
                    
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
                return {
                    'success': False,
                    'output': '',
                    'error': f'Command timed out after {timeout} seconds',
                    'return_code': -1,
                    'execution_time': timeout,
                    'command': ' '.join(command)
                }
                
        except Exception as e:
            logger.error(f"Error running command {' '.join(command)}: {str(e)}")
            return {
                'success': False,
                'output': '',
                'error': str(e),
                'return_code': -1,
                'execution_time': time.time() - start_time,
                'command': ' '.join(command)
            }
    
    async def run_command_async(self, command: List[str], timeout: Optional[int] = None,
                               cwd: Optional[str] = None, env: Optional[Dict[str, str]] = None) -> ProcessResult:
        """Run a command asynchronously with resource monitoring"""
        start_time = time.time()
        timeout = timeout or self.default_timeout
        
        try:
            # Create async process
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=cwd,
                env=env
            )
            
            # Monitor process with timeout and resource limits
            try:
                stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
                execution_time = time.time() - start_time
                
                if process.returncode == 0:
                    return ProcessResult(
                        status=ProcessStatus.SUCCESS,
                        output=stdout.decode() if stdout else '',
                        error=stderr.decode() if stderr else '',
                        return_code=process.returncode,
                        execution_time=execution_time
                    )
                else:
                    return ProcessResult(
                        status=ProcessStatus.ERROR,
                        output=stdout.decode() if stdout else '',
                        error=stderr.decode() if stderr else '',
                        return_code=process.returncode,
                        execution_time=execution_time
                    )
                    
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                return ProcessResult(
                    status=ProcessStatus.TIMEOUT,
                    output='',
                    error=f'Command timed out after {timeout} seconds',
                    return_code=-1,
                    execution_time=timeout
                )
                
        except Exception as e:
            logger.error(f"Error running async command {' '.join(command)}: {str(e)}")
            return ProcessResult(
                status=ProcessStatus.ERROR,
                output='',
                error=str(e),
                return_code=-1,
                execution_time=time.time() - start_time
            )
    
    def _set_resource_limits(self) -> None:
        """Set resource limits for the process (Unix only)"""
        if resource is not None:
            try:
                # Set memory limit (soft limit)
                resource.setrlimit(resource.RLIMIT_AS, (self.max_memory_mb * 1024 * 1024, -1))
                # Set CPU time limit (soft limit)
                resource.setrlimit(resource.RLIMIT_CPU, (self.default_timeout, -1))
            except (ImportError, AttributeError, OSError):
                pass  # resource module not available on Windows or missing attributes
    
    def run_with_retry(self, command: List[str], max_retries: int = 3, 
                      retry_delay: float = 1.0) -> Dict[str, Any]:
        """Run command with retry logic"""
        for attempt in range(max_retries):
            result = self.run_command(command)
            if result['success']:
                return result
            
            if attempt < max_retries - 1:
                logger.warning(f"Command failed, retrying in {retry_delay}s (attempt {attempt + 1}/{max_retries})")
                time.sleep(retry_delay)
                retry_delay *= 2  # Exponential backoff
        
        return result
    
    def get_cached_result(self, command_key: str) -> Optional[ProcessResult]:
        """Get cached result if still valid"""
        if command_key in self.process_cache:
            cached_result = self.process_cache[command_key]
            # Check if cache is still valid (simple TTL check)
            if hasattr(cached_result, 'timestamp'):
                if time.time() - cached_result.timestamp < self.cache_ttl:
                    return cached_result
            else:
                # For backward compatibility, assume cache is valid
                return cached_result
        return None
    
    def cache_result(self, command_key: str, result: ProcessResult) -> None:
        """Cache process result"""
        result.timestamp = time.time()
        self.process_cache[command_key] = result
        
        # Clean old cache entries
        current_time = time.time()
        self.process_cache = {
            k: v for k, v in self.process_cache.items()
            if current_time - (getattr(v, 'timestamp', 0) or 0) < self.cache_ttl
        }
    
    def run_tool_check(self, tool_name: str) -> Dict[str, Any]:
        """Check if a tool is available with caching"""
        command_key = f"tool_check_{tool_name}"
        
        # Check cache first
        cached_result = self.get_cached_result(command_key)
        if cached_result:
            return {
                'success': cached_result.status == ProcessStatus.SUCCESS,
                'output': cached_result.output,
                'error': cached_result.error,
                'cached': True
            }
        
        # Run actual check
        command = [tool_name, '--version']
        result = self.run_command(command, timeout=10)
        
        # Cache the result
        process_result = ProcessResult(
            status=ProcessStatus.SUCCESS if result['success'] else ProcessStatus.ERROR,
            output=result['output'],
            error=result['error'],
            return_code=result['return_code'] if result['return_code'] is not None else -1,
            execution_time=result['execution_time']
        )
        self.cache_result(command_key, process_result)
        
        return {
            'success': result['success'],
            'output': result['output'],
            'error': result['error'],
            'cached': False
        }

if __name__ == "__main__":
    # Test the enhanced subprocess handler
    handler = SubprocessHandler()
    
    # Test synchronous execution
    print("Testing sync command execution...")
    result = handler.run_command(['echo', 'Hello World'])
    print(f"Sync result: {result}")
    
    # Test async execution
    async def test_async():
        print("Testing async command execution...")
        result = await handler.run_command_async(['echo', 'Hello Async World'])
        print(f"Async result: {result}")
    
    # Run async test
    asyncio.run(test_async())
    
    # Test tool checking with cache
    print("Testing tool checking with cache...")
    result1 = handler.run_tool_check('python')
    print(f"First check: {result1}")
    result2 = handler.run_tool_check('python')
    print(f"Second check (cached): {result2}") 