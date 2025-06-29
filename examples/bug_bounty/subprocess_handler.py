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

@dataclass
class SubprocessResult:
    """Result of subprocess execution with comprehensive metadata"""
    success: bool
    return_code: int
    stdout: str
    stderr: str
    execution_time: float
    command: str
    error_type: Optional[str] = None
    error_message: Optional[str] = None
    killed_by_timeout: bool = False
    memory_usage: Optional[float] = None
    cpu_usage: Optional[float] = None

class SubprocessHandler:
    """Robust subprocess handler with comprehensive error handling and monitoring"""
    
    def __init__(self, timeout: int = 300, max_retries: int = 3):
        self.timeout = timeout
        self.max_retries = max_retries
        self.logger = logging.getLogger(__name__)
        
    async def run_command(
        self, 
        command: List[str], 
        cwd: Optional[str] = None,
        env: Optional[Dict[str, str]] = None,
        input_data: Optional[str] = None,
        capture_output: bool = True
    ) -> SubprocessResult:
        """Execute command with comprehensive error handling and retries"""
        
        start_time = time.time()
        last_error = None
        
        for attempt in range(self.max_retries):
            try:
                self.logger.info(f"Executing command (attempt {attempt + 1}): {' '.join(command)}")
                
                # Prepare environment
                process_env = os.environ.copy()
                if env:
                    process_env.update(env)
                
                # Execute command
                if input_data:
                    process = await asyncio.create_subprocess_exec(
                        *command,
                        cwd=cwd,
                        env=process_env,
                        stdin=asyncio.subprocess.PIPE,
                        stdout=asyncio.subprocess.PIPE if capture_output else None,
                        stderr=asyncio.subprocess.PIPE if capture_output else None
                    )
                    stdout, stderr = await asyncio.wait_for(
                        process.communicate(input=input_data.encode()),
                        timeout=self.timeout
                    )
                else:
                    process = await asyncio.create_subprocess_exec(
                        *command,
                        cwd=cwd,
                        env=process_env,
                        stdout=asyncio.subprocess.PIPE if capture_output else None,
                        stderr=asyncio.subprocess.PIPE if capture_output else None
                    )
                    stdout, stderr = await asyncio.wait_for(
                        process.communicate(),
                        timeout=self.timeout
                    )
                
                execution_time = time.time() - start_time
                
                # Decode output
                stdout_str = stdout.decode('utf-8', errors='ignore') if stdout else ""
                stderr_str = stderr.decode('utf-8', errors='ignore') if stderr else ""
                
                result = SubprocessResult(
                    success=process.returncode == 0,
                    return_code=process.returncode,
                    stdout=stdout_str,
                    stderr=stderr_str,
                    execution_time=execution_time,
                    command=' '.join(command)
                )
                
                if result.success:
                    self.logger.info(f"Command succeeded in {execution_time:.2f}s")
                    return result
                else:
                    self.logger.warning(f"Command failed with return code {process.returncode}")
                    last_error = result
                    
            except asyncio.TimeoutError:
                execution_time = time.time() - start_time
                self.logger.error(f"Command timed out after {execution_time:.2f}s")
                last_error = SubprocessResult(
                    success=False,
                    return_code=-1,
                    stdout="",
                    stderr="",
                    execution_time=execution_time,
                    command=' '.join(command),
                    error_type="timeout",
                    error_message=f"Command timed out after {self.timeout}s",
                    killed_by_timeout=True
                )
                
            except FileNotFoundError:
                execution_time = time.time() - start_time
                self.logger.error(f"Command not found: {command[0]}")
                last_error = SubprocessResult(
                    success=False,
                    return_code=-1,
                    stdout="",
                    stderr="",
                    execution_time=execution_time,
                    command=' '.join(command),
                    error_type="file_not_found",
                    error_message=f"Command not found: {command[0]}"
                )
                
            except PermissionError:
                execution_time = time.time() - start_time
                self.logger.error(f"Permission denied for command: {' '.join(command)}")
                last_error = SubprocessResult(
                    success=False,
                    return_code=-1,
                    stdout="",
                    stderr="",
                    execution_time=execution_time,
                    command=' '.join(command),
                    error_type="permission_denied",
                    error_message="Permission denied"
                )
                
            except Exception as e:
                execution_time = time.time() - start_time
                self.logger.error(f"Unexpected error executing command: {str(e)}")
                last_error = SubprocessResult(
                    success=False,
                    return_code=-1,
                    stdout="",
                    stderr="",
                    execution_time=execution_time,
                    command=' '.join(command),
                    error_type="unexpected_error",
                    error_message=str(e)
                )
            
            # Wait before retry
            if attempt < self.max_retries - 1:
                wait_time = 2 ** attempt  # Exponential backoff
                self.logger.info(f"Retrying in {wait_time}s...")
                await asyncio.sleep(wait_time)
        
        return last_error
    
    def run_sync_command(
        self, 
        command: List[str], 
        cwd: Optional[str] = None,
        env: Optional[Dict[str, str]] = None,
        input_data: Optional[str] = None,
        capture_output: bool = True
    ) -> SubprocessResult:
        """Synchronous version of run_command for non-async contexts"""
        
        start_time = time.time()
        last_error = None
        
        for attempt in range(self.max_retries):
            try:
                self.logger.info(f"Executing sync command (attempt {attempt + 1}): {' '.join(command)}")
                
                # Prepare environment
                process_env = os.environ.copy()
                if env:
                    process_env.update(env)
                
                # Execute command
                if input_data:
                    process = subprocess.run(
                        command,
                        cwd=cwd,
                        env=process_env,
                        input=input_data.encode(),
                        capture_output=capture_output,
                        timeout=self.timeout,
                        text=True
                    )
                else:
                    process = subprocess.run(
                        command,
                        cwd=cwd,
                        env=process_env,
                        capture_output=capture_output,
                        timeout=self.timeout,
                        text=True
                    )
                
                execution_time = time.time() - start_time
                
                result = SubprocessResult(
                    success=process.returncode == 0,
                    return_code=process.returncode,
                    stdout=process.stdout or "",
                    stderr=process.stderr or "",
                    execution_time=execution_time,
                    command=' '.join(command)
                )
                
                if result.success:
                    self.logger.info(f"Sync command succeeded in {execution_time:.2f}s")
                    return result
                else:
                    self.logger.warning(f"Sync command failed with return code {process.returncode}")
                    last_error = result
                    
            except subprocess.TimeoutExpired:
                execution_time = time.time() - start_time
                self.logger.error(f"Sync command timed out after {execution_time:.2f}s")
                last_error = SubprocessResult(
                    success=False,
                    return_code=-1,
                    stdout="",
                    stderr="",
                    execution_time=execution_time,
                    command=' '.join(command),
                    error_type="timeout",
                    error_message=f"Command timed out after {self.timeout}s",
                    killed_by_timeout=True
                )
                
            except FileNotFoundError:
                execution_time = time.time() - start_time
                self.logger.error(f"Sync command not found: {command[0]}")
                last_error = SubprocessResult(
                    success=False,
                    return_code=-1,
                    stdout="",
                    stderr="",
                    execution_time=execution_time,
                    command=' '.join(command),
                    error_type="file_not_found",
                    error_message=f"Command not found: {command[0]}"
                )
                
            except PermissionError:
                execution_time = time.time() - start_time
                self.logger.error(f"Permission denied for sync command: {' '.join(command)}")
                last_error = SubprocessResult(
                    success=False,
                    return_code=-1,
                    stdout="",
                    stderr="",
                    execution_time=execution_time,
                    command=' '.join(command),
                    error_type="permission_denied",
                    error_message="Permission denied"
                )
                
            except Exception as e:
                execution_time = time.time() - start_time
                self.logger.error(f"Unexpected error executing sync command: {str(e)}")
                last_error = SubprocessResult(
                    success=False,
                    return_code=-1,
                    stdout="",
                    stderr="",
                    execution_time=execution_time,
                    command=' '.join(command),
                    error_type="unexpected_error",
                    error_message=str(e)
                )
            
            # Wait before retry
            if attempt < self.max_retries - 1:
                wait_time = 2 ** attempt
                self.logger.info(f"Retrying sync command in {wait_time}s...")
                time.sleep(wait_time)
        
        return last_error
    
    def check_command_exists(self, command: str) -> bool:
        """Check if a command exists in PATH"""
        try:
            result = subprocess.run(
                ['which', command],
                capture_output=True,
                text=True,
                timeout=10
            )
            return result.returncode == 0
        except:
            return False
    
    def get_command_version(self, command: str) -> Optional[str]:
        """Get version of a command if available"""
        try:
            result = subprocess.run(
                [command, '--version'],
                capture_output=True,
                text=True,
                timeout=30
            )
            if result.returncode == 0:
                return result.stdout.strip().split('\n')[0]
        except:
            pass
        return None

# Global instance for easy access
subprocess_handler = SubprocessHandler() 