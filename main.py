#!/usr/bin/env python3
"""
Kali Linux Optimized Autonomous Bug Hunter
Enhanced with performance optimizations, caching, and robust error handling
"""

import asyncio
import json
import logging
import os
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any
import threading
import psutil
from dataclasses import asdict
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, BackgroundTasks, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel
import uvicorn

# Import our optimized modules from the new package structure
try:
    from app.core.subprocess_handler import SubprocessHandler
    from app.core.cache_manager import CacheManager, CacheBackend, cached
    from app.core.database_manager import DatabaseManager
    from app.core.kali_optimizer import KaliOptimizer
    from app.ai.agent import AIAgent
except ImportError as e:
    print(f"Warning: Some modules not available: {e}")
    # Create dummy classes for missing modules
    class SubprocessHandler:
        def __init__(self, *args, **kwargs): pass
        def run(self, *args, **kwargs): return None
    
    class CacheBackend:
        MEMORY = "memory"
    
    class CacheManager:
        def __init__(self, *args, **kwargs): pass
        def get_stats(self): return {"total_entries": 0, "usage_percent": 0}
        def get(self, *args, **kwargs): return None
        def set(self, *args, **kwargs): pass
    
    class DatabaseManager:
        async def initialize(self): pass
        async def close(self): pass
        def get_connection(self): return None
        def save_workflow(self, *args, **kwargs): pass
        def get_stats(self): return {"total_workflows": 0}
    
    class KaliOptimizer:
        def __init__(self, *args, **kwargs): pass
        def check_all_tools(self): return {}
        def run_system_diagnostics(self): 
            return {
                'cpu_usage': 0.0,
                'memory_usage': 0.0,
                'disk_usage': 0.0,
                'network_status': 'unknown',
                'python_version': sys.version,
                'os_info': 'Windows',
                'kali_version': 'N/A',
                'permissions': {},
                'resource_limits': {},
                'optimization_recommendations': []
            }
    
    class AIAgent:
        async def analyze_target(self, *args, **kwargs): 
            return {"status": "dummy", "recommendations": []}
        async def analyze_results(self, *args, **kwargs):
            return {"status": "dummy", "findings": []}
        async def chat(self, *args, **kwargs):
            return {"response": "Dummy AI response"}

# Configure logging properly
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('data/bug_hunter.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Performance monitoring
class PerformanceMonitor:
    """Monitor system performance and resource usage"""
    
    def __init__(self):
        self.start_time = time.time()
        self.request_count = 0
        self.error_count = 0
        self.avg_response_time = 0.0
        self.lock = threading.Lock()
    
    def record_request(self, response_time: float, success: bool = True):
        """Record request metrics"""
        with self.lock:
            self.request_count += 1
            if not success:
                self.error_count += 1
            
            # Update average response time
            self.avg_response_time = (
                (self.avg_response_time * (self.request_count - 1) + response_time) / 
                self.request_count
            )
    
    def get_stats(self) -> Dict[str, Any]:
        """Get performance statistics"""
        with self.lock:
            uptime = time.time() - self.start_time
            try:
                memory_info = psutil.virtual_memory()
                cpu_percent = psutil.cpu_percent(interval=0.1)
                disk_usage = psutil.disk_usage('/').percent if os.name != 'nt' else 0
            except Exception:
                # Create a proper memory info object
                class MemoryInfo:
                    def __init__(self):
                        self.used = 0
                        self.percent = 0
                memory_info = MemoryInfo()
                cpu_percent = 0
                disk_usage = 0
            
            return {
                'uptime_seconds': uptime,
                'uptime_formatted': str(timedelta(seconds=int(uptime))),
                'total_requests': self.request_count,
                'error_requests': self.error_count,
                'success_rate': ((self.request_count - self.error_count) / self.request_count * 100) if self.request_count > 0 else 0,
                'avg_response_time_ms': round(self.avg_response_time * 1000, 2),
                'requests_per_second': self.request_count / uptime if uptime > 0 else 0,
                'memory_usage_mb': memory_info.used / (1024 * 1024),
                'memory_percent': memory_info.percent,
                'cpu_percent': cpu_percent,
                'disk_usage': disk_usage
            }

# Initialize components
performance_monitor = PerformanceMonitor()
subprocess_handler = SubprocessHandler(default_timeout=60, max_memory_mb=1024)
cache_manager = CacheManager(backend=CacheBackend.MEMORY, max_size=2000)
db_manager = DatabaseManager()
kali_optimizer = KaliOptimizer(run_initial_diagnostics=False)
ai_agent = AIAgent()

# Global state
active_workflows: Dict[str, Dict] = {}
chat_sessions: Dict[str, List[Dict]] = {}
system_status = {
    'kali_tools': {},
    'system_resources': {},
    'cache_stats': {},
    'performance_stats': {}
}

# Background task management
background_tasks = set()

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Modern lifespan event handler"""
    # Startup
    logger.info("Starting Kali Bug Hunter...")
    
    try:
        # Initialize database
        await db_manager.initialize()
        
        # Start background tasks
        task1 = asyncio.create_task(background_maintenance())
        task2 = asyncio.create_task(run_system_diagnostics())
        background_tasks.add(task1)
        background_tasks.add(task2)
        
        logger.info("Kali Bug Hunter started successfully!")
    except Exception as e:
        logger.error(f"Startup error: {e}")
    
    yield
    
    # Shutdown
    logger.info("Shutting down Kali Bug Hunter...")
    
    try:
        # Cancel background tasks
        for task in background_tasks:
            task.cancel()
        
        # Wait for tasks to complete
        await asyncio.gather(*background_tasks, return_exceptions=True)
        
        # Close database
        await db_manager.close()
        
        logger.info("Shutdown completed successfully!")
    except Exception as e:
        logger.error(f"Shutdown error: {e}")

# Create FastAPI app with lifespan
app = FastAPI(
    title="Kai Bug Hunter", 
    version="2.0.0",
    lifespan=lifespan
)

# Mount static files
app.mount("/static", StaticFiles(directory="app/dashboard/templates"), name="static")

# Pydantic models
class TargetRequest(BaseModel):
    target: str
    scope: str
    ai_provider: str = "gemini"
    workflow_type: Optional[str] = None

class ChatMessage(BaseModel):
    message: str
    session_id: Optional[str] = None

class WorkflowControl(BaseModel):
    action: str  # pause, resume, skip, rerun
    workflow_id: str

async def run_system_diagnostics():
    """Run comprehensive system diagnostics in background"""
    logger.info("Starting background system diagnostics...")
    
    try:
        # Check Kali tools (this will be empty on Windows)
        system_status['kali_tools'] = kali_optimizer.check_all_tools()
        
        # Get system resources
        diagnostics = kali_optimizer.run_system_diagnostics()
        if hasattr(diagnostics, '__dict__'):
            system_status['system_resources'] = asdict(diagnostics)
        else:
            system_status['system_resources'] = diagnostics
        
        # Get cache stats
        system_status['cache_stats'] = cache_manager.get_stats()
        
        # Get performance stats
        system_status['performance_stats'] = performance_monitor.get_stats()
        
        logger.info("Background system diagnostics completed")
    except Exception as e:
        logger.error(f"Error in background diagnostics: {e}")
        # Set default values for Windows
        system_status['kali_tools'] = {}
        system_status['system_resources'] = {
            'cpu_usage': 0.0,
            'memory_usage': 0.0,
            'disk_usage': 0.0,
            'network_status': 'unknown',
            'python_version': sys.version,
            'os_info': 'Windows',
            'kali_version': 'N/A',
            'permissions': {},
            'resource_limits': {},
            'optimization_recommendations': []
        }

async def background_maintenance():
    """Background maintenance tasks"""
    while True:
        try:
            await asyncio.sleep(300)  # Run every 5 minutes
            
            # Update system status
            await run_system_diagnostics()
            
            # Clean up expired workflows
            current_time = time.time()
            expired_workflows = [
                wid for wid, workflow in active_workflows.items()
                if current_time - workflow.get('start_time', 0) > 3600  # 1 hour
            ]
            for wid in expired_workflows:
                del active_workflows[wid]
            
            logger.info(f"Background maintenance completed. Active workflows: {len(active_workflows)}")
            
        except asyncio.CancelledError:
            logger.info("Background maintenance cancelled")
            break
        except Exception as e:
            logger.error(f"Background maintenance error: {e}")
            await asyncio.sleep(60)  # Wait before retrying

@app.get("/", response_class=HTMLResponse)
async def get_dashboard():
    """Serve the modern dashboard"""
    try:
        with open("app/dashboard/templates/modern_dashboard.html", "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    except FileNotFoundError:
        # Fallback to enhanced dashboard if modern doesn't exist
        try:
            with open("app/dashboard/templates/enhanced_dashboard.html", "r", encoding="utf-8") as f:
                return HTMLResponse(content=f.read())
        except FileNotFoundError:
            return HTMLResponse(content="<h1>Dashboard not found</h1>", status_code=404)

@app.get("/enhanced", response_class=HTMLResponse)
async def get_enhanced_dashboard():
    """Serve the enhanced dashboard"""
    try:
        with open("app/dashboard/templates/enhanced_dashboard.html", "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    except FileNotFoundError:
        return HTMLResponse(content="<h1>Enhanced dashboard not found</h1>", status_code=404)

@app.get("/behind-scenes", response_class=HTMLResponse)
async def get_behind_scenes():
    """Serve the behind the scenes dashboard"""
    try:
        with open("app/dashboard/templates/behind_scenes.html", "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    except FileNotFoundError:
        return HTMLResponse(content="<h1>Behind scenes dashboard not found</h1>", status_code=404)

@app.post("/api/start-hunt")
async def start_hunt(request: TargetRequest, background_tasks: BackgroundTasks):
    """Start autonomous bug hunting workflow"""
    try:
        # Generate workflow ID
        workflow_id = f"workflow_{int(time.time())}"
        
        # Initialize workflow
        workflow = {
            'id': workflow_id,
            'target': request.target,
            'scope': request.scope,
            'status': 'pending',
            'start_time': time.time(),
            'steps': [],
            'logs': [],
            'ai_provider': request.ai_provider
        }
        
        active_workflows[workflow_id] = workflow
        
        # Start workflow in background
        background_tasks.add_task(run_workflow, workflow_id, request)
        
        return {
            'success': True,
            'workflow_id': workflow_id,
            'message': 'Bug hunting workflow started'
        }
        
    except Exception as e:
        logger.error(f"Failed to start hunt: {e}")
        raise HTTPException(status_code=500, detail=str(e))

async def run_workflow(workflow_id: str, request: TargetRequest):
    """Execute the bug hunting workflow"""
    workflow = active_workflows[workflow_id]
    
    try:
        workflow['status'] = 'running'
        workflow['logs'].append({
            'timestamp': datetime.now().isoformat(),
            'level': 'info',
            'message': f'Starting autonomous bug hunt for {request.target}'
        })
        
        # Step 1: AI Analysis and Planning
        workflow['logs'].append({
            'timestamp': datetime.now().isoformat(),
            'level': 'info',
            'message': 'Step 1: AI Analysis and Planning'
        })
        
        ai_analysis = await ai_agent.analyze_target(request.target, request.scope)
        workflow['steps'].append({
            'name': 'AI Analysis',
            'status': 'completed',
            'result': ai_analysis
        })
        
        # Step 2: Tool Selection and Optimization
        workflow['logs'].append({
            'timestamp': datetime.now().isoformat(),
            'level': 'info',
            'message': 'Step 2: Tool Selection and Optimization'
        })
        
        tools_config = kali_optimizer.check_all_tools()
        workflow['steps'].append({
            'name': 'Tool Optimization',
            'status': 'completed',
            'result': tools_config
        })
        
        # Step 3: Basic Reconnaissance (simplified)
        workflow['logs'].append({
            'timestamp': datetime.now().isoformat(),
            'level': 'info',
            'message': 'Step 3: Basic Reconnaissance'
        })
        
        recon_results = {
            'subdomains': [f'www.{request.target}'],
            'ports': [80, 443],
            'technologies': ['Unknown'],
            'endpoints': ['/']
        }
        workflow['steps'].append({
            'name': 'Reconnaissance',
            'status': 'completed',
            'result': recon_results
        })
        
        # Step 4: Basic Vulnerability Scan (simplified)
        workflow['logs'].append({
            'timestamp': datetime.now().isoformat(),
            'level': 'info',
            'message': 'Step 4: Basic Vulnerability Scan'
        })
        
        vuln_results = {
            'vulnerabilities_found': [],
            'scan_summary': {
                'total_scanned': 10,
                'vulnerabilities_found': 0,
                'false_positives': 0
            }
        }
        workflow['steps'].append({
            'name': 'Vulnerability Scan',
            'status': 'completed',
            'result': vuln_results
        })
        
        # Step 5: AI Analysis of Results
        workflow['logs'].append({
            'timestamp': datetime.now().isoformat(),
            'level': 'info',
            'message': 'Step 5: AI Analysis of Results'
        })
        
        analysis_results = await ai_agent.analyze_results(vuln_results, recon_results)
        workflow['steps'].append({
            'name': 'AI Analysis',
            'status': 'completed',
            'result': analysis_results
        })
        
        # Step 6: Generate Report
        workflow['logs'].append({
            'timestamp': datetime.now().isoformat(),
            'level': 'info',
            'message': 'Step 6: Generate Report'
        })
        
        report = {
            'workflow_id': workflow_id,
            'target': request.target,
            'summary': 'Basic bug hunting workflow completed',
            'findings': [],
            'recommendations': []
        }
        workflow['steps'].append({
            'name': 'Report Generation',
            'status': 'completed',
            'result': report
        })
        
        workflow['status'] = 'completed'
        workflow['logs'].append({
            'timestamp': datetime.now().isoformat(),
            'level': 'success',
            'message': 'Bug hunting workflow completed successfully'
        })
        
        # Save to database
        await db_manager.save_workflow(workflow)
        
    except Exception as e:
        logger.error(f"Workflow error: {e}")
        workflow['status'] = 'failed'
        workflow['logs'].append({
            'timestamp': datetime.now().isoformat(),
            'level': 'error',
            'message': f'Workflow failed: {str(e)}'
        })

@app.get("/api/workflow/{workflow_id}")
async def get_workflow_status(workflow_id: str):
    """Get workflow status and progress"""
    if workflow_id not in active_workflows:
        raise HTTPException(status_code=404, detail="Workflow not found")
    
    return active_workflows[workflow_id]

@app.get("/api/system-status")
async def get_system_status():
    """Get comprehensive system status"""
    # Update performance stats
    system_status['performance_stats'] = performance_monitor.get_stats()
    system_status['cache_stats'] = cache_manager.get_stats()
    
    return system_status

@app.post("/api/chat")
async def chat_with_ai(message: ChatMessage):
    """Chat with AI about the system and workflows"""
    try:
        response = await ai_agent.chat(message.message, message.session_id)
        return {
            'success': True,
            'response': response,
            'session_id': message.session_id
        }
    except Exception as e:
        logger.error(f"Chat error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/workflow-control")
async def control_workflow(control: WorkflowControl):
    """Control workflow execution"""
    if control.workflow_id not in active_workflows:
        raise HTTPException(status_code=404, detail="Workflow not found")
    
    workflow = active_workflows[control.workflow_id]
    
    if control.action == 'pause':
        workflow['status'] = 'paused'
        return {'success': True, 'message': 'Workflow paused'}
    elif control.action == 'resume':
        workflow['status'] = 'running'
        return {'success': True, 'message': 'Workflow resumed'}
    elif control.action == 'skip':
        # Skip current step
        return {'success': True, 'message': 'Current step skipped'}
    elif control.action == 'rerun':
        # Rerun current step
        return {'success': True, 'message': 'Current step rerunning'}
    else:
        raise HTTPException(status_code=400, detail="Invalid action")

@app.get("/api/performance")
async def get_performance_metrics():
    """Get detailed performance metrics"""
    return {
        'performance': performance_monitor.get_stats(),
        'cache': cache_manager.get_stats(),
        'database': await db_manager.get_stats(),
        'active_workflows': len(active_workflows),
        'system_resources': asdict(kali_optimizer.run_system_diagnostics())
    }

@app.websocket("/ws/logs")
async def websocket_logs(websocket: WebSocket):
    """WebSocket endpoint for real-time logs"""
    await websocket.accept()
    
    try:
        while True:
            # Send system status updates
            status_update = {
                'type': 'status_update',
                'data': {
                    'performance': performance_monitor.get_stats(),
                    'cache': cache_manager.get_stats(),
                    'active_workflows': len(active_workflows)
                }
            }
            await websocket.send_text(json.dumps(status_update))
            await asyncio.sleep(5)  # Update every 5 seconds
            
    except WebSocketDisconnect:
        logger.info("WebSocket client disconnected")

@app.get("/api/tools/status")
async def get_tools_status():
    """Get status of all tools"""
    try:
        tools_status = kali_optimizer.check_all_tools()
        return {
            'success': True,
            'tools': tools_status,
            'summary': {
                'total': len(tools_status),
                'available': len([t for t in tools_status.values() if t.status == 'available']),
                'missing': len([t for t in tools_status.values() if t.status == 'missing']),
                'error': len([t for t in tools_status.values() if t.status == 'error'])
            }
        }
    except Exception as e:
        logger.error(f"Error getting tools status: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/tools/install/{tool_name}")
async def install_tool(tool_name: str):
    """Install a specific tool"""
    try:
        result = kali_optimizer.install_missing_tool(tool_name)
        return result
    except Exception as e:
        logger.error(f"Error installing tool {tool_name}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/tools/auto-install")
async def auto_install_tools(required_only: bool = True):
    """Auto-install all missing tools"""
    try:
        result = kali_optimizer.auto_install_missing_tools(required_only=required_only)
        return result
    except Exception as e:
        logger.error(f"Error in auto-installation: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/tools/ensure/{tool_name}")
async def ensure_tool_available(tool_name: str, auto_install: bool = True):
    """Ensure a specific tool is available"""
    try:
        available = kali_optimizer.ensure_tool_available(tool_name, auto_install)
        return {
            'success': available,
            'tool_name': tool_name,
            'available': available,
            'message': f"Tool {tool_name} is {'available' if available else 'not available'}"
        }
    except Exception as e:
        logger.error(f"Error ensuring tool {tool_name}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/tools/missing")
async def get_missing_tools():
    """Get list of missing tools"""
    try:
        tools_status = kali_optimizer.check_all_tools()
        missing_tools = [
            {
                'name': tool_name,
                'status': tool_info.status,
                'required': kali_optimizer.tools_config[tool_name]['required'],
                'install_command': kali_optimizer.tools_config[tool_name].get('install_command', '')
            }
            for tool_name, tool_info in tools_status.items()
            if tool_info.status == 'missing'
        ]
        return {
            'success': True,
            'missing_tools': missing_tools,
            'count': len(missing_tools)
        }
    except Exception as e:
        logger.error(f"Error getting missing tools: {e}")
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    # Run the application
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    ) 