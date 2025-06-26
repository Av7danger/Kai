"""
Web Dashboard for Enhanced Bug Bounty Framework
FastAPI-based web interface for monitoring and managing scans
"""

from fastapi import FastAPI, HTTPException, BackgroundTasks, Depends, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
from typing import Dict, List, Optional, Any
import asyncio
import json
import logging
import uuid
from datetime import datetime, timedelta
from pathlib import Path
import os

# Import our enhanced framework components
from enhanced_integration import enhanced_framework, enhanced_target_analysis, enhanced_comprehensive_scan
from real_security_tools import comprehensive_security_scan, security_tools
from optimization_manager import optimization_manager

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("dashboard")

# Initialize FastAPI app
app = FastAPI(
    title="Enhanced Bug Bounty Framework Dashboard",
    description="Web interface for managing and monitoring security scans",
    version="2.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc"
)

# Security
security = HTTPBearer()

# Static files and templates
static_dir = Path(__file__).parent / "static"
templates_dir = Path(__file__).parent / "templates"

# Create directories if they don't exist
static_dir.mkdir(exist_ok=True)
templates_dir.mkdir(exist_ok=True)

app.mount("/static", StaticFiles(directory=static_dir), name="static")
templates = Jinja2Templates(directory=templates_dir)

# Global state management
class DashboardState:
    def __init__(self):
        self.active_scans: Dict[str, Dict] = {}
        self.completed_scans: Dict[str, Dict] = {}
        self.scan_history: List[Dict] = []
        self.connected_clients: List[WebSocket] = []
        self.system_stats = {
            'uptime': datetime.now(),
            'total_scans': 0,
            'active_scan_count': 0,
            'success_rate': 0.0
        }

dashboard_state = DashboardState()

# Pydantic models for API
class ScanRequest(BaseModel):
    target: str = Field(..., description="Target domain or URL to scan")
    scope: Optional[Dict[str, Any]] = Field(None, description="Scan scope configuration")
    scan_type: str = Field("comprehensive", description="Type of scan to perform")
    tools: Optional[List[str]] = Field(None, description="Specific tools to use")
    severity_filter: Optional[List[str]] = Field(["medium", "high", "critical"], description="Vulnerability severity filter")

class ScanResponse(BaseModel):
    scan_id: str
    status: str
    message: str
    estimated_time: Optional[int] = None

class ScanStatus(BaseModel):
    scan_id: str
    status: str
    progress: float
    current_phase: str
    start_time: datetime
    estimated_completion: Optional[datetime] = None
    results_summary: Optional[Dict[str, Any]] = None

class SystemStats(BaseModel):
    uptime: str
    total_scans: int
    active_scans: int
    success_rate: float
    cpu_usage: float
    memory_usage: float
    cache_hit_ratio: float

# WebSocket connection manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info(f"WebSocket client connected. Total: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
        logger.info(f"WebSocket client disconnected. Total: {len(self.active_connections)}")

    async def send_personal_message(self, message: dict, websocket: WebSocket):
        try:
            await websocket.send_text(json.dumps(message))
        except:
            self.disconnect(websocket)

    async def broadcast(self, message: dict):
        disconnected = []
        for connection in self.active_connections:
            try:
                await connection.send_text(json.dumps(message))
            except:
                disconnected.append(connection)
        
        # Remove disconnected clients
        for conn in disconnected:
            self.disconnect(conn)

manager = ConnectionManager()

# Authentication (basic implementation)
async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    # In production, implement proper JWT validation
    token = credentials.credentials
    if token != "demo-token":  # Replace with proper authentication
        raise HTTPException(status_code=401, detail="Invalid authentication credentials")
    return {"username": "demo_user"}

# API Routes

@app.get("/", response_class=HTMLResponse)
async def dashboard_home():
    """Main dashboard page"""
    return """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Enhanced Bug Bounty Framework Dashboard</title>
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <script src="https://unpkg.com/alpinejs@3.x.x/dist/cdn.min.js" defer></script>
        <script src="https://cdn.tailwindcss.com"></script>
        <style>
            .scan-card { transition: all 0.3s ease; }
            .scan-card:hover { transform: translateY(-2px); box-shadow: 0 4px 12px rgba(0,0,0,0.15); }
            .status-running { color: #3B82F6; }
            .status-completed { color: #10B981; }
            .status-failed { color: #EF4444; }
        </style>
    </head>
    <body class="bg-gray-100 min-h-screen">
        <div x-data="dashboardApp()" x-init="init()">
            <!-- Header -->
            <header class="bg-white shadow-sm border-b border-gray-200">
                <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
                    <div class="flex justify-between items-center py-4">
                        <div class="flex items-center">
                            <h1 class="text-2xl font-bold text-gray-900">🛡️ Bug Bounty Framework</h1>
                            <span class="ml-3 px-2 py-1 bg-green-100 text-green-800 text-xs font-semibold rounded-full">v2.0 Enhanced</span>
                        </div>
                        <div class="flex items-center space-x-4">
                            <div class="text-sm text-gray-500">
                                <span x-text="'Active Scans: ' + stats.active_scans"></span>
                            </div>
                            <div class="text-sm text-gray-500">
                                <span x-text="'Success Rate: ' + stats.success_rate + '%'"></span>
                            </div>
                        </div>
                    </div>
                </div>
            </header>

            <!-- Main Content -->
            <main class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
                <!-- Stats Cards -->
                <div class="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
                    <div class="bg-white p-6 rounded-lg shadow">
                        <div class="flex items-center">
                            <div class="flex-shrink-0">
                                <div class="w-8 h-8 bg-blue-500 rounded-md flex items-center justify-center">
                                    <span class="text-white text-sm font-bold">📊</span>
                                </div>
                            </div>
                            <div class="ml-4">
                                <p class="text-sm font-medium text-gray-500">Total Scans</p>
                                <p class="text-2xl font-semibold text-gray-900" x-text="stats.total_scans">0</p>
                            </div>
                        </div>
                    </div>
                    
                    <div class="bg-white p-6 rounded-lg shadow">
                        <div class="flex items-center">
                            <div class="flex-shrink-0">
                                <div class="w-8 h-8 bg-green-500 rounded-md flex items-center justify-center">
                                    <span class="text-white text-sm font-bold">⚡</span>
                                </div>
                            </div>
                            <div class="ml-4">
                                <p class="text-sm font-medium text-gray-500">Active Scans</p>
                                <p class="text-2xl font-semibold text-gray-900" x-text="stats.active_scans">0</p>
                            </div>
                        </div>
                    </div>
                    
                    <div class="bg-white p-6 rounded-lg shadow">
                        <div class="flex items-center">
                            <div class="flex-shrink-0">
                                <div class="w-8 h-8 bg-purple-500 rounded-md flex items-center justify-center">
                                    <span class="text-white text-sm font-bold">🧠</span>
                                </div>
                            </div>
                            <div class="ml-4">
                                <p class="text-sm font-medium text-gray-500">Cache Hit Ratio</p>
                                <p class="text-2xl font-semibold text-gray-900" x-text="stats.cache_hit_ratio + '%'">0%</p>
                            </div>
                        </div>
                    </div>
                    
                    <div class="bg-white p-6 rounded-lg shadow">
                        <div class="flex items-center">
                            <div class="flex-shrink-0">
                                <div class="w-8 h-8 bg-red-500 rounded-md flex items-center justify-center">
                                    <span class="text-white text-sm font-bold">💾</span>
                                </div>
                            </div>
                            <div class="ml-4">
                                <p class="text-sm font-medium text-gray-500">Memory Usage</p>
                                <p class="text-2xl font-semibold text-gray-900" x-text="stats.memory_usage + '%'">0%</p>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Scan Form -->
                <div class="bg-white p-6 rounded-lg shadow mb-8">
                    <h2 class="text-lg font-semibold text-gray-900 mb-4">🎯 Start New Scan</h2>
                    <form @submit.prevent="startScan()">
                        <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
                            <div>
                                <label class="block text-sm font-medium text-gray-700 mb-2">Target</label>
                                <input 
                                    x-model="newScan.target" 
                                    type="text" 
                                    placeholder="example.com or https://example.com"
                                    class="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                                    required
                                >
                            </div>
                            <div>
                                <label class="block text-sm font-medium text-gray-700 mb-2">Scan Type</label>
                                <select 
                                    x-model="newScan.scan_type"
                                    class="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                                >
                                    <option value="comprehensive">Comprehensive</option>
                                    <option value="quick">Quick Scan</option>
                                    <option value="deep">Deep Scan</option>
                                </select>
                            </div>
                            <div>
                                <label class="block text-sm font-medium text-gray-700 mb-2">Severity Filter</label>
                                <select 
                                    x-model="newScan.severity"
                                    class="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                                >
                                    <option value="all">All Severities</option>
                                    <option value="high">High & Critical</option>
                                    <option value="medium">Medium & Above</option>
                                </select>
                            </div>
                        </div>
                        <div class="mt-4">
                            <button 
                                type="submit"
                                :disabled="scanning"
                                class="px-6 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed"
                            >
                                <span x-show="!scanning">🚀 Start Scan</span>
                                <span x-show="scanning">⏳ Starting...</span>
                            </button>
                        </div>
                    </form>
                </div>

                <!-- Active Scans -->
                <div class="bg-white p-6 rounded-lg shadow mb-8" x-show="Object.keys(activeScans).length > 0">
                    <h2 class="text-lg font-semibold text-gray-900 mb-4">⚡ Active Scans</h2>
                    <div class="space-y-4">
                        <template x-for="(scan, scanId) in activeScans" :key="scanId">
                            <div class="border border-gray-200 rounded-lg p-4 scan-card">
                                <div class="flex justify-between items-start mb-2">
                                    <div>
                                        <h3 class="font-medium text-gray-900" x-text="scan.target"></h3>
                                        <p class="text-sm text-gray-500" x-text="scan.current_phase"></p>
                                    </div>
                                    <span class="px-2 py-1 bg-blue-100 text-blue-800 text-xs font-semibold rounded-full status-running">
                                        Running
                                    </span>
                                </div>
                                <div class="w-full bg-gray-200 rounded-full h-2 mb-2">
                                    <div class="bg-blue-600 h-2 rounded-full transition-all duration-300" :style="'width: ' + scan.progress + '%'"></div>
                                </div>
                                <div class="flex justify-between text-xs text-gray-500">
                                    <span x-text="'Progress: ' + scan.progress + '%'"></span>
                                    <span x-text="'Started: ' + new Date(scan.start_time).toLocaleTimeString()"></span>
                                </div>
                            </div>
                        </template>
                    </div>
                </div>

                <!-- Recent Scans -->
                <div class="bg-white p-6 rounded-lg shadow">
                    <h2 class="text-lg font-semibold text-gray-900 mb-4">📋 Recent Scans</h2>
                    <div class="space-y-4" x-show="recentScans.length > 0">
                        <template x-for="scan in recentScans" :key="scan.id">
                            <div class="border border-gray-200 rounded-lg p-4 scan-card">
                                <div class="flex justify-between items-start">
                                    <div>
                                        <h3 class="font-medium text-gray-900" x-text="scan.target"></h3>
                                        <p class="text-sm text-gray-500" x-text="'Completed: ' + new Date(scan.completed_at).toLocaleString()"></p>
                                        <div class="mt-2 flex space-x-4 text-xs text-gray-600" x-show="scan.results">
                                            <span x-text="'Subdomains: ' + (scan.results.subdomain_count || 0)"></span>
                                            <span x-text="'Live Hosts: ' + (scan.results.live_host_count || 0)"></span>
                                            <span x-text="'Vulnerabilities: ' + (scan.results.vulnerability_count || 0)"></span>
                                        </div>
                                    </div>
                                    <div class="flex items-center space-x-2">
                                        <span class="px-2 py-1 text-xs font-semibold rounded-full"
                                              :class="scan.status === 'completed' ? 'bg-green-100 text-green-800 status-completed' : 'bg-red-100 text-red-800 status-failed'"
                                              x-text="scan.status">
                                        </span>
                                        <button 
                                            @click="viewReport(scan.id)"
                                            class="px-3 py-1 bg-gray-100 text-gray-700 rounded text-xs hover:bg-gray-200"
                                        >
                                            View Report
                                        </button>
                                    </div>
                                </div>
                            </div>
                        </template>
                    </div>
                    <div x-show="recentScans.length === 0" class="text-center text-gray-500 py-8">
                        No recent scans found. Start your first scan above! 🚀
                    </div>
                </div>
            </main>
        </div>

        <script>
            function dashboardApp() {
                return {
                    stats: {
                        total_scans: 0,
                        active_scans: 0,
                        success_rate: 0,
                        cache_hit_ratio: 0,
                        memory_usage: 0
                    },
                    activeScans: {},
                    recentScans: [],
                    newScan: {
                        target: '',
                        scan_type: 'comprehensive',
                        severity: 'medium'
                    },
                    scanning: false,
                    websocket: null,

                    init() {
                        this.connectWebSocket();
                        this.loadStats();
                        this.loadRecentScans();
                        
                        // Refresh data every 30 seconds
                        setInterval(() => {
                            this.loadStats();
                            this.loadRecentScans();
                        }, 30000);
                    },

                    connectWebSocket() {
                        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
                        this.websocket = new WebSocket(`${protocol}//${window.location.host}/ws`);
                        
                        this.websocket.onmessage = (event) => {
                            const data = JSON.parse(event.data);
                            this.handleWebSocketMessage(data);
                        };
                        
                        this.websocket.onclose = () => {
                            // Reconnect after 5 seconds
                            setTimeout(() => this.connectWebSocket(), 5000);
                        };
                    },

                    handleWebSocketMessage(data) {
                        if (data.type === 'scan_update') {
                            this.activeScans[data.scan_id] = data.scan_data;
                        } else if (data.type === 'scan_completed') {
                            delete this.activeScans[data.scan_id];
                            this.loadRecentScans();
                        } else if (data.type === 'stats_update') {
                            this.stats = data.stats;
                        }
                    },

                    async loadStats() {
                        try {
                            const response = await fetch('/api/stats');
                            this.stats = await response.json();
                        } catch (error) {
                            console.error('Failed to load stats:', error);
                        }
                    },

                    async loadRecentScans() {
                        try {
                            const response = await fetch('/api/scans/recent');
                            this.recentScans = await response.json();
                        } catch (error) {
                            console.error('Failed to load recent scans:', error);
                        }
                    },

                    async startScan() {
                        if (!this.newScan.target) return;
                        
                        this.scanning = true;
                        
                        try {
                            const response = await fetch('/api/scans/start', {
                                method: 'POST',
                                headers: {
                                    'Content-Type': 'application/json'
                                },
                                body: JSON.stringify({
                                    target: this.newScan.target,
                                    scan_type: this.newScan.scan_type,
                                    severity_filter: this.newScan.severity === 'all' ? null : [this.newScan.severity, 'high', 'critical']
                                })
                            });
                            
                            const result = await response.json();
                            
                            if (response.ok) {
                                // Reset form
                                this.newScan.target = '';
                                alert(`Scan started successfully! ID: ${result.scan_id}`);
                            } else {
                                alert(`Failed to start scan: ${result.message}`);
                            }
                        } catch (error) {
                            alert(`Error starting scan: ${error.message}`);
                        } finally {
                            this.scanning = false;
                        }
                    },

                    viewReport(scanId) {
                        window.open(`/api/scans/${scanId}/report`, '_blank');
                    }
                }
            }
        </script>
    </body>
    </html>
    """

@app.get("/api/stats", response_model=SystemStats)
async def get_system_stats():
    """Get current system statistics"""
    try:
        # Get optimization stats
        opt_stats = optimization_manager.get_comprehensive_stats()
        
        # Calculate uptime
        uptime_delta = datetime.now() - dashboard_state.system_stats['uptime']
        uptime_str = str(uptime_delta).split('.')[0]  # Remove microseconds
        
        # Get resource usage (mock data if psutil not available)
        try:
            import psutil
            cpu_usage = psutil.cpu_percent()
            memory_usage = psutil.virtual_memory().percent
        except ImportError:
            cpu_usage = 25.0  # Mock data
            memory_usage = 45.0  # Mock data
        
        stats = SystemStats(
            uptime=uptime_str,
            total_scans=dashboard_state.system_stats['total_scans'],
            active_scans=len(dashboard_state.active_scans),
            success_rate=dashboard_state.system_stats['success_rate'],
            cpu_usage=cpu_usage,
            memory_usage=memory_usage,
            cache_hit_ratio=opt_stats.get('cache_stats', {}).get('hit_ratio', 0) * 100
        )
        
        return stats
        
    except Exception as e:
        logger.error(f"Error getting system stats: {e}")
        raise HTTPException(status_code=500, detail="Failed to get system stats")

@app.post("/api/scans/start", response_model=ScanResponse)
async def start_scan(scan_request: ScanRequest, background_tasks: BackgroundTasks):
    """Start a new security scan"""
    try:
        # Generate unique scan ID
        scan_id = str(uuid.uuid4())
        
        # Validate target
        if not scan_request.target:
            raise HTTPException(status_code=400, detail="Target is required")
        
        # Create scan record
        scan_record = {
            'id': scan_id,
            'target': scan_request.target,
            'scan_type': scan_request.scan_type,
            'status': 'starting',
            'progress': 0,
            'current_phase': 'Initializing',
            'start_time': datetime.now(),
            'severity_filter': scan_request.severity_filter
        }
        
        dashboard_state.active_scans[scan_id] = scan_record
        dashboard_state.system_stats['total_scans'] += 1
        
        # Start scan in background
        background_tasks.add_task(execute_scan, scan_id, scan_request)
        
        # Broadcast scan start
        await manager.broadcast({
            'type': 'scan_started',
            'scan_id': scan_id,
            'scan_data': scan_record
        })
        
        return ScanResponse(
            scan_id=scan_id,
            status="started",
            message=f"Scan started for {scan_request.target}",
            estimated_time=300  # 5 minutes estimate
        )
        
    except Exception as e:
        logger.error(f"Error starting scan: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to start scan: {str(e)}")

@app.get("/api/scans/recent")
async def get_recent_scans(limit: int = 10):
    """Get recent completed scans"""
    try:
        # Sort by completion time and limit results
        recent = sorted(
            dashboard_state.scan_history, 
            key=lambda x: x.get('completed_at', ''), 
            reverse=True
        )[:limit]
        
        return recent
        
    except Exception as e:
        logger.error(f"Error getting recent scans: {e}")
        raise HTTPException(status_code=500, detail="Failed to get recent scans")

@app.get("/api/scans/{scan_id}/status", response_model=ScanStatus)
async def get_scan_status(scan_id: str):
    """Get status of a specific scan"""
    try:
        # Check active scans first
        if scan_id in dashboard_state.active_scans:
            scan = dashboard_state.active_scans[scan_id]
            return ScanStatus(**scan)
        
        # Check completed scans
        for completed_scan in dashboard_state.scan_history:
            if completed_scan['id'] == scan_id:
                return ScanStatus(
                    scan_id=scan_id,
                    status=completed_scan['status'],
                    progress=100,
                    current_phase='Completed',
                    start_time=completed_scan['start_time'],
                    results_summary=completed_scan.get('results')
                )
        
        raise HTTPException(status_code=404, detail="Scan not found")
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting scan status: {e}")
        raise HTTPException(status_code=500, detail="Failed to get scan status")

@app.get("/api/scans/{scan_id}/report")
async def get_scan_report(scan_id: str):
    """Get detailed report for a completed scan"""
    try:
        # Find completed scan
        scan = None
        for completed_scan in dashboard_state.scan_history:
            if completed_scan['id'] == scan_id:
                scan = completed_scan
                break
        
        if not scan:
            raise HTTPException(status_code=404, detail="Scan report not found")
        
        # Return HTML report or JSON based on Accept header
        return JSONResponse(scan.get('detailed_results', {}))
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting scan report: {e}")
        raise HTTPException(status_code=500, detail="Failed to get scan report")

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for real-time updates"""
    await manager.connect(websocket)
    try:
        while True:
            # Keep connection alive
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)

# Background task for executing scans
async def execute_scan(scan_id: str, scan_request: ScanRequest):
    """Execute a security scan in the background"""
    try:
        logger.info(f"Starting scan {scan_id} for target {scan_request.target}")
        
        # Update scan status
        await update_scan_progress(scan_id, 10, "Target Analysis")
        
        # Phase 1: Target Analysis
        target_analysis = await enhanced_target_analysis(
            scan_request.target, 
            scan_request.scope
        )
        
        await update_scan_progress(scan_id, 30, "Reconnaissance")
        
        # Phase 2: Comprehensive Scan
        if scan_request.scan_type == "comprehensive":
            scan_results = await enhanced_comprehensive_scan(scan_request.target, scan_request.scope)
        else:
            # Use real security tools for quick/deep scans
            scan_config = {
                'run_nuclei': scan_request.scan_type == "deep",
                'nuclei_severity': scan_request.severity_filter or ['medium', 'high', 'critical'],
                'max_nuclei_targets': 10 if scan_request.scan_type == "quick" else 50
            }
            scan_results = await comprehensive_security_scan(scan_request.target, scan_config)
        
        await update_scan_progress(scan_id, 70, "Vulnerability Analysis")
        
        # Phase 3: Generate Report
        if 'summary' in scan_results:
            results_summary = scan_results['summary'].data
        else:
            results_summary = {
                'subdomain_count': 0,
                'live_host_count': 0,
                'vulnerability_count': 0
            }
        
        await update_scan_progress(scan_id, 90, "Generating Report")
        
        # Complete scan
        await complete_scan(scan_id, "completed", results_summary, scan_results)
        
        logger.info(f"Scan {scan_id} completed successfully")
        
    except Exception as e:
        logger.error(f"Scan {scan_id} failed: {e}")
        await complete_scan(scan_id, "failed", {}, {'error': str(e)})

async def update_scan_progress(scan_id: str, progress: int, phase: str):
    """Update scan progress and broadcast to clients"""
    if scan_id in dashboard_state.active_scans:
        dashboard_state.active_scans[scan_id]['progress'] = progress
        dashboard_state.active_scans[scan_id]['current_phase'] = phase
        
        await manager.broadcast({
            'type': 'scan_update',
            'scan_id': scan_id,
            'scan_data': dashboard_state.active_scans[scan_id]
        })

async def complete_scan(scan_id: str, status: str, results_summary: Dict, detailed_results: Dict):
    """Complete a scan and move it to history"""
    if scan_id in dashboard_state.active_scans:
        scan_record = dashboard_state.active_scans[scan_id].copy()
        scan_record.update({
            'status': status,
            'progress': 100,
            'completed_at': datetime.now().isoformat(),
            'results': results_summary,
            'detailed_results': detailed_results
        })
        
        # Move to history
        dashboard_state.scan_history.append(scan_record)
        del dashboard_state.active_scans[scan_id]
        
        # Update success rate
        completed_scans = len(dashboard_state.scan_history)
        successful_scans = len([s for s in dashboard_state.scan_history if s['status'] == 'completed'])
        dashboard_state.system_stats['success_rate'] = (successful_scans / completed_scans * 100) if completed_scans > 0 else 0
        
        # Broadcast completion
        await manager.broadcast({
            'type': 'scan_completed',
            'scan_id': scan_id,
            'status': status
        })

# Health check endpoint
@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}

if __name__ == "__main__":
    import uvicorn
    
    print("🚀 Starting Enhanced Bug Bounty Framework Dashboard")
    print("📊 Dashboard will be available at: http://localhost:8000")
    print("📚 API Documentation: http://localhost:8000/api/docs")
    
    uvicorn.run(
        "web_dashboard:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
