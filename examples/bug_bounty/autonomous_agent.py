"""
Autonomous Bug Bounty Agent System
Fully autonomous bug bounty hunting with intelligent scope management,
adaptive workflows, and comprehensive process handling
"""

import asyncio
import json
import logging
import time
import traceback
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
import yaml
import hashlib
import threading
from concurrent.futures import ThreadPoolExecutor
import signal
import sys

from dotenv import load_dotenv
from gemini_bug_bounty_agent import BugBountyAgent

load_dotenv()

class Priority(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class TaskStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"
    RETRYING = "retrying"

@dataclass
class ScopeConfig:
    """Bug bounty scope configuration"""
    targets: List[str]
    in_scope: List[str]
    out_of_scope: List[str]
    allowed_methods: List[str]
    forbidden_paths: List[str]
    rate_limit: int = 10
    max_depth: int = 3
    timeout: int = 3600
    business_hours_only: bool = False
    safe_mode: bool = True
    
    def is_in_scope(self, target: str) -> bool:
        """Check if target is within scope"""
        for allowed in self.in_scope:
            if self._matches_pattern(target, allowed):
                for forbidden in self.out_of_scope:
                    if self._matches_pattern(target, forbidden):
                        return False
                return True
        return False
    
    def _matches_pattern(self, target: str, pattern: str) -> bool:
        """Check if target matches scope pattern"""
        import re
        # Convert wildcard patterns to regex
        pattern = pattern.replace("*", ".*").replace("?", ".")
        return bool(re.match(f"^{pattern}$", target, re.IGNORECASE))

@dataclass
class BugReport:
    """Bug bounty finding structure"""
    id: str
    title: str
    description: str
    severity: Priority
    cvss_score: float
    target: str
    endpoint: str
    vulnerability_type: str
    proof_of_concept: str
    impact: str
    remediation: str
    references: List[str]
    discovered_at: str
    confidence: float
    false_positive_probability: float
    
    def to_markdown(self) -> str:
        """Convert bug report to markdown format"""
        return f"""# {self.title}

**Severity:** {self.severity.value.upper()}
**CVSS Score:** {self.cvss_score}
**Target:** {self.target}
**Endpoint:** {self.endpoint}
**Type:** {self.vulnerability_type}
**Confidence:** {self.confidence:.2%}

## Description
{self.description}

## Proof of Concept
```
{self.proof_of_concept}
```

## Impact
{self.impact}

## Remediation
{self.remediation}

## References
{chr(10).join(f"- {ref}" for ref in self.references)}

---
*Discovered: {self.discovered_at}*
*Report ID: {self.id}*
"""

class IntelligentLogger:
    """Advanced logging system with context awareness"""
    
    def __init__(self, session_id: str, results_dir: Path):
        self.session_id = session_id
        self.results_dir = results_dir
        self.setup_logging()
        self.metrics = {
            "start_time": datetime.now(),
            "tasks_completed": 0,
            "tasks_failed": 0,
            "vulnerabilities_found": 0,
            "false_positives": 0,
            "api_calls": 0,
            "errors": []
        }
    
    def setup_logging(self):
        """Setup comprehensive logging"""
        log_format = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - [%(session_id)s] - %(message)s'
        )
        
        # Main logger
        self.logger = logging.getLogger('autonomous_bb')
        self.logger.setLevel(logging.DEBUG)
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(log_format)
        
        # File handler
        file_handler = logging.FileHandler(
            self.results_dir / f"autonomous_bb_{self.session_id}.log"
        )
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(log_format)
        
        # Error handler
        error_handler = logging.FileHandler(
            self.results_dir / f"errors_{self.session_id}.log"
        )
        error_handler.setLevel(logging.ERROR)
        error_handler.setFormatter(log_format)
        
        self.logger.addHandler(console_handler)
        self.logger.addHandler(file_handler)
        self.logger.addHandler(error_handler)
        
        # Add session context
        old_factory = logging.getLogRecordFactory()
        def record_factory(*args, **kwargs):
            record = old_factory(*args, **kwargs)
            record.session_id = self.session_id
            return record
        logging.setLogRecordFactory(record_factory)
    
    def log_task_start(self, task_name: str, details: Dict = None):
        """Log task start with context"""
        self.logger.info(f"🚀 Starting task: {task_name}", extra={"task": task_name, "details": details})
    
    def log_task_complete(self, task_name: str, duration: float, results: Dict = None):
        """Log task completion"""
        self.metrics["tasks_completed"] += 1
        self.logger.info(f"✅ Completed task: {task_name} in {duration:.2f}s", 
                        extra={"task": task_name, "duration": duration, "results": results})
    
    def log_vulnerability(self, bug_report: BugReport):
        """Log discovered vulnerability"""
        self.metrics["vulnerabilities_found"] += 1
        self.logger.warning(f"🚨 Vulnerability found: {bug_report.title} [{bug_report.severity.value}]",
                           extra={"vulnerability": asdict(bug_report)})
    
    def log_error(self, error: Exception, context: str, recoverable: bool = True):
        """Log error with full context"""
        self.metrics["tasks_failed"] += 1
        error_data = {
            "error_type": type(error).__name__,
            "error_message": str(error),
            "context": context,
            "recoverable": recoverable,
            "traceback": traceback.format_exc()
        }
        self.metrics["errors"].append(error_data)
        
        if recoverable:
            self.logger.error(f"❌ Recoverable error in {context}: {error}", extra=error_data)
        else:
            self.logger.critical(f"💥 Critical error in {context}: {error}", extra=error_data)
    
    def get_metrics(self) -> Dict:
        """Get session metrics"""
        self.metrics["duration"] = (datetime.now() - self.metrics["start_time"]).total_seconds()
        self.metrics["success_rate"] = (
            self.metrics["tasks_completed"] / 
            max(1, self.metrics["tasks_completed"] + self.metrics["tasks_failed"])
        )
        return self.metrics.copy()

class ProcessManager:
    """Advanced process and resource management"""
    
    def __init__(self, max_workers: int = 10, memory_limit_mb: int = 4096):
        self.max_workers = max_workers
        self.memory_limit_mb = memory_limit_mb
        self.active_tasks = {}
        self.resource_monitor = {}
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        self._shutdown_requested = False
        
        # Setup signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals gracefully"""
        print(f"\n🛑 Received signal {signum}, initiating graceful shutdown...")
        self._shutdown_requested = True
        self.shutdown()
    
    async def execute_task(self, task_func, task_id: str, *args, **kwargs):
        """Execute task with monitoring and error handling"""
        start_time = time.time()
        self.active_tasks[task_id] = {
            "start_time": start_time,
            "function": task_func.__name__,
            "status": TaskStatus.RUNNING
        }
        
        try:
            # Check memory usage
            if self._check_memory_usage():
                raise MemoryError("Memory limit exceeded")
            
            # Execute task
            if asyncio.iscoroutinefunction(task_func):
                result = await task_func(*args, **kwargs)
            else:
                loop = asyncio.get_event_loop()
                result = await loop.run_in_executor(self.executor, task_func, *args, **kwargs)
            
            self.active_tasks[task_id]["status"] = TaskStatus.COMPLETED
            self.active_tasks[task_id]["duration"] = time.time() - start_time
            
            return result
            
        except Exception as e:
            self.active_tasks[task_id]["status"] = TaskStatus.FAILED
            self.active_tasks[task_id]["error"] = str(e)
            raise
    
    def _check_memory_usage(self) -> bool:
        """Check if memory usage exceeds limit"""
        try:
            import psutil
            process = psutil.Process()
            memory_mb = process.memory_info().rss / 1024 / 1024
            return memory_mb > self.memory_limit_mb
        except ImportError:
            return False  # psutil not available, skip check
    
    def get_active_tasks(self) -> Dict:
        """Get currently active tasks"""
        return self.active_tasks.copy()
    
    def shutdown(self):
        """Gracefully shutdown all processes"""
        print("🔄 Shutting down process manager...")
        self.executor.shutdown(wait=True)
        print("✅ Process manager shutdown complete")

class AdaptiveWorkflowEngine:
    """Intelligent workflow engine that adapts based on findings and context"""
    
    def __init__(self, scope_config: ScopeConfig, logger: IntelligentLogger, process_manager: ProcessManager):
        self.scope_config = scope_config
        self.logger = logger
        self.process_manager = process_manager
        self.workflow_state = {
            "current_phase": None,
            "completed_phases": [],
            "discovered_assets": [],
            "vulnerabilities": [],
            "next_actions": [],
            "confidence_scores": {}
        }
        self.decision_engine = DecisionEngine(logger)
    
    async def execute_autonomous_workflow(self, hunter: BugBountyAgent) -> Dict:
        """Execute fully autonomous bug bounty workflow"""
        self.logger.log_task_start("autonomous_workflow", {"scope": asdict(self.scope_config)})
        workflow_start = time.time()
        
        try:
            # Phase 1: Intelligence gathering and scope validation
            await self._phase_intelligence_gathering(hunter)
            
            # Phase 2: Adaptive reconnaissance
            await self._phase_adaptive_reconnaissance(hunter)
            
            # Phase 3: Smart vulnerability discovery
            await self._phase_smart_vulnerability_discovery(hunter)
            
            # Phase 4: Intelligent exploitation and validation
            await self._phase_intelligent_exploitation(hunter)
            
            # Phase 5: Automated reporting and next steps
            await self._phase_automated_reporting(hunter)
            
            workflow_duration = time.time() - workflow_start
            self.logger.log_task_complete("autonomous_workflow", workflow_duration, self.workflow_state)
            
            return self.workflow_state
            
        except Exception as e:
            self.logger.log_error(e, "autonomous_workflow", recoverable=False)
            raise
    
    async def _phase_intelligence_gathering(self, hunter: BugBountyAgent):
        """Phase 1: Gather intelligence and validate scope"""
        self.workflow_state["current_phase"] = "intelligence_gathering"
        phase_start = time.time()
        
        self.logger.log_task_start("intelligence_gathering")
        
        intelligence_prompt = f"""
        Perform comprehensive intelligence gathering for bug bounty targets:
        
        Scope: {self.scope_config.targets}
        In Scope: {self.scope_config.in_scope}
        Out of Scope: {self.scope_config.out_of_scope}
        
        Tasks:
        1. Validate all targets are reachable and in scope
        2. Gather OSINT on target organization
        3. Identify technology stack and infrastructure
        4. Map external attack surface
        5. Prioritize targets based on attack surface and business value
        6. Generate adaptive reconnaissance plan
        
        Provide structured analysis with confidence scores and next recommended actions.
        Focus on maximizing bug bounty potential while staying within scope.
        """
        
        result = await hunter.agent.run(intelligence_prompt)
        
        # Analyze results and update workflow state
        self.workflow_state["intelligence"] = result.final_output
        
        # Extract targets and validate scope
        validated_targets = []
        for target in self.scope_config.targets:
            if self.scope_config.is_in_scope(target):
                validated_targets.append(target)
                self.logger.logger.info(f"✅ Target validated: {target}")
            else:
                self.logger.logger.warning(f"⚠️ Target out of scope: {target}")
        
        self.workflow_state["validated_targets"] = validated_targets
        
        # Use decision engine to plan next phase
        next_actions = await self.decision_engine.plan_reconnaissance(
            validated_targets, result.final_output
        )
        self.workflow_state["next_actions"] = next_actions
        
        phase_duration = time.time() - phase_start
        self.logger.log_task_complete("intelligence_gathering", phase_duration)
        self.workflow_state["completed_phases"].append("intelligence_gathering")
    
    async def _phase_adaptive_reconnaissance(self, hunter: BugBountyAgent):
        """Phase 2: Adaptive reconnaissance based on intelligence"""
        self.workflow_state["current_phase"] = "adaptive_reconnaissance"
        phase_start = time.time()
        
        self.logger.log_task_start("adaptive_reconnaissance")
        
        for target in self.workflow_state["validated_targets"]:
            # Skip if shutdown requested
            if self.process_manager._shutdown_requested:
                break
                
            try:
                task_id = f"recon_{hashlib.md5(target.encode()).hexdigest()[:8]}"
                
                recon_result = await self.process_manager.execute_task(
                    self._adaptive_target_reconnaissance,
                    task_id,
                    hunter,
                    target
                )
                
                self.workflow_state["discovered_assets"].extend(recon_result.get("assets", []))
                
                # Analyze findings for immediate high-value targets
                if recon_result.get("high_value_findings"):
                    self.workflow_state["next_actions"].insert(0, {
                        "action": "immediate_vuln_scan",
                        "target": target,
                        "priority": Priority.HIGH,
                        "reason": "High-value findings detected"
                    })
                
            except Exception as e:
                self.logger.log_error(e, f"reconnaissance_target_{target}", recoverable=True)
                continue
        
        phase_duration = time.time() - phase_start
        self.logger.log_task_complete("adaptive_reconnaissance", phase_duration)
        self.workflow_state["completed_phases"].append("adaptive_reconnaissance")
    
    async def _adaptive_target_reconnaissance(self, hunter: BugBountyAgent, target: str) -> Dict:
        """Perform adaptive reconnaissance on a single target"""
        
        recon_prompt = f"""
        Perform adaptive reconnaissance on {target}:
        
        Context from intelligence phase: {self.workflow_state.get("intelligence", "")}
        
        Adaptive tasks based on target characteristics:
        1. Subdomain enumeration with multiple techniques
        2. Port scanning optimized for target type
        3. Technology fingerprinting
        4. API endpoint discovery
        5. Content discovery with smart wordlists
        6. Certificate analysis and historical data
        7. Social media and public exposure analysis
        
        Rate limit: {self.scope_config.rate_limit} req/sec
        Safe mode: {self.scope_config.safe_mode}
        
        Identify high-value targets for immediate vulnerability testing.
        Provide confidence scores for each finding.
        """
        
        result = await hunter.agent.run(recon_prompt)
        
        return {
            "target": target,
            "reconnaissance_data": result.final_output,
            "assets": self._extract_assets_from_result(result.final_output),
            "high_value_findings": self._identify_high_value_findings(result.final_output)
        }
    
    async def _phase_smart_vulnerability_discovery(self, hunter: BugBountyAgent):
        """Phase 3: Intelligent vulnerability discovery"""
        self.workflow_state["current_phase"] = "vulnerability_discovery"
        phase_start = time.time()
        
        self.logger.log_task_start("smart_vulnerability_discovery")
        
        # Prioritize targets based on reconnaissance findings
        prioritized_targets = await self.decision_engine.prioritize_vulnerability_targets(
            self.workflow_state["discovered_assets"],
            self.workflow_state["next_actions"]
        )
        
        for target_info in prioritized_targets:
            if self.process_manager._shutdown_requested:
                break
                
            try:
                task_id = f"vulnscan_{hashlib.md5(target_info['target'].encode()).hexdigest()[:8]}"
                
                vuln_result = await self.process_manager.execute_task(
                    self._intelligent_vulnerability_scan,
                    task_id,
                    hunter,
                    target_info
                )
                
                # Process and validate findings
                for finding in vuln_result.get("vulnerabilities", []):
                    validated_finding = await self._validate_vulnerability(hunter, finding)
                    if validated_finding and validated_finding.confidence > 0.7:
                        self.workflow_state["vulnerabilities"].append(validated_finding)
                        self.logger.log_vulnerability(validated_finding)
                
            except Exception as e:
                self.logger.log_error(e, f"vulnerability_scan_{target_info['target']}", recoverable=True)
                continue
        
        phase_duration = time.time() - phase_start
        self.logger.log_task_complete("smart_vulnerability_discovery", phase_duration)
        self.workflow_state["completed_phases"].append("vulnerability_discovery")
    
    async def _intelligent_vulnerability_scan(self, hunter: BugBountyAgent, target_info: Dict) -> Dict:
        """Perform intelligent vulnerability scanning"""
        
        vuln_prompt = f"""
        Perform intelligent vulnerability scanning on {target_info['target']}:
        
        Target context: {target_info}
        Previous findings: {self.workflow_state.get("vulnerabilities", [])}
        
        Intelligent vulnerability discovery:
        1. Technology-specific vulnerability testing
        2. Business logic flaw analysis
        3. Authentication and authorization bypass testing
        4. Input validation testing (XSS, SQLi, etc.)
        5. API security testing
        6. Configuration and deployment issues
        7. Custom payload generation based on target characteristics
        
        For each finding:
        - Provide detailed proof of concept
        - Assess business impact
        - Calculate confidence score
        - Suggest remediation
        - Rate false positive probability
        
        Focus on high-impact, low false-positive findings suitable for bug bounty submission.
        """
        
        result = await hunter.agent.run(vuln_prompt)
        
        return {
            "target": target_info["target"],
            "scan_data": result.final_output,
            "vulnerabilities": self._extract_vulnerabilities_from_result(result.final_output)
        }
    
    async def _validate_vulnerability(self, hunter: BugBountyAgent, finding_data: Dict) -> Optional[BugReport]:
        """Validate and structure vulnerability finding"""
        
        validation_prompt = f"""
        Validate and structure this vulnerability finding:
        
        Finding: {finding_data}
        
        Validation tasks:
        1. Verify the vulnerability is real and exploitable
        2. Assess the actual business impact
        3. Check for false positive indicators
        4. Refine the proof of concept
        5. Calculate accurate CVSS score
        6. Provide clear remediation steps
        
        Return structured validation with confidence score (0.0-1.0).
        Only approve findings with >70% confidence for bug bounty submission.
        """
        
        validation_result = await hunter.agent.run(validation_prompt)
        
        # Extract structured data from validation result
        try:
            bug_report = self._create_bug_report_from_validation(validation_result.final_output, finding_data)
            return bug_report
        except Exception as e:
            self.logger.log_error(e, f"validate_vulnerability_{finding_data.get('title', 'unknown')}", recoverable=True)
            return None
    
    async def _phase_intelligent_exploitation(self, hunter: BugBountyAgent):
        """Phase 4: Intelligent exploitation and impact demonstration"""
        self.workflow_state["current_phase"] = "intelligent_exploitation"
        phase_start = time.time()
        
        self.logger.log_task_start("intelligent_exploitation")
        
        # Only proceed with high-confidence vulnerabilities
        high_confidence_vulns = [
            vuln for vuln in self.workflow_state["vulnerabilities"]
            if vuln.confidence > 0.8 and vuln.severity in [Priority.CRITICAL, Priority.HIGH]
        ]
        
        for vulnerability in high_confidence_vulns:
            if self.process_manager._shutdown_requested:
                break
                
            try:
                # Enhance proof of concept and impact demonstration
                enhanced_poc = await self._enhance_proof_of_concept(hunter, vulnerability)
                vulnerability.proof_of_concept = enhanced_poc
                
                # Calculate business impact
                business_impact = await self._calculate_business_impact(hunter, vulnerability)
                vulnerability.impact = business_impact
                
            except Exception as e:
                self.logger.log_error(e, f"exploitation_{vulnerability.id}", recoverable=True)
                continue
        
        phase_duration = time.time() - phase_start
        self.logger.log_task_complete("intelligent_exploitation", phase_duration)
        self.workflow_state["completed_phases"].append("intelligent_exploitation")
    
    async def _phase_automated_reporting(self, hunter: BugBountyAgent):
        """Phase 5: Automated reporting and next steps"""
        self.workflow_state["current_phase"] = "automated_reporting"
        phase_start = time.time()
        
        self.logger.log_task_start("automated_reporting")
        
        # Generate comprehensive report
        report_prompt = f"""
        Generate comprehensive bug bounty report:
        
        Scope: {asdict(self.scope_config)}
        Vulnerabilities: {len(self.workflow_state["vulnerabilities"])}
        Session metrics: {self.logger.get_metrics()}
        
        Create:
        1. Executive summary with key findings
        2. Technical details for each vulnerability
        3. Risk assessment and business impact
        4. Remediation roadmap
        5. Next steps for continued testing
        6. Lessons learned and methodology improvements
        
        Format for professional bug bounty submission.
        """
        
        report_result = await hunter.agent.run(report_prompt)
        self.workflow_state["final_report"] = report_result.final_output
        
        # Generate next steps
        next_steps = await self.decision_engine.generate_next_steps(self.workflow_state)
        self.workflow_state["next_steps"] = next_steps
        
        phase_duration = time.time() - phase_start
        self.logger.log_task_complete("automated_reporting", phase_duration)
        self.workflow_state["completed_phases"].append("automated_reporting")
    
    def _extract_assets_from_result(self, result_text: str) -> List[Dict]:
        """Extract discovered assets from result text"""
        # Implementation would parse the AI response for structured asset data
        # This is a simplified version
        assets = []
        lines = result_text.split('\n')
        for line in lines:
            if 'discovered' in line.lower() and ('subdomain' in line.lower() or 'endpoint' in line.lower()):
                assets.append({"type": "endpoint", "value": line.strip(), "confidence": 0.8})
        return assets
    
    def _identify_high_value_findings(self, result_text: str) -> bool:
        """Identify if reconnaissance found high-value targets"""
        high_value_indicators = [
            'admin', 'api', 'internal', 'dev', 'staging', 'test',
            'backup', 'database', 'config', 'secret'
        ]
        return any(indicator in result_text.lower() for indicator in high_value_indicators)
    
    def _extract_vulnerabilities_from_result(self, result_text: str) -> List[Dict]:
        """Extract vulnerability findings from result text"""
        # Implementation would parse AI response for structured vulnerability data
        vulnerabilities = []
        # Simplified extraction logic
        if 'vulnerability' in result_text.lower() or 'exploit' in result_text.lower():
            vulnerabilities.append({
                "title": "Detected Vulnerability",
                "description": result_text[:500],
                "confidence": 0.7
            })
        return vulnerabilities
    
    def _create_bug_report_from_validation(self, validation_text: str, finding_data: Dict) -> BugReport:
        """Create structured bug report from validation result"""
        # This would parse the AI validation response and create a structured report
        return BugReport(
            id=hashlib.md5(f"{finding_data.get('title', 'unknown')}{datetime.now()}".encode()).hexdigest()[:16],
            title=finding_data.get('title', 'Vulnerability Found'),
            description=validation_text[:1000],
            severity=Priority.MEDIUM,  # Would be extracted from validation
            cvss_score=5.0,  # Would be calculated from validation
            target=finding_data.get('target', 'unknown'),
            endpoint=finding_data.get('endpoint', '/'),
            vulnerability_type=finding_data.get('type', 'unknown'),
            proof_of_concept=finding_data.get('poc', ''),
            impact=finding_data.get('impact', ''),
            remediation=finding_data.get('remediation', ''),
            references=[],
            discovered_at=datetime.now().isoformat(),
            confidence=finding_data.get('confidence', 0.7),
            false_positive_probability=0.3
        )
    
    async def _enhance_proof_of_concept(self, hunter: BugBountyAgent, vulnerability: BugReport) -> str:
        """Enhance proof of concept for vulnerability"""
        poc_prompt = f"""
        Enhance the proof of concept for this vulnerability:
        
        Vulnerability: {vulnerability.title}
        Current PoC: {vulnerability.proof_of_concept}
        Target: {vulnerability.target}
        
        Create a detailed, step-by-step proof of concept that:
        1. Clearly demonstrates the vulnerability
        2. Shows the actual impact
        3. Provides exact reproduction steps
        4. Includes necessary payloads and tools
        5. Explains the business risk
        
        Make it suitable for bug bounty submission.
        """
        
        result = await hunter.agent.run(poc_prompt)
        return result.final_output
    
    async def _calculate_business_impact(self, hunter: BugBountyAgent, vulnerability: BugReport) -> str:
        """Calculate detailed business impact"""
        impact_prompt = f"""
        Calculate the business impact for this vulnerability:
        
        Vulnerability: {vulnerability.title}
        Type: {vulnerability.vulnerability_type}
        Target: {vulnerability.target}
        CVSS: {vulnerability.cvss_score}
        
        Assess:
        1. Data exposure risk
        2. Financial impact
        3. Compliance implications
        4. Reputational damage
        5. Operational disruption
        6. Attack scenarios
        
        Provide quantifiable business impact assessment.
        """
        
        result = await hunter.agent.run(impact_prompt)
        return result.final_output

class DecisionEngine:
    """AI-powered decision engine for workflow optimization"""
    
    def __init__(self, logger: IntelligentLogger):
        self.logger = logger
    
    async def plan_reconnaissance(self, targets: List[str], intelligence: str) -> List[Dict]:
        """Plan reconnaissance phase based on intelligence"""
        # AI-powered planning logic
        return [
            {"action": "subdomain_enum", "priority": Priority.HIGH, "targets": targets},
            {"action": "port_scan", "priority": Priority.MEDIUM, "targets": targets}
        ]
    
    async def prioritize_vulnerability_targets(self, assets: List[Dict], actions: List[Dict]) -> List[Dict]:
        """Prioritize targets for vulnerability scanning"""
        # AI-powered prioritization
        prioritized = []
        for asset in assets:
            priority_score = self._calculate_priority_score(asset)
            prioritized.append({
                "target": asset.get("value", ""),
                "priority_score": priority_score,
                "asset_info": asset
            })
        
        return sorted(prioritized, key=lambda x: x["priority_score"], reverse=True)
    
    def _calculate_priority_score(self, asset: Dict) -> float:
        """Calculate priority score for asset"""
        score = asset.get("confidence", 0.5)
        
        # Boost score for high-value indicators
        value = asset.get("value", "").lower()
        if any(indicator in value for indicator in ["admin", "api", "internal"]):
            score += 0.3
        
        return min(score, 1.0)
    
    async def generate_next_steps(self, workflow_state: Dict) -> List[str]:
        """Generate next steps based on workflow results"""
        next_steps = []
        
        vulns = workflow_state.get("vulnerabilities", [])
        if vulns:
            next_steps.append(f"Submit {len(vulns)} validated vulnerabilities to bug bounty platform")
            
        if workflow_state.get("discovered_assets"):
            next_steps.append("Continue testing on newly discovered assets")
        
        next_steps.append("Monitor for new attack surface changes")
        
        return next_steps
