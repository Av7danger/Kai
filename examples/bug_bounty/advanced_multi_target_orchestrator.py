#!/usr/bin/env python3
"""
🚀 ADVANCED MULTI-TARGET GEMINI ORCHESTRATOR
🧠 Intelligent campaign management across multiple targets simultaneously
⚡ Advanced resource allocation, priority management, and cross-target correlation
🎯 Enterprise-grade multi-tenant agentic bug bounty operations
"""

import asyncio
import json
import logging
import time
import os
import sqlite3
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Set, Tuple
from dataclasses import dataclass, field
from collections import defaultdict, deque
from enum import Enum
import threading
import heapq
import uuid
from pathlib import Path

# Import our core system
try:
    from ultra_optimized_gemini_system import UltraOrchestrator
    CORE_SYSTEM_AVAILABLE = True
except ImportError:
    CORE_SYSTEM_AVAILABLE = False

# Import Gemini API
try:
    import google.generativeai as genai
    GEMINI_AVAILABLE = True
except ImportError:
    GEMINI_AVAILABLE = False

class SimpleGeminiAPI:
    """Simple Gemini API wrapper for compatibility"""
    
    def __init__(self, model=None):
        self.model = model
    
    async def get_gemini_decision(self, template_key: str, **kwargs):
        """Simple Gemini decision with fallback"""
        try:
            if self.model and GEMINI_AVAILABLE:
                prompt = kwargs.get('prompt_override', f"Template: {template_key}")
                response = await self.model.generate_content_async(prompt)
                return MockGeminiResponse(response.text)
            else:
                return MockGeminiResponse("Simulation mode")
        except:
            return MockGeminiResponse("Fallback response")

class MockGeminiResponse:
    """Mock response for compatibility"""
    
    def __init__(self, text: str):
        self.text = text
        self.reasoning = "Mock reasoning"
        self.action = "continue"
        self.confidence = 0.8
        self.next_steps = ["step1", "step2"]
        self.priority = 5
        self.context_updates = {}
        self.resource_requirements = {}

class CampaignStatus(Enum):
    """Campaign status types"""
    PLANNING = "planning"
    ACTIVE = "active"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    SUSPENDED = "suspended"

class ResourceAllocationStrategy(Enum):
    """Resource allocation strategies"""
    BALANCED = "balanced"
    PRIORITY_FOCUSED = "priority_focused"
    ROUND_ROBIN = "round_robin"
    ADAPTIVE = "adaptive"
    VULNERABILITY_FOCUSED = "vulnerability_focused"

@dataclass
class MultiTargetCampaign:
    """Multi-target campaign definition"""
    id: str
    name: str
    targets: List[str]
    priority: int
    status: CampaignStatus
    resource_budget: Dict[str, float]
    time_budget: float  # hours
    risk_tolerance: str
    created_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    findings: List[Dict] = field(default_factory=list)
    metrics: Dict[str, Any] = field(default_factory=dict)
    gemini_insights: Dict[str, Any] = field(default_factory=dict)

@dataclass
class TargetAllocation:
    """Resource allocation for specific target"""
    target: str
    campaign_id: str
    allocated_resources: Dict[str, float]
    priority_score: float
    estimated_completion: datetime
    current_phase: str
    gemini_strategy: Dict[str, Any]

class IntelligentResourceManager:
    """AI-powered resource management and allocation"""
    
    def __init__(self, gemini_api):
        self.gemini_api = gemini_api
        self.resource_pools = {
            'cpu_cores': os.cpu_count() or 4,
            'memory_gb': 8.0,  # Default, should be detected
            'network_bandwidth': 100.0,  # Mbps
            'storage_gb': 50.0,
            'gemini_api_calls': 1000  # Daily budget
        }
        self.active_allocations = {}
        self.performance_history = deque(maxlen=1000)
        
    async def optimize_resource_allocation(self, campaigns: List[MultiTargetCampaign]) -> Dict[str, TargetAllocation]:
        """Use Gemini to optimize resource allocation across campaigns"""
        
        # Prepare context for Gemini
        allocation_context = {
            'available_resources': self.resource_pools,
            'active_campaigns': len([c for c in campaigns if c.status == CampaignStatus.ACTIVE]),
            'campaign_priorities': {c.id: c.priority for c in campaigns},
            'target_count': sum(len(c.targets) for c in campaigns),
            'resource_history': list(self.performance_history)[-10:]  # Last 10 allocations
        }
        
        gemini_prompt = f"""
ROLE: Expert Resource Allocation Strategist for Bug Bounty Operations

TASK: Optimize resource allocation across multiple concurrent bug bounty campaigns

CONTEXT: {json.dumps(allocation_context, indent=2)}

CAMPAIGNS:
{json.dumps([{'id': c.id, 'targets': c.targets, 'priority': c.priority, 'status': c.status.value} for c in campaigns], indent=2)}

REQUIREMENTS:
1. Maximize overall campaign efficiency
2. Respect priority levels and resource constraints
3. Ensure fair allocation while prioritizing high-value targets
4. Consider cross-target correlation opportunities
5. Optimize for both speed and thoroughness

PROVIDE JSON RESPONSE:
{{
    "reasoning": "detailed allocation strategy and rationale",
    "allocation_strategy": "balanced|priority_focused|adaptive",
    "target_allocations": {{
        "target_domain.com": {{
            "cpu_percentage": 25.0,
            "memory_percentage": 20.0,
            "priority_score": 8.5,
            "estimated_hours": 2.5,
            "recommended_phase": "reconnaissance",
            "special_focus": ["subdomain_enumeration", "technology_detection"]
        }}
    }},
    "resource_optimization": {{
        "parallel_targets": 4,
        "sequential_phases": ["recon", "scanning", "analysis"],
        "cross_correlation_opportunities": ["shared_infrastructure", "common_technologies"]
    }},
    "performance_predictions": {{
        "expected_completion": "2024-01-15T18:00:00",
        "estimated_findings": 15,
        "resource_efficiency": 0.85
    }}
}}
"""
        
        try:
            response = await self.gemini_api.get_gemini_decision('resource_allocation', 
                                                              context=allocation_context,
                                                              prompt_override=gemini_prompt)
            
            # Parse and validate allocation
            allocations = {}
            if hasattr(response, 'context_updates') and 'target_allocations' in response.context_updates:
                allocation_data = response.context_updates['target_allocations']
                
                for target, allocation in allocation_data.items():
                    allocations[target] = TargetAllocation(
                        target=target,
                        campaign_id="",  # Will be set by orchestrator
                        allocated_resources={
                            'cpu_percentage': allocation.get('cpu_percentage', 25.0),
                            'memory_percentage': allocation.get('memory_percentage', 25.0)
                        },
                        priority_score=allocation.get('priority_score', 5.0),
                        estimated_completion=datetime.now() + timedelta(hours=allocation.get('estimated_hours', 2)),
                        current_phase=allocation.get('recommended_phase', 'reconnaissance'),
                        gemini_strategy=allocation
                    )
            
            return allocations
            
        except Exception as e:
            logging.error(f"Resource allocation optimization failed: {e}")
            return self._fallback_allocation(campaigns)
    
    def _fallback_allocation(self, campaigns: List[MultiTargetCampaign]) -> Dict[str, TargetAllocation]:
        """Fallback resource allocation strategy"""
        allocations = {}
        total_targets = sum(len(c.targets) for c in campaigns)
        
        if total_targets > 0:
            cpu_per_target = 80.0 / total_targets  # Use 80% of CPU
            memory_per_target = 70.0 / total_targets  # Use 70% of memory
            
            for campaign in campaigns:
                for target in campaign.targets:
                    allocations[target] = TargetAllocation(
                        target=target,
                        campaign_id=campaign.id,
                        allocated_resources={
                            'cpu_percentage': min(cpu_per_target, 25.0),
                            'memory_percentage': min(memory_per_target, 25.0)
                        },
                        priority_score=campaign.priority,
                        estimated_completion=datetime.now() + timedelta(hours=2),
                        current_phase='reconnaissance',
                        gemini_strategy={}
                    )
        
        return allocations

class CrossTargetCorrelationEngine:
    """Identify patterns and correlations across multiple targets"""
    
    def __init__(self, gemini_api):
        self.gemini_api = gemini_api
        self.correlation_cache = {}
        self.pattern_database = defaultdict(list)
        
    async def analyze_cross_target_patterns(self, campaign_results: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze patterns across multiple targets using Gemini"""
        
        # Extract key data for correlation analysis
        correlation_data = {}
        for target, results in campaign_results.items():
            correlation_data[target] = {
                'technologies': results.get('technologies', []),
                'subdomains': results.get('subdomains', []),
                'vulnerabilities': results.get('vulnerabilities', []),
                'ip_ranges': results.get('ip_ranges', []),
                'certificates': results.get('certificates', []),
                'dns_records': results.get('dns_records', [])
            }
        
        gemini_prompt = f"""
ROLE: Advanced Cybersecurity Pattern Recognition Expert

TASK: Analyze cross-target correlations and identify strategic patterns

TARGET_DATA: {json.dumps(correlation_data, indent=2)}

ANALYZE:
1. Shared infrastructure and technologies
2. Common vulnerability patterns
3. Related organizational assets
4. Certificate and DNS correlations
5. Attack surface overlaps
6. Strategic targeting opportunities

PROVIDE JSON RESPONSE:
{{
    "reasoning": "detailed pattern analysis and correlation findings",
    "infrastructure_correlations": {{
        "shared_hosting": ["target1.com", "target2.com"],
        "common_cdn": ["cloudflare", "targets_using_it"],
        "certificate_relationships": ["shared_ca", "wildcard_patterns"]
    }},
    "vulnerability_patterns": {{
        "common_technologies": ["nginx", "wordpress", "specific_versions"],
        "shared_misconfigurations": ["cors", "security_headers"],
        "systematic_weaknesses": ["input_validation", "authentication"]
    }},
    "strategic_insights": {{
        "priority_targets": ["most_vulnerable_target"],
        "attack_chains": ["lateral_movement_opportunities"],
        "efficiency_gains": ["shared_tooling", "batch_operations"]
    }},
    "recommendations": {{
        "focus_areas": ["specific_attack_vectors"],
        "resource_reallocation": ["optimize_for_patterns"],
        "cross_target_attacks": ["pivot_opportunities"]
    }}
}}
"""
        
        try:
            response = await self.gemini_api.get_gemini_decision('cross_correlation', 
                                                              context=correlation_data,
                                                              prompt_override=gemini_prompt)
            return response.context_updates if hasattr(response, 'context_updates') else {}
            
        except Exception as e:
            logging.error(f"Cross-target correlation analysis failed: {e}")
            return {}

class AdvancedMultiTargetOrchestrator:
    """Advanced orchestrator for multi-target bug bounty campaigns"""
    
    def __init__(self, gemini_api_key: Optional[str] = None):
        self.db_path = "advanced_multi_target_campaigns.db"
        self.gemini_api_key = gemini_api_key or os.getenv('GEMINI_API_KEY')
        
        # Initialize core components
        if CORE_SYSTEM_AVAILABLE:
            self.core_orchestrator = UltraOrchestrator()
            # Create a simple Gemini API interface
            if GEMINI_AVAILABLE and self.gemini_api_key:
                try:
                    if hasattr(genai, 'configure'):
                        genai.configure(api_key=self.gemini_api_key)
                        self.gemini_model = genai.GenerativeModel('gemini-pro')
                    else:
                        self.gemini_model = None
                    self.gemini_api = SimpleGeminiAPI(self.gemini_model)
                except:
                    self.gemini_api = SimpleGeminiAPI(None)
            else:
                self.gemini_api = SimpleGeminiAPI(None)
        else:
            self.core_orchestrator = None
            self.gemini_api = SimpleGeminiAPI(None)
        
        # Advanced components
        self.resource_manager = IntelligentResourceManager(self.gemini_api)
        self.correlation_engine = CrossTargetCorrelationEngine(self.gemini_api)
        
        # Campaign management
        self.active_campaigns = {}
        self.campaign_queue = []
        self.results_database = {}
        
        # Performance tracking
        self.performance_metrics = {
            'total_campaigns': 0,
            'successful_campaigns': 0,
            'total_findings': 0,
            'average_campaign_time': 0,
            'resource_efficiency': 0
        }
        
        # Initialize database
        self._init_database()
        
        logging.info("🚀 Advanced Multi-Target Orchestrator initialized")
    
    def _init_database(self):
        """Initialize advanced campaign database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS multi_campaigns (
                        id TEXT PRIMARY KEY,
                        name TEXT NOT NULL,
                        targets TEXT NOT NULL,  -- JSON array
                        priority INTEGER NOT NULL,
                        status TEXT NOT NULL,
                        resource_budget TEXT,  -- JSON
                        time_budget REAL,
                        risk_tolerance TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        started_at TIMESTAMP,
                        completed_at TIMESTAMP,
                        findings TEXT,  -- JSON
                        metrics TEXT,   -- JSON
                        gemini_insights TEXT  -- JSON
                    )
                """)
                
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS target_allocations (
                        id TEXT PRIMARY KEY,
                        target TEXT NOT NULL,
                        campaign_id TEXT NOT NULL,
                        allocated_resources TEXT,  -- JSON
                        priority_score REAL,
                        estimated_completion TIMESTAMP,
                        current_phase TEXT,
                        gemini_strategy TEXT,  -- JSON
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (campaign_id) REFERENCES multi_campaigns (id)
                    )
                """)
                
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS cross_correlations (
                        id TEXT PRIMARY KEY,
                        campaign_ids TEXT,  -- JSON array
                        correlation_type TEXT,
                        pattern_data TEXT,  -- JSON
                        confidence_score REAL,
                        strategic_value TEXT,
                        discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                
                conn.commit()
                logging.info("📊 Advanced campaign database initialized")
                
        except Exception as e:
            logging.error(f"Database initialization failed: {e}")
    
    async def create_campaign(self, name: str, targets: List[str], 
                            priority: int = 5, resource_budget: Optional[Dict[str, float]] = None,
                            time_budget: float = 8.0, risk_tolerance: str = "medium") -> str:
        """Create a new multi-target campaign with Gemini optimization"""
        
        campaign_id = f"campaign_{uuid.uuid4().hex[:8]}"
        
        # Use Gemini to optimize campaign parameters
        campaign_context = {
            'targets': targets,
            'target_count': len(targets),
            'priority': priority,
            'resource_budget': resource_budget or {},
            'time_budget': time_budget,
            'risk_tolerance': risk_tolerance
        }
        
        gemini_prompt = f"""
ROLE: Expert Bug Bounty Campaign Strategist

TASK: Optimize multi-target campaign configuration and strategy

CAMPAIGN_CONTEXT: {json.dumps(campaign_context, indent=2)}

OPTIMIZE:
1. Target prioritization and sequencing
2. Resource allocation strategy
3. Testing methodology per target
4. Risk assessment and mitigation
5. Expected timeline and milestones

PROVIDE JSON RESPONSE:
{{
    "reasoning": "campaign optimization strategy and rationale",
    "optimized_config": {{
        "target_priority_order": ["target1.com", "target2.com"],
        "recommended_resource_budget": {{
            "cpu_hours": 16.0,
            "memory_gb": 4.0,
            "api_calls": 500
        }},
        "testing_strategy": {{
            "parallel_targets": 3,
            "sequential_phases": ["recon", "vuln_scan", "manual_testing"],
            "special_considerations": ["rate_limiting", "stealth_mode"]
        }}
    }},
    "timeline_optimization": {{
        "estimated_total_hours": 6.5,
        "critical_path": ["reconnaissance", "vulnerability_scanning"],
        "parallel_opportunities": ["subdomain_enum", "tech_detection"]
    }},
    "risk_mitigation": {{
        "stealth_measures": ["request_throttling", "user_agent_rotation"],
        "compliance_checks": ["scope_validation", "permission_verification"],
        "fallback_strategies": ["rate_limit_handling", "detection_avoidance"]
    }}
}}
"""
        
        try:
            if self.gemini_api:
                response = await self.gemini_api.get_gemini_decision('campaign_optimization',
                                                                   context=campaign_context,
                                                                   prompt_override=gemini_prompt)
                gemini_insights = response.context_updates if hasattr(response, 'context_updates') else {}
            else:
                gemini_insights = {}
            
            # Create campaign with Gemini optimizations
            campaign = MultiTargetCampaign(
                id=campaign_id,
                name=name,
                targets=targets,
                priority=priority,
                status=CampaignStatus.PLANNING,
                resource_budget=resource_budget or {'cpu_hours': 8.0, 'memory_gb': 2.0},
                time_budget=time_budget,
                risk_tolerance=risk_tolerance,
                created_at=datetime.now(),
                gemini_insights=gemini_insights
            )
            
            # Store in database
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT INTO multi_campaigns 
                    (id, name, targets, priority, status, resource_budget, time_budget, 
                     risk_tolerance, findings, metrics, gemini_insights)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    campaign.id, campaign.name, json.dumps(campaign.targets),
                    campaign.priority, campaign.status.value,
                    json.dumps(campaign.resource_budget), campaign.time_budget,
                    campaign.risk_tolerance, json.dumps(campaign.findings),
                    json.dumps(campaign.metrics), json.dumps(campaign.gemini_insights)
                ))
                conn.commit()
            
            self.active_campaigns[campaign_id] = campaign
            logging.info(f"🎯 Created multi-target campaign {campaign_id} with {len(targets)} targets")
            
            return campaign_id
            
        except Exception as e:
            logging.error(f"Campaign creation failed: {e}")
            raise
    
    async def execute_campaign(self, campaign_id: str) -> Dict[str, Any]:
        """Execute multi-target campaign with intelligent orchestration"""
        
        if campaign_id not in self.active_campaigns:
            raise ValueError(f"Campaign {campaign_id} not found")
        
        campaign = self.active_campaigns[campaign_id]
        campaign.status = CampaignStatus.ACTIVE
        campaign.started_at = datetime.now()
        
        logging.info(f"🚀 Starting campaign {campaign_id} with {len(campaign.targets)} targets")
        
        try:
            # Step 1: Optimize resource allocation
            allocations = await self.resource_manager.optimize_resource_allocation([campaign])
            logging.info(f"🎯 Resource allocations: {len(allocations)} targets allocated")
            
            # Fallback: if no allocations, create default ones
            if not allocations:
                logging.warning("⚠️ No allocations received, creating fallback allocations")
                for target in campaign.targets:
                    allocations[target] = TargetAllocation(
                        target=target,
                        campaign_id=campaign_id,
                        allocated_resources={'cpu_percentage': 30.0, 'memory_percentage': 25.0},
                        priority_score=campaign.priority,
                        estimated_completion=datetime.now() + timedelta(hours=2),
                        current_phase='reconnaissance',
                        gemini_strategy={}
                    )
            
            # Step 2: Execute targets in parallel with intelligent scheduling
            results = {}
            tasks = []
            
            for target in campaign.targets:
                if target in allocations:
                    allocation = allocations[target]
                    allocation.campaign_id = campaign_id
                    
                    # Create target execution task
                    task = asyncio.create_task(
                        self._execute_target_with_allocation(target, allocation, campaign)
                    )
                    tasks.append(task)
            
            # Wait for all targets to complete
            logging.info(f"⏳ Waiting for {len(tasks)} target execution tasks to complete")
            target_results = await asyncio.gather(*tasks, return_exceptions=True)
            logging.info(f"✅ All target tasks completed, processing {len(target_results)} results")
            
            # Process results
            for i, result in enumerate(target_results):
                target = campaign.targets[i]
                logging.info(f"🎯 Processing result for {target}: {type(result)}")
                
                if isinstance(result, Exception):
                    logging.error(f"❌ Task failed for {target}: {result}")
                    results[target] = {'error': str(result), 'success': False}
                else:
                    success = result.get('success', False) if isinstance(result, dict) else False
                    logging.info(f"✅ Task succeeded for {target}: {success}")
                    results[target] = result
            
            # Step 3: Cross-target correlation analysis
            correlations = await self.correlation_engine.analyze_cross_target_patterns(results)
            
            # Step 4: Final Gemini analysis and recommendations
            final_analysis = await self._get_final_campaign_analysis(campaign, results, correlations)
            
            # Update campaign
            campaign.status = CampaignStatus.COMPLETED
            campaign.completed_at = datetime.now()
            campaign.findings = [results, correlations, final_analysis]
            
            # Update metrics
            self._update_performance_metrics(campaign, results)
            
            # Save results
            await self._save_campaign_results(campaign, results, correlations)
            
            return {
                'campaign_id': campaign_id,
                'status': 'completed',
                'execution_time': (campaign.completed_at - campaign.started_at).total_seconds(),
                'targets_processed': len(campaign.targets),
                'target_results': results,
                'cross_correlations': correlations,
                'final_analysis': final_analysis,
                'performance_metrics': campaign.metrics
            }
            
        except Exception as e:
            campaign.status = CampaignStatus.FAILED
            logging.error(f"Campaign {campaign_id} failed: {e}")
            raise
    
    async def _execute_target_with_allocation(self, target: str, allocation: TargetAllocation, 
                                            campaign: MultiTargetCampaign) -> Dict[str, Any]:
        """Execute single target with resource allocation"""
        
        if not self.core_orchestrator:
            # Enhanced simulation mode with more realistic results
            await asyncio.sleep(2)  # Simulate execution time
            findings_count = 5 + (hash(target) % 10)  # Randomize findings
            return {
                'target': target,
                'success': True,
                'findings_count': findings_count,
                'execution_time': 2.0,
                'phase_completed': allocation.current_phase,
                'vulnerabilities': ['sql_injection', 'xss', 'csrf', 'ssrf', 'rce'][:(findings_count % 5) + 1],
                'subdomains': [f'{target}', f'www.{target}', f'api.{target}', f'admin.{target}'],
                'technologies': ['nginx', 'php', 'mysql'],
                'simulated': True
            }
        
        try:
            # Use core orchestrator with allocation constraints
            context = {
                'target': target,
                'campaign_id': campaign.id,
                'resource_allocation': allocation.allocated_resources,
                'priority_score': allocation.priority_score,
                'current_phase': allocation.current_phase,
                'gemini_strategy': allocation.gemini_strategy
            }
            
            # Execute with core system - enhanced simulation mode
            if self.core_orchestrator and hasattr(self.core_orchestrator, 'execute_agentic_campaign'):
                result = await self.core_orchestrator.execute_agentic_campaign(target, context)
            else:
                # Enhanced simulation mode with realistic results
                await asyncio.sleep(1.5)
                findings_count = 3 + (hash(target) % 7)  # Randomize findings
                result = {
                    'target': target,
                    'success': True,
                    'findings_count': findings_count,
                    'execution_time': 1.5,
                    'phase_completed': allocation.current_phase,
                    'vulnerabilities': ['sql_injection', 'xss', 'csrf', 'ssrf'][:(findings_count % 4) + 1],
                    'subdomains': [f'{target}', f'www.{target}', f'api.{target}'],
                    'technologies': ['nginx', 'php'],
                    'simulated': True
                }
            return result
            
        except Exception as e:
            logging.error(f"Target execution failed for {target}: {e}")
            return {
                'target': target,
                'success': False,
                'error': str(e),
                'execution_time': 0
            }
    
    async def _get_final_campaign_analysis(self, campaign: MultiTargetCampaign, 
                                         results: Dict[str, Any], 
                                         correlations: Dict[str, Any]) -> Dict[str, Any]:
        """Get final Gemini analysis of campaign results"""
        
        if not self.gemini_api:
            return {'analysis': 'Gemini not available - simulation mode'}
        
        analysis_context = {
            'campaign_info': {
                'id': campaign.id,
                'targets': campaign.targets,
                'duration': (datetime.now() - campaign.started_at).total_seconds() if campaign.started_at else 0
            },
            'results_summary': {
                'successful_targets': len([r for r in results.values() if r.get('success', False)]),
                'total_findings': sum(r.get('findings_count', 0) for r in results.values()),
                'average_execution_time': sum(r.get('execution_time', 0) for r in results.values()) / max(len(results), 1)
            },
            'correlations': correlations
        }
        
        gemini_prompt = f"""
ROLE: Senior Bug Bounty Campaign Analyst

TASK: Provide comprehensive final analysis of multi-target campaign

CAMPAIGN_DATA: {json.dumps(analysis_context, indent=2)}

ANALYZE:
1. Overall campaign effectiveness and ROI
2. Target-specific insights and recommendations
3. Cross-target strategic implications
4. Security posture assessment
5. Future campaign optimization opportunities

PROVIDE JSON RESPONSE:
{{
    "reasoning": "comprehensive campaign analysis and strategic insights",
    "campaign_effectiveness": {{
        "overall_score": 8.5,
        "efficiency_rating": "high",
        "findings_quality": "excellent",
        "resource_utilization": "optimal"
    }},
    "key_findings": {{
        "critical_vulnerabilities": 3,
        "high_impact_discoveries": 7,
        "strategic_insights": ["shared_infrastructure", "common_patterns"]
    }},
    "recommendations": {{
        "immediate_actions": ["patch_critical_vulns", "investigate_correlations"],
        "strategic_focus": ["infrastructure_hardening", "detection_improvement"],
        "future_campaigns": ["expanded_scope", "deeper_analysis"]
    }},
    "next_steps": {{
        "priority_targets": ["highest_value_targets"],
        "follow_up_testing": ["specific_areas_for_deeper_analysis"],
        "resource_optimization": ["lessons_learned_for_efficiency"]
    }}
}}
"""
        
        try:
            response = await self.gemini_api.get_gemini_decision('final_analysis',
                                                              context=analysis_context,
                                                              prompt_override=gemini_prompt)
            return response.context_updates if hasattr(response, 'context_updates') else {}
            
        except Exception as e:
            logging.error(f"Final campaign analysis failed: {e}")
            return {'error': str(e)}
    
    async def _save_campaign_results(self, campaign: MultiTargetCampaign, 
                                   results: Dict[str, Any], 
                                   correlations: Dict[str, Any]):
        """Save comprehensive campaign results"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                # Update campaign
                conn.execute("""
                    UPDATE multi_campaigns 
                    SET status = ?, started_at = ?, completed_at = ?, 
                        findings = ?, metrics = ?
                    WHERE id = ?
                """, (
                    campaign.status.value, campaign.started_at, campaign.completed_at,
                    json.dumps(campaign.findings), json.dumps(campaign.metrics),
                    campaign.id
                ))
                
                # Save correlations
                if correlations:
                    correlation_id = f"corr_{uuid.uuid4().hex[:8]}"
                    conn.execute("""
                        INSERT INTO cross_correlations 
                        (id, campaign_ids, correlation_type, pattern_data, confidence_score, strategic_value)
                        VALUES (?, ?, ?, ?, ?, ?)
                    """, (
                        correlation_id, json.dumps([campaign.id]), 'multi_target',
                        json.dumps(correlations), 0.8, 'high'
                    ))
                
                conn.commit()
                
        except Exception as e:
            logging.error(f"Failed to save campaign results: {e}")
    
    def _update_performance_metrics(self, campaign: MultiTargetCampaign, results: Dict[str, Any]):
        """Update performance metrics"""
        successful_targets = len([r for r in results.values() if r.get('success', False)])
        total_findings = sum(r.get('findings_count', 0) for r in results.values())
        
        campaign.metrics = {
            'success_rate': successful_targets / len(campaign.targets) * 100,
            'findings_per_target': total_findings / len(campaign.targets),
            'execution_efficiency': 1.0,  # Placeholder
            'resource_utilization': 0.85  # Placeholder
        }
        
        # Update global metrics
        self.performance_metrics['total_campaigns'] += 1
        if campaign.status == CampaignStatus.COMPLETED:
            self.performance_metrics['successful_campaigns'] += 1
        self.performance_metrics['total_findings'] += total_findings
    
    def get_campaign_status(self, campaign_id: str) -> Dict[str, Any]:
        """Get detailed campaign status"""
        if campaign_id not in self.active_campaigns:
            return {'error': 'Campaign not found'}
        
        campaign = self.active_campaigns[campaign_id]
        
        return {
            'id': campaign.id,
            'name': campaign.name,
            'status': campaign.status.value,
            'targets': campaign.targets,
            'progress': len(campaign.findings) / len(campaign.targets) * 100,
            'metrics': campaign.metrics,
            'gemini_insights': campaign.gemini_insights
        }
    
    def list_campaigns(self) -> List[Dict[str, Any]]:
        """List all campaigns with summary"""
        return [
            {
                'id': campaign.id,
                'name': campaign.name,
                'status': campaign.status.value,
                'target_count': len(campaign.targets),
                'priority': campaign.priority,
                'created_at': campaign.created_at.isoformat()
            }
            for campaign in self.active_campaigns.values()
        ]

async def demonstrate_multi_target_orchestrator():
    """Demonstrate advanced multi-target orchestration"""
    print("🚀 ADVANCED MULTI-TARGET GEMINI ORCHESTRATOR DEMONSTRATION")
    print("=" * 70)
    
    try:
        # Initialize orchestrator
        orchestrator = AdvancedMultiTargetOrchestrator()
        
        # Create test campaign
        targets = ["target1.example.com", "target2.example.com", "target3.example.com"]
        campaign_id = await orchestrator.create_campaign(
            name="Enterprise Security Assessment",
            targets=targets,
            priority=8,
            time_budget=6.0,
            risk_tolerance="medium"
        )
        
        print(f"📋 Created campaign: {campaign_id}")
        print(f"🎯 Targets: {len(targets)}")
        
        # Execute campaign
        results = await orchestrator.execute_campaign(campaign_id)
        
        print(f"\n✅ Campaign completed successfully!")
        print(f"⏱️  Execution time: {results['execution_time']:.2f} seconds")
        print(f"🎯 Targets processed: {results['targets_processed']}")
        
        # Show results summary
        successful_targets = len([r for r in results['target_results'].values() if r.get('success', False)])
        print(f"✅ Successful targets: {successful_targets}/{len(targets)}")
        
        if 'cross_correlations' in results and results['cross_correlations']:
            print(f"🔗 Cross-target correlations discovered")
        
        if 'final_analysis' in results and results['final_analysis']:
            print(f"🧠 Gemini strategic analysis completed")
        
        # Show campaign status
        status = orchestrator.get_campaign_status(campaign_id)
        print(f"\n📊 Final Status: {status['status']}")
        
        return results
        
    except Exception as e:
        print(f"❌ Demonstration failed: {e}")
        return None

if __name__ == "__main__":
    print("🧠 Advanced Multi-Target Gemini Orchestrator")
    
    if not CORE_SYSTEM_AVAILABLE:
        print("⚠️  Core system not available - running in simulation mode")
    
    results = asyncio.run(demonstrate_multi_target_orchestrator())
    
    if results:
        print(f"\n💫 Advanced orchestration completed successfully!")
    else:
        print(f"\n❌ Orchestration failed")
