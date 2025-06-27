#!/usr/bin/env python3
"""
🤝 HUMAN-IN-THE-LOOP (HITL) ESCALATION FRAMEWORK
🚨 Strategic AI decision escalation with human oversight
⚡ Critical action validation and expert intervention
🎯 Seamless human-AI collaboration for high-stakes decisions

Strategic Implementation of Expert Feedback Recommendation #2:
"Integrate Human-in-the-Loop (HITL) escalation framework for critical actions"
"""

import asyncio
import json
import logging
import sqlite3
import time
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Optional, Any, Callable, Tuple
from dataclasses import dataclass, field
# Email functionality would be imported in production
# import smtplib
# from email.mime.text import MimeText
# from email.mime.multipart import MimeMultipart


class EscalationLevel(Enum):
    """Levels of human escalation"""
    NONE = "none"
    NOTIFICATION = "notification"
    APPROVAL_REQUIRED = "approval_required"
    IMMEDIATE_HALT = "immediate_halt"
    EXPERT_CONSULTATION = "expert_consultation"


class DecisionRisk(Enum):
    """Risk levels for AI decisions"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    CATASTROPHIC = "catastrophic"


class HumanRole(Enum):
    """Human roles in the HITL system"""
    SECURITY_ANALYST = "security_analyst"
    SENIOR_PENTESTER = "senior_pentester"
    SECURITY_MANAGER = "security_manager"
    COMPLIANCE_OFFICER = "compliance_officer"
    TECHNICAL_LEAD = "technical_lead"


@dataclass
class EscalationRule:
    """Rule defining when and how to escalate to humans"""
    trigger_condition: str
    risk_threshold: DecisionRisk
    escalation_level: EscalationLevel
    target_roles: List[HumanRole]
    timeout_minutes: int
    fallback_action: str
    escalation_message: str


@dataclass
class HumanExpert:
    """Human expert in the HITL system"""
    expert_id: str
    name: str
    role: HumanRole
    contact_email: str
    contact_phone: Optional[str]
    expertise_areas: List[str]
    availability_schedule: Dict[str, Any]
    escalation_priority: int  # Lower number = higher priority


@dataclass
class EscalationRequest:
    """Request for human intervention"""
    request_id: str
    timestamp: datetime
    ai_decision: Dict[str, Any]
    escalation_reason: str
    risk_level: DecisionRisk
    required_roles: List[HumanRole]
    deadline: datetime
    context_data: Dict[str, Any]
    ai_recommendation: str
    alternative_options: List[Dict[str, Any]]
    status: str = "pending"
    assigned_expert: Optional[str] = None
    human_response: Optional[Dict[str, Any]] = None


class HumanInTheLoopFramework:
    """
    Advanced Human-in-the-Loop escalation framework for AI decisions.
    Ensures critical security decisions receive appropriate human oversight.
    """
    
    def __init__(self, db_path: str = "hitl_system.db"):
        self.db_path = db_path
        self.logger = self._setup_logging()
        self.experts: Dict[str, HumanExpert] = {}
        self.escalation_rules: List[EscalationRule] = []
        self.pending_escalations: Dict[str, EscalationRequest] = {}
        
        # Initialize database
        self._init_database()
        
        # Load default escalation rules
        self._load_default_escalation_rules()
        
        # Register default experts
        self._register_default_experts()
    
    def _setup_logging(self) -> logging.Logger:
        """Setup logging for HITL framework."""
        logger = logging.getLogger("HITL_Framework")
        logger.setLevel(logging.INFO)
        
        if not logger.handlers:
            handler = logging.StreamHandler()
            handler.setLevel(logging.INFO)
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        
        return logger
    
    def _init_database(self):
        """Initialize HITL database for tracking escalations and responses."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Escalation requests table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS escalation_requests (
                request_id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                ai_decision TEXT NOT NULL,
                escalation_reason TEXT NOT NULL,
                risk_level TEXT NOT NULL,
                required_roles TEXT NOT NULL,
                deadline TEXT NOT NULL,
                context_data TEXT,
                ai_recommendation TEXT,
                status TEXT DEFAULT 'pending',
                assigned_expert TEXT,
                human_response TEXT,
                resolution_time REAL,
                feedback_quality REAL
            )
        ''')
        
        # Human experts table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS human_experts (
                expert_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                role TEXT NOT NULL,
                contact_email TEXT NOT NULL,
                contact_phone TEXT,
                expertise_areas TEXT,
                availability_schedule TEXT,
                escalation_priority INTEGER,
                response_time_avg REAL,
                decision_quality_score REAL
            )
        ''')
        
        # Escalation performance metrics
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS escalation_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                escalation_count INTEGER,
                avg_response_time REAL,
                human_override_rate REAL,
                decision_accuracy REAL,
                expert_satisfaction_score REAL
            )
        ''')
        
        # Decision audit trail
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS decision_audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                decision_id TEXT NOT NULL,
                decision_type TEXT NOT NULL,
                ai_confidence REAL,
                human_involved BOOLEAN,
                final_decision TEXT,
                decision_rationale TEXT,
                outcome_quality REAL
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def _load_default_escalation_rules(self):
        """Load default escalation rules for common scenarios."""
        default_rules = [
            EscalationRule(
                trigger_condition="high_risk_target_selection",
                risk_threshold=DecisionRisk.HIGH,
                escalation_level=EscalationLevel.APPROVAL_REQUIRED,
                target_roles=[HumanRole.SENIOR_PENTESTER, HumanRole.SECURITY_MANAGER],
                timeout_minutes=30,
                fallback_action="select_lower_risk_targets",
                escalation_message="AI selected high-risk target requiring human approval"
            ),
            EscalationRule(
                trigger_condition="critical_vulnerability_exploitation",
                risk_threshold=DecisionRisk.CRITICAL,
                escalation_level=EscalationLevel.IMMEDIATE_HALT,
                target_roles=[HumanRole.SECURITY_MANAGER, HumanRole.COMPLIANCE_OFFICER],
                timeout_minutes=15,
                fallback_action="halt_all_operations",
                escalation_message="Critical vulnerability found - immediate human oversight required"
            ),
            EscalationRule(
                trigger_condition="scope_boundary_uncertainty",
                risk_threshold=DecisionRisk.MEDIUM,
                escalation_level=EscalationLevel.EXPERT_CONSULTATION,
                target_roles=[HumanRole.COMPLIANCE_OFFICER, HumanRole.SECURITY_MANAGER],
                timeout_minutes=60,
                fallback_action="apply_conservative_scope",
                escalation_message="Scope interpretation requires expert clarification"
            ),
            EscalationRule(
                trigger_condition="aggressive_scanning_proposal",
                risk_threshold=DecisionRisk.HIGH,
                escalation_level=EscalationLevel.APPROVAL_REQUIRED,
                target_roles=[HumanRole.SENIOR_PENTESTER],
                timeout_minutes=45,
                fallback_action="use_passive_scanning",
                escalation_message="AI proposes aggressive scanning techniques requiring approval"
            ),
            EscalationRule(
                trigger_condition="legal_compliance_risk",
                risk_threshold=DecisionRisk.HIGH,
                escalation_level=EscalationLevel.IMMEDIATE_HALT,
                target_roles=[HumanRole.COMPLIANCE_OFFICER, HumanRole.SECURITY_MANAGER],
                timeout_minutes=20,
                fallback_action="halt_scanning",
                escalation_message="Potential legal/compliance violation detected"
            )
        ]
        
        self.escalation_rules.extend(default_rules)
        self.logger.info(f"Loaded {len(default_rules)} default escalation rules")
    
    def _register_default_experts(self):
        """Register default human experts in the system."""
        default_experts = [
            HumanExpert(
                expert_id="analyst_001",
                name="Senior Security Analyst",
                role=HumanRole.SECURITY_ANALYST,
                contact_email="analyst@security-team.com",
                contact_phone="+1-555-0101",
                expertise_areas=["vulnerability_assessment", "risk_analysis", "compliance"],
                availability_schedule={"timezone": "UTC", "hours": "09:00-17:00"},
                escalation_priority=3
            ),
            HumanExpert(
                expert_id="pentester_001",
                name="Lead Penetration Tester",
                role=HumanRole.SENIOR_PENTESTER,
                contact_email="pentester@security-team.com",
                contact_phone="+1-555-0102",
                expertise_areas=["exploitation", "tool_selection", "target_assessment"],
                availability_schedule={"timezone": "UTC", "hours": "08:00-18:00"},
                escalation_priority=2
            ),
            HumanExpert(
                expert_id="manager_001",
                name="Security Manager",
                role=HumanRole.SECURITY_MANAGER,
                contact_email="manager@security-team.com",
                contact_phone="+1-555-0103",
                expertise_areas=["risk_management", "strategic_decisions", "resource_allocation"],
                availability_schedule={"timezone": "UTC", "hours": "08:00-17:00"},
                escalation_priority=1
            ),
            HumanExpert(
                expert_id="compliance_001",
                name="Compliance Officer",
                role=HumanRole.COMPLIANCE_OFFICER,
                contact_email="compliance@security-team.com",
                contact_phone="+1-555-0104",
                expertise_areas=["legal_compliance", "scope_validation", "regulatory_requirements"],
                availability_schedule={"timezone": "UTC", "hours": "09:00-16:00"},
                escalation_priority=1
            )
        ]
        
        for expert in default_experts:
            self.experts[expert.expert_id] = expert
            self._store_expert(expert)
        
        self.logger.info(f"Registered {len(default_experts)} human experts")
    
    def _store_expert(self, expert: HumanExpert):
        """Store expert information in database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO human_experts
            (expert_id, name, role, contact_email, contact_phone, 
             expertise_areas, availability_schedule, escalation_priority)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            expert.expert_id,
            expert.name,
            expert.role.value,
            expert.contact_email,
            expert.contact_phone,
            json.dumps(expert.expertise_areas),
            json.dumps(expert.availability_schedule),
            expert.escalation_priority
        ))
        
        conn.commit()
        conn.close()
    
    async def evaluate_escalation_need(
        self, 
        ai_decision: Dict[str, Any], 
        context: Dict[str, Any]
    ) -> Optional[EscalationRequest]:
        """
        Evaluate if an AI decision requires human escalation.
        
        Args:
            ai_decision: The AI's proposed decision
            context: Context information for the decision
            
        Returns:
            EscalationRequest if escalation needed, None otherwise
        """
        try:
            # Analyze decision risk
            risk_level = self._assess_decision_risk(ai_decision, context)
            
            # Check against escalation rules
            matching_rules = self._find_matching_escalation_rules(ai_decision, context, risk_level)
            
            if not matching_rules:
                return None
            
            # Select highest priority rule
            escalation_rule = min(matching_rules, key=lambda r: r.escalation_level.value)
            
            # Create escalation request
            request_id = f"escalation_{int(time.time())}_{hash(str(ai_decision)) % 10000}"
            
            escalation_request = EscalationRequest(
                request_id=request_id,
                timestamp=datetime.now(),
                ai_decision=ai_decision,
                escalation_reason=escalation_rule.escalation_message,
                risk_level=risk_level,
                required_roles=escalation_rule.target_roles,
                deadline=datetime.now() + timedelta(minutes=escalation_rule.timeout_minutes),
                context_data=context,
                ai_recommendation=ai_decision.get("recommendation", ""),
                alternative_options=ai_decision.get("alternatives", [])
            )
            
            # Store escalation request
            await self._store_escalation_request(escalation_request)
            
            self.logger.warning(
                f"Escalation required: {escalation_rule.escalation_message} "
                f"(Risk: {risk_level.value}, Timeout: {escalation_rule.timeout_minutes}m)"
            )
            
            return escalation_request
            
        except Exception as e:
            self.logger.error(f"Error evaluating escalation need: {str(e)}")
            return None
    
    def _assess_decision_risk(self, ai_decision: Dict[str, Any], context: Dict[str, Any]) -> DecisionRisk:
        """Assess the risk level of an AI decision."""
        risk_factors = []
        
        # Check confidence level
        confidence = ai_decision.get("confidence", 0.5)
        if confidence < 0.3:
            risk_factors.append("low_ai_confidence")
        
        # Check target criticality
        target_info = context.get("target_info", {})
        if target_info.get("criticality") == "high":
            risk_factors.append("high_criticality_target")
        
        # Check scope boundaries
        if context.get("scope_uncertainty", False):
            risk_factors.append("scope_uncertainty")
        
        # Check vulnerability severity
        vuln_severity = ai_decision.get("vulnerability_severity", "low")
        if vuln_severity in ["critical", "high"]:
            risk_factors.append("high_severity_finding")
        
        # Check resource requirements
        resource_usage = ai_decision.get("resource_usage", {})
        if resource_usage.get("aggressive_scanning", False):
            risk_factors.append("aggressive_techniques")
        
        # Check compliance implications
        if context.get("compliance_sensitive", False):
            risk_factors.append("compliance_risk")
        
        # Calculate overall risk
        risk_score = len(risk_factors)
        
        if risk_score >= 4:
            return DecisionRisk.CATASTROPHIC
        elif risk_score >= 3:
            return DecisionRisk.CRITICAL
        elif risk_score >= 2:
            return DecisionRisk.HIGH
        elif risk_score >= 1:
            return DecisionRisk.MEDIUM
        else:
            return DecisionRisk.LOW
    
    def _find_matching_escalation_rules(
        self, 
        ai_decision: Dict[str, Any], 
        context: Dict[str, Any], 
        risk_level: DecisionRisk
    ) -> List[EscalationRule]:
        """Find escalation rules that match the current situation."""
        matching_rules = []
        
        for rule in self.escalation_rules:
            # Check risk threshold
            risk_levels = [DecisionRisk.LOW, DecisionRisk.MEDIUM, DecisionRisk.HIGH, 
                          DecisionRisk.CRITICAL, DecisionRisk.CATASTROPHIC]
            if risk_levels.index(risk_level) < risk_levels.index(rule.risk_threshold):
                continue
            
            # Check trigger conditions
            if self._evaluate_trigger_condition(rule.trigger_condition, ai_decision, context):
                matching_rules.append(rule)
        
        return matching_rules
    
    def _evaluate_trigger_condition(
        self, 
        condition: str, 
        ai_decision: Dict[str, Any], 
        context: Dict[str, Any]
    ) -> bool:
        """Evaluate if a trigger condition is met."""
        condition_checks = {
            "high_risk_target_selection": lambda: (
                context.get("target_info", {}).get("criticality") == "high" or
                ai_decision.get("target_risk_score", 0) > 8.0
            ),
            "critical_vulnerability_exploitation": lambda: (
                ai_decision.get("vulnerability_severity") == "critical" or
                ai_decision.get("exploit_potential", False)
            ),
            "scope_boundary_uncertainty": lambda: (
                context.get("scope_uncertainty", False) or
                ai_decision.get("scope_confidence", 1.0) < 0.7
            ),
            "aggressive_scanning_proposal": lambda: (
                ai_decision.get("resource_usage", {}).get("aggressive_scanning", False) or
                ai_decision.get("scan_intensity", "low") in ["high", "aggressive"]
            ),
            "legal_compliance_risk": lambda: (
                context.get("compliance_sensitive", False) or
                ai_decision.get("compliance_risk", False)
            )
        }
        
        checker = condition_checks.get(condition)
        if checker:
            try:
                return checker()
            except Exception as e:
                self.logger.error(f"Error evaluating condition {condition}: {str(e)}")
                return False
        
        return False
    
    async def _store_escalation_request(self, request: EscalationRequest):
        """Store escalation request in database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO escalation_requests
            (request_id, timestamp, ai_decision, escalation_reason, risk_level,
             required_roles, deadline, context_data, ai_recommendation, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            request.request_id,
            request.timestamp.isoformat(),
            json.dumps(request.ai_decision),
            request.escalation_reason,
            request.risk_level.value,
            json.dumps([role.value for role in request.required_roles]),
            request.deadline.isoformat(),
            json.dumps(request.context_data),
            request.ai_recommendation,
            request.status
        ))
        
        conn.commit()
        conn.close()
        
        # Add to pending escalations
        self.pending_escalations[request.request_id] = request
    
    async def assign_escalation(self, request_id: str) -> Optional[HumanExpert]:
        """Assign an escalation to the most appropriate human expert."""
        if request_id not in self.pending_escalations:
            return None
        
        request = self.pending_escalations[request_id]
        
        # Find available experts with required roles
        available_experts = []
        for expert in self.experts.values():
            if expert.role in request.required_roles:
                # Check availability (simplified - would integrate with real calendar)
                if self._is_expert_available(expert):
                    available_experts.append(expert)
        
        if not available_experts:
            self.logger.warning(f"No available experts for escalation {request_id}")
            return None
        
        # Select expert based on priority and expertise match
        selected_expert = min(available_experts, key=lambda e: (
            e.escalation_priority,
            -len(set(e.expertise_areas) & set(self._extract_required_expertise(request)))
        ))
        
        # Assign expert to request
        request.assigned_expert = selected_expert.expert_id
        request.status = "assigned"
        
        # Update database
        await self._update_escalation_status(request_id, "assigned", selected_expert.expert_id)
        
        # Notify expert
        await self._notify_expert(selected_expert, request)
        
        self.logger.info(f"Assigned escalation {request_id} to {selected_expert.name}")
        return selected_expert
    
    def _is_expert_available(self, expert: HumanExpert) -> bool:
        """Check if expert is available (simplified implementation)."""
        # In a real implementation, this would check calendar systems, 
        # current workload, time zones, etc.
        current_hour = datetime.now().hour
        
        # Simple availability check based on schedule
        schedule = expert.availability_schedule.get("hours", "09:00-17:00")
        start_hour = int(schedule.split("-")[0].split(":")[0])
        end_hour = int(schedule.split("-")[1].split(":")[0])
        
        return start_hour <= current_hour <= end_hour
    
    def _extract_required_expertise(self, request: EscalationRequest) -> List[str]:
        """Extract required expertise areas from escalation request."""
        decision_type = request.ai_decision.get("decision_type", "")
        context_type = request.context_data.get("type", "")
        
        expertise_mapping = {
            "target_selection": ["target_assessment", "risk_analysis"],
            "tool_selection": ["tool_expertise", "technical_assessment"],
            "vulnerability_assessment": ["vulnerability_analysis", "exploitation"],
            "scope_validation": ["compliance", "legal_requirements"],
            "resource_allocation": ["resource_management", "strategic_planning"]
        }
        
        required_expertise = []
        for key, areas in expertise_mapping.items():
            if key in decision_type.lower() or key in context_type.lower():
                required_expertise.extend(areas)
        
        return required_expertise
    
    async def _update_escalation_status(self, request_id: str, status: str, expert_id: Optional[str] = None):
        """Update escalation status in database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        if expert_id:
            cursor.execute('''
                UPDATE escalation_requests 
                SET status = ?, assigned_expert = ?
                WHERE request_id = ?
            ''', (status, expert_id, request_id))
        else:
            cursor.execute('''
                UPDATE escalation_requests 
                SET status = ?
                WHERE request_id = ?
            ''', (status, request_id))
        
        conn.commit()
        conn.close()
    
    async def _notify_expert(self, expert: HumanExpert, request: EscalationRequest):
        """Notify expert about escalation (simplified implementation)."""
        # In a real implementation, this would send emails, SMS, Slack messages, etc.
        notification_message = f"""
        🚨 SECURITY ESCALATION REQUIRED 🚨
        
        Request ID: {request.request_id}
        Risk Level: {request.risk_level.value.upper()}
        Deadline: {request.deadline.strftime('%Y-%m-%d %H:%M:%S')}
        
        Reason: {request.escalation_reason}
        
        AI Recommendation: {request.ai_recommendation}
        
        Please review and respond via the HITL dashboard.
        """
        
        self.logger.info(f"NOTIFICATION SENT to {expert.name}: {notification_message}")
        
        # In production, implement actual notification:
        # - Email notification
        # - SMS for critical escalations
        # - Slack/Teams integration
        # - Dashboard alerts
    
    async def submit_human_response(
        self, 
        request_id: str, 
        expert_id: str, 
        decision: str, 
        rationale: str, 
        confidence: float = 0.9
    ) -> bool:
        """Submit human expert response to escalation."""
        if request_id not in self.pending_escalations:
            return False
        
        request = self.pending_escalations[request_id]
        
        if request.assigned_expert != expert_id:
            self.logger.warning(f"Expert {expert_id} not assigned to escalation {request_id}")
            return False
        
        # Create human response
        human_response = {
            "expert_id": expert_id,
            "decision": decision,
            "rationale": rationale,
            "confidence": confidence,
            "timestamp": datetime.now().isoformat(),
            "response_time": (datetime.now() - request.timestamp).total_seconds()
        }
        
        request.human_response = human_response
        request.status = "resolved"
        
        # Update database
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE escalation_requests
            SET status = ?, human_response = ?, resolution_time = ?
            WHERE request_id = ?
        ''', (
            "resolved",
            json.dumps(human_response),
            human_response["response_time"],
            request_id
        ))
        
        conn.commit()
        conn.close()
        
        # Remove from pending
        del self.pending_escalations[request_id]
        
        self.logger.info(f"Human response submitted for escalation {request_id}")
        return True
    
    async def get_escalation_dashboard_data(self) -> Dict[str, Any]:
        """Get data for the HITL dashboard."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Get pending escalations
        cursor.execute('''
            SELECT request_id, timestamp, escalation_reason, risk_level, 
                   required_roles, deadline, status
            FROM escalation_requests 
            WHERE status IN ('pending', 'assigned')
            ORDER BY deadline ASC
        ''')
        
        pending_escalations = []
        for row in cursor.fetchall():
            pending_escalations.append({
                "request_id": row[0],
                "timestamp": row[1],
                "reason": row[2],
                "risk_level": row[3],
                "required_roles": json.loads(row[4]),
                "deadline": row[5],
                "status": row[6]
            })
        
        # Get escalation statistics
        cursor.execute('''
            SELECT 
                COUNT(*) as total_escalations,
                AVG(resolution_time) as avg_resolution_time,
                COUNT(CASE WHEN status = 'resolved' THEN 1 END) as resolved_count
            FROM escalation_requests
            WHERE timestamp > datetime('now', '-7 days')
        ''')
        
        stats = cursor.fetchone()
        
        # Get expert performance
        cursor.execute('''
            SELECT 
                assigned_expert,
                COUNT(*) as assignments,
                AVG(resolution_time) as avg_response_time
            FROM escalation_requests
            WHERE assigned_expert IS NOT NULL
            AND timestamp > datetime('now', '-30 days')
            GROUP BY assigned_expert
        ''')
        
        expert_performance = {}
        for row in cursor.fetchall():
            expert_performance[row[0]] = {
                "assignments": row[1],
                "avg_response_time": row[2] or 0
            }
        
        conn.close()
        
        return {
            "pending_escalations": pending_escalations,
            "statistics": {
                "total_escalations_7d": stats[0] or 0,
                "avg_resolution_time": stats[1] or 0,
                "resolution_rate": (stats[2] or 0) / max(stats[0] or 1, 1)
            },
            "expert_performance": expert_performance,
            "available_experts": len([e for e in self.experts.values() if self._is_expert_available(e)])
        }
    
    async def create_hitl_dashboard(self) -> str:
        """Create HTML dashboard for HITL management."""
        dashboard_data = await self.get_escalation_dashboard_data()
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>HITL Dashboard - Human-in-the-Loop Management</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; background: #f0f2f5; }}
                .container {{ max-width: 1400px; margin: 0 auto; }}
                .header {{ text-align: center; color: #2c3e50; margin-bottom: 30px; }}
                .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 30px; }}
                .stat-card {{ background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); text-align: center; }}
                .stat-value {{ font-size: 2.5em; font-weight: bold; color: #3498db; }}
                .stat-label {{ color: #7f8c8d; font-size: 0.9em; margin-top: 5px; }}
                .escalations-section {{ background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 20px; }}
                .escalation-item {{ border: 1px solid #ddd; margin: 10px 0; padding: 15px; border-radius: 5px; }}
                .escalation-critical {{ border-left: 5px solid #e74c3c; background: #fadbd8; }}
                .escalation-high {{ border-left: 5px solid #f39c12; background: #fef9e7; }}
                .escalation-medium {{ border-left: 5px solid #f1c40f; background: #fcf3cf; }}
                .escalation-low {{ border-left: 5px solid #27ae60; background: #d5f4e6; }}
                .escalation-header {{ font-weight: bold; color: #2c3e50; }}
                .escalation-meta {{ color: #7f8c8d; font-size: 0.9em; margin: 5px 0; }}
                .deadline-urgent {{ color: #e74c3c; font-weight: bold; }}
                .deadline-warning {{ color: #f39c12; }}
                .deadline-normal {{ color: #27ae60; }}
                .expert-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; }}
                .expert-card {{ background: white; padding: 15px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
                .expert-available {{ border-left: 4px solid #27ae60; }}
                .expert-busy {{ border-left: 4px solid #e74c3c; }}
                .btn {{ padding: 10px 20px; background: #3498db; color: white; border: none; border-radius: 5px; cursor: pointer; text-decoration: none; display: inline-block; }}
                .btn:hover {{ background: #2980b9; }}
                .btn-danger {{ background: #e74c3c; }}
                .btn-danger:hover {{ background: #c0392b; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🤝 Human-in-the-Loop (HITL) Dashboard</h1>
                    <p>Strategic AI Decision Escalation & Expert Oversight</p>
                </div>
                
                <div class="stats-grid">
                    <div class="stat-card">
                        <div class="stat-value">{len(dashboard_data['pending_escalations'])}</div>
                        <div class="stat-label">Pending Escalations</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value">{dashboard_data['statistics']['total_escalations_7d']}</div>
                        <div class="stat-label">Escalations (7 Days)</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value">{dashboard_data['statistics']['avg_resolution_time']:.1f}m</div>
                        <div class="stat-label">Avg Resolution Time</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value">{dashboard_data['statistics']['resolution_rate']:.1%}</div>
                        <div class="stat-label">Resolution Rate</div>
                    </div>
                </div>
                
                <div class="escalations-section">
                    <h2>🚨 Active Escalations Requiring Human Intervention</h2>
        """
        
        if dashboard_data['pending_escalations']:
            for escalation in dashboard_data['pending_escalations']:
                # Determine urgency based on deadline
                deadline = datetime.fromisoformat(escalation['deadline'])
                time_remaining = (deadline - datetime.now()).total_seconds() / 60
                
                if time_remaining < 15:
                    deadline_class = "deadline-urgent"
                    urgency_text = "🔥 URGENT"
                elif time_remaining < 60:
                    deadline_class = "deadline-warning"
                    urgency_text = "⚠️ WARNING"
                else:
                    deadline_class = "deadline-normal"
                    urgency_text = "📋 NORMAL"
                
                risk_class = f"escalation-{escalation['risk_level'].lower()}"
                
                html_content += f"""
                    <div class="escalation-item {risk_class}">
                        <div class="escalation-header">
                            {escalation['request_id']} - {escalation['reason']}
                        </div>
                        <div class="escalation-meta">
                            Risk Level: <strong>{escalation['risk_level'].upper()}</strong> | 
                            Status: <strong>{escalation['status'].upper()}</strong> | 
                            Required Roles: {', '.join(escalation['required_roles'])}
                        </div>
                        <div class="escalation-meta {deadline_class}">
                            {urgency_text} Deadline: {deadline.strftime('%Y-%m-%d %H:%M:%S')} 
                            ({time_remaining:.0f} minutes remaining)
                        </div>
                        <div style="margin-top: 10px;">
                            <a href="#" class="btn">Review Details</a>
                            <a href="#" class="btn">Assign Expert</a>
                            <a href="#" class="btn btn-danger">Emergency Override</a>
                        </div>
                    </div>
                """
        else:
            html_content += """
                    <div style="text-align: center; color: #7f8c8d; padding: 40px;">
                        <h3>✅ No Active Escalations</h3>
                        <p>All AI decisions are operating within acceptable parameters</p>
                    </div>
            """
        
        html_content += """
                </div>
                
                <div class="escalations-section">
                    <h2>👥 Expert Availability & Performance</h2>
                    <div class="expert-grid">
        """
        
        for expert_id, expert in self.experts.items():
            is_available = self._is_expert_available(expert)
            availability_class = "expert-available" if is_available else "expert-busy"
            performance = dashboard_data['expert_performance'].get(expert_id, {})
            
            html_content += f"""
                        <div class="expert-card {availability_class}">
                            <h4>{expert.name}</h4>
                            <p><strong>Role:</strong> {expert.role.value.replace('_', ' ').title()}</p>
                            <p><strong>Status:</strong> {'🟢 Available' if is_available else '🔴 Busy'}</p>
                            <p><strong>Expertise:</strong> {', '.join(expert.expertise_areas[:3])}{'...' if len(expert.expertise_areas) > 3 else ''}</p>
                            <p><strong>Recent Assignments:</strong> {performance.get('assignments', 0)}</p>
                            <p><strong>Avg Response Time:</strong> {performance.get('avg_response_time', 0):.1f}m</p>
                            <div style="margin-top: 10px;">
                                <a href="mailto:{expert.contact_email}" class="btn">Contact</a>
                            </div>
                        </div>
            """
        
        html_content += f"""
                    </div>
                </div>
                
                <div style="margin-top: 30px; text-align: center; color: #7f8c8d;">
                    <p>Dashboard Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                    <p>HITL Framework ensures critical security decisions receive appropriate human oversight</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        # Save dashboard
        dashboard_path = "hitl_dashboard.html"
        with open(dashboard_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        self.logger.info(f"HITL dashboard created: {dashboard_path}")
        return dashboard_path


async def demonstrate_hitl_framework():
    """Demonstration of the Human-in-the-Loop escalation framework."""
    print("🤝 Human-in-the-Loop (HITL) Escalation Framework")
    print("=" * 70)
    
    # Initialize HITL framework
    hitl = HumanInTheLoopFramework()
    
    print("\n📋 Framework Initialized with:")
    print(f"- {len(hitl.experts)} human experts registered")
    print(f"- {len(hitl.escalation_rules)} escalation rules loaded")
    print(f"- Database initialized at: {hitl.db_path}")
    
    # Simulate AI decisions requiring escalation
    test_scenarios = [
        {
            "name": "High-Risk Target Selection",
            "ai_decision": {
                "decision_type": "target_selection",
                "selected_target": "api.banking-corp.com",
                "confidence": 0.65,
                "target_risk_score": 9.2,
                "recommendation": "Prioritize this target for comprehensive scanning"
            },
            "context": {
                "target_info": {"criticality": "high", "sector": "financial"},
                "scope_uncertainty": False,
                "compliance_sensitive": True
            }
        },
        {
            "name": "Critical Vulnerability Found",
            "ai_decision": {
                "decision_type": "vulnerability_assessment",
                "vulnerability_severity": "critical",
                "exploit_potential": True,
                "recommendation": "Immediate exploitation recommended for proof of concept"
            },
            "context": {
                "target_info": {"production_system": True},
                "compliance_sensitive": True
            }
        },
        {
            "name": "Aggressive Scanning Proposal",
            "ai_decision": {
                "decision_type": "tool_selection",
                "scan_intensity": "aggressive",
                "resource_usage": {"aggressive_scanning": True},
                "recommendation": "Deploy high-intensity scanning for maximum coverage"
            },
            "context": {
                "target_info": {"response_time_critical": True},
                "business_hours": True
            }
        }
    ]
    
    escalation_requests = []
    
    print("\n🚨 Testing Escalation Scenarios...")
    
    for i, scenario in enumerate(test_scenarios, 1):
        print(f"\n{i}. {scenario['name']}:")
        
        # Evaluate escalation need
        escalation = await hitl.evaluate_escalation_need(
            scenario['ai_decision'], 
            scenario['context']
        )
        
        if escalation:
            print(f"   ⚠️ Escalation Required: {escalation.escalation_reason}")
            print(f"   📊 Risk Level: {escalation.risk_level.value.upper()}")
            print(f"   👥 Required Roles: {[role.value for role in escalation.required_roles]}")
            print(f"   ⏰ Deadline: {escalation.deadline.strftime('%H:%M:%S')}")
            
            # Assign escalation to expert
            assigned_expert = await hitl.assign_escalation(escalation.request_id)
            if assigned_expert:
                print(f"   ✅ Assigned to: {assigned_expert.name} ({assigned_expert.role.value})")
            
            escalation_requests.append(escalation)
        else:
            print("   ✅ No escalation required - AI decision within acceptable parameters")
    
    # Simulate human responses
    print(f"\n📝 Simulating Human Expert Responses...")
    
    for escalation in escalation_requests[:2]:  # Respond to first 2 escalations
        expert_responses = [
            ("approved_with_conditions", "Approved with additional monitoring and rate limiting", 0.85),
            ("rejected", "Risk too high for current context, recommend alternative approach", 0.92),
            ("approved", "Proceed as recommended by AI after legal review", 0.78)
        ]
        
        decision, rationale, confidence = expert_responses[escalation_requests.index(escalation) % len(expert_responses)]
        
        success = await hitl.submit_human_response(
            escalation.request_id,
            escalation.assigned_expert,
            decision,
            rationale,
            confidence
        )
        
        if success:
            print(f"   ✅ Expert response recorded for {escalation.request_id}")
            print(f"      Decision: {decision}")
            print(f"      Rationale: {rationale[:60]}...")
    
    # Generate dashboard
    print(f"\n📊 Generating HITL Dashboard...")
    dashboard_path = await hitl.create_hitl_dashboard()
    print(f"   📄 Dashboard created: {dashboard_path}")
    
    # Display summary statistics
    dashboard_data = await hitl.get_escalation_dashboard_data()
    
    print(f"\n📈 HITL Framework Summary:")
    print(f"   - Pending Escalations: {len(dashboard_data['pending_escalations'])}")
    print(f"   - Available Experts: {dashboard_data['available_experts']}")
    print(f"   - Resolution Rate: {dashboard_data['statistics']['resolution_rate']:.1%}")
    print(f"   - Avg Resolution Time: {dashboard_data['statistics']['avg_resolution_time']:.1f} minutes")
    
    print(f"\n✅ Human-in-the-Loop Framework Demonstration Complete!")
    print(f"\nKey Features Demonstrated:")
    print(f"- Risk-based escalation triggers")
    print(f"- Expert assignment and notification")
    print(f"- Human response collection")
    print(f"- Real-time dashboard monitoring")
    print(f"- Performance metrics and analytics")
    print(f"- Comprehensive audit trail")
    
    return dashboard_path


if __name__ == "__main__":
    asyncio.run(demonstrate_hitl_framework())
