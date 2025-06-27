#!/usr/bin/env python3
"""
⚖️ DYNAMIC LEGAL & COMPLIANCE MODULE
📋 Automated Rules of Engagement (RoE) interpretation and enforcement
🛡️ Real-time compliance monitoring and legal boundary validation
🎯 Strategic implementation of Expert Feedback Recommendation #3

This module implements intelligent legal and compliance automation that:
- Dynamically interprets Rules of Engagement (RoE)
- Enforces legal boundaries in real-time
- Provides compliance validation for all AI decisions
- Maintains audit trails for regulatory requirements
- Adapts to changing legal frameworks and jurisdictions
"""

import asyncio
import json
import logging
import re
import sqlite3
import time
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
import hashlib


class ComplianceFramework(Enum):
    """Supported compliance frameworks"""
    GDPR = "gdpr"
    HIPAA = "hipaa"
    PCI_DSS = "pci_dss"
    SOX = "sox"
    ISO27001 = "iso27001"
    NIST = "nist"
    OWASP = "owasp"
    CCPA = "ccpa"
    SOC2 = "soc2"


class LegalJurisdiction(Enum):
    """Legal jurisdictions with different regulations"""
    US = "united_states"
    EU = "european_union"
    UK = "united_kingdom"
    CANADA = "canada"
    AUSTRALIA = "australia"
    SINGAPORE = "singapore"
    GLOBAL = "global"


class ComplianceLevel(Enum):
    """Compliance requirement levels"""
    MANDATORY = "mandatory"
    RECOMMENDED = "recommended"
    OPTIONAL = "optional"
    PROHIBITED = "prohibited"


class RiskClassification(Enum):
    """Risk classifications for compliance assessment"""
    COMPLIANT = "compliant"
    LOW_RISK = "low_risk"
    MEDIUM_RISK = "medium_risk"
    HIGH_RISK = "high_risk"
    VIOLATION = "violation"


@dataclass
class ComplianceRule:
    """Individual compliance rule definition"""
    rule_id: str
    framework: ComplianceFramework
    jurisdiction: LegalJurisdiction
    title: str
    description: str
    requirement_level: ComplianceLevel
    applicable_actions: List[str]
    prohibited_actions: List[str]
    conditions: Dict[str, Any]
    penalties: Dict[str, str]
    last_updated: datetime


@dataclass
class RulesOfEngagement:
    """Parsed and structured Rules of Engagement"""
    document_id: str
    client_name: str
    scope_definition: Dict[str, Any]
    authorized_actions: List[str]
    prohibited_actions: List[str]
    time_restrictions: Dict[str, Any]
    target_restrictions: Dict[str, Any]
    technical_constraints: Dict[str, Any]
    reporting_requirements: Dict[str, Any]
    emergency_contacts: List[Dict[str, str]]
    legal_framework: LegalJurisdiction
    compliance_requirements: List[ComplianceFramework]
    expiration_date: Optional[datetime]
    digital_signature_hash: str


@dataclass
class ComplianceAssessment:
    """Result of compliance assessment"""
    assessment_id: str
    timestamp: datetime
    proposed_action: Dict[str, Any]
    risk_classification: RiskClassification
    compliance_status: bool
    violated_rules: List[str]
    warnings: List[str]
    recommendations: List[str]
    required_approvals: List[str]
    mitigation_strategies: List[str]
    confidence_score: float


class DynamicLegalComplianceModule:
    """
    Advanced legal and compliance module that provides real-time validation
    of AI decisions against Rules of Engagement and regulatory frameworks.
    """
    
    def __init__(self, db_path: str = "legal_compliance.db"):
        self.db_path = db_path
        self.logger = self._setup_logging()
        
        # In-memory compliance rules cache
        self.compliance_rules: Dict[str, ComplianceRule] = {}
        self.active_roe: Optional[RulesOfEngagement] = None
        
        # Initialize database
        self._init_database()
        
        # Load default compliance rules
        self._load_default_compliance_rules()
        
        # Initialize compliance frameworks
        self._initialize_compliance_frameworks()
    
    def _setup_logging(self) -> logging.Logger:
        """Setup logging for compliance module."""
        logger = logging.getLogger("ComplianceModule")
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
        """Initialize compliance database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Compliance rules table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS compliance_rules (
                rule_id TEXT PRIMARY KEY,
                framework TEXT NOT NULL,
                jurisdiction TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT,
                requirement_level TEXT NOT NULL,
                applicable_actions TEXT,
                prohibited_actions TEXT,
                conditions TEXT,
                penalties TEXT,
                last_updated TEXT
            )
        ''')
        
        # Rules of Engagement table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS rules_of_engagement (
                document_id TEXT PRIMARY KEY,
                client_name TEXT NOT NULL,
                scope_definition TEXT,
                authorized_actions TEXT,
                prohibited_actions TEXT,
                time_restrictions TEXT,
                target_restrictions TEXT,
                technical_constraints TEXT,
                reporting_requirements TEXT,
                emergency_contacts TEXT,
                legal_framework TEXT,
                compliance_requirements TEXT,
                expiration_date TEXT,
                digital_signature_hash TEXT,
                created_at TEXT,
                status TEXT DEFAULT 'active'
            )
        ''')
        
        # Compliance assessments table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS compliance_assessments (
                assessment_id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                proposed_action TEXT,
                risk_classification TEXT,
                compliance_status BOOLEAN,
                violated_rules TEXT,
                warnings TEXT,
                recommendations TEXT,
                required_approvals TEXT,
                mitigation_strategies TEXT,
                confidence_score REAL,
                resolution_status TEXT DEFAULT 'pending'
            )
        ''')
        
        # Compliance violations audit
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS compliance_violations (
                violation_id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                violation_type TEXT,
                severity TEXT,
                description TEXT,
                affected_systems TEXT,
                remediation_actions TEXT,
                responsible_party TEXT,
                resolution_date TEXT,
                lessons_learned TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def _load_default_compliance_rules(self):
        """Load default compliance rules for common frameworks."""
        default_rules = [
            # GDPR Rules
            ComplianceRule(
                rule_id="GDPR_001",
                framework=ComplianceFramework.GDPR,
                jurisdiction=LegalJurisdiction.EU,
                title="Personal Data Protection",
                description="Processing of personal data must have legal basis and data subject consent",
                requirement_level=ComplianceLevel.MANDATORY,
                applicable_actions=["data_collection", "data_processing", "data_storage"],
                prohibited_actions=["unauthorized_data_access", "data_transfer_non_eu"],
                conditions={"data_type": "personal", "explicit_consent": True},
                penalties={"fine": "4% of annual revenue or €20M", "criminal": "possible"},
                last_updated=datetime.now()
            ),
            
            # PCI-DSS Rules
            ComplianceRule(
                rule_id="PCI_001",
                framework=ComplianceFramework.PCI_DSS,
                jurisdiction=LegalJurisdiction.GLOBAL,
                title="Cardholder Data Protection",
                description="Cardholder data must be protected with encryption and access controls",
                requirement_level=ComplianceLevel.MANDATORY,
                applicable_actions=["payment_processing", "card_data_handling"],
                prohibited_actions=["unencrypted_card_storage", "unauthorized_card_access"],
                conditions={"data_type": "payment_card", "encryption": "required"},
                penalties={"fine": "$100K+ per incident", "license_revocation": "possible"},
                last_updated=datetime.now()
            ),
            
            # HIPAA Rules
            ComplianceRule(
                rule_id="HIPAA_001",
                framework=ComplianceFramework.HIPAA,
                jurisdiction=LegalJurisdiction.US,
                title="Protected Health Information",
                description="PHI must be protected with appropriate safeguards",
                requirement_level=ComplianceLevel.MANDATORY,
                applicable_actions=["health_data_processing", "medical_records_access"],
                prohibited_actions=["phi_disclosure", "unauthorized_health_access"],
                conditions={"data_type": "health", "minimum_necessary": True},
                penalties={"fine": "$100 to $50K per incident", "criminal": "up to 10 years"},
                last_updated=datetime.now()
            ),
            
            # Bug Bounty Specific Rules
            ComplianceRule(
                rule_id="BB_001",
                framework=ComplianceFramework.OWASP,
                jurisdiction=LegalJurisdiction.GLOBAL,
                title="Authorized Testing Only",
                description="Security testing must be within authorized scope",
                requirement_level=ComplianceLevel.MANDATORY,
                applicable_actions=["vulnerability_scanning", "penetration_testing"],
                prohibited_actions=["out_of_scope_testing", "data_exfiltration"],
                conditions={"written_authorization": True, "scope_defined": True},
                penalties={"civil": "damages", "criminal": "unauthorized access charges"},
                last_updated=datetime.now()
            ),
            
            ComplianceRule(
                rule_id="BB_002",
                framework=ComplianceFramework.OWASP,
                jurisdiction=LegalJurisdiction.GLOBAL,
                title="No Data Exploitation",
                description="Testing must not involve actual data exploitation",
                requirement_level=ComplianceLevel.MANDATORY,
                applicable_actions=["proof_of_concept", "vulnerability_validation"],
                prohibited_actions=["data_download", "data_modification", "data_deletion"],
                conditions={"read_only_access": True, "no_data_extraction": True},
                penalties={"immediate_termination": "yes", "legal_action": "possible"},
                last_updated=datetime.now()
            )
        ]
        
        for rule in default_rules:
            self.compliance_rules[rule.rule_id] = rule
            self._store_compliance_rule(rule)
        
        self.logger.info(f"Loaded {len(default_rules)} default compliance rules")
    
    def _store_compliance_rule(self, rule: ComplianceRule):
        """Store compliance rule in database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO compliance_rules
            (rule_id, framework, jurisdiction, title, description, requirement_level,
             applicable_actions, prohibited_actions, conditions, penalties, last_updated)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            rule.rule_id,
            rule.framework.value,
            rule.jurisdiction.value,
            rule.title,
            rule.description,
            rule.requirement_level.value,
            json.dumps(rule.applicable_actions),
            json.dumps(rule.prohibited_actions),
            json.dumps(rule.conditions),
            json.dumps(rule.penalties),
            rule.last_updated.isoformat()
        ))
        
        conn.commit()
        conn.close()
    
    def _initialize_compliance_frameworks(self):
        """Initialize framework-specific validation logic."""
        self.framework_validators = {
            ComplianceFramework.GDPR: self._validate_gdpr_compliance,
            ComplianceFramework.PCI_DSS: self._validate_pci_compliance,
            ComplianceFramework.HIPAA: self._validate_hipaa_compliance,
            ComplianceFramework.OWASP: self._validate_owasp_compliance
        }
        
        self.logger.info("Initialized compliance framework validators")
    
    async def load_rules_of_engagement(self, roe_document: Dict[str, Any]) -> str:
        """Load and parse Rules of Engagement document."""
        try:
            # Parse RoE document
            roe = RulesOfEngagement(
                document_id=roe_document.get("document_id", f"roe_{int(time.time())}"),
                client_name=roe_document.get("client_name", "Unknown Client"),
                scope_definition=roe_document.get("scope", {}),
                authorized_actions=roe_document.get("authorized_actions", []),
                prohibited_actions=roe_document.get("prohibited_actions", []),
                time_restrictions=roe_document.get("time_restrictions", {}),
                target_restrictions=roe_document.get("target_restrictions", {}),
                technical_constraints=roe_document.get("technical_constraints", {}),
                reporting_requirements=roe_document.get("reporting_requirements", {}),
                emergency_contacts=roe_document.get("emergency_contacts", []),
                legal_framework=LegalJurisdiction(roe_document.get("jurisdiction", "global")),
                compliance_requirements=[ComplianceFramework(f) for f in roe_document.get("compliance_frameworks", [])],
                expiration_date=datetime.fromisoformat(roe_document["expiration_date"]) if roe_document.get("expiration_date") else None,
                digital_signature_hash=self._generate_roe_hash(roe_document)
            )
            
            # Validate RoE
            validation_result = await self._validate_roe(roe)
            if not validation_result["valid"]:
                raise ValueError(f"Invalid RoE: {validation_result['errors']}")
            
            # Store RoE
            await self._store_roe(roe)
            
            # Set as active RoE
            self.active_roe = roe
            
            self.logger.info(f"Loaded Rules of Engagement: {roe.document_id} for {roe.client_name}")
            return roe.document_id
            
        except Exception as e:
            self.logger.error(f"Error loading RoE: {str(e)}")
            raise
    
    def _generate_roe_hash(self, roe_document: Dict[str, Any]) -> str:
        """Generate cryptographic hash for RoE integrity."""
        # Remove dynamic fields for consistent hashing
        static_content = {k: v for k, v in roe_document.items() 
                         if k not in ["timestamp", "signature", "document_id"]}
        
        content_json = json.dumps(static_content, sort_keys=True, separators=(',', ':'))
        return hashlib.sha256(content_json.encode('utf-8')).hexdigest()
    
    async def _validate_roe(self, roe: RulesOfEngagement) -> Dict[str, Any]:
        """Validate Rules of Engagement for completeness and consistency."""
        errors = []
        warnings = []
        
        # Check required fields
        if not roe.client_name:
            errors.append("Client name is required")
        
        if not roe.scope_definition:
            errors.append("Scope definition is required")
        
        if not roe.authorized_actions:
            warnings.append("No authorized actions specified")
        
        # Check scope definition
        scope = roe.scope_definition
        if "domains" not in scope and "ip_ranges" not in scope:
            errors.append("Scope must include either domains or IP ranges")
        
        # Check time restrictions
        if roe.time_restrictions:
            if "timezone" not in roe.time_restrictions:
                warnings.append("Timezone not specified for time restrictions")
        
        # Check expiration
        if roe.expiration_date and roe.expiration_date < datetime.now():
            errors.append("RoE has expired")
        
        # Check compliance requirements
        if not roe.compliance_requirements:
            warnings.append("No compliance frameworks specified")
        
        return {
            "valid": len(errors) == 0,
            "errors": errors,
            "warnings": warnings
        }
    
    async def _store_roe(self, roe: RulesOfEngagement):
        """Store Rules of Engagement in database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO rules_of_engagement
            (document_id, client_name, scope_definition, authorized_actions,
             prohibited_actions, time_restrictions, target_restrictions,
             technical_constraints, reporting_requirements, emergency_contacts,
             legal_framework, compliance_requirements, expiration_date,
             digital_signature_hash, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            roe.document_id,
            roe.client_name,
            json.dumps(roe.scope_definition),
            json.dumps(roe.authorized_actions),
            json.dumps(roe.prohibited_actions),
            json.dumps(roe.time_restrictions),
            json.dumps(roe.target_restrictions),
            json.dumps(roe.technical_constraints),
            json.dumps(roe.reporting_requirements),
            json.dumps(roe.emergency_contacts),
            roe.legal_framework.value,
            json.dumps([f.value for f in roe.compliance_requirements]),
            roe.expiration_date.isoformat() if roe.expiration_date else None,
            roe.digital_signature_hash,
            datetime.now().isoformat()
        ))
        
        conn.commit()
        conn.close()
    
    async def assess_compliance(self, proposed_action: Dict[str, Any]) -> ComplianceAssessment:
        """
        Assess compliance of a proposed AI action against all applicable rules.
        
        Args:
            proposed_action: The action the AI wants to take
            
        Returns:
            ComplianceAssessment with detailed compliance analysis
        """
        try:
            assessment_id = f"assessment_{int(time.time())}_{hash(str(proposed_action)) % 10000}"
            timestamp = datetime.now()
            
            # Check if RoE is loaded
            if not self.active_roe:
                return ComplianceAssessment(
                    assessment_id=assessment_id,
                    timestamp=timestamp,
                    proposed_action=proposed_action,
                    risk_classification=RiskClassification.VIOLATION,
                    compliance_status=False,
                    violated_rules=["NO_ROE"],
                    warnings=["No Rules of Engagement loaded"],
                    recommendations=["Load valid RoE before proceeding"],
                    required_approvals=["legal_team"],
                    mitigation_strategies=["Halt all operations until RoE is provided"],
                    confidence_score=1.0
                )
            
            # Initialize assessment variables
            violated_rules = []
            warnings = []
            recommendations = []
            required_approvals = []
            mitigation_strategies = []
            
            # 1. Check RoE compliance
            roe_violations = await self._check_roe_compliance(proposed_action)
            violated_rules.extend(roe_violations)
            
            # 2. Check scope compliance
            scope_issues = await self._check_scope_compliance(proposed_action)
            if scope_issues:
                violated_rules.extend(scope_issues["violations"])
                warnings.extend(scope_issues["warnings"])
            
            # 3. Check time restrictions
            time_issues = await self._check_time_compliance(proposed_action)
            if time_issues:
                violated_rules.extend(time_issues)
            
            # 4. Check framework-specific compliance
            framework_issues = await self._check_framework_compliance(proposed_action)
            violated_rules.extend(framework_issues)
            
            # 5. Check technical constraints
            tech_issues = await self._check_technical_compliance(proposed_action)
            if tech_issues:
                warnings.extend(tech_issues)
            
            # Determine risk classification
            risk_classification = self._calculate_risk_classification(
                violated_rules, warnings, proposed_action
            )
            
            # Generate recommendations
            if violated_rules:
                recommendations.extend([
                    "Review and modify proposed action to address violations",
                    "Consult legal team before proceeding",
                    "Consider alternative approaches within scope"
                ])
                required_approvals.extend(["legal_team", "security_manager"])
            
            if risk_classification in [RiskClassification.HIGH_RISK, RiskClassification.VIOLATION]:
                mitigation_strategies.extend([
                    "Implement additional safeguards",
                    "Increase monitoring and logging",
                    "Establish emergency stop procedures"
                ])
            
            # Calculate confidence score
            confidence_score = self._calculate_compliance_confidence(
                proposed_action, violated_rules, warnings
            )
            
            # Create assessment
            assessment = ComplianceAssessment(
                assessment_id=assessment_id,
                timestamp=timestamp,
                proposed_action=proposed_action,
                risk_classification=risk_classification,
                compliance_status=len(violated_rules) == 0,
                violated_rules=violated_rules,
                warnings=warnings,
                recommendations=recommendations,
                required_approvals=required_approvals,
                mitigation_strategies=mitigation_strategies,
                confidence_score=confidence_score
            )
            
            # Store assessment
            await self._store_assessment(assessment)
            
            self.logger.info(
                f"Compliance assessment completed: {assessment_id} "
                f"(Status: {'COMPLIANT' if assessment.compliance_status else 'NON-COMPLIANT'}, "
                f"Risk: {risk_classification.value})"
            )
            
            return assessment
            
        except Exception as e:
            self.logger.error(f"Error in compliance assessment: {str(e)}")
            # Return safe default assessment
            return ComplianceAssessment(
                assessment_id=f"error_{int(time.time())}",
                timestamp=datetime.now(),
                proposed_action=proposed_action,
                risk_classification=RiskClassification.VIOLATION,
                compliance_status=False,
                violated_rules=["ASSESSMENT_ERROR"],
                warnings=[f"Assessment failed: {str(e)}"],
                recommendations=["Manual legal review required"],
                required_approvals=["legal_team", "security_manager"],
                mitigation_strategies=["Halt operations pending manual review"],
                confidence_score=0.0
            )
    
    async def _check_roe_compliance(self, proposed_action: Dict[str, Any]) -> List[str]:
        """Check compliance against Rules of Engagement."""
        violations = []
        
        if not self.active_roe:
            return ["NO_ACTIVE_ROE"]
        
        action_type = proposed_action.get("action_type", "")
        target = proposed_action.get("target", "")
        
        # Check authorized actions
        if action_type and action_type not in self.active_roe.authorized_actions:
            if "all_security_testing" not in self.active_roe.authorized_actions:
                violations.append(f"UNAUTHORIZED_ACTION_{action_type}")
        
        # Check prohibited actions
        if action_type in self.active_roe.prohibited_actions:
            violations.append(f"PROHIBITED_ACTION_{action_type}")
        
        # Check target restrictions
        if target and self.active_roe.target_restrictions:
            if not self._is_target_authorized(target, self.active_roe.target_restrictions):
                violations.append(f"UNAUTHORIZED_TARGET_{target}")
        
        return violations
    
    async def _check_scope_compliance(self, proposed_action: Dict[str, Any]) -> Optional[Dict[str, List[str]]]:
        """Check if action is within defined scope."""
        if not self.active_roe or not self.active_roe.scope_definition:
            return None
        
        violations = []
        warnings = []
        
        target = proposed_action.get("target", "")
        scope = self.active_roe.scope_definition
        
        # Check domain scope
        if "domains" in scope and target:
            authorized_domains = scope["domains"]
            if not any(domain in target for domain in authorized_domains):
                violations.append(f"OUT_OF_SCOPE_DOMAIN_{target}")
        
        # Check IP range scope
        if "ip_ranges" in scope and target:
            # Simplified IP range check (would need proper CIDR validation in production)
            if self._is_ip_address(target):
                if not self._is_ip_in_ranges(target, scope["ip_ranges"]):
                    violations.append(f"OUT_OF_SCOPE_IP_{target}")
        
        # Check subdomain restrictions
        if "include_subdomains" in scope and not scope["include_subdomains"]:
            if target and "." in target and target.count(".") > 1:
                warnings.append(f"SUBDOMAIN_WARNING_{target}")
        
        return {"violations": violations, "warnings": warnings} if violations or warnings else None
    
    async def _check_time_compliance(self, proposed_action: Dict[str, Any]) -> List[str]:
        """Check time-based restrictions."""
        violations = []
        
        if not self.active_roe or not self.active_roe.time_restrictions:
            return violations
        
        now = datetime.now()
        time_restrictions = self.active_roe.time_restrictions
        
        # Check testing hours
        if "allowed_hours" in time_restrictions:
            allowed_hours = time_restrictions["allowed_hours"]
            current_hour = now.hour
            
            if "start" in allowed_hours and "end" in allowed_hours:
                start_hour = int(allowed_hours["start"].split(":")[0])
                end_hour = int(allowed_hours["end"].split(":")[0])
                
                if not (start_hour <= current_hour <= end_hour):
                    violations.append(f"OUTSIDE_ALLOWED_HOURS_{current_hour}")
        
        # Check business days
        if "business_days_only" in time_restrictions and time_restrictions["business_days_only"]:
            if now.weekday() >= 5:  # Saturday = 5, Sunday = 6
                violations.append("WEEKEND_TESTING_PROHIBITED")
        
        # Check blackout periods
        if "blackout_periods" in time_restrictions:
            for blackout in time_restrictions["blackout_periods"]:
                start_date = datetime.fromisoformat(blackout["start"])
                end_date = datetime.fromisoformat(blackout["end"])
                
                if start_date <= now <= end_date:
                    violations.append(f"BLACKOUT_PERIOD_{blackout.get('reason', 'unknown')}")
        
        return violations
    
    async def _check_framework_compliance(self, proposed_action: Dict[str, Any]) -> List[str]:
        """Check compliance against specific frameworks."""
        violations = []
        
        if not self.active_roe:
            return violations
        
        for framework in self.active_roe.compliance_requirements:
            if framework in self.framework_validators:
                framework_violations = await self.framework_validators[framework](proposed_action)
                violations.extend(framework_violations)
        
        return violations
    
    async def _check_technical_compliance(self, proposed_action: Dict[str, Any]) -> List[str]:
        """Check technical constraints compliance."""
        warnings = []
        
        if not self.active_roe or not self.active_roe.technical_constraints:
            return warnings
        
        constraints = self.active_roe.technical_constraints
        
        # Check rate limiting
        if "rate_limit" in constraints:
            proposed_rate = proposed_action.get("requests_per_second", 0)
            max_rate = constraints["rate_limit"]
            
            if proposed_rate > max_rate:
                warnings.append(f"RATE_LIMIT_EXCEEDED_{proposed_rate}>{max_rate}")
        
        # Check concurrent connections
        if "max_connections" in constraints:
            proposed_connections = proposed_action.get("max_connections", 1)
            max_connections = constraints["max_connections"]
            
            if proposed_connections > max_connections:
                warnings.append(f"CONNECTION_LIMIT_EXCEEDED_{proposed_connections}>{max_connections}")
        
        # Check tool restrictions
        if "prohibited_tools" in constraints:
            proposed_tool = proposed_action.get("tool", "")
            if proposed_tool in constraints["prohibited_tools"]:
                warnings.append(f"PROHIBITED_TOOL_{proposed_tool}")
        
        return warnings
    
    def _is_target_authorized(self, target: str, restrictions: Dict[str, Any]) -> bool:
        """Check if target is authorized based on restrictions."""
        # Simplified target authorization check
        if "allowed_targets" in restrictions:
            return any(allowed in target for allowed in restrictions["allowed_targets"])
        
        if "blocked_targets" in restrictions:
            return not any(blocked in target for blocked in restrictions["blocked_targets"])
        
        return True  # Default allow if no restrictions
    
    def _is_ip_address(self, target: str) -> bool:
        """Check if target is an IP address."""
        import re
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        return bool(re.match(ip_pattern, target))
    
    def _is_ip_in_ranges(self, ip: str, ranges: List[str]) -> bool:
        """Check if IP is in allowed ranges (simplified)."""
        # In production, use proper CIDR calculation
        for ip_range in ranges:
            if ip_range in ip or ip in ip_range:
                return True
        return False
    
    def _calculate_risk_classification(
        self, 
        violations: List[str], 
        warnings: List[str], 
        proposed_action: Dict[str, Any]
    ) -> RiskClassification:
        """Calculate overall risk classification."""
        if any("VIOLATION" in v or "PROHIBITED" in v for v in violations):
            return RiskClassification.VIOLATION
        
        if len(violations) >= 2:
            return RiskClassification.HIGH_RISK
        
        if len(violations) == 1:
            return RiskClassification.MEDIUM_RISK
        
        if len(warnings) >= 2:
            return RiskClassification.LOW_RISK
        
        return RiskClassification.COMPLIANT
    
    def _calculate_compliance_confidence(
        self, 
        proposed_action: Dict[str, Any], 
        violations: List[str], 
        warnings: List[str]
    ) -> float:
        """Calculate confidence score for compliance assessment."""
        base_confidence = 0.9
        
        # Reduce confidence for each issue
        confidence_reduction = len(violations) * 0.2 + len(warnings) * 0.1
        
        # Reduce confidence for incomplete action data
        action_completeness = len([v for v in proposed_action.values() if v]) / max(len(proposed_action), 1)
        confidence_reduction += (1 - action_completeness) * 0.3
        
        return max(0.0, base_confidence - confidence_reduction)
    
    async def _store_assessment(self, assessment: ComplianceAssessment):
        """Store compliance assessment in database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO compliance_assessments
            (assessment_id, timestamp, proposed_action, risk_classification,
             compliance_status, violated_rules, warnings, recommendations,
             required_approvals, mitigation_strategies, confidence_score)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            assessment.assessment_id,
            assessment.timestamp.isoformat(),
            json.dumps(assessment.proposed_action),
            assessment.risk_classification.value,
            assessment.compliance_status,
            json.dumps(assessment.violated_rules),
            json.dumps(assessment.warnings),
            json.dumps(assessment.recommendations),
            json.dumps(assessment.required_approvals),
            json.dumps(assessment.mitigation_strategies),
            assessment.confidence_score
        ))
        
        conn.commit()
        conn.close()
    
    # Framework-specific validators
    async def _validate_gdpr_compliance(self, proposed_action: Dict[str, Any]) -> List[str]:
        """Validate GDPR compliance."""
        violations = []
        
        # Check for personal data handling
        if "data_type" in proposed_action and "personal" in proposed_action["data_type"]:
            if not proposed_action.get("explicit_consent", False):
                violations.append("GDPR_NO_CONSENT")
            
            if proposed_action.get("data_transfer_location") and "non-eu" in proposed_action["data_transfer_location"]:
                violations.append("GDPR_ILLEGAL_TRANSFER")
        
        return violations
    
    async def _validate_pci_compliance(self, proposed_action: Dict[str, Any]) -> List[str]:
        """Validate PCI-DSS compliance."""
        violations = []
        
        # Check for payment card data
        if "data_type" in proposed_action and "payment" in proposed_action["data_type"]:
            if not proposed_action.get("encryption_enabled", False):
                violations.append("PCI_UNENCRYPTED_DATA")
        
        return violations
    
    async def _validate_hipaa_compliance(self, proposed_action: Dict[str, Any]) -> List[str]:
        """Validate HIPAA compliance."""
        violations = []
        
        # Check for health information
        if "data_type" in proposed_action and "health" in proposed_action["data_type"]:
            if not proposed_action.get("minimum_necessary", False):
                violations.append("HIPAA_EXCESSIVE_ACCESS")
        
        return violations
    
    async def _validate_owasp_compliance(self, proposed_action: Dict[str, Any]) -> List[str]:
        """Validate OWASP/Bug Bounty compliance."""
        violations = []
        
        # Check for data exploitation
        if proposed_action.get("action_type") in ["data_download", "data_modification"]:
            violations.append("OWASP_DATA_EXPLOITATION")
        
        # Check for denial of service
        if proposed_action.get("requests_per_second", 0) > 100:
            violations.append("OWASP_POTENTIAL_DOS")
        
        return violations
    
    async def create_compliance_dashboard(self) -> str:
        """Create HTML dashboard for compliance monitoring."""
        # Get recent assessments
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT assessment_id, timestamp, risk_classification, compliance_status,
                   violated_rules, warnings, confidence_score
            FROM compliance_assessments
            ORDER BY timestamp DESC LIMIT 20
        ''')
        
        recent_assessments = []
        for row in cursor.fetchall():
            recent_assessments.append({
                "assessment_id": row[0],
                "timestamp": row[1],
                "risk_classification": row[2],
                "compliance_status": row[3],
                "violated_rules": json.loads(row[4]) if row[4] else [],
                "warnings": json.loads(row[5]) if row[5] else [],
                "confidence_score": row[6]
            })
        
        # Calculate statistics
        total_assessments = len(recent_assessments)
        compliant_assessments = sum(1 for a in recent_assessments if a["compliance_status"])
        compliance_rate = (compliant_assessments / max(total_assessments, 1)) * 100
        
        conn.close()
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Legal & Compliance Dashboard</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; background: #f8f9fa; }}
                .container {{ max-width: 1400px; margin: 0 auto; }}
                .header {{ text-align: center; color: #2c3e50; margin-bottom: 30px; }}
                .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 30px; }}
                .stat-card {{ background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); text-align: center; }}
                .stat-value {{ font-size: 2.5em; font-weight: bold; color: #27ae60; }}
                .stat-value.warning {{ color: #f39c12; }}
                .stat-value.danger {{ color: #e74c3c; }}
                .stat-label {{ color: #7f8c8d; font-size: 0.9em; margin-top: 5px; }}
                .roe-info {{ background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 20px; }}
                .assessment-list {{ background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
                .assessment-item {{ border: 1px solid #ddd; margin: 10px 0; padding: 15px; border-radius: 5px; }}
                .assessment-compliant {{ border-left: 5px solid #27ae60; background: #d5f4e6; }}
                .assessment-violation {{ border-left: 5px solid #e74c3c; background: #fadbd8; }}
                .assessment-warning {{ border-left: 5px solid #f39c12; background: #fef9e7; }}
                .assessment-header {{ font-weight: bold; color: #2c3e50; }}
                .assessment-meta {{ color: #7f8c8d; font-size: 0.9em; margin: 5px 0; }}
                .compliance-frameworks {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; }}
                .framework-card {{ background: #ecf0f1; padding: 15px; border-radius: 5px; text-align: center; }}
                .framework-active {{ background: #d5f4e6; border: 2px solid #27ae60; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>⚖️ Legal & Compliance Dashboard</h1>
                    <p>Dynamic Rules of Engagement & Regulatory Compliance Monitoring</p>
                </div>
                
                <div class="stats-grid">
                    <div class="stat-card">
                        <div class="stat-value">{compliance_rate:.1f}%</div>
                        <div class="stat-label">Compliance Rate</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value">{total_assessments}</div>
                        <div class="stat-label">Total Assessments</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value {'danger' if total_assessments - compliant_assessments > 0 else ''}">{total_assessments - compliant_assessments}</div>
                        <div class="stat-label">Violations Detected</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value">{len(self.compliance_rules)}</div>
                        <div class="stat-label">Active Rules</div>
                    </div>
                </div>
                
                <div class="roe-info">
                    <h2>📋 Active Rules of Engagement</h2>
        """
        
        if self.active_roe:
            html_content += f"""
                    <p><strong>Document ID:</strong> {self.active_roe.document_id}</p>
                    <p><strong>Client:</strong> {self.active_roe.client_name}</p>
                    <p><strong>Legal Framework:</strong> {self.active_roe.legal_framework.value.replace('_', ' ').title()}</p>
                    <p><strong>Authorized Actions:</strong> {', '.join(self.active_roe.authorized_actions[:5])}{'...' if len(self.active_roe.authorized_actions) > 5 else ''}</p>
                    <p><strong>Expiration:</strong> {self.active_roe.expiration_date.strftime('%Y-%m-%d') if self.active_roe.expiration_date else 'No expiration'}</p>
                    
                    <h3>🛡️ Active Compliance Frameworks</h3>
                    <div class="compliance-frameworks">
            """
            
            for framework in self.active_roe.compliance_requirements:
                html_content += f"""
                        <div class="framework-card framework-active">
                            <strong>{framework.value.upper()}</strong>
                        </div>
                """
            
            html_content += """
                    </div>
            """
        else:
            html_content += """
                    <div style="text-align: center; color: #e74c3c; padding: 20px;">
                        <h3>⚠️ No Active Rules of Engagement</h3>
                        <p>Load RoE document to enable compliance monitoring</p>
                    </div>
            """
        
        html_content += """
                </div>
                
                <div class="assessment-list">
                    <h2>📊 Recent Compliance Assessments</h2>
        """
        
        if recent_assessments:
            for assessment in recent_assessments[:10]:
                status_class = "assessment-compliant" if assessment["compliance_status"] else "assessment-violation"
                risk_text = assessment["risk_classification"].replace('_', ' ').title()
                
                html_content += f"""
                    <div class="assessment-item {status_class}">
                        <div class="assessment-header">
                            {assessment['assessment_id']} - {risk_text}
                        </div>
                        <div class="assessment-meta">
                            Status: <strong>{'COMPLIANT' if assessment['compliance_status'] else 'NON-COMPLIANT'}</strong> | 
                            Confidence: {assessment['confidence_score']:.2f} | 
                            Time: {assessment['timestamp']}
                        </div>
                """
                
                if assessment["violated_rules"]:
                    html_content += f"""
                        <div style="color: #e74c3c; margin: 5px 0;">
                            <strong>Violations:</strong> {', '.join(assessment['violated_rules'][:3])}{'...' if len(assessment['violated_rules']) > 3 else ''}
                        </div>
                    """
                
                if assessment["warnings"]:
                    html_content += f"""
                        <div style="color: #f39c12; margin: 5px 0;">
                            <strong>Warnings:</strong> {', '.join(assessment['warnings'][:2])}{'...' if len(assessment['warnings']) > 2 else ''}
                        </div>
                    """
                
                html_content += """
                    </div>
                """
        else:
            html_content += """
                    <div style="text-align: center; color: #7f8c8d; padding: 40px;">
                        <h3>📋 No Assessments Yet</h3>
                        <p>Compliance assessments will appear here as AI actions are evaluated</p>
                    </div>
            """
        
        html_content += f"""
                </div>
                
                <div style="margin-top: 30px; text-align: center; color: #7f8c8d;">
                    <p>Dashboard Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                    <p>Dynamic Legal & Compliance Module ensures all AI decisions comply with legal frameworks</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        # Save dashboard
        dashboard_path = "compliance_dashboard.html"
        with open(dashboard_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        self.logger.info(f"Compliance dashboard created: {dashboard_path}")
        return dashboard_path


async def demonstrate_compliance_module():
    """Demonstration of the Dynamic Legal & Compliance Module."""
    print("⚖️ Dynamic Legal & Compliance Module")
    print("=" * 70)
    
    # Initialize compliance module
    compliance = DynamicLegalComplianceModule()
    
    print(f"\n📋 Module Initialized with:")
    print(f"- {len(compliance.compliance_rules)} compliance rules loaded")
    print(f"- {len(compliance.framework_validators)} framework validators")
    print(f"- Database initialized at: {compliance.db_path}")
    
    # Load sample Rules of Engagement
    print(f"\n📄 Loading Sample Rules of Engagement...")
    
    sample_roe = {
        "document_id": "ROE_2025_001",
        "client_name": "TechCorp Security Assessment",
        "jurisdiction": "united_states",
        "compliance_frameworks": ["owasp", "pci_dss"],
        "scope": {
            "domains": ["api.techcorp.com", "staging.techcorp.com"],
            "ip_ranges": ["192.168.1.0/24", "10.0.0.0/8"],
            "include_subdomains": True
        },
        "authorized_actions": [
            "vulnerability_scanning",
            "penetration_testing",
            "proof_of_concept",
            "network_reconnaissance"
        ],
        "prohibited_actions": [
            "data_exfiltration",
            "data_modification",
            "denial_of_service",
            "social_engineering"
        ],
        "time_restrictions": {
            "allowed_hours": {"start": "09:00", "end": "17:00"},
            "business_days_only": True,
            "timezone": "EST"
        },
        "technical_constraints": {
            "rate_limit": 10,
            "max_connections": 5,
            "prohibited_tools": ["sqlmap", "metasploit"]
        },
        "reporting_requirements": {
            "daily_reports": True,
            "immediate_critical": True
        },
        "emergency_contacts": [
            {"name": "Security Manager", "phone": "+1-555-0101", "email": "security@techcorp.com"}
        ],
        "expiration_date": "2025-12-31T23:59:59"
    }
    
    roe_id = await compliance.load_rules_of_engagement(sample_roe)
    print(f"✅ Rules of Engagement loaded: {roe_id}")
    
    # Test compliance scenarios
    test_scenarios = [
        {
            "name": "Compliant Vulnerability Scan",
            "action": {
                "action_type": "vulnerability_scanning",
                "target": "api.techcorp.com",
                "tool": "nuclei",
                "requests_per_second": 5,
                "max_connections": 3
            }
        },
        {
            "name": "Out-of-Scope Target",
            "action": {
                "action_type": "vulnerability_scanning",
                "target": "external-service.com",
                "tool": "nmap"
            }
        },
        {
            "name": "Prohibited Action",
            "action": {
                "action_type": "data_exfiltration",
                "target": "api.techcorp.com",
                "data_type": "customer_records"
            }
        },
        {
            "name": "Rate Limit Violation",
            "action": {
                "action_type": "vulnerability_scanning",
                "target": "api.techcorp.com",
                "requests_per_second": 50,
                "tool": "nuclei"
            }
        },
        {
            "name": "PCI Data Handling",
            "action": {
                "action_type": "penetration_testing",
                "target": "api.techcorp.com",
                "data_type": "payment_card",
                "encryption_enabled": False
            }
        }
    ]
    
    print(f"\n🧪 Testing Compliance Scenarios...")
    
    for i, scenario in enumerate(test_scenarios, 1):
        print(f"\n{i}. {scenario['name']}:")
        
        assessment = await compliance.assess_compliance(scenario['action'])
        
        print(f"   📊 Risk Classification: {assessment.risk_classification.value.upper()}")
        print(f"   ✅ Compliance Status: {'COMPLIANT' if assessment.compliance_status else 'NON-COMPLIANT'}")
        print(f"   🎯 Confidence Score: {assessment.confidence_score:.2f}")
        
        if assessment.violated_rules:
            print(f"   ⚠️ Violations: {', '.join(assessment.violated_rules[:3])}{'...' if len(assessment.violated_rules) > 3 else ''}")
        
        if assessment.warnings:
            print(f"   🔸 Warnings: {', '.join(assessment.warnings[:2])}{'...' if len(assessment.warnings) > 2 else ''}")
        
        if assessment.recommendations:
            print(f"   💡 Recommendations: {assessment.recommendations[0]}")
    
    # Generate compliance dashboard
    print(f"\n📊 Generating Compliance Dashboard...")
    dashboard_path = await compliance.create_compliance_dashboard()
    print(f"   📄 Dashboard created: {dashboard_path}")
    
    print(f"\n✅ Dynamic Legal & Compliance Module Demonstration Complete!")
    print(f"\nKey Features Demonstrated:")
    print(f"- Dynamic Rules of Engagement interpretation")
    print(f"- Multi-framework compliance validation")
    print(f"- Real-time legal boundary enforcement")
    print(f"- Risk-based compliance assessment")
    print(f"- Automated violation detection")
    print(f"- Comprehensive audit trail")
    print(f"- Interactive compliance dashboard")
    
    return dashboard_path


if __name__ == "__main__":
    asyncio.run(demonstrate_compliance_module())
