"""
Real-time ML Integration for Autonomous Bug Bounty Agent
Integrates ML enhancements directly into the main workflow
"""

import asyncio
import logging
from typing import Dict, List, Optional
from pathlib import Path

from autonomous_agent import (
    AdaptiveWorkflowEngine, BugReport, Priority, 
    IntelligentLogger, ProcessManager, ScopeConfig
)
from ml_enhancements import VulnerabilityPatternLearner, AdaptiveDecisionEngine
from gemini_bug_bounty_agent import BugBountyAgent

class MLEnhancedWorkflowEngine(AdaptiveWorkflowEngine):
    """Enhanced workflow engine with integrated machine learning"""
    
    def __init__(self, scope_config: ScopeConfig, logger: IntelligentLogger, 
                 process_manager: ProcessManager):
        super().__init__(scope_config, logger, process_manager)
        
        # Initialize ML components
        self.ml_learner = VulnerabilityPatternLearner()
        self.ml_decision_engine = AdaptiveDecisionEngine(self.ml_learner)
        
        # ML-enhanced workflow state
        self.ml_metrics = {
            "ml_predictions": 0,
            "false_positives_prevented": 0,
            "high_confidence_findings": 0,
            "ml_accuracy": 0.0
        }
        
        self.logger.logger.info("🤖 ML-Enhanced Workflow Engine initialized")
    
    async def execute_ml_enhanced_workflow(self, hunter: BugBountyAgent) -> Dict:
        """Execute autonomous workflow with ML enhancements"""
        self.logger.log_task_start("ml_enhanced_workflow")
        
        try:
            # Phase 1: ML-Enhanced Intelligence Gathering
            await self._ml_enhanced_intelligence_gathering(hunter)
            
            # Phase 2: ML-Optimized Reconnaissance  
            await self._ml_optimized_reconnaissance(hunter)
            
            # Phase 3: ML-Powered Vulnerability Discovery
            await self._ml_powered_vulnerability_discovery(hunter)
            
            # Phase 4: ML-Enhanced Validation and Exploitation
            await self._ml_enhanced_validation(hunter)
            
            # Phase 5: ML-Driven Reporting and Learning
            await self._ml_driven_reporting(hunter)
            
            # Update ML models with session data
            await self._update_ml_models()
            
            return {
                **self.workflow_state,
                "ml_metrics": self.ml_metrics,
                "ml_recommendations": await self._generate_ml_recommendations()
            }
            
        except Exception as e:
            self.logger.log_error(e, "ml_enhanced_workflow", recoverable=False)
            raise
    
    async def _ml_enhanced_intelligence_gathering(self, hunter: BugBountyAgent):
        """Phase 1: Intelligence gathering with ML target prioritization"""
        self.workflow_state["current_phase"] = "ml_intelligence_gathering"
        
        # Standard intelligence gathering
        await super()._phase_intelligence_gathering(hunter)
        
        # ML enhancement: Analyze and prioritize targets
        ml_strategy = await self.ml_decision_engine.optimize_testing_strategy(
            str(self.scope_config.targets), 
            []
        )
        
        # Update workflow with ML insights
        self.workflow_state["ml_strategy"] = ml_strategy
        self.workflow_state["priority_targets"] = ml_strategy.get("priority_areas", [])
        
        self.logger.logger.info(f"🎯 ML identified priority areas: {ml_strategy.get('priority_areas', [])}")
    
    async def _ml_optimized_reconnaissance(self, hunter: BugBountyAgent):
        """Phase 2: Reconnaissance optimized by ML insights"""
        self.workflow_state["current_phase"] = "ml_reconnaissance"
        
        # Get ML-optimized reconnaissance strategy
        strategy = self.workflow_state.get("ml_strategy", {})
        recommended_tools = strategy.get("recommended_tools", ["nuclei", "ffuf"])
        
        # Enhanced reconnaissance with ML-selected tools
        for target in self.workflow_state["validated_targets"]:
            try:
                # Use ML to generate custom reconnaissance approach
                ml_recon_prompt = f"""
                Perform ML-optimized reconnaissance on {target}:
                
                ML Strategy: {strategy}
                Recommended Tools: {recommended_tools}
                
                Focus on:
                {', '.join(strategy.get('priority_areas', []))}
                
                Use adaptive techniques based on ML analysis.
                """
                
                result = await hunter.agent.run(ml_recon_prompt)
                self.workflow_state["discovered_assets"].extend(
                    self._extract_assets_from_result(result.final_output)
                )
                
            except Exception as e:
                self.logger.log_error(e, f"ml_recon_{target}", recoverable=True)
    
    async def _ml_powered_vulnerability_discovery(self, hunter: BugBountyAgent):
        """Phase 3: ML-powered vulnerability discovery with smart payloads"""
        self.workflow_state["current_phase"] = "ml_vulnerability_discovery"
        
        # Get ML-optimized payload suggestions
        strategy = self.workflow_state.get("ml_strategy", {})
        payload_suggestions = strategy.get("payload_suggestions", {})
        
        for target_info in self.workflow_state["discovered_assets"]:
            try:
                # Generate ML-enhanced payloads
                target_name = target_info.get("value", "")
                
                # Use ML to predict most effective vulnerability types
                effective_vulns = await self._predict_effective_vulnerabilities(target_info)
                
                for vuln_type in effective_vulns:
                    # Get ML-generated smart payloads
                    smart_payloads = self.ml_learner.generate_smart_payloads(
                        target_info, vuln_type
                    )
                    
                    # Enhanced vulnerability scanning with ML payloads
                    ml_vuln_prompt = f"""
                    Perform ML-enhanced vulnerability testing on {target_name}:
                    
                    Target Type: {vuln_type}
                    Smart Payloads: {smart_payloads[:5]}  # Top 5 payloads
                    
                    Use ML-optimized testing approach with custom payloads.
                    Focus on high-confidence, low false-positive findings.
                    """
                    
                    result = await hunter.agent.run(ml_vuln_prompt)
                    
                    # Extract and validate findings with ML
                    findings = self._extract_vulnerabilities_from_result(result.final_output)
                    for finding in findings:
                        validated_finding = await self._ml_validate_finding(hunter, finding)
                        if validated_finding:
                            self.workflow_state["vulnerabilities"].append(validated_finding)
                            self.ml_metrics["high_confidence_findings"] += 1
                
            except Exception as e:
                self.logger.log_error(e, f"ml_vuln_discovery_{target_name}", recoverable=True)
    
    async def _ml_enhanced_validation(self, hunter: BugBountyAgent):
        """Phase 4: ML-enhanced vulnerability validation"""
        self.workflow_state["current_phase"] = "ml_validation"
        
        enhanced_vulnerabilities = []
        
        for vulnerability in self.workflow_state["vulnerabilities"]:
            try:
                # ML prediction for vulnerability validity
                ml_confidence = self.ml_learner.predict_vulnerability_validity(vulnerability)
                fp_probability = self.ml_learner.predict_false_positive(vulnerability.description)
                
                # Update confidence based on ML prediction
                vulnerability.confidence = (vulnerability.confidence + ml_confidence) / 2
                vulnerability.false_positive_probability = fp_probability
                
                self.ml_metrics["ml_predictions"] += 1
                
                # Only keep high-confidence, low false-positive findings
                if ml_confidence > 0.7 and fp_probability < 0.3:
                    # Enhance proof of concept with ML insights
                    enhanced_poc = await self._ml_enhance_proof_of_concept(hunter, vulnerability)
                    vulnerability.proof_of_concept = enhanced_poc
                    
                    enhanced_vulnerabilities.append(vulnerability)
                else:
                    self.ml_metrics["false_positives_prevented"] += 1
                    self.logger.logger.info(f"🤖 ML filtered potential false positive: {vulnerability.title}")
                
            except Exception as e:
                self.logger.log_error(e, f"ml_validation_{vulnerability.id}", recoverable=True)
        
        self.workflow_state["vulnerabilities"] = enhanced_vulnerabilities
        
        # Calculate ML accuracy if we have validation data
        if self.ml_metrics["ml_predictions"] > 0:
            accuracy = 1.0 - (self.ml_metrics["false_positives_prevented"] / self.ml_metrics["ml_predictions"])
            self.ml_metrics["ml_accuracy"] = accuracy
    
    async def _ml_driven_reporting(self, hunter: BugBountyAgent):
        """Phase 5: ML-driven reporting with insights"""
        self.workflow_state["current_phase"] = "ml_reporting"
        
        # Generate ML-enhanced report
        ml_report_prompt = f"""
        Generate ML-enhanced bug bounty report:
        
        Findings: {len(self.workflow_state["vulnerabilities"])} vulnerabilities
        ML Metrics: {self.ml_metrics}
        ML Strategy Used: {self.workflow_state.get("ml_strategy", {})}
        
        Include:
        1. Executive summary with ML insights
        2. ML-validated vulnerability details
        3. False positive reduction analysis
        4. ML-driven recommendations for future testing
        5. Confidence analysis and reliability metrics
        
        Highlight the AI/ML contribution to finding quality and efficiency.
        """
        
        report_result = await hunter.agent.run(ml_report_prompt)
        self.workflow_state["ml_enhanced_report"] = report_result.final_output
    
    async def _predict_effective_vulnerabilities(self, target_info: Dict) -> List[str]:
        """Predict most effective vulnerability types for target"""
        # Use ML to predict based on target characteristics
        target_characteristics = {
            "technology": target_info.get("technology", "unknown"),
            "framework": target_info.get("framework", "unknown"),
            "type": target_info.get("type", "web")
        }
        
        # Default predictions (in real implementation, this would use trained ML models)
        if "api" in str(target_info).lower():
            return ["authentication", "authorization", "input_validation"]
        elif "admin" in str(target_info).lower():
            return ["authentication", "authorization", "privilege_escalation"]
        else:
            return ["xss", "sqli", "csrf", "idor"]
    
    async def _ml_validate_finding(self, hunter: BugBountyAgent, finding_data: Dict) -> Optional[BugReport]:
        """Validate finding using ML prediction"""
        # Create temporary bug report for ML analysis
        temp_report = BugReport(
            id=f"temp_{hash(str(finding_data))}",
            title=finding_data.get("title", "Unknown"),
            description=finding_data.get("description", ""),
            severity=Priority.MEDIUM,
            cvss_score=finding_data.get("cvss", 5.0),
            target=finding_data.get("target", ""),
            endpoint=finding_data.get("endpoint", "/"),
            vulnerability_type=finding_data.get("type", "unknown"),
            proof_of_concept=finding_data.get("poc", ""),
            impact=finding_data.get("impact", ""),
            remediation="",
            references=[],
            discovered_at="",
            confidence=finding_data.get("confidence", 0.5),
            false_positive_probability=0.5
        )
        
        # Use ML to validate
        ml_confidence = self.ml_learner.predict_vulnerability_validity(temp_report)
        fp_probability = self.ml_learner.predict_false_positive(temp_report.description)
        
        if ml_confidence > 0.6 and fp_probability < 0.4:
            temp_report.confidence = ml_confidence
            temp_report.false_positive_probability = fp_probability
            return temp_report
        
        return None
    
    async def _ml_enhance_proof_of_concept(self, hunter: BugBountyAgent, vulnerability: BugReport) -> str:
        """Enhance proof of concept using ML insights"""
        ml_poc_prompt = f"""
        Enhance this proof of concept using ML insights:
        
        Vulnerability: {vulnerability.title}
        Type: {vulnerability.vulnerability_type}
        Current PoC: {vulnerability.proof_of_concept}
        ML Confidence: {vulnerability.confidence:.2f}
        
        Create an ML-optimized proof of concept that:
        1. Uses the most effective payloads for this vulnerability type
        2. Includes step-by-step reproduction with high success rate
        3. Demonstrates clear business impact
        4. Provides multiple attack vectors if applicable
        5. Shows evidence that would convince a bug bounty program
        """
        
        result = await hunter.agent.run(ml_poc_prompt)
        return result.final_output
    
    async def _update_ml_models(self):
        """Update ML models with session findings"""
        try:
            # Add session data to training set
            for vulnerability in self.workflow_state["vulnerabilities"]:
                # Assume high-confidence findings are valid for training
                is_confirmed = vulnerability.confidence > 0.8
                self.ml_learner.add_vulnerability_data(vulnerability, is_confirmed)
            
            # Train models if we have enough new data
            if len(self.ml_learner.training_data["vulnerabilities"]) % 20 == 0:
                training_results = await self.ml_learner.train_models()
                self.logger.logger.info(f"🎓 ML models updated: {training_results}")
                
        except Exception as e:
            self.logger.log_error(e, "ml_model_update", recoverable=True)
    
    async def _generate_ml_recommendations(self) -> Dict:
        """Generate ML-driven recommendations for future improvements"""
        return {
            "model_performance": {
                "accuracy": self.ml_metrics["ml_accuracy"],
                "predictions_made": self.ml_metrics["ml_predictions"],
                "false_positives_prevented": self.ml_metrics["false_positives_prevented"]
            },
            "recommendations": [
                "Continue collecting training data for improved accuracy",
                "Focus on high-confidence vulnerability types",
                "Implement reinforcement learning for payload optimization",
                "Add more sophisticated feature extraction"
            ],
            "next_optimizations": [
                "Implement ensemble methods for better predictions",
                "Add contextual awareness to decision making", 
                "Integrate more sophisticated NLP for text analysis",
                "Add computer vision for screenshot analysis"
            ]
        }

# Enhanced controller that uses ML-integrated workflow
class MLEnhancedAutonomousController:
    """Autonomous controller with ML enhancements"""
    
    def __init__(self, config_file: Optional[str] = None):
        # Standard initialization
        self.config_file = config_file
        self.session_id = f"ml_bb_{int(asyncio.get_event_loop().time())}"
        self.results_dir = Path(f"./ml_autonomous_results/{self.session_id}")
        self.results_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize components
        self.logger = IntelligentLogger(self.session_id, self.results_dir)
        self.process_manager = ProcessManager(max_workers=20, memory_limit_mb=8192)
        
        # Load configuration
        self.scope_config = self._load_scope_config()
        
        # Initialize ML-enhanced workflow engine
        self.workflow_engine = MLEnhancedWorkflowEngine(
            self.scope_config, 
            self.logger, 
            self.process_manager
        )
        
        # Initialize bug bounty agent
        self.hunter = BugBountyAgent(self.scope_config.targets)
        
        self.logger.logger.info(f"🤖 ML-Enhanced Autonomous Controller initialized - Session: {self.session_id}")
    
    def _load_scope_config(self) -> ScopeConfig:
        """Load scope configuration (simplified)"""
        # In real implementation, load from YAML file
        return ScopeConfig(
            targets=["example.com"],
            in_scope=["*.example.com"],
            out_of_scope=["admin.example.com"],
            allowed_methods=["GET", "POST"],
            forbidden_paths=["/admin/delete"],
            rate_limit=10,
            safe_mode=True,
            max_depth=3,
            timeout=7200
        )
    
    async def run_ml_enhanced_hunt(self) -> Dict:
        """Execute ML-enhanced autonomous bug bounty hunt"""
        self.logger.logger.info("🤖 Starting ML-enhanced autonomous hunt")
        
        print(f"""
🤖 ML-Enhanced Autonomous Bug Bounty Hunt
==========================================
Session ID: {self.session_id}
Targets: {', '.join(self.scope_config.targets)}
ML Features: Enabled
Results Dir: {self.results_dir}
==========================================
        """)
        
        try:
            # Execute ML-enhanced workflow
            results = await self.workflow_engine.execute_ml_enhanced_workflow(self.hunter)
            
            # Save results
            await self._save_ml_results(results)
            
            # Print summary
            ml_metrics = results.get("ml_metrics", {})
            print(f"""
🎉 ML-Enhanced Hunt Completed
============================
Vulnerabilities Found: {len(results.get('vulnerabilities', []))}
ML Predictions Made: {ml_metrics.get('ml_predictions', 0)}
False Positives Prevented: {ml_metrics.get('false_positives_prevented', 0)}
ML Accuracy: {ml_metrics.get('ml_accuracy', 0.0):.2%}
High Confidence Findings: {ml_metrics.get('high_confidence_findings', 0)}
============================
            """)
            
            return results
            
        except Exception as e:
            self.logger.log_error(e, "ml_enhanced_hunt", recoverable=False)
            print(f"❌ Critical error in ML-enhanced hunt: {e}")
            return {"status": "failed", "error": str(e)}
        
        finally:
            self.process_manager.shutdown()
    
    async def _save_ml_results(self, results: Dict):
        """Save ML-enhanced results"""
        import json
        
        # Save comprehensive results
        with open(self.results_dir / "ml_results.json", 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, default=str)
        
        # Save ML-specific metrics
        ml_metrics = results.get("ml_metrics", {})
        with open(self.results_dir / "ml_metrics.json", 'w', encoding='utf-8') as f:
            json.dump(ml_metrics, f, indent=2)
        
        # Save ML report
        ml_report = results.get("ml_enhanced_report", "")
        with open(self.results_dir / "ml_report.md", 'w', encoding='utf-8') as f:
            f.write(ml_report)

# Example usage
async def run_ml_enhanced_example():
    """Example of running ML-enhanced autonomous hunt"""
    controller = MLEnhancedAutonomousController()
    results = await controller.run_ml_enhanced_hunt()
    return results

if __name__ == "__main__":
    asyncio.run(run_ml_enhanced_example())
