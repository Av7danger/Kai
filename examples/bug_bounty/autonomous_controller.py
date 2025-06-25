"""
Autonomous Bug Bounty Controller
Main interface for fully autonomous bug bounty hunting operations
"""

import asyncio
import json
import yaml
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime
import argparse
import sys

from autonomous_agent import (
    ScopeConfig, 
    AdaptiveWorkflowEngine, 
    IntelligentLogger, 
    ProcessManager,
    Priority,
    BugReport
)
from gemini_bug_bounty_agent import BugBountyAgent

class AutonomousBugBountyController:
    """Main controller for autonomous bug bounty operations"""
    
    def __init__(self, config_file: Optional[str] = None):
        self.config_file = config_file
        self.session_id = f"auto_bb_{int(datetime.now().timestamp())}"
        self.results_dir = Path(f"./autonomous_results/{self.session_id}")
        self.results_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize components
        self.logger = IntelligentLogger(self.session_id, self.results_dir)
        self.process_manager = ProcessManager(max_workers=20, memory_limit_mb=8192)
        
        # Load configuration
        self.scope_config = self._load_scope_config()
        
        # Initialize workflow engine
        self.workflow_engine = AdaptiveWorkflowEngine(
            self.scope_config, 
            self.logger, 
            self.process_manager
        )
        
        # Initialize bug bounty agent
        self.hunter = BugBountyAgent(self.scope_config.targets)
        
        self.logger.logger.info(f"🚀 Autonomous Bug Bounty Controller initialized - Session: {self.session_id}")
    
    def _load_scope_config(self) -> ScopeConfig:
        """Load scope configuration from file or create default"""
        if self.config_file and Path(self.config_file).exists():
            try:
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    if self.config_file.endswith('.yaml') or self.config_file.endswith('.yml'):
                        config_data = yaml.safe_load(f)
                    else:
                        config_data = json.load(f)
                
                return ScopeConfig(**config_data)
            except Exception as e:
                self.logger.logger.error(f"Failed to load config: {e}")
                return self._create_default_config()
        else:
            return self._create_default_config()
    
    def _create_default_config(self) -> ScopeConfig:
        """Create default scope configuration"""
        return ScopeConfig(
            targets=["example.com"],
            in_scope=["*.example.com", "example.com"],
            out_of_scope=["mail.example.com", "*.internal.example.com"],
            allowed_methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
            forbidden_paths=["/admin/delete", "/admin/reset"],
            rate_limit=10,
            max_depth=3,
            timeout=7200,  # 2 hours
            business_hours_only=False,
            safe_mode=True
        )
    
    async def run_autonomous_hunt(self) -> Dict:
        """Execute fully autonomous bug bounty hunt"""
        self.logger.logger.info("🎯 Starting autonomous bug bounty hunt")
        print(f"""
🎯 Autonomous Bug Bounty Hunt Starting
========================================
Session ID: {self.session_id}
Targets: {', '.join(self.scope_config.targets)}
In Scope: {', '.join(self.scope_config.in_scope)}
Out of Scope: {', '.join(self.scope_config.out_of_scope)}
Safe Mode: {self.scope_config.safe_mode}
Rate Limit: {self.scope_config.rate_limit} req/sec
Results Dir: {self.results_dir}
========================================
        """)
        
        try:
            # Execute autonomous workflow
            results = await self.workflow_engine.execute_autonomous_workflow(self.hunter)
            
            # Save comprehensive results
            await self._save_session_results(results)
            
            # Generate final summary
            summary = self._generate_session_summary(results)
            
            print(f"""
🎉 Autonomous Bug Bounty Hunt Completed
======================================
{summary}
======================================
            """)
            
            return results
            
        except KeyboardInterrupt:
            self.logger.logger.warning("🛑 Hunt interrupted by user")
            print("\n🛑 Autonomous hunt interrupted. Saving partial results...")
            await self._save_partial_results()
            return {"status": "interrupted"}
            
        except Exception as e:
            self.logger.log_error(e, "autonomous_hunt", recoverable=False)
            print(f"❌ Critical error in autonomous hunt: {e}")
            await self._save_error_results(e)
            return {"status": "failed", "error": str(e)}
        
        finally:
            self.process_manager.shutdown()
    
    async def _save_session_results(self, results: Dict):
        """Save comprehensive session results"""
        # Main results file
        with open(self.results_dir / "session_results.json", 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, default=str)
        
        # Individual vulnerability reports
        vulnerabilities = results.get("vulnerabilities", [])
        for i, vuln in enumerate(vulnerabilities):
            if isinstance(vuln, BugReport):
                # Save as markdown
                with open(self.results_dir / f"vulnerability_{i+1:03d}.md", 'w', encoding='utf-8') as f:
                    f.write(vuln.to_markdown())
                
                # Save as JSON
                with open(self.results_dir / f"vulnerability_{i+1:03d}.json", 'w', encoding='utf-8') as f:
                    json.dump(vuln.__dict__, f, indent=2, default=str)
        
        # Session metrics
        metrics = self.logger.get_metrics()
        with open(self.results_dir / "session_metrics.json", 'w', encoding='utf-8') as f:
            json.dump(metrics, f, indent=2, default=str)
        
        # Final report
        if results.get("final_report"):
            with open(self.results_dir / "final_report.md", 'w', encoding='utf-8') as f:
                f.write(results["final_report"])
        
        # Scope configuration used
        with open(self.results_dir / "scope_config.json", 'w', encoding='utf-8') as f:
            json.dump(self.scope_config.__dict__, f, indent=2, default=str)
        
        self.logger.logger.info(f"💾 Session results saved to {self.results_dir}")
    
    async def _save_partial_results(self):
        """Save partial results on interruption"""
        partial_results = {
            "status": "interrupted",
            "session_id": self.session_id,
            "workflow_state": self.workflow_engine.workflow_state,
            "metrics": self.logger.get_metrics(),
            "active_tasks": self.process_manager.get_active_tasks()
        }
        
        with open(self.results_dir / "partial_results.json", 'w', encoding='utf-8') as f:
            json.dump(partial_results, f, indent=2, default=str)
    
    async def _save_error_results(self, error: Exception):
        """Save error results for analysis"""
        error_results = {
            "status": "failed",
            "session_id": self.session_id,
            "error": str(error),
            "error_type": type(error).__name__,
            "workflow_state": self.workflow_engine.workflow_state,
            "metrics": self.logger.get_metrics()
        }
        
        with open(self.results_dir / "error_results.json", 'w', encoding='utf-8') as f:
            json.dump(error_results, f, indent=2, default=str)
    
    def _generate_session_summary(self, results: Dict) -> str:
        """Generate human-readable session summary"""
        metrics = self.logger.get_metrics()
        vulnerabilities = results.get("vulnerabilities", [])
        
        # Count vulnerabilities by severity
        severity_counts = {}
        for vuln in vulnerabilities:
            if isinstance(vuln, BugReport):
                severity = vuln.severity.value
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        summary = f"""
Session ID: {self.session_id}
Duration: {metrics.get('duration', 0):.1f} seconds
Targets Tested: {len(self.scope_config.targets)}
Tasks Completed: {metrics.get('tasks_completed', 0)}
Tasks Failed: {metrics.get('tasks_failed', 0)}
Success Rate: {metrics.get('success_rate', 0):.1%}

VULNERABILITIES FOUND: {len(vulnerabilities)}
"""
        
        if severity_counts:
            summary += "\nBy Severity:\n"
            for severity, count in severity_counts.items():
                summary += f"  {severity.upper()}: {count}\n"
        
        if results.get("next_steps"):
            summary += "\nNEXT STEPS:\n"
            for step in results["next_steps"]:
                summary += f"  • {step}\n"
        
        return summary
    
    def create_scope_template(self, output_file: str = "bug_bounty_scope.yaml"):
        """Create scope configuration template"""
        template = {
            "targets": [
                "example.com",
                "api.example.com"
            ],
            "in_scope": [
                "*.example.com",
                "example.com",
                "api.example.com"
            ],
            "out_of_scope": [
                "mail.example.com",
                "internal.example.com",
                "*.internal.example.com"
            ],
            "allowed_methods": [
                "GET",
                "POST",
                "PUT",
                "DELETE",
                "PATCH",
                "OPTIONS"
            ],
            "forbidden_paths": [
                "/admin/delete",
                "/admin/reset",
                "/admin/users/delete"
            ],
            "rate_limit": 10,
            "max_depth": 3,
            "timeout": 7200,
            "business_hours_only": False,
            "safe_mode": True
        }
        
        with open(output_file, 'w', encoding='utf-8') as f:
            yaml.dump(template, f, default_flow_style=False, indent=2)
        
        print(f"✅ Scope template created: {output_file}")
        print("📝 Edit this file with your bug bounty program details")

async def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description="Autonomous Bug Bounty Hunter")
    parser.add_argument(
        "--config", 
        "-c", 
        help="Scope configuration file (YAML or JSON)",
        default=None
    )
    parser.add_argument(
        "--create-template", 
        action="store_true",
        help="Create scope configuration template"
    )
    parser.add_argument(
        "--template-file",
        default="bug_bounty_scope.yaml",
        help="Template file name (default: bug_bounty_scope.yaml)"
    )
    
    args = parser.parse_args()
    
    if args.create_template:
        controller = AutonomousBugBountyController()
        controller.create_scope_template(args.template_file)
        return
    
    if not args.config:
        print("❌ No configuration file specified!")
        print("💡 Use --create-template to create a template first")
        print("💡 Then use --config <file> to specify your scope")
        return
    
    try:
        # Initialize controller
        controller = AutonomousBugBountyController(args.config)
        
        # Run autonomous hunt
        results = await controller.run_autonomous_hunt()
        
        # Exit with appropriate code
        if results.get("status") == "failed":
            sys.exit(1)
        elif results.get("status") == "interrupted":
            sys.exit(2)
        else:
            sys.exit(0)
            
    except Exception as e:
        print(f"💥 Fatal error: {e}")
        sys.exit(3)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n🛑 Interrupted by user")
        sys.exit(2)
