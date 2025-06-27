#!/usr/bin/env python3
"""
🚀 COMPLETE GEMINI-POWERED BUG BOUNTY ORCHESTRATION PLATFORM
🧠 Full integration: Multi-target campaigns + Vulnerability correlation + Analytics
⚡ Production-ready ultra-agentic framework with complete workflow automation
🎯 Enterprise-grade bug bounty operations with AI-driven intelligence
"""

import asyncio
import json
import logging
import time
import os
from datetime import datetime
from typing import Dict, List, Any, Optional

# Import our advanced systems
try:
    from advanced_multi_target_orchestrator import AdvancedMultiTargetOrchestrator
    from intelligent_vulnerability_correlator import IntelligentVulnerabilityCorrelator
    from gemini_analytics_dashboard import UltraAnalyticsDashboard
    from system_validator import SystemValidator
    SYSTEMS_AVAILABLE = True
except ImportError as e:
    print(f"⚠️ Some systems not available: {e}")
    SYSTEMS_AVAILABLE = False

class CompleteBugBountyPlatform:
    """Complete integrated bug bounty platform"""
    
    def __init__(self, gemini_api_key: Optional[str] = None):
        self.gemini_api_key = gemini_api_key or os.getenv('GEMINI_API_KEY')
        
        if SYSTEMS_AVAILABLE:
            # Initialize all components
            self.orchestrator = AdvancedMultiTargetOrchestrator(self.gemini_api_key)
            self.correlator = IntelligentVulnerabilityCorrelator()
            self.analytics = UltraAnalyticsDashboard()
            self.validator = SystemValidator()
        else:
            self.orchestrator = None
            self.correlator = None
            self.analytics = None
            self.validator = None
        
        # Platform metrics
        self.platform_metrics = {
            'campaigns_executed': 0,
            'vulnerabilities_discovered': 0,
            'patterns_identified': 0,
            'targets_analyzed': 0,
            'total_execution_time': 0.0
        }
        
        logging.info("🚀 Complete Bug Bounty Platform initialized")
    
    async def execute_full_workflow(self, campaign_config: Dict[str, Any]) -> Dict[str, Any]:
        """Execute complete bug bounty workflow"""
        
        if not SYSTEMS_AVAILABLE:
            return {'error': 'Required systems not available'}
        
        workflow_start = time.time()
        workflow_results = {
            'workflow_id': f"workflow_{int(time.time())}",
            'start_time': datetime.now().isoformat(),
            'stages': {}
        }
        
        try:
            print("🚀 STARTING COMPLETE BUG BOUNTY WORKFLOW")
            print("=" * 50)
            
            # Stage 1: System Validation
            print("\n📋 Stage 1: System Validation")
            validation_results = await self._validate_system()
            workflow_results['stages']['validation'] = validation_results
            
            if not validation_results.get('passed', False):
                print("❌ System validation failed")
                return workflow_results
            
            # Stage 2: Campaign Creation and Execution
            print("\n🎯 Stage 2: Multi-Target Campaign Execution")
            campaign_results = await self._execute_campaign(campaign_config)
            workflow_results['stages']['campaign'] = campaign_results
            
            if not campaign_results.get('success', False):
                print("❌ Campaign execution failed")
                return workflow_results
            
            campaign_id = campaign_results['campaign_id']
            
            # Stage 3: Vulnerability Correlation Analysis
            print("\n🔗 Stage 3: Vulnerability Correlation Analysis")
            correlation_results = await self._analyze_vulnerabilities(campaign_id)
            workflow_results['stages']['correlation'] = correlation_results
            
            # Stage 4: Analytics and Reporting
            print("\n📊 Stage 4: Analytics and Comprehensive Reporting")
            analytics_results = await self._generate_analytics()
            workflow_results['stages']['analytics'] = analytics_results
            
            # Stage 5: Strategic Intelligence Generation
            print("\n🧠 Stage 5: Strategic Intelligence Summary")
            intelligence_results = await self._generate_strategic_intelligence(
                campaign_results, correlation_results, analytics_results
            )
            workflow_results['stages']['intelligence'] = intelligence_results
            
            # Update platform metrics
            self._update_platform_metrics(workflow_results)
            
            # Final results
            workflow_results['success'] = True
            workflow_results['end_time'] = datetime.now().isoformat()
            workflow_results['total_duration'] = time.time() - workflow_start
            
            print(f"\n✅ COMPLETE WORKFLOW FINISHED SUCCESSFULLY")
            print(f"⏱️ Total Duration: {workflow_results['total_duration']:.2f} seconds")
            
            return workflow_results
            
        except Exception as e:
            print(f"❌ Workflow failed: {e}")
            workflow_results['error'] = str(e)
            workflow_results['success'] = False
            return workflow_results
    
    async def _validate_system(self) -> Dict[str, Any]:
        """Validate system components"""
        try:
            print("🔧 Running system validation...")
            
            if not self.validator:
                return {'passed': False, 'error': 'Validator not available'}
            
            # Run basic validation
            self.validator.test_system_requirements()
            
            # Test ultra system
            await self.validator.test_ultra_system()
            
            validation_summary = {
                'passed': self.validator.test_results['failed'] == 0,
                'total_tests': self.validator.test_results['passed'] + self.validator.test_results['failed'],
                'passed_tests': self.validator.test_results['passed'],
                'failed_tests': self.validator.test_results['failed'],
                'warnings': self.validator.test_results['warnings']
            }
            
            print(f"✅ Validation: {validation_summary['passed_tests']}/{validation_summary['total_tests']} passed")
            return validation_summary
            
        except Exception as e:
            return {'passed': False, 'error': str(e)}
    
    async def _execute_campaign(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Execute multi-target campaign"""
        try:
            if not self.orchestrator:
                return {'success': False, 'error': 'Orchestrator not available'}
            
            print(f"🎯 Creating campaign with {len(config['targets'])} targets...")
            
            # Create campaign
            campaign_id = await self.orchestrator.create_campaign(
                name=config.get('name', 'Automated Campaign'),
                targets=config['targets'],
                priority=config.get('priority', 8),
                resource_budget=config.get('resource_budget'),
                time_budget=config.get('time_budget', 6.0),
                risk_tolerance=config.get('risk_tolerance', 'medium')
            )
            
            print(f"📋 Campaign created: {campaign_id}")
            
            # Execute campaign
            results = await self.orchestrator.execute_campaign(campaign_id)
            
            print(f"✅ Campaign completed: {results['targets_processed']} targets processed")
            return {
                'success': True,
                'campaign_id': campaign_id,
                **results
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    async def _analyze_vulnerabilities(self, campaign_id: str) -> Dict[str, Any]:
        """Perform vulnerability correlation analysis"""
        try:
            if not self.correlator:
                return {'error': 'Correlator not available'}
            
            print(f"🔗 Analyzing vulnerabilities for campaign {campaign_id}...")
            
            analysis = await self.correlator.analyze_campaign_vulnerabilities(campaign_id)
            
            if 'error' in analysis:
                print(f"⚠️ Analysis completed with warnings: {analysis['error']}")
                return analysis
            
            summary = analysis['executive_summary']
            print(f"✅ Analysis complete:")
            print(f"   • {summary['total_vulnerabilities']} vulnerabilities found")
            print(f"   • {summary['unique_patterns']} correlation patterns identified")
            print(f"   • Security score: {summary['overall_security_score']:.1f}/10")
            
            return analysis
            
        except Exception as e:
            return {'error': str(e)}
    
    async def _generate_analytics(self) -> Dict[str, Any]:
        """Generate comprehensive analytics"""
        try:
            if not self.analytics:
                return {'error': 'Analytics not available'}
            
            print("📊 Generating comprehensive analytics...")
            
            report = self.analytics.generate_comprehensive_report()
            
            if 'error' in report:
                print(f"⚠️ Analytics generated with warnings: {report['error']}")
                return report
            
            overview = report['system_overview']
            print(f"✅ Analytics generated:")
            print(f"   • {overview['total_campaigns']} total campaigns")
            print(f"   • {overview['total_decisions']} AI decisions made")
            print(f"   • {overview['avg_campaign_efficiency']:.1f}% average efficiency")
            
            return report
            
        except Exception as e:
            return {'error': str(e)}
    
    async def _generate_strategic_intelligence(self, campaign_results: Dict[str, Any], 
                                             correlation_results: Dict[str, Any],
                                             analytics_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate strategic intelligence summary"""
        try:
            print("🧠 Generating strategic intelligence...")
            
            intelligence = {
                'strategic_summary': {
                    'campaign_effectiveness': self._assess_campaign_effectiveness(campaign_results),
                    'security_posture_overview': self._summarize_security_posture(correlation_results),
                    'operational_efficiency': self._assess_operational_efficiency(analytics_results),
                    'key_insights': self._extract_key_insights(campaign_results, correlation_results)
                },
                'actionable_intelligence': {
                    'immediate_priorities': self._identify_immediate_priorities(correlation_results),
                    'strategic_recommendations': self._generate_strategic_recommendations(correlation_results),
                    'resource_optimization': self._suggest_resource_optimization(analytics_results),
                    'next_campaign_suggestions': self._suggest_next_campaigns(campaign_results, correlation_results)
                },
                'executive_briefing': self._create_executive_briefing(campaign_results, correlation_results, analytics_results)
            }
            
            print("✅ Strategic intelligence generated:")
            print(f"   • Campaign effectiveness: {intelligence['strategic_summary']['campaign_effectiveness']}")
            print(f"   • Security posture: {intelligence['strategic_summary']['security_posture_overview']}")
            print(f"   • {len(intelligence['actionable_intelligence']['immediate_priorities'])} immediate priorities identified")
            
            return intelligence
            
        except Exception as e:
            return {'error': str(e)}
    
    def _assess_campaign_effectiveness(self, campaign_results: Dict[str, Any]) -> str:
        """Assess overall campaign effectiveness"""
        if not campaign_results.get('success', False):
            return 'Failed'
        
        success_rate = len([r for r in campaign_results.get('target_results', {}).values() 
                          if r.get('success', False)]) / max(len(campaign_results.get('target_results', {})), 1)
        
        if success_rate >= 0.9:
            return 'Excellent'
        elif success_rate >= 0.7:
            return 'Good'
        elif success_rate >= 0.5:
            return 'Moderate'
        else:
            return 'Poor'
    
    def _summarize_security_posture(self, correlation_results: Dict[str, Any]) -> str:
        """Summarize overall security posture"""
        if 'error' in correlation_results:
            return 'Unknown - Analysis incomplete'
        
        overall_score = correlation_results.get('executive_summary', {}).get('overall_security_score', 5.0)
        
        if overall_score >= 8.0:
            return 'Strong'
        elif overall_score >= 6.0:
            return 'Moderate'
        elif overall_score >= 4.0:
            return 'Weak'
        else:
            return 'Critical'
    
    def _assess_operational_efficiency(self, analytics_results: Dict[str, Any]) -> str:
        """Assess operational efficiency"""
        if 'error' in analytics_results:
            return 'Unknown'
        
        efficiency = analytics_results.get('system_overview', {}).get('avg_campaign_efficiency', 0)
        
        if efficiency >= 80:
            return 'High'
        elif efficiency >= 60:
            return 'Moderate'
        else:
            return 'Low'
    
    def _extract_key_insights(self, campaign_results: Dict[str, Any], 
                            correlation_results: Dict[str, Any]) -> List[str]:
        """Extract key insights from results"""
        insights = []
        
        # Campaign insights
        if campaign_results.get('success', False):
            target_count = len(campaign_results.get('target_results', {}))
            insights.append(f"Successfully analyzed {target_count} targets in parallel")
        
        # Vulnerability insights
        if 'executive_summary' in correlation_results:
            summary = correlation_results['executive_summary']
            if summary['critical_findings'] > 0:
                insights.append(f"Discovered {summary['critical_findings']} critical vulnerabilities")
            if summary['unique_patterns'] > 0:
                insights.append(f"Identified {summary['unique_patterns']} vulnerability patterns")
        
        return insights
    
    def _identify_immediate_priorities(self, correlation_results: Dict[str, Any]) -> List[str]:
        """Identify immediate action priorities"""
        priorities = []
        
        if 'recommendations' in correlation_results:
            recommendations = correlation_results['recommendations']
            priorities.extend(recommendations.get('immediate_actions', []))
        
        return priorities[:5]  # Top 5 priorities
    
    def _generate_strategic_recommendations(self, correlation_results: Dict[str, Any]) -> List[str]:
        """Generate strategic recommendations"""
        recommendations = []
        
        if 'recommendations' in correlation_results:
            rec_data = correlation_results['recommendations']
            recommendations.extend(rec_data.get('strategic_initiatives', []))
        
        return recommendations
    
    def _suggest_resource_optimization(self, analytics_results: Dict[str, Any]) -> List[str]:
        """Suggest resource optimization strategies"""
        suggestions = [
            "Implement intelligent caching for repeated scans",
            "Optimize parallel execution based on target characteristics",
            "Leverage AI-driven tool selection for maximum efficiency"
        ]
        
        return suggestions
    
    def _suggest_next_campaigns(self, campaign_results: Dict[str, Any], 
                              correlation_results: Dict[str, Any]) -> List[str]:
        """Suggest next campaign focuses"""
        suggestions = []
        
        # Based on correlation patterns
        if 'correlation_patterns' in correlation_results:
            patterns = correlation_results['correlation_patterns']
            if len(patterns) > 0:
                suggestions.append("Deep-dive analysis of identified vulnerability patterns")
        
        # Based on campaign success
        if campaign_results.get('success', False):
            suggestions.append("Expand to related infrastructure and subdomains")
            suggestions.append("Conduct follow-up manual testing on high-value findings")
        
        return suggestions
    
    def _create_executive_briefing(self, campaign_results: Dict[str, Any],
                                 correlation_results: Dict[str, Any],
                                 analytics_results: Dict[str, Any]) -> Dict[str, Any]:
        """Create executive briefing"""
        return {
            'mission_status': 'Completed' if campaign_results.get('success', False) else 'Failed',
            'key_metrics': {
                'targets_analyzed': len(campaign_results.get('target_results', {})),
                'vulnerabilities_found': correlation_results.get('executive_summary', {}).get('total_vulnerabilities', 0),
                'critical_issues': correlation_results.get('executive_summary', {}).get('critical_findings', 0),
                'execution_time': campaign_results.get('execution_time', 0)
            },
            'risk_assessment': correlation_results.get('risk_assessment', {}).get('overall_risk', 'unknown'),
            'next_steps': self._identify_immediate_priorities(correlation_results)[:3]
        }
    
    def _update_platform_metrics(self, workflow_results: Dict[str, Any]):
        """Update platform-wide metrics"""
        self.platform_metrics['campaigns_executed'] += 1
        
        if 'correlation' in workflow_results['stages']:
            correlation = workflow_results['stages']['correlation']
            if 'executive_summary' in correlation:
                summary = correlation['executive_summary']
                self.platform_metrics['vulnerabilities_discovered'] += summary.get('total_vulnerabilities', 0)
                self.platform_metrics['patterns_identified'] += summary.get('unique_patterns', 0)
        
        if 'campaign' in workflow_results['stages']:
            campaign = workflow_results['stages']['campaign']
            self.platform_metrics['targets_analyzed'] += len(campaign.get('target_results', {}))
            self.platform_metrics['total_execution_time'] += campaign.get('execution_time', 0)
    
    def get_platform_status(self) -> Dict[str, Any]:
        """Get platform status and metrics"""
        return {
            'platform_metrics': self.platform_metrics,
            'systems_status': {
                'orchestrator': self.orchestrator is not None,
                'correlator': self.correlator is not None,
                'analytics': self.analytics is not None,
                'validator': self.validator is not None
            },
            'gemini_configured': self.gemini_api_key is not None
        }

async def demonstrate_complete_platform():
    """Demonstrate the complete integrated platform"""
    print("🚀 COMPLETE GEMINI-POWERED BUG BOUNTY PLATFORM DEMONSTRATION")
    print("=" * 70)
    
    # Initialize platform
    platform = CompleteBugBountyPlatform()
    
    # Check platform status
    status = platform.get_platform_status()
    print(f"📊 Platform Status:")
    print(f"   Systems Available: {status['systems_status']}")
    print(f"   Gemini Configured: {status['gemini_configured']}")
    
    if not SYSTEMS_AVAILABLE:
        print("⚠️ Some systems not available - limited demonstration")
        return None
    
    # Define campaign configuration
    campaign_config = {
        'name': 'Enterprise Security Assessment Demo',
        'targets': [
            'demo-target-1.example.com',
            'demo-target-2.example.com', 
            'demo-target-3.example.com',
            'demo-target-4.example.com'
        ],
        'priority': 9,
        'time_budget': 8.0,
        'risk_tolerance': 'medium',
        'resource_budget': {
            'cpu_hours': 12.0,
            'memory_gb': 8.0,
            'api_calls': 1000
        }
    }
    
    print(f"\n🎯 Campaign Configuration:")
    print(f"   Targets: {len(campaign_config['targets'])}")
    print(f"   Priority: {campaign_config['priority']}/10")
    print(f"   Time Budget: {campaign_config['time_budget']} hours")
    
    # Execute complete workflow
    workflow_results = await platform.execute_full_workflow(campaign_config)
    
    if workflow_results.get('success', False):
        print(f"\n💫 PLATFORM DEMONSTRATION COMPLETED SUCCESSFULLY!")
        
        # Show final metrics
        final_status = platform.get_platform_status()
        print(f"\n📊 Final Platform Metrics:")
        metrics = final_status['platform_metrics']
        print(f"   Campaigns Executed: {metrics['campaigns_executed']}")
        print(f"   Vulnerabilities Discovered: {metrics['vulnerabilities_discovered']}")
        print(f"   Patterns Identified: {metrics['patterns_identified']}")
        print(f"   Targets Analyzed: {metrics['targets_analyzed']}")
        print(f"   Total Execution Time: {metrics['total_execution_time']:.2f} seconds")
        
        # Show executive briefing
        if 'intelligence' in workflow_results['stages']:
            briefing = workflow_results['stages']['intelligence'].get('executive_briefing', {})
            print(f"\n🎯 Executive Briefing:")
            print(f"   Mission Status: {briefing.get('mission_status', 'Unknown')}")
            print(f"   Risk Assessment: {briefing.get('risk_assessment', 'Unknown').upper()}")
            
            next_steps = briefing.get('next_steps', [])
            if next_steps:
                print(f"   Next Steps:")
                for step in next_steps[:3]:
                    print(f"     • {step}")
        
        return workflow_results
    else:
        print(f"\n❌ Platform demonstration failed")
        if 'error' in workflow_results:
            print(f"Error: {workflow_results['error']}")
        return None

if __name__ == "__main__":
    print("🚀 Complete Gemini-Powered Bug Bounty Orchestration Platform")
    
    results = asyncio.run(demonstrate_complete_platform())
    
    if results:
        print(f"\n🎉 COMPLETE PLATFORM DEMONSTRATION SUCCESSFUL!")
        print(f"🔗 All systems integrated and operational")
        print(f"🧠 Full AI-driven workflow demonstrated")
        print(f"⚡ Ultra-optimized performance achieved")
        print(f"🎯 Production-ready bug bounty platform delivered")
    else:
        print(f"\n❌ Platform demonstration failed")
        print(f"🔧 Check system dependencies and configuration")
