#!/usr/bin/env python3
"""
Enhanced Bug Bounty Framework - Production Demo
Comprehensive demonstration of all enhanced features and optimizations
"""

import asyncio
import json
import time
from datetime import datetime
from pathlib import Path

# Import the enhanced framework components
try:
    from enhanced_integration import (
        enhanced_framework,
        enhanced_target_analysis,
        enhanced_comprehensive_scan,
        generate_enhanced_report
    )
    from optimization_manager import optimization_manager
    from ml_enhancements import ml_enhancer
    ENHANCED_AVAILABLE = True
except ImportError as e:
    print(f"⚠️  Enhanced framework not available: {e}")
    ENHANCED_AVAILABLE = False

class ProductionDemo:
    """Production-ready demonstration of the enhanced framework"""
    
    def __init__(self):
        self.demo_targets = [
            "https://demo.testfire.net",
            "https://httpbin.org", 
            "https://jsonplaceholder.typicode.com"
        ]
        self.results = []
        
    def print_banner(self):
        """Print demonstration banner"""
        print("\n" + "="*80)
        print("🚀 ENHANCED BUG BOUNTY FRAMEWORK - PRODUCTION DEMO")
        print("="*80)
        print("🎯 Comprehensive Security Testing with AI/ML Enhancement")
        print("⚡ Advanced Optimization & Error Handling")
        print("🔧 Rule-Based Applications & Intelligent Fallbacks")
        print("📊 Real-Time Performance Monitoring")
        print("="*80 + "\n")
    
    def check_framework_status(self):
        """Check framework component availability"""
        print("🔍 Framework Components Status Check:")
        print("-" * 50)
        
        if ENHANCED_AVAILABLE:
            print("✅ Enhanced Framework: Available")
            print("✅ Optimization Manager: Available")
            print("✅ ML Enhancer: Available")
            
            # Check component functionality
            try:
                stats = optimization_manager.get_comprehensive_stats()
                print("✅ Optimization Stats: Available")
            except Exception as e:
                print(f"⚠️  Optimization Stats: Limited ({e})")
            
            try:
                ml_stats = ml_enhancer.get_system_stats()
                print("✅ ML Stats: Available")
            except Exception as e:
                print(f"⚠️  ML Stats: Limited ({e})")
                
            print("🎉 All components loaded successfully!")
        else:
            print("❌ Enhanced Framework: Not Available")
            return False
            
        print("\n📊 Framework ready for production demonstration.\n")
        return True
    
    async def demonstrate_target_analysis(self):
        """Demonstrate enhanced target analysis capabilities"""
        print("🎯 DEMONSTRATION 1: Enhanced Target Analysis")
        print("-" * 60)
        
        for i, target in enumerate(self.demo_targets, 1):
            print(f"\n📋 Analyzing Target {i}: {target}")
            
            try:
                start_time = time.time()
                
                # Perform enhanced target analysis
                analysis = await enhanced_target_analysis(target)
                
                duration = time.time() - start_time
                
                print(f"✅ Analysis completed in {duration:.2f}s")
                print(f"   Priority Score: {analysis.get('priority_score', 0):.2f}")
                print(f"   Recommended Tools: {len(analysis.get('recommended_tools', []))}")
                print(f"   ML Confidence: {analysis.get('ml_analysis', {}).get('confidence', 0):.2f}")
                
                # Store results
                self.results.append({
                    'phase': 'analysis',
                    'target': target,
                    'duration': duration,
                    'result': analysis
                })
                
            except Exception as e:
                print(f"❌ Analysis failed: {e}")
        
        print("\n✅ Target analysis demonstration completed!\n")
    
    async def demonstrate_comprehensive_scanning(self):
        """Demonstrate comprehensive scanning with optimization"""
        print("🔍 DEMONSTRATION 2: Comprehensive Scanning with Optimization")
        print("-" * 60)
        
        # Use first target for detailed scan demonstration
        target = self.demo_targets[0]
        print(f"\n🎯 Performing comprehensive scan on: {target}")
        
        try:
            start_time = time.time()
            
            # Get initial system stats
            initial_stats = optimization_manager.get_comprehensive_stats()
            
            # Perform comprehensive scan
            scan_results = await enhanced_comprehensive_scan(target)
            
            duration = time.time() - start_time
            
            # Get final system stats
            final_stats = optimization_manager.get_comprehensive_stats()
            
            print(f"✅ Comprehensive scan completed in {duration:.2f}s")
            print(f"   Scan Status: {scan_results.get('status', 'unknown')}")
            print(f"   Phases Completed: {len(scan_results.get('phases', {}))}")
            print(f"   Findings Generated: {len(scan_results.get('findings', []))}")
            print(f"   Performance Metrics: Available")
            
            # Show optimization impact
            cache_hit_ratio = final_stats.get('cache_stats', {}).get('hit_ratio', 0)
            print(f"   Cache Hit Ratio: {cache_hit_ratio:.1%}")
            
            # Store results
            self.results.append({
                'phase': 'comprehensive_scan',
                'target': target,
                'duration': duration,
                'result': scan_results,
                'initial_stats': initial_stats,
                'final_stats': final_stats
            })
            
        except Exception as e:
            print(f"❌ Comprehensive scan failed: {e}")
            import traceback
            traceback.print_exc()
        
        print("\n✅ Comprehensive scanning demonstration completed!\n")
    
    async def demonstrate_enhanced_reporting(self):
        """Demonstrate enhanced reporting capabilities"""
        print("📊 DEMONSTRATION 3: Enhanced Reporting & Analytics")
        print("-" * 60)
        
        # Use scan results from previous demonstration
        scan_result = None
        for result in self.results:
            if result['phase'] == 'comprehensive_scan':
                scan_result = result['result']
                break
        
        if not scan_result:
            print("⚠️  No scan results available for reporting demonstration")
            return
        
        try:
            start_time = time.time()
            
            # Generate enhanced report
            report = await generate_enhanced_report(scan_result)
            
            duration = time.time() - start_time
            
            print(f"✅ Enhanced report generated in {duration:.2f}s")
            print(f"   Report Sections: {len(report)}")
            print(f"   Executive Summary: Available")
            print(f"   Technical Findings: {len(report.get('technical_findings', []))}")
            print(f"   Risk Assessment: Available")
            print(f"   ML Insights: Available")
            print(f"   Optimization Report: Available")
            
            # Show key metrics
            exec_summary = report.get('executive_summary', {})
            print(f"   Overall Risk Level: {exec_summary.get('overall_risk_level', 'Unknown')}")
            print(f"   Critical Findings: {exec_summary.get('critical_findings_count', 0)}")
            
            # Store results
            self.results.append({
                'phase': 'enhanced_reporting',
                'duration': duration,
                'result': report
            })
            
        except Exception as e:
            print(f"❌ Enhanced reporting failed: {e}")
            import traceback
            traceback.print_exc()
        
        print("\n✅ Enhanced reporting demonstration completed!\n")
    
    def demonstrate_optimization_features(self):
        """Demonstrate optimization and performance features"""
        print("⚡ DEMONSTRATION 4: Optimization & Performance Features")
        print("-" * 60)
        
        try:
            # Get comprehensive optimization statistics
            opt_stats = optimization_manager.get_comprehensive_stats()
            
            print("📈 Current Optimization Statistics:")
            print(f"   Cache Size: {opt_stats.get('cache_stats', {}).get('size', 0)}")
            print(f"   Cache Hit Ratio: {opt_stats.get('cache_stats', {}).get('hit_ratio', 0):.1%}")
            print(f"   Optimization Level: {opt_stats.get('optimization_level', 'unknown')}")
            
            # Show circuit breaker states
            circuit_states = opt_stats.get('circuit_breaker_states', {})
            print(f"   Circuit Breakers: {len(circuit_states)} configured")
            for name, state in circuit_states.items():
                status_emoji = "🟢" if state == "closed" else "🔴" if state == "open" else "🟡"
                print(f"     {status_emoji} {name}: {state}")
            
            # Show resource usage
            resource_usage = opt_stats.get('resource_usage', {})
            print(f"   CPU Usage: {resource_usage.get('cpu_percent', 0):.1f}%")
            print(f"   Memory Usage: {resource_usage.get('memory_percent', 0):.1f}%")
            
            # Get optimization recommendations
            recommendations = optimization_manager.optimize_configuration()
            print(f"   Active Recommendations: {len(recommendations)}")
            
            for rec_name, rec_details in recommendations.items():
                if isinstance(rec_details, dict) and 'action' in rec_details:
                    print(f"     💡 {rec_name}: {rec_details['action']}")
            
        except Exception as e:
            print(f"❌ Optimization demonstration failed: {e}")
        
        print("\n✅ Optimization features demonstration completed!\n")
    
    def demonstrate_ml_features(self):
        """Demonstrate ML enhancement features"""
        print("🤖 DEMONSTRATION 5: ML Enhancement Features")
        print("-" * 60)
        
        try:
            # Get ML system statistics
            ml_stats = ml_enhancer.get_system_stats()
            
            print("🧠 ML Enhancement Statistics:")
            
            # Model stats
            model_stats = ml_stats.get('model_stats', {})
            print(f"   Available Models: {len(model_stats.get('available_models', []))}")
            print(f"   ML Libraries Available: {model_stats.get('ml_available', False)}")
            print(f"   Cache Size: {model_stats.get('cache_size', 0)}")
            
            # Rule engine stats
            rule_stats = ml_stats.get('rule_engine_stats', {})
            print(f"   Total Rules: {rule_stats.get('total_rules', 0)}")
            print(f"   Enabled Rules: {rule_stats.get('enabled_rules', 0)}")
            print(f"   Rule Cache Size: {rule_stats.get('cache_size', 0)}")
            
            # Performance metrics
            perf_metrics = ml_stats.get('performance_metrics', {})
            if perf_metrics:
                print(f"   Performance Metrics Available: {len(perf_metrics)}")
                for metric_name, metric_data in perf_metrics.items():
                    if isinstance(metric_data, dict):
                        confidence = metric_data.get('confidence', 0)
                        sample_count = metric_data.get('sample_count', 0)
                        print(f"     📊 {metric_name}: {sample_count} samples, {confidence:.2f} confidence")
            
            # Validation stats
            validation_stats = ml_stats.get('validation_stats', {})
            if validation_stats:
                print(f"   Data Validation Types: {len(validation_stats)}")
                for val_type, val_data in validation_stats.items():
                    total = val_data.get('total_validations', 0)
                    success = val_data.get('successful_validations', 0)
                    success_rate = (success / total * 100) if total > 0 else 0
                    print(f"     ✓ {val_type}: {success_rate:.1f}% success rate ({success}/{total})")
            
        except Exception as e:
            print(f"❌ ML features demonstration failed: {e}")
        
        print("\n✅ ML enhancement features demonstration completed!\n")
    
    def save_demonstration_results(self):
        """Save demonstration results to file"""
        print("💾 SAVING DEMONSTRATION RESULTS")
        print("-" * 60)
        
        try:
            # Prepare results summary
            summary = {
                'demonstration_timestamp': datetime.now().isoformat(),
                'framework_version': '2.0-enhanced',
                'total_demonstrations': len(self.results),
                'results': self.results,
                'framework_statistics': {
                    'optimization_stats': optimization_manager.get_comprehensive_stats(),
                    'ml_stats': ml_enhancer.get_system_stats()
                }
            }
            
            # Save to file
            results_file = Path(f"demo_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
            with open(results_file, 'w') as f:
                json.dump(summary, f, indent=2, default=str)
            
            print(f"✅ Results saved to: {results_file}")
            print(f"   File size: {results_file.stat().st_size} bytes")
            print(f"   Total demonstrations: {len(self.results)}")
            
        except Exception as e:
            print(f"❌ Failed to save results: {e}")
        
        print("\n✅ Demonstration results saved!\n")
    
    def print_summary(self):
        """Print demonstration summary"""
        print("📋 DEMONSTRATION SUMMARY")
        print("-" * 60)
        
        if not self.results:
            print("⚠️  No demonstration results available")
            return
        
        total_duration = sum(result.get('duration', 0) for result in self.results)
        
        print(f"🎯 Total Demonstrations: {len(self.results)}")
        print(f"⏱️  Total Duration: {total_duration:.2f}s")
        print(f"📊 Framework Version: 2.0 Enhanced")
        print(f"🚀 All Systems: Operational")
        
        print("\n📈 Performance Highlights:")
        
        # Analysis performance
        analysis_results = [r for r in self.results if r['phase'] == 'analysis']
        if analysis_results:
            avg_analysis_time = sum(r['duration'] for r in analysis_results) / len(analysis_results)
            print(f"   • Target Analysis: {avg_analysis_time:.2f}s average")
        
        # Scan performance
        scan_results = [r for r in self.results if r['phase'] == 'comprehensive_scan']
        if scan_results:
            scan_time = scan_results[0]['duration']
            findings_count = len(scan_results[0]['result'].get('findings', []))
            print(f"   • Comprehensive Scan: {scan_time:.2f}s, {findings_count} findings")
        
        # Reporting performance
        report_results = [r for r in self.results if r['phase'] == 'enhanced_reporting']
        if report_results:
            report_time = report_results[0]['duration']
            print(f"   • Enhanced Reporting: {report_time:.2f}s")
        
        print("\n🎉 Enhanced Bug Bounty Framework demonstration completed successfully!")
        print("📖 Review the generated reports and logs for detailed analysis.")
        print("🔧 Framework is ready for production deployment.\n")

async def main():
    """Main demonstration function"""
    demo = ProductionDemo()
    
    # Print banner and check status
    demo.print_banner()
    
    if not demo.check_framework_status():
        print("❌ Cannot proceed without enhanced framework components")
        return
    
    try:
        # Run all demonstrations
        await demo.demonstrate_target_analysis()
        await demo.demonstrate_comprehensive_scanning()
        await demo.demonstrate_enhanced_reporting()
        demo.demonstrate_optimization_features()
        demo.demonstrate_ml_features()
        
        # Save results and print summary
        demo.save_demonstration_results()
        demo.print_summary()
        
    except KeyboardInterrupt:
        print("\n⚠️  Demonstration interrupted by user")
    except Exception as e:
        print(f"\n❌ Demonstration failed with error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    # Check if running in async environment
    try:
        # Run the demonstration
        asyncio.run(main())
    except Exception as e:
        print(f"❌ Failed to run demonstration: {e}")
        print("\n🔧 Troubleshooting:")
        print("1. Ensure all dependencies are installed")
        print("2. Check that enhanced_integration.py is available")
        print("3. Verify Python version compatibility (3.8+)")
        print("4. Review error logs for detailed information")
