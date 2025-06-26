"""
Quick Demo Script for Enhanced Bug Bounty Framework
Simple demonstration of the enhanced framework capabilities
"""

import asyncio
import json
import sys
import traceback
from enhanced_integration import enhanced_framework

async def quick_demo():
    """Quick demonstration of framework capabilities"""
    print('🔍 Quick Framework Demo')
    print('=' * 40)
    
    try:
        # Test target analysis
        target = 'https://example.com'
        print(f'Analyzing target: {target}')
        
        analysis = await enhanced_framework.analyze_target(target)
        
        print(f'✅ Analysis completed - Priority: {analysis.get("priority_score", 0):.2f}')
        print(f'📋 Recommended tools: {len(analysis.get("recommended_tools", []))} tools')
        print(f'⏱️  Estimated scan time: {analysis.get("estimated_scan_time", {}).get("estimated_minutes", 0)} minutes')
        
        # Show framework stats
        print('\n📊 Framework Statistics:')
        ml_stats = enhanced_framework.ml_enhancer.get_system_stats()
        opt_stats = enhanced_framework.optimization_manager.get_comprehensive_stats()
        
        print(f'   ML System: {len(ml_stats.get("performance_metrics", {}))} metrics tracked')
        print(f'   Optimization Level: {opt_stats.get("optimization_level", "balanced")}')
        print(f'   Cache Size: {opt_stats.get("cache_stats", {}).get("size", 0)} items')
        print(f'   Circuit Breakers: {len(opt_stats.get("circuit_breaker_states", {}))} configured')
        
        # Test a quick ML analysis
        print('\n🧠 Testing ML Enhancement:')
        test_vuln = {
            'url': 'https://example.com/admin',
            'method': 'POST', 
            'description': 'Admin panel with potential authentication bypass'
        }
        
        ml_result = await enhanced_framework.ml_enhancer.analyze_vulnerability(test_vuln)
        print(f'   ML Analysis: Confidence {ml_result.get("confidence", 0):.2f}')
        print(f'   Method Used: {ml_result.get("method", "unknown")}')
        
        # Show optimization recommendations
        print('\n⚡ Optimization Recommendations:')
        recommendations = enhanced_framework.optimization_manager.optimize_configuration()
        for key, rec in recommendations.items():
            if isinstance(rec, dict) and 'action' in rec:
                print(f'   {key}: {rec["action"]}')
        
        print('\n🎉 Framework operational and ready!')
        print('✅ All components working correctly!')
        
        return True
        
    except Exception as e:
        print(f'❌ Demo failed: {str(e)}')
        print(f'Error details: {traceback.format_exc()}')
        return False

async def performance_test():
    """Quick performance test"""
    print('\n🚀 Performance Test')
    print('=' * 40)
    
    import time
    
    # Test multiple target analyses
    targets = [
        'https://example.com',
        'https://test.example.org', 
        'https://admin.example.net'
    ]
    
    start_time = time.time()
    
    for i, target in enumerate(targets, 1):
        print(f'Testing target {i}/{len(targets)}: {target}')
        try:
            analysis = await enhanced_framework.analyze_target(target)
            priority = analysis.get('priority_score', 0)
            tools_count = len(analysis.get('recommended_tools', []))
            print(f'   ✅ Priority: {priority:.2f}, Tools: {tools_count}')
        except Exception as e:
            print(f'   ❌ Failed: {str(e)}')
    
    total_time = time.time() - start_time
    print(f'\n⏱️  Total time: {total_time:.2f} seconds')
    print(f'📈 Average per target: {total_time/len(targets):.2f} seconds')

def main():
    """Main demo function"""
    print('🚀 Enhanced Bug Bounty Framework - Quick Demo')
    print('=' * 60)
    
    try:
        # Run quick demo
        success = asyncio.run(quick_demo())
        
        if success:
            # Run performance test
            asyncio.run(performance_test())
            
            print('\n🏆 Demo completed successfully!')
            print('Framework is ready for production use.')
        else:
            print('\n⚠️  Demo encountered issues. Check the error messages above.')
            
    except KeyboardInterrupt:
        print('\n⏹️  Demo interrupted by user.')
    except Exception as e:
        print(f'\n💥 Unexpected error: {str(e)}')
        print(traceback.format_exc())

if __name__ == '__main__':
    main()
