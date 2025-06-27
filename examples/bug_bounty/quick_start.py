#!/usr/bin/env python3
"""
🚀 QUICK START LAUNCHER - Your Bug Bounty Money Machine
💰 Simple launcher to get you started immediately
"""

import asyncio
import os
from quick_start_config import GEMINI_API_KEY, HUNTER_PROFILE, SYSTEM_CONFIG
from personal_bug_bounty_optimizer import PersonalBugBountyOptimizer

async def quick_start_demo():
    """Quick start demonstration"""
    print("🚀 WELCOME TO YOUR BUG BOUNTY MONEY MACHINE!")
    print("=" * 60)
    
    # Check API key
    if GEMINI_API_KEY == "your_gemini_api_key_here":
        print("⚠️  SETUP REQUIRED:")
        print("   1. Get your API key: https://makersuite.google.com/app/apikey")
        print("   2. Edit quick_start_config.py and add your API key")
        print("   3. Run this script again")
        print("\n🔧 For now, running in SIMULATION mode...")
        api_key = None
    else:
        print("✅ API Key configured - running with full AI power!")
        api_key = GEMINI_API_KEY
        os.environ['GEMINI_API_KEY'] = api_key
    
    # Initialize your personal optimizer
    print(f"\n🎯 Initializing Your Personal Bug Bounty Optimizer...")
    optimizer = PersonalBugBountyOptimizer(HUNTER_PROFILE)
    
    print(f"\n📋 Your Hunter Profile:")
    for key, value in HUNTER_PROFILE.items():
        print(f"   {key}: {value}")
    
    # Generate your personalized plan
    print(f"\n💰 Generating Your Money-Making Plan...")
    daily_plan = optimizer.generate_daily_hunting_plan()
    
    print(f"\n📈 Your Daily Earning Plan:")
    print(f"   💰 Expected Daily Earnings: ${daily_plan['expected_daily_earnings']:,.0f}")
    print(f"   📅 Expected Monthly Earnings: ${daily_plan['expected_monthly_earnings']:,.0f}")
    
    # Show your competitive advantages
    print(f"\n🏆 Your Competitive Advantages:")
    analysis = optimizer.generate_competitive_analysis()
    
    typical_monthly = analysis['typical_hunter_profile']['avg_monthly_earnings']
    your_monthly = analysis['your_optimized_profile']['projected_monthly_earnings']
    multiplier = your_monthly / typical_monthly
    
    print(f"   📊 Typical Hunter: ${typical_monthly:,}/month")
    print(f"   🚀 YOU with AI: ${your_monthly:,}/month")
    print(f"   ⚡ Advantage: {multiplier:.1f}x earnings potential!")
    
    # Show 12-month projection
    print(f"\n📈 Your 12-Month Earnings Projection:")
    projection = optimizer.create_earnings_projection()
    
    print(f"   💰 Conservative: ${projection['conservative_estimate']:,}")
    print(f"   🎯 Realistic: ${projection['total_12_month_projection']:,}")
    print(f"   🚀 Optimistic: ${projection['optimistic_estimate']:,}")
    
    # Export your config
    config_file = optimizer.export_personal_optimization_config()
    print(f"\n💾 Your personal config saved to: personal_bug_bounty_config.json")
    
    print(f"\n🎯 NEXT STEPS TO START MAKING MONEY:")
    print(f"   1. Get your Gemini API key (if not done)")
    print(f"   2. Run: python ultra_optimized_gemini_system.py")
    print(f"   3. Or run: python complete_platform_integration.py")
    print(f"   4. Start with easy targets to build confidence")
    print(f"   5. Use forensic reporting for maximum acceptance rates")
    
    print(f"\n💰 GO MAKE THAT MONEY! 🚀")

if __name__ == "__main__":
    asyncio.run(quick_start_demo())
