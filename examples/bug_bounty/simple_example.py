#!/usr/bin/env python3
"""
Simple Bug Bounty Example
Quick example showing how to use the enhanced CAI bug bounty agent with Gemini
"""

import asyncio
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

async def simple_bug_bounty_example():
    """Simple example of using the bug bounty agent"""
    
    print("🎯 Simple Bug Bounty Example with CAI + Gemini")
    print("=" * 50)
    
    # Check if API key is configured
    if not os.getenv('GOOGLE_API_KEY') and not os.getenv('OPENAI_API_KEY'):
        print("❌ No API key found!")
        print("Please set GOOGLE_API_KEY or OPENAI_API_KEY in your .env file")
        print("Copy .env.example to .env and add your API keys")
        return
    
    # Import the bug bounty agent
    try:
        from gemini_bug_bounty_agent import BugBountyAgent, quick_recon
    except ImportError as e:
        print(f"❌ Import error: {e}")
        print("Make sure you're running from the bug_bounty directory")
        return
    
    # Target for demonstration (use a safe, authorized target)
    target = "testfire.net"  # Altoro Mutual - a safe testing site
    
    print(f"🔍 Target: {target}")
    print("📝 Note: Using testfire.net - a legitimate testing site")
    print()
    
    try:
        # Example 1: Quick reconnaissance
        print("🚀 Running quick reconnaissance...")
        recon_results = await quick_recon(target)
        print("✅ Reconnaissance complete!")
        print(f"📊 Results preview: {recon_results['recon_results'][:200]}...")
        print()
        
        # Example 2: Create a bug bounty agent
        print("🤖 Creating bug bounty agent...")
        hunter = BugBountyAgent([target])
        print("✅ Agent created with Gemini integration!")
        print()
        
        # Example 3: Simple vulnerability assessment
        print("🛡️ Running basic security assessment...")
        assessment_prompt = f"""
        Perform a basic security assessment on {target}:
        1. Analyze the main page for technologies used
        2. Check for common security headers
        3. Look for obvious vulnerabilities or misconfigurations
        4. Provide a summary of findings and recommendations
        
        Stay within ethical boundaries and focus on passive analysis.
        """
        
        result = await hunter.agent.run(assessment_prompt)
        print("✅ Assessment complete!")
        print("📋 Summary:")
        print(result.final_output)
        
    except Exception as e:
        print(f"❌ Error during assessment: {str(e)}")
        print("This might be due to network issues or missing dependencies")
    
    print("\n🎉 Example completed!")
    print("\n📚 Next steps:")
    print("1. Review the findings above")
    print("2. Try the full workflow: python bug_bounty_workflow.py testfire.net full")
    print("3. Explore focused scans: python bug_bounty_workflow.py testfire.net xss")
    print("4. Read the README.md for more advanced usage")

async def test_gemini_connection():
    """Test Gemini API connection"""
    print("🧪 Testing Gemini API connection...")
    
    if not os.getenv('GOOGLE_API_KEY'):
        print("⚠️ GOOGLE_API_KEY not set, skipping Gemini test")
        return False
    
    try:
        # Simple test using the CAI framework
        from agents import Agent, Runner
        
        # Create a simple agent with Gemini
        test_agent = Agent(
            name="Test Agent",
            instructions="You are a helpful cybersecurity assistant. Respond briefly.",
            model="gemini/gemini-1.5-pro-latest"
        )
        
        result = await Runner.run(test_agent, "Say hello and confirm you're using Gemini")
        print("✅ Gemini connection successful!")
        print(f"📝 Response: {result.final_output}")
        return True
        
    except Exception as e:
        print(f"❌ Gemini connection failed: {str(e)}")
        print("💡 Try setting OPENAI_API_KEY as a fallback")
        return False

def check_prerequisites():
    """Check if prerequisites are met"""
    print("🔍 Checking prerequisites...")
    
    # Check Python version
    import sys
    if sys.version_info < (3, 9):
        print("❌ Python 3.9+ required")
        return False
    print(f"✅ Python {sys.version_info.major}.{sys.version_info.minor}")
    
    # Check CAI installation
    try:
        import cai
        print("✅ CAI framework installed")
    except ImportError:
        print("❌ CAI framework not installed")
        print("💡 Run: pip install cai-framework")
        return False
    
    # Check agents import
    try:
        import agents
        print("✅ Agents module available")
    except ImportError:
        print("❌ Agents module not available")
        print("💡 Make sure CAI is properly installed")
        return False
    
    return True

async def main():
    """Main function"""
    print("🎯 CAI Bug Bounty Testing & Demo")
    print("=" * 40)
    
    # Check prerequisites
    if not check_prerequisites():
        print("\n❌ Prerequisites not met. Please install required dependencies.")
        return
    
    print()
    
    # Test API connection
    await test_gemini_connection()
    print()
    
    # Run the example
    await simple_bug_bounty_example()

if __name__ == "__main__":
    # Run the example
    asyncio.run(main())
