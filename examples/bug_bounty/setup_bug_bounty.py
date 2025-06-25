#!/usr/bin/env python3
"""
Bug Bounty Setup Script
Quick setup for CAI bug bounty hunting with Gemini integration
"""

import os
import subprocess
import sys
from pathlib import Path

def check_python_version():
    """Check if Python version is compatible"""
    if sys.version_info < (3, 9):
        print("❌ Python 3.9 or higher is required")
        sys.exit(1)
    print(f"✅ Python {sys.version_info.major}.{sys.version_info.minor} detected")

def install_cai_framework():
    """Install CAI framework and dependencies"""
    print("📦 Installing CAI framework...")
    try:
        subprocess.run([sys.executable, "-m", "pip", "install", "cai-framework"], check=True)
        print("✅ CAI framework installed")
    except subprocess.CalledProcessError:
        print("❌ Failed to install CAI framework")
        sys.exit(1)

def install_bug_bounty_tools():
    """Install additional bug bounty tools"""
    tools = {
        "subfinder": "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
        "assetfinder": "go install github.com/tomnomnom/assetfinder@latest",
        "nuclei": "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        "ffuf": "go install github.com/ffuf/ffuf/v2@latest",
        "gau": "go install github.com/lc/gau/v2/cmd/gau@latest",
        "waybackurls": "go install github.com/tomnomnom/waybackurls@latest",
        "paramspider": "pip install paramspider"
    }
    
    print("🛠️  Installing bug bounty tools...")
    
    # Check if Go is installed
    try:
        subprocess.run(["go", "version"], check=True, capture_output=True)
        go_available = True
        print("✅ Go detected")
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("⚠️  Go not found. Some tools will be skipped.")
        go_available = False
    
    for tool, install_cmd in tools.items():
        try:
            if install_cmd.startswith("go") and not go_available:
                print(f"⏭️  Skipping {tool} (Go required)")
                continue
                
            print(f"  Installing {tool}...")
            subprocess.run(install_cmd.split(), check=True, capture_output=True)
            print(f"  ✅ {tool} installed")
        except subprocess.CalledProcessError:
            print(f"  ⚠️  Failed to install {tool}")

def setup_environment():
    """Setup environment configuration"""
    print("⚙️  Setting up environment...")
    
    # Create bug bounty directory
    bb_dir = Path.home() / "bug_bounty"
    bb_dir.mkdir(exist_ok=True)
    
    # Create results directory
    results_dir = bb_dir / "results"
    results_dir.mkdir(exist_ok=True)
    
    # Create wordlists directory
    wordlists_dir = bb_dir / "wordlists"
    wordlists_dir.mkdir(exist_ok=True)
    
    # Download common wordlists
    print("  📥 Downloading wordlists...")
    wordlists = {
        "common.txt": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt",
        "big.txt": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/big.txt",
        "parameters.txt": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/burp-parameter-names.txt"
    }
    
    for filename, url in wordlists.items():
        try:
            import requests
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            
            with open(wordlists_dir / filename, 'w') as f:
                f.write(response.text)
            print(f"  ✅ Downloaded {filename}")
        except Exception as e:
            print(f"  ⚠️  Failed to download {filename}: {str(e)}")
    
    print(f"✅ Environment setup complete at {bb_dir}")

def create_config_file():
    """Create configuration file from template"""
    print("📝 Creating configuration file...")
    
    config_content = """# Bug Bounty Configuration
# Copy this to .env and fill in your API keys

# === Primary Model Configuration ===
# Google Gemini (Recommended for bug bounty)
GOOGLE_API_KEY=your_google_gemini_api_key_here
CAI_MODEL=gemini/gemini-1.5-pro-latest

# === Fallback Models ===
OPENAI_API_KEY=your_openai_api_key_here
ANTHROPIC_API_KEY=your_anthropic_api_key_here

# === Search & Intelligence APIs ===
GOOGLE_SEARCH_API_KEY=your_google_search_api_key_here
GOOGLE_SEARCH_CX=your_custom_search_engine_id_here
PERPLEXITY_API_KEY=your_perplexity_api_key_here
SHODAN_API_KEY=your_shodan_api_key_here

# === Bug Bounty Configuration ===
RATE_LIMIT=10
USER_AGENT="BugBountyBot/1.0 (Security Research)"
MAX_THREADS=50
REQUEST_TIMEOUT=30

# === Paths ===
WORDLISTS_DIR=~/bug_bounty/wordlists
RESULTS_DIR=~/bug_bounty/results

# === Logging ===
CAI_LOG_LEVEL=info
CAI_ENABLE_TRACING=true
"""
    
    with open("bug_bounty_config.env", "w") as f:
        f.write(config_content)
    
    print("✅ Configuration template created: bug_bounty_config.env")

def setup_gemini_integration():
    """Provide instructions for Gemini setup"""
    print("\n🤖 Google Gemini Setup Instructions:")
    print("1. Go to https://makersuite.google.com/app/apikey")
    print("2. Sign in with your Google account")
    print("3. Click 'Create API Key'")
    print("4. Copy the API key to your .env file as GOOGLE_API_KEY")
    print("5. Gemini Pro 1.5 is recommended for bug bounty hunting")
    print("\n💡 Gemini advantages for bug bounty:")
    print("   - Superior pattern recognition")
    print("   - Better false positive reduction")
    print("   - Enhanced correlation of findings")
    print("   - Improved attack chain analysis")

def test_installation():
    """Test the installation"""
    print("\n🧪 Testing installation...")
    
    try:
        # Test CAI import
        import cai
        print("✅ CAI framework import successful")
    except ImportError:
        print("❌ CAI framework import failed")
        return False
    
    # Test tool availability
    tools_to_test = ["nmap", "curl"]
    for tool in tools_to_test:
        try:
            subprocess.run([tool, "--version"], capture_output=True, check=True)
            print(f"✅ {tool} available")
        except (subprocess.CalledProcessError, FileNotFoundError):
            print(f"⚠️  {tool} not found (install manually if needed)")
    
    return True

def print_quick_start():
    """Print quick start guide"""
    print("\n🚀 Quick Start Guide:")
    print("1. Copy bug_bounty_config.env to .env and add your API keys")
    print("2. Set your GOOGLE_API_KEY for Gemini integration")
    print("3. Run a quick scan:")
    print("   python examples/bug_bounty/bug_bounty_workflow.py example.com quick")
    print("4. Run a full assessment:")
    print("   python examples/bug_bounty/bug_bounty_workflow.py example.com full")
    print("5. Focus on specific vulnerabilities:")
    print("   python examples/bug_bounty/bug_bounty_workflow.py example.com xss")
    print("\n📚 Documentation:")
    print("   - CAI Framework: https://github.com/aliasrobotics/cai")
    print("   - Bug Bounty Guide: examples/bug_bounty/README.md")

def main():
    """Main setup function"""
    print("🎯 CAI Bug Bounty Setup with Gemini Integration")
    print("=" * 50)
    
    check_python_version()
    install_cai_framework()
    install_bug_bounty_tools()
    setup_environment()
    create_config_file()
    setup_gemini_integration()
    
    if test_installation():
        print("\n🎉 Setup completed successfully!")
        print_quick_start()
    else:
        print("\n❌ Setup completed with some issues. Please check the error messages above.")

if __name__ == "__main__":
    main()
