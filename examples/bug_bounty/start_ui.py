#!/usr/bin/env python3
"""
🚀 SIMPLE BUG BOUNTY UI LAUNCHER
Quick way to start the web interface
"""

import subprocess
import sys
import os

def check_dependencies():
    """Check if required packages are installed"""
    try:
        import flask
        print("✅ Flask is installed")
        return True
    except ImportError:
        print("❌ Flask not found")
        print("Installing Flask...")
        try:
            subprocess.run([sys.executable, '-m', 'pip', 'install', 'flask'], check=True)
            print("✅ Flask installed successfully")
            return True
        except subprocess.CalledProcessError:
            print("❌ Failed to install Flask")
            return False

def main():
    print("🎯 Bug Bounty Hunter - Web UI Launcher")
    print("=" * 50)
    
    # Check dependencies
    if not check_dependencies():
        print("❌ Failed to install dependencies")
        return
    
    # Create workspace
    workspace = os.path.expanduser("~/bb_pro_workspace")
    os.makedirs(workspace, exist_ok=True)
    os.makedirs(f"{workspace}/results", exist_ok=True)
    print(f"✅ Workspace ready: {workspace}")
    
    # Start the web UI
    print("\n🚀 Starting Web UI...")
    print("📱 Open your browser to: http://localhost:5000")
    print("🔧 Press Ctrl+C to stop")
    print("-" * 50)
    
    try:
        # Import and run the web UI
        from web_ui import app, BugBountyUI
        
        # Initialize database
        print("🗄️ Initializing database...")
        bug_bounty_ui = BugBountyUI()
        print("✅ Database ready!")
        
        app.run(debug=False, host='0.0.0.0', port=5000)
    except ImportError:
        print("❌ web_ui.py not found in current directory")
    except KeyboardInterrupt:
        print("\n👋 Shutting down...")
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    main()
