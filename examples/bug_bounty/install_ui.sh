#!/bin/bash
# 🎯 Bug Bounty Hunter UI - Installation Script

echo "🚀 Installing Bug Bounty Hunter Web UI..."

# Install Python packages
echo "📦 Installing Python dependencies..."
pip3 install flask

# Create workspace directory
echo "📁 Creating workspace directory..."
mkdir -p ~/bb_pro_workspace/results

# Make script executable
chmod +x web_ui.py

echo "✅ Installation complete!"
echo ""
echo "🌐 To start the web UI:"
echo "python3 web_ui.py"
echo ""
echo "📱 Then open your browser to: http://localhost:5000"
echo "🎯 Happy bug hunting!"
