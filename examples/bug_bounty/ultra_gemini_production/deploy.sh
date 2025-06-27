#!/bin/bash

# Ultra Gemini Agentic System Deployment Script
set -e

echo "🚀 Deploying Ultra Gemini Agentic System..."

# Check requirements
command -v docker >/dev/null 2>&1 || { echo "Docker is required but not installed. Aborting." >&2; exit 1; }
command -v docker-compose >/dev/null 2>&1 || { echo "Docker Compose is required but not installed. Aborting." >&2; exit 1; }

# Create necessary directories
mkdir -p data logs ssl

# Set permissions
chmod +x production_main.py

# Check for API key
if [ -z "$GEMINI_API_KEY" ]; then
    echo "⚠️ Warning: GEMINI_API_KEY environment variable not set"
    echo "Set it with: export GEMINI_API_KEY='your_api_key_here'"
fi

# Build and start services
echo "📦 Building Docker images..."
docker-compose build

echo "🔧 Starting services..."
docker-compose up -d

echo "⏳ Waiting for services to be ready..."
sleep 30

# Health check
echo "🔍 Performing health check..."
if docker-compose ps | grep -q "Up"; then
    echo "✅ Deployment successful!"
    echo "📊 Dashboard available at: http://localhost"
    echo "📈 Metrics available at: http://localhost:9090"
    echo "📋 Logs: docker-compose logs -f"
else
    echo "❌ Deployment failed. Check logs: docker-compose logs"
    exit 1
fi

echo "🎯 Ultra Gemini Agentic System is now running!"
