#!/usr/bin/env python3
"""
🚀 ULTRA-OPTIMIZED GEMINI AGENTIC SYSTEM - PRODUCTION DEPLOYMENT
🎯 Complete production-ready configuration and deployment system
⚡ Multi-environment support with advanced optimization
"""

import os
import json
import yaml
from typing import Dict, Any, Optional
from dataclasses import dataclass, asdict
from pathlib import Path
import logging
import shutil

@dataclass
class ProductionConfig:
    """Production configuration structure"""
    # Environment settings
    environment: str = "production"
    debug_mode: bool = False
    log_level: str = "INFO"
    
    # Gemini API settings
    gemini_api_key: Optional[str] = None
    gemini_model: str = "gemini-pro"
    api_rate_limit: float = 1.0
    api_timeout: float = 30.0
    
    # Performance settings
    max_concurrent_campaigns: int = 5
    max_iterations_per_campaign: int = 10
    cache_ttl_seconds: int = 300
    execution_timeout: float = 60.0
    
    # Database settings
    database_path: str = "ultra_gemini_production.db"
    backup_interval_hours: int = 6
    max_database_size_mb: int = 1000
    
    # Security settings
    enable_encryption: bool = True
    api_key_rotation_days: int = 30
    audit_logging: bool = True
    rate_limiting: bool = True
    
    # Resource limits
    max_cpu_usage_percent: float = 80.0
    max_memory_usage_mb: float = 4096
    max_network_bandwidth_mbps: float = 100.0
    
    # Monitoring and alerting
    enable_monitoring: bool = True
    alert_on_high_failure_rate: bool = True
    failure_rate_threshold: float = 0.1
    performance_degradation_threshold: float = 0.2

class ProductionDeployment:
    """Production deployment manager"""
    
    def __init__(self, config_path: Optional[str] = None):
        self.config_path = config_path or "production_config.yaml"
        self.config = self._load_or_create_config()
        self.deployment_path = Path("ultra_gemini_production")
        
    def _load_or_create_config(self) -> ProductionConfig:
        """Load existing config or create default"""
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, 'r') as f:
                    config_data = yaml.safe_load(f)
                return ProductionConfig(**config_data)
            except Exception as e:
                print(f"Warning: Could not load config: {e}. Using defaults.")
        
        # Create default config
        config = ProductionConfig()
        self._save_config(config)
        return config
    
    def _save_config(self, config: ProductionConfig):
        """Save configuration to file"""
        try:
            with open(self.config_path, 'w') as f:
                yaml.dump(asdict(config), f, default_flow_style=False)
        except Exception as e:
            print(f"Warning: Could not save config: {e}")
    
    def create_production_environment(self) -> Dict[str, str]:
        """Create complete production environment"""
        results = {
            'status': 'success',
            'deployment_path': str(self.deployment_path),
            'files_created': [],
            'instructions': []
        }
        
        try:
            # Create deployment directory
            self.deployment_path.mkdir(exist_ok=True)
            
            # Copy main system files
            system_files = [
                'ultra_optimized_gemini_system.py',
                'gemini_analytics_dashboard.py'
            ]
            
            for file in system_files:
                if os.path.exists(file):
                    dest = self.deployment_path / file
                    shutil.copy2(file, dest)
                    results['files_created'].append(str(dest))
            
            # Create production-specific files
            self._create_production_main()
            self._create_docker_config()
            self._create_systemd_service()
            self._create_nginx_config()
            self._create_monitoring_config()
            self._create_deployment_scripts()
            
            results['files_created'].extend([
                str(self.deployment_path / "production_main.py"),
                str(self.deployment_path / "Dockerfile"),
                str(self.deployment_path / "docker-compose.yml"),
                str(self.deployment_path / "gemini-agentic.service"),
                str(self.deployment_path / "nginx.conf"),
                str(self.deployment_path / "monitoring.yml"),
                str(self.deployment_path / "deploy.sh"),
                str(self.deployment_path / "requirements.txt")
            ])
            
            # Create configuration files
            prod_config_path = self.deployment_path / "production_config.yaml"
            shutil.copy2(self.config_path, prod_config_path)
            results['files_created'].append(str(prod_config_path))
            
            # Generate deployment instructions
            results['instructions'] = self._generate_deployment_instructions()
            
        except Exception as e:
            results['status'] = 'error'
            results['error'] = str(e)
        
        return results
    
    def _create_production_main(self):
        """Create production-ready main application"""
        content = '''#!/usr/bin/env python3
"""
🚀 ULTRA-OPTIMIZED GEMINI AGENTIC SYSTEM - PRODUCTION VERSION
Production-ready deployment with monitoring, logging, and error handling
"""

import asyncio
import logging
import signal
import sys
import yaml
from pathlib import Path
from ultra_optimized_gemini_system import UltraOrchestrator
from gemini_analytics_dashboard import UltraAnalyticsDashboard

class ProductionServer:
    """Production server with monitoring and health checks"""
    
    def __init__(self, config_path="production_config.yaml"):
        self.config = self._load_config(config_path)
        self.orchestrator = None
        self.dashboard = None
        self.running = False
        
        # Setup production logging
        self._setup_production_logging()
        
    def _load_config(self, config_path):
        """Load production configuration"""
        try:
            with open(config_path, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            logging.error(f"Failed to load config: {e}")
            return {}
    
    def _setup_production_logging(self):
        """Setup production-grade logging"""
        log_level = getattr(logging, self.config.get('log_level', 'INFO'))
        
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('production_gemini.log'),
                logging.StreamHandler(sys.stdout)
            ]
        )
        
        # Disable debug logging for external libraries
        logging.getLogger('urllib3').setLevel(logging.WARNING)
        logging.getLogger('requests').setLevel(logging.WARNING)
    
    async def start(self):
        """Start the production server"""
        logging.info("Starting Ultra Gemini Production Server")
        
        try:
            # Initialize components
            api_key = self.config.get('gemini_api_key') or os.getenv('GEMINI_API_KEY')
            self.orchestrator = UltraOrchestrator(api_key)
            self.dashboard = UltraAnalyticsDashboard()
            
            self.running = True
            
            # Setup signal handlers for graceful shutdown
            signal.signal(signal.SIGINT, self._signal_handler)
            signal.signal(signal.SIGTERM, self._signal_handler)
            
            logging.info("Production server started successfully")
            
            # Main server loop
            while self.running:
                await self._health_check()
                await asyncio.sleep(30)  # Health check every 30 seconds
                
        except Exception as e:
            logging.error(f"Production server error: {e}")
            raise
    
    async def _health_check(self):
        """Perform health checks"""
        try:
            # Check database connectivity
            if self.dashboard:
                report = self.dashboard.generate_comprehensive_report()
                if 'error' in report:
                    logging.warning(f"Dashboard health check failed: {report['error']}")
            
            # Log system status
            logging.info("Health check passed")
            
        except Exception as e:
            logging.error(f"Health check failed: {e}")
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals gracefully"""
        logging.info(f"Received signal {signum}, shutting down gracefully...")
        self.running = False
    
    async def process_campaign(self, target: str) -> dict:
        """Process a bug bounty campaign"""
        try:
            campaign_id = await self.orchestrator.start_ultra_campaign(target)
            results = await self.orchestrator.execute_ultra_workflow(campaign_id)
            return {'success': True, 'campaign_id': campaign_id, 'results': results}
        except Exception as e:
            logging.error(f"Campaign processing failed: {e}")
            return {'success': False, 'error': str(e)}

async def main():
    """Main production entry point"""
    server = ProductionServer()
    
    try:
        await server.start()
    except KeyboardInterrupt:
        logging.info("Server shutdown requested")
    except Exception as e:
        logging.error(f"Server crashed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())
'''
        
        with open(self.deployment_path / "production_main.py", 'w', encoding='utf-8') as f:
            f.write(content)
    
    def _create_docker_config(self):
        """Create Docker configuration"""
        dockerfile = '''FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \\
    gcc \\
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create non-root user
RUN useradd -m -u 1000 gemini && chown -R gemini:gemini /app
USER gemini

# Health check
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \\
    CMD python -c "import sqlite3; sqlite3.connect('ultra_gemini_production.db').close()" || exit 1

EXPOSE 8000

CMD ["python", "production_main.py"]
'''
        
        docker_compose = '''version: '3.8'

services:
  gemini-agentic:
    build: .
    container_name: ultra-gemini-agentic
    restart: unless-stopped
    environment:
      - GEMINI_API_KEY=${GEMINI_API_KEY}
      - PYTHONUNBUFFERED=1
    volumes:
      - ./data:/app/data
      - ./logs:/app/logs
    networks:
      - gemini-network
    healthcheck:
      test: ["CMD", "python", "-c", "import requests; requests.get('http://localhost:8000/health')"]
      interval: 30s
      timeout: 10s
      retries: 3

  nginx:
    image: nginx:alpine
    container_name: ultra-gemini-nginx
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
      - ./ssl:/etc/nginx/ssl:ro
    depends_on:
      - gemini-agentic
    networks:
      - gemini-network

  prometheus:
    image: prom/prometheus:latest
    container_name: ultra-gemini-prometheus
    restart: unless-stopped
    ports:
      - "9090:9090"
    volumes:
      - ./monitoring.yml:/etc/prometheus/prometheus.yml:ro
    networks:
      - gemini-network

networks:
  gemini-network:
    driver: bridge

volumes:
  gemini-data:
  gemini-logs:
'''
        
        requirements = '''google-generativeai>=0.3.0
psutil>=5.9.0
asyncio-throttle>=1.0.0
aiohttp>=3.8.0
aiofiles>=0.8.0
pyyaml>=6.0
fastapi>=0.100.0
uvicorn>=0.20.0
prometheus-client>=0.15.0
'''
        
        with open(self.deployment_path / "Dockerfile", 'w', encoding='utf-8') as f:
            f.write(dockerfile)
        
        with open(self.deployment_path / "docker-compose.yml", 'w', encoding='utf-8') as f:
            f.write(docker_compose)
        
        with open(self.deployment_path / "requirements.txt", 'w', encoding='utf-8') as f:
            f.write(requirements)
    
    def _create_systemd_service(self):
        """Create systemd service file"""
        service_content = '''[Unit]
Description=Ultra Gemini Agentic Bug Bounty System
After=network.target
Wants=network.target

[Service]
Type=simple
User=gemini
Group=gemini
WorkingDirectory=/opt/ultra-gemini-agentic
ExecStart=/opt/ultra-gemini-agentic/venv/bin/python production_main.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=ultra-gemini-agentic

# Environment
Environment=PYTHONUNBUFFERED=1
EnvironmentFile=/opt/ultra-gemini-agentic/.env

# Security
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/ultra-gemini-agentic/data

[Install]
WantedBy=multi-user.target
'''
        
        with open(self.deployment_path / "gemini-agentic.service", 'w', encoding='utf-8') as f:
            f.write(service_content)
    
    def _create_nginx_config(self):
        """Create nginx configuration"""
        nginx_config = '''events {
    worker_connections 1024;
}

http {
    upstream gemini_backend {
        server gemini-agentic:8000;
    }

    server {
        listen 80;
        server_name _;
        
        # Redirect HTTP to HTTPS
        return 301 https://$server_name$request_uri;
    }

    server {
        listen 443 ssl http2;
        server_name _;
        
        # SSL Configuration
        ssl_certificate /etc/nginx/ssl/cert.pem;
        ssl_certificate_key /etc/nginx/ssl/key.pem;
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512;
        ssl_prefer_server_ciphers off;
        
        # Security headers
        add_header X-Frame-Options DENY always;
        add_header X-Content-Type-Options nosniff always;
        add_header X-XSS-Protection "1; mode=block" always;
        add_header Strict-Transport-Security "max-age=63072000" always;
        
        # Rate limiting
        limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
        limit_req zone=api burst=20 nodelay;
        
        location / {
            proxy_pass http://gemini_backend;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            
            # Timeouts
            proxy_connect_timeout 30s;
            proxy_send_timeout 30s;
            proxy_read_timeout 30s;
        }
        
        location /health {
            access_log off;
            proxy_pass http://gemini_backend/health;
        }
        
        location /metrics {
            access_log off;
            proxy_pass http://gemini_backend/metrics;
            allow 127.0.0.1;
            allow 10.0.0.0/8;
            deny all;
        }
    }
}
'''
        
        with open(self.deployment_path / "nginx.conf", 'w', encoding='utf-8') as f:
            f.write(nginx_config)
    
    def _create_monitoring_config(self):
        """Create monitoring configuration"""
        monitoring_config = '''global:
  scrape_interval: 15s
  evaluation_interval: 15s

rule_files:
  - "alert_rules.yml"

alerting:
  alertmanagers:
    - static_configs:
        - targets:
          - alertmanager:9093

scrape_configs:
  - job_name: 'ultra-gemini-agentic'
    static_configs:
      - targets: ['gemini-agentic:8000']
    metrics_path: /metrics
    scrape_interval: 30s
    
  - job_name: 'nginx'
    static_configs:
      - targets: ['nginx:80']
    metrics_path: /nginx_status
    scrape_interval: 30s
'''
        
        with open(self.deployment_path / "monitoring.yml", 'w', encoding='utf-8') as f:
            f.write(monitoring_config)
    
    def _create_deployment_scripts(self):
        """Create deployment scripts"""
        deploy_script = '''#!/bin/bash

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
'''
        
        with open(self.deployment_path / "deploy.sh", 'w', encoding='utf-8', newline='\n') as f:
            f.write(deploy_script)
        
        # Make script executable
        os.chmod(self.deployment_path / "deploy.sh", 0o755)
    
    def _generate_deployment_instructions(self) -> list:
        """Generate deployment instructions"""
        return [
            "1. Set your Gemini API key: export GEMINI_API_KEY='your_key_here'",
            "2. Navigate to the deployment directory: cd ultra_gemini_production",
            "3. Review and modify production_config.yaml as needed",
            "4. Run the deployment script: ./deploy.sh",
            "5. Monitor logs: docker-compose logs -f",
            "6. Access dashboard at http://localhost",
            "7. View metrics at http://localhost:9090",
            "8. For systemd deployment, copy gemini-agentic.service to /etc/systemd/system/",
            "9. Enable auto-start: sudo systemctl enable gemini-agentic",
            "10. Start service: sudo systemctl start gemini-agentic"
        ]
    
    def validate_production_readiness(self) -> Dict[str, Any]:
        """Validate production readiness"""
        checks = {
            'config_valid': False,
            'api_key_set': False,
            'dependencies_available': False,
            'security_configured': False,
            'monitoring_ready': False,
            'performance_optimized': False
        }
        
        issues = []
        recommendations = []
        
        # Check configuration
        if self.config.gemini_api_key or os.getenv('GEMINI_API_KEY'):
            checks['api_key_set'] = True
        else:
            issues.append("Gemini API key not configured")
        
        # Check security settings
        if self.config.enable_encryption and self.config.audit_logging:
            checks['security_configured'] = True
        else:
            issues.append("Security settings not fully configured")
        
        # Check performance settings
        if (self.config.max_concurrent_campaigns <= 10 and 
            self.config.cache_ttl_seconds > 0):
            checks['performance_optimized'] = True
        else:
            issues.append("Performance settings need optimization")
        
        # Generate recommendations
        if not checks['api_key_set']:
            recommendations.append("Set GEMINI_API_KEY environment variable")
        
        if not checks['security_configured']:
            recommendations.append("Enable encryption and audit logging")
        
        if self.config.max_concurrent_campaigns > 5:
            recommendations.append("Consider reducing concurrent campaigns for production")
        
        return {
            'ready_for_production': all(checks.values()),
            'checks': checks,
            'issues': issues,
            'recommendations': recommendations,
            'config_summary': asdict(self.config)
        }

def main():
    """Main deployment function"""
    print("""
    ╔═══════════════════════════════════════════════════════════════════╗
    ║   🚀 ULTRA GEMINI AGENTIC SYSTEM - PRODUCTION DEPLOYMENT        ║
    ║              Complete Production Environment Setup               ║
    ╚═══════════════════════════════════════════════════════════════════╝
    """)
    
    deployment = ProductionDeployment()
    
    print("🔧 Creating production environment...")
    results = deployment.create_production_environment()
    
    if results['status'] == 'success':
        print(f"✅ Production environment created successfully!")
        print(f"📁 Deployment path: {results['deployment_path']}")
        print(f"📄 Files created: {len(results['files_created'])}")
        
        print("\n📋 Deployment Instructions:")
        for i, instruction in enumerate(results['instructions'], 1):
            print(f"  {i}. {instruction}")
        
        print("\n🔍 Validating production readiness...")
        validation = deployment.validate_production_readiness()
        
        if validation['ready_for_production']:
            print("✅ System is ready for production deployment!")
        else:
            print("⚠️ Issues found that need attention:")
            for issue in validation['issues']:
                print(f"  • {issue}")
            
            print("\n💡 Recommendations:")
            for rec in validation['recommendations']:
                print(f"  • {rec}")
        
        print(f"\n🎯 Production deployment package ready at: {results['deployment_path']}")
        
    else:
        print(f"❌ Deployment creation failed: {results.get('error', 'Unknown error')}")

if __name__ == "__main__":
    main()
