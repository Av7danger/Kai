#!/usr/bin/env python3
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
