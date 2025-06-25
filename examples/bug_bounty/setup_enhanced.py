"""
Enhanced Setup Script for Next-Generation CAI Bug Bounty Framework
Includes ML enhancements, threat intelligence, and advanced features
"""

import os
import sys
import subprocess
import json
from pathlib import Path
from typing import Dict, List, Optional

class NextGenBugBountySetup:
    """Enhanced setup for next-generation bug bounty features"""
    
    def __init__(self):
        self.project_root = Path.cwd()
        self.venv_path = self.project_root / "venv"
        self.requirements_file = self.project_root / "requirements_enhanced.txt"
        
    def run_setup(self):
        """Run complete enhanced setup"""
        print("🚀 Next-Generation CAI Bug Bounty Setup")
        print("=" * 50)
        
        try:
            # Step 1: Environment setup
            self._create_enhanced_requirements()
            self._setup_python_environment()
            
            # Step 2: Install dependencies
            self._install_enhanced_dependencies()
            
            # Step 3: Setup configuration
            self._setup_enhanced_configuration()
            
            # Step 4: Create directory structure
            self._create_enhanced_directories()
            
            # Step 5: Setup ML models directory
            self._setup_ml_environment()
            
            # Step 6: Create quick start scripts
            self._create_quick_start_scripts()
            
            # Step 7: Validation
            self._validate_enhanced_setup()
            
            print("\n🎉 Enhanced Setup Complete!")
            self._print_next_steps()
            
        except Exception as e:
            print(f"❌ Setup failed: {e}")
            sys.exit(1)
    
    def _create_enhanced_requirements(self):
        """Create enhanced requirements file with all dependencies"""
        requirements = [
            # Core CAI framework
            "cai-framework>=1.0.0",
            
            # Enhanced ML dependencies
            "scikit-learn>=1.3.0",
            "numpy>=1.24.0",
            "pandas>=2.0.0",
            "tensorflow>=2.13.0",  # For advanced ML features
            "torch>=2.0.0",        # PyTorch for neural networks
            "transformers>=4.30.0", # For NLP features
            
            # Threat intelligence
            "aiohttp>=3.8.0",
            "requests>=2.31.0",
            "python-nvd3>=0.15.0",
            
            # Computer vision (future)
            "opencv-python>=4.8.0",
            "pillow>=10.0.0",
            
            # Data processing
            "asyncio>=3.4.3",
            "asyncpg>=0.28.0",
            "redis>=4.5.0",
            
            # Reporting and visualization
            "matplotlib>=3.7.0",
            "seaborn>=0.12.0",
            "plotly>=5.15.0",
            "jinja2>=3.1.0",
            "markdown>=3.4.0",
            
            # Security tools integration
            "python-nmap>=0.7.1",
            "shodan>=1.29.0",
            "censys>=2.2.0",
            
            # Configuration and utilities
            "python-dotenv>=1.0.0",
            "pyyaml>=6.0",
            "click>=8.1.0",
            "rich>=13.4.0",
            
            # Development and testing
            "pytest>=7.4.0",
            "pytest-asyncio>=0.21.0",
            "black>=23.7.0",
            "flake8>=6.0.0",
            
            # Optional blockchain features
            "web3>=6.9.0",
            "eth-account>=0.9.0",
        ]
        
        print("📝 Creating enhanced requirements file...")
        with open(self.requirements_file, 'w') as f:
            f.write('\n'.join(requirements))
        
        print(f"✅ Enhanced requirements saved to {self.requirements_file}")
    
    def _setup_python_environment(self):
        """Setup Python virtual environment"""
        print("🐍 Setting up Python environment...")
        
        if self.venv_path.exists():
            print("⚠️ Virtual environment already exists")
            return
        
        # Create virtual environment
        subprocess.run([sys.executable, "-m", "venv", str(self.venv_path)], check=True)
        print(f"✅ Virtual environment created at {self.venv_path}")
    
    def _install_enhanced_dependencies(self):
        """Install all enhanced dependencies"""
        print("📦 Installing enhanced dependencies...")
        
        # Get pip path
        if os.name == 'nt':  # Windows
            pip_path = self.venv_path / "Scripts" / "pip.exe"
        else:  # Linux/Mac
            pip_path = self.venv_path / "bin" / "pip"
        
        # Upgrade pip first
        subprocess.run([str(pip_path), "install", "--upgrade", "pip"], check=True)
        
        # Install requirements
        subprocess.run([
            str(pip_path), "install", "-r", str(self.requirements_file)
        ], check=True)
        
        print("✅ Enhanced dependencies installed")
    
    def _setup_enhanced_configuration(self):
        """Setup enhanced configuration files"""
        print("⚙️ Setting up enhanced configuration...")
        
        # Enhanced .env file
        env_content = """# CAI Bug Bounty Enhanced Configuration

# API Keys - Primary
GOOGLE_API_KEY=your_gemini_api_key_here
OPENAI_API_KEY=your_openai_api_key_here

# Threat Intelligence APIs
VULNERS_API_KEY=your_vulners_api_key_here
SHODAN_API_KEY=your_shodan_api_key_here
CENSYS_API_ID=your_censys_api_id_here
CENSYS_SECRET=your_censys_secret_here

# Bug Bounty Platform APIs
HACKERONE_API_TOKEN=your_hackerone_token_here
BUGCROWD_API_TOKEN=your_bugcrowd_token_here

# Database Configuration (for ML and data storage)
DATABASE_URL=postgresql://user:password@localhost/cai_bugbounty
REDIS_URL=redis://localhost:6379/0

# ML Configuration
ML_MODEL_PATH=./ml_models
ML_TRAINING_DATA_PATH=./training_data
ML_ENABLE_GPU=false
ML_BATCH_SIZE=32

# Advanced Features
ENABLE_COMPUTER_VISION=false
ENABLE_BLOCKCHAIN_FEATURES=false
ENABLE_DISTRIBUTED_LEARNING=false

# Security Configuration
MAX_CONCURRENT_SCANS=10
RATE_LIMIT_PER_SECOND=5
ENABLE_STEALTH_MODE=true
USER_AGENT_ROTATION=true

# Reporting Configuration
REPORT_FORMAT=json,html,pdf
EXECUTIVE_REPORTS=true
TREND_ANALYSIS=true

# Logging Configuration
LOG_LEVEL=INFO
LOG_TO_FILE=true
LOG_ROTATION=daily
"""
        
        env_file = self.project_root / ".env.enhanced"
        with open(env_file, 'w') as f:
            f.write(env_content)
        
        print(f"✅ Enhanced configuration saved to {env_file}")
        
        # Enhanced scope configuration template
        scope_config = {
            "version": "2.0",
            "metadata": {
                "name": "Enhanced Bug Bounty Program",
                "description": "Next-generation autonomous bug bounty testing",
                "created": "2024-01-01",
                "ml_enabled": True,
                "threat_intel_enabled": True
            },
            "targets": [
                "example.com",
                "api.example.com"
            ],
            "in_scope": [
                "*.example.com",
                "api.example.com",
                "staging.example.com"
            ],
            "out_of_scope": [
                "admin.example.com",
                "internal.example.com",
                "*.internal.example.com"
            ],
            "allowed_methods": ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
            "forbidden_paths": [
                "/admin/delete",
                "/admin/reset",
                "/system/shutdown"
            ],
            "testing_config": {
                "rate_limit": 10,
                "max_depth": 3,
                "timeout": 7200,
                "safe_mode": True,
                "stealth_mode": True,
                "business_hours_only": False
            },
            "ml_config": {
                "enable_real_time_learning": True,
                "confidence_threshold": 0.7,
                "false_positive_threshold": 0.3,
                "auto_model_update": True
            },
            "threat_intel_config": {
                "enable_cve_feeds": True,
                "enable_exploit_monitoring": True,
                "threat_score_threshold": 60.0,
                "update_frequency": 3600
            },
            "reporting_config": {
                "auto_generate_reports": True,
                "include_executive_summary": True,
                "include_trend_analysis": True,
                "include_ml_metrics": True
            }
        }
        
        scope_file = self.project_root / "enhanced_scope.yaml"
        import yaml
        with open(scope_file, 'w') as f:
            yaml.dump(scope_config, f, default_flow_style=False, indent=2)
        
        print(f"✅ Enhanced scope configuration saved to {scope_file}")
    
    def _create_enhanced_directories(self):
        """Create enhanced directory structure"""
        print("📁 Creating enhanced directory structure...")
        
        directories = [
            "ml_models",
            "training_data",
            "threat_intelligence",
            "reports/executive",
            "reports/technical",
            "reports/ml_analytics",
            "logs/ml",
            "logs/threat_intel",
            "logs/autonomous",
            "cache/cve_data",
            "cache/exploit_data",
            "cache/ml_predictions",
            "results/enhanced",
            "results/ml_enhanced",
            "config/templates",
            "scripts/automation",
            "scripts/ml_training"
        ]
        
        for dir_path in directories:
            full_path = self.project_root / dir_path
            full_path.mkdir(parents=True, exist_ok=True)
        
        print("✅ Enhanced directory structure created")
    
    def _setup_ml_environment(self):
        """Setup ML models and training environment"""
        print("🤖 Setting up ML environment...")
        
        # Create ML configuration
        ml_config = {
            "models": {
                "vulnerability_classifier": {
                    "type": "RandomForestClassifier",
                    "parameters": {
                        "n_estimators": 100,
                        "random_state": 42
                    }
                },
                "false_positive_detector": {
                    "type": "RandomForestClassifier", 
                    "parameters": {
                        "n_estimators": 100,
                        "random_state": 42
                    }
                },
                "payload_generator": {
                    "type": "TransformerModel",
                    "parameters": {
                        "model_name": "gpt2",
                        "max_length": 512
                    }
                }
            },
            "training": {
                "batch_size": 32,
                "learning_rate": 0.001,
                "epochs": 50,
                "validation_split": 0.2,
                "early_stopping": True
            },
            "features": {
                "text_features": ["title", "description", "poc"],
                "numerical_features": ["cvss_score", "confidence"],
                "categorical_features": ["severity", "vulnerability_type"]
            }
        }
        
        ml_config_file = self.project_root / "config" / "ml_config.yaml"
        import yaml
        with open(ml_config_file, 'w') as f:
            yaml.dump(ml_config, f, default_flow_style=False, indent=2)
        
        print("✅ ML environment configured")
    
    def _create_quick_start_scripts(self):
        """Create enhanced quick start scripts"""
        print("📜 Creating enhanced quick start scripts...")
        
        # Enhanced quick start script
        quick_start_script = """#!/usr/bin/env python3
\"\"\"
Enhanced Quick Start for CAI Bug Bounty Framework
Includes ML enhancements and threat intelligence
\"\"\"

import asyncio
import sys
from pathlib import Path

# Add the project root to Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from ml_enhanced_workflow import MLEnhancedAutonomousController

async def enhanced_quick_start():
    \"\"\"Enhanced quick start with ML and threat intelligence\"\"\"
    
    print(\"🚀 Enhanced CAI Bug Bounty Quick Start\")
    print(\"=\" * 40)
    
    # Check configuration
    env_file = project_root / \".env.enhanced\"
    if not env_file.exists():
        print(\"❌ Enhanced configuration not found!\")
        print(\"Please run setup_enhanced.py first\")
        return
    
    # Initialize enhanced controller
    try:
        controller = MLEnhancedAutonomousController(\"enhanced_scope.yaml\")
        
        print(\"🤖 Starting ML-enhanced autonomous hunt...\")
        results = await controller.run_ml_enhanced_hunt()
        
        print(\"\\n✅ Enhanced hunt completed!\")
        print(f\"Results saved to: {controller.results_dir}\")
        
        # Print summary
        if results.get(\"ml_metrics\"):
            ml_metrics = results[\"ml_metrics\"]
            print(\"\\n📊 ML Enhancement Summary:\")
            print(f\"  • ML Predictions: {ml_metrics.get('ml_predictions', 0)}\")
            print(f\"  • False Positives Prevented: {ml_metrics.get('false_positives_prevented', 0)}\")
            print(f\"  • ML Accuracy: {ml_metrics.get('ml_accuracy', 0.0):.2%}\")
        
    except Exception as e:
        print(f\"❌ Error during enhanced hunt: {e}\")
        print(\"Please check your configuration and try again\")

if __name__ == \"__main__\":
    asyncio.run(enhanced_quick_start())
"""
        
        script_file = self.project_root / "enhanced_quick_start.py"
        with open(script_file, 'w') as f:
            f.write(quick_start_script)
        
        # Make script executable on Unix systems
        if os.name != 'nt':
            os.chmod(script_file, 0o755)
        
        # ML training script
        ml_training_script = """#!/usr/bin/env python3
\"\"\"
ML Model Training Script for CAI Bug Bounty Framework
\"\"\"

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from ml_enhancements import VulnerabilityPatternLearner

async def train_ml_models():
    \"\"\"Train ML models with available data\"\"\"
    
    print(\"🎓 Training ML Models for Bug Bounty Enhancement\")
    print(\"=\" * 50)
    
    try:
        # Initialize ML learner
        learner = VulnerabilityPatternLearner()
        
        print(\"📊 Loading training data...\")
        # In a real implementation, you would load actual training data here
        
        print(\"🤖 Training models...\")
        results = await learner.train_models()
        
        print(\"\\n✅ Training completed!\")
        print(\"📈 Training Results:\")
        for metric, value in results.items():
            if isinstance(value, float):
                print(f\"  • {metric}: {value:.3f}\")
            else:
                print(f\"  • {metric}: {value}\")
        
    except Exception as e:
        print(f\"❌ Training failed: {e}\")

if __name__ == \"__main__\":
    asyncio.run(train_ml_models())
"""
        
        training_script_file = self.project_root / "scripts" / "train_ml_models.py"
        with open(training_script_file, 'w') as f:
            f.write(ml_training_script)
        
        print("✅ Enhanced quick start scripts created")
    
    def _validate_enhanced_setup(self):
        """Validate enhanced setup"""
        print("✅ Validating enhanced setup...")
        
        required_files = [
            ".env.enhanced",
            "enhanced_scope.yaml",
            "config/ml_config.yaml",
            "enhanced_quick_start.py",
            "scripts/train_ml_models.py"
        ]
        
        required_dirs = [
            "ml_models",
            "training_data",
            "threat_intelligence",
            "reports/executive"
        ]
        
        # Check files
        for file_path in required_files:
            if not (self.project_root / file_path).exists():
                raise FileNotFoundError(f"Required file missing: {file_path}")
        
        # Check directories
        for dir_path in required_dirs:
            if not (self.project_root / dir_path).exists():
                raise FileNotFoundError(f"Required directory missing: {dir_path}")
        
        print("✅ Enhanced setup validation passed")
    
    def _print_next_steps(self):
        """Print next steps for users"""
        print("""
🎯 Next Steps:

1. Configure API Keys:
   • Edit .env.enhanced with your API keys
   • Get Gemini API key: https://makersuite.google.com/app/apikey
   • Get Vulners API key: https://vulners.com/userinfo
   • Get Shodan API key: https://developer.shodan.io/

2. Test Basic Setup:
   python enhanced_quick_start.py

3. Configure Your Target:
   • Edit enhanced_scope.yaml with your target details
   • Set appropriate rate limits and safety settings
   • Configure ML and threat intelligence options

4. Run Enhanced Hunt:
   python -c "from ml_enhanced_workflow import MLEnhancedAutonomousController; import asyncio; asyncio.run(MLEnhancedAutonomousController().run_ml_enhanced_hunt())"

5. Train ML Models (optional):
   python scripts/train_ml_models.py

6. Advanced Features:
   • Enable computer vision: Set ENABLE_COMPUTER_VISION=true
   • Enable blockchain features: Set ENABLE_BLOCKCHAIN_FEATURES=true
   • Setup distributed learning: Configure DATABASE_URL and REDIS_URL

📚 Documentation:
   • README.md: Basic usage
   • next_gen_enhancements.py: Feature roadmap
   • ml_enhancements.py: ML capabilities
   • threat_intelligence.py: Threat intel integration

⚠️  Important:
   • Always ensure you have proper authorization
   • Follow responsible disclosure practices
   • Start with safe_mode=true for initial testing
   • Review scope configuration carefully

🚀 Happy Bug Hunting with Enhanced AI Capabilities!
""")

def main():
    """Main setup function"""
    setup = NextGenBugBountySetup()
    setup.run_setup()

if __name__ == "__main__":
    main()
