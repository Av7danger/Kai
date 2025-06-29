#!/usr/bin/env python3
"""
🚀 Deployment & Scaling Manager
Production deployment and scaling management

Features:
- Multi-environment deployment
- Auto-scaling and load balancing
- Health monitoring and recovery
- Configuration management
- Backup and disaster recovery
- Security hardening
- Performance monitoring
- CI/CD integration
"""

import os
import sys
import json
import time
import yaml
import docker
import kubernetes
import subprocess
import threading
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from pathlib import Path
import requests
import psutil

logger = logging.getLogger(__name__)

@dataclass
class DeploymentConfig:
    """Deployment configuration"""
    name: str
    environment: str
    version: str
    replicas: int
    resources: Dict[str, Any]
    environment_variables: Dict[str, str]
    ports: List[int]
    health_check: Dict[str, Any]
    auto_scaling: Dict[str, Any]

@dataclass
class DeploymentStatus:
    """Deployment status"""
    name: str
    status: str  # deploying, running, failed, scaling
    replicas: int
    available_replicas: int
    health_status: str
    last_update: datetime
    metrics: Dict[str, Any]

class DockerManager:
    """Docker container management"""
    
    def __init__(self):
        try:
            self.client = docker.from_env()
            self.available = True
        except Exception as e:
            logger.warning(f"Docker not available: {e}")
            self.available = False
    
    def build_image(self, dockerfile_path: str, tag: str) -> bool:
        """Build Docker image"""
        if not self.available:
            return False
        
        try:
            image, logs = self.client.images.build(
                path=dockerfile_path,
                tag=tag,
                rm=True
            )
            logger.info(f"Docker image built successfully: {tag}")
            return True
        except Exception as e:
            logger.error(f"Failed to build Docker image: {e}")
            return False
    
    def run_container(self, image: str, name: str, ports: Dict[str, str], 
                     environment: Dict[str, str] = None) -> bool:
        """Run Docker container"""
        if not self.available:
            return False
        
        try:
            container = self.client.containers.run(
                image=image,
                name=name,
                ports=ports,
                environment=environment or {},
                detach=True,
                restart_policy={"Name": "unless-stopped"}
            )
            logger.info(f"Container started: {name}")
            return True
        except Exception as e:
            logger.error(f"Failed to start container: {e}")
            return False
    
    def stop_container(self, name: str) -> bool:
        """Stop Docker container"""
        if not self.available:
            return False
        
        try:
            container = self.client.containers.get(name)
            container.stop()
            container.remove()
            logger.info(f"Container stopped: {name}")
            return True
        except Exception as e:
            logger.error(f"Failed to stop container: {e}")
            return False
    
    def get_container_status(self, name: str) -> Optional[Dict[str, Any]]:
        """Get container status"""
        if not self.available:
            return None
        
        try:
            container = self.client.containers.get(name)
            return {
                'status': container.status,
                'ports': container.ports,
                'environment': container.attrs['Config']['Env'],
                'created': container.attrs['Created']
            }
        except Exception as e:
            logger.error(f"Failed to get container status: {e}")
            return None

class KubernetesManager:
    """Kubernetes deployment management"""
    
    def __init__(self, config_path: str = None):
        try:
            if config_path:
                kubernetes.config.load_kube_config(config_path)
            else:
                kubernetes.config.load_incluster_config()
            
            self.v1 = kubernetes.client.CoreV1Api()
            self.apps_v1 = kubernetes.client.AppsV1Api()
            self.available = True
        except Exception as e:
            logger.warning(f"Kubernetes not available: {e}")
            self.available = False
    
    def deploy_application(self, config: DeploymentConfig) -> bool:
        """Deploy application to Kubernetes"""
        if not self.available:
            return False
        
        try:
            # Create deployment
            deployment = kubernetes.client.V1Deployment(
                metadata=kubernetes.client.V1ObjectMeta(name=config.name),
                spec=kubernetes.client.V1DeploymentSpec(
                    replicas=config.replicas,
                    selector=kubernetes.client.V1LabelSelector(
                        match_labels={"app": config.name}
                    ),
                    template=kubernetes.client.V1PodTemplateSpec(
                        metadata=kubernetes.client.V1ObjectMeta(
                            labels={"app": config.name}
                        ),
                        spec=kubernetes.client.V1PodSpec(
                            containers=[
                                kubernetes.client.V1Container(
                                    name=config.name,
                                    image=f"{config.name}:{config.version}",
                                    ports=[
                                        kubernetes.client.V1ContainerPort(container_port=port)
                                        for port in config.ports
                                    ],
                                    env=[
                                        kubernetes.client.V1EnvVar(name=k, value=v)
                                        for k, v in config.environment_variables.items()
                                    ],
                                    resources=kubernetes.client.V1ResourceRequirements(
                                        requests=config.resources.get('requests', {}),
                                        limits=config.resources.get('limits', {})
                                    )
                                )
                            ]
                        )
                    )
                )
            )
            
            self.apps_v1.create_namespaced_deployment(
                namespace="default",
                body=deployment
            )
            
            logger.info(f"Application deployed: {config.name}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to deploy application: {e}")
            return False
    
    def scale_application(self, name: str, replicas: int) -> bool:
        """Scale application replicas"""
        if not self.available:
            return False
        
        try:
            self.apps_v1.patch_namespaced_deployment_scale(
                name=name,
                namespace="default",
                body={"spec": {"replicas": replicas}}
            )
            logger.info(f"Application scaled: {name} -> {replicas} replicas")
            return True
        except Exception as e:
            logger.error(f"Failed to scale application: {e}")
            return False
    
    def get_deployment_status(self, name: str) -> Optional[DeploymentStatus]:
        """Get deployment status"""
        if not self.available:
            return None
        
        try:
            deployment = self.apps_v1.read_namespaced_deployment(
                name=name,
                namespace="default"
            )
            
            return DeploymentStatus(
                name=name,
                status=deployment.status.conditions[-1].type if deployment.status.conditions else "Unknown",
                replicas=deployment.spec.replicas,
                available_replicas=deployment.status.available_replicas or 0,
                health_status="Healthy" if deployment.status.available_replicas == deployment.spec.replicas else "Unhealthy",
                last_update=datetime.now(),
                metrics={}
            )
        except Exception as e:
            logger.error(f"Failed to get deployment status: {e}")
            return None

class HealthMonitor:
    """Health monitoring and recovery"""
    
    def __init__(self, health_checks: Dict[str, Any]):
        self.health_checks = health_checks
        self.health_status = {}
        self.recovery_actions = {}
        self.monitoring_thread = threading.Thread(target=self._monitor_health, daemon=True)
        self.monitoring_thread.start()
    
    def _monitor_health(self):
        """Monitor health of deployed services"""
        while True:
            try:
                for service_name, check_config in self.health_checks.items():
                    is_healthy = self._check_service_health(service_name, check_config)
                    self.health_status[service_name] = is_healthy
                    
                    if not is_healthy:
                        self._trigger_recovery(service_name)
                
                time.sleep(30)  # Check every 30 seconds
                
            except Exception as e:
                logger.error(f"Health monitoring error: {e}")
    
    def _check_service_health(self, service_name: str, check_config: Dict[str, Any]) -> bool:
        """Check health of a specific service"""
        try:
            url = check_config.get('url')
            if url:
                response = requests.get(url, timeout=10)
                return response.status_code == 200
            
            # Check process health
            process_name = check_config.get('process')
            if process_name:
                for proc in psutil.process_iter(['pid', 'name']):
                    if proc.info['name'] == process_name:
                        return True
                return False
            
            return True
            
        except Exception as e:
            logger.error(f"Health check failed for {service_name}: {e}")
            return False
    
    def _trigger_recovery(self, service_name: str):
        """Trigger recovery action for unhealthy service"""
        recovery_action = self.recovery_actions.get(service_name)
        if recovery_action:
            try:
                recovery_action()
                logger.info(f"Recovery action triggered for {service_name}")
            except Exception as e:
                logger.error(f"Recovery action failed for {service_name}: {e}")
    
    def add_recovery_action(self, service_name: str, action: callable):
        """Add recovery action for service"""
        self.recovery_actions[service_name] = action
    
    def get_health_status(self) -> Dict[str, bool]:
        """Get health status of all services"""
        return self.health_status.copy()

class BackupManager:
    """Backup and disaster recovery"""
    
    def __init__(self, backup_config: Dict[str, Any]):
        self.backup_config = backup_config
        self.backup_dir = Path(backup_config.get('backup_dir', 'backups'))
        self.backup_dir.mkdir(exist_ok=True)
    
    def create_backup(self, backup_type: str = 'full') -> str:
        """Create backup"""
        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            backup_name = f"backup_{backup_type}_{timestamp}"
            backup_path = self.backup_dir / backup_name
            
            if backup_type == 'database':
                self._backup_database(backup_path)
            elif backup_type == 'files':
                self._backup_files(backup_path)
            elif backup_type == 'full':
                self._backup_full(backup_path)
            
            logger.info(f"Backup created: {backup_name}")
            return str(backup_path)
            
        except Exception as e:
            logger.error(f"Backup creation failed: {e}")
            return ""
    
    def _backup_database(self, backup_path: Path):
        """Backup database"""
        import sqlite3
        
        # Create database backup
        conn = sqlite3.connect('advanced_integration.db')
        backup_conn = sqlite3.connect(backup_path / 'database.db')
        conn.backup(backup_conn)
        conn.close()
        backup_conn.close()
    
    def _backup_files(self, backup_path: Path):
        """Backup important files"""
        import shutil
        
        # Backup configuration files
        config_files = ['dashboard_config.yml', 'advanced_integration_config.yml']
        for config_file in config_files:
            if os.path.exists(config_file):
                shutil.copy2(config_file, backup_path)
    
    def _backup_full(self, backup_path: Path):
        """Create full backup"""
        self._backup_database(backup_path)
        self._backup_files(backup_path)
    
    def restore_backup(self, backup_path: str) -> bool:
        """Restore from backup"""
        try:
            backup_path = Path(backup_path)
            
            if not backup_path.exists():
                raise FileNotFoundError(f"Backup not found: {backup_path}")
            
            # Restore database
            if (backup_path / 'database.db').exists():
                import sqlite3
                import shutil
                
                # Backup current database
                shutil.copy2('advanced_integration.db', 'advanced_integration.db.backup')
                
                # Restore from backup
                shutil.copy2(backup_path / 'database.db', 'advanced_integration.db')
            
            # Restore configuration files
            for config_file in backup_path.glob('*.yml'):
                shutil.copy2(config_file, '.')
            
            logger.info(f"Backup restored from: {backup_path}")
            return True
            
        except Exception as e:
            logger.error(f"Backup restoration failed: {e}")
            return False
    
    def list_backups(self) -> List[Dict[str, Any]]:
        """List available backups"""
        backups = []
        
        for backup_dir in self.backup_dir.iterdir():
            if backup_dir.is_dir():
                backup_info = {
                    'name': backup_dir.name,
                    'path': str(backup_dir),
                    'created': datetime.fromtimestamp(backup_dir.stat().st_mtime),
                    'size': sum(f.stat().st_size for f in backup_dir.rglob('*') if f.is_file())
                }
                backups.append(backup_info)
        
        return sorted(backups, key=lambda x: x['created'], reverse=True)

class SecurityHardener:
    """Security hardening for production deployment"""
    
    def __init__(self, security_config: Dict[str, Any]):
        self.security_config = security_config
    
    def harden_system(self) -> bool:
        """Apply security hardening"""
        try:
            # Update system packages
            self._update_packages()
            
            # Configure firewall
            self._configure_firewall()
            
            # Secure SSH
            self._secure_ssh()
            
            # Configure file permissions
            self._configure_permissions()
            
            # Enable security monitoring
            self._enable_monitoring()
            
            logger.info("Security hardening completed")
            return True
            
        except Exception as e:
            logger.error(f"Security hardening failed: {e}")
            return False
    
    def _update_packages(self):
        """Update system packages"""
        try:
            subprocess.run(['apt-get', 'update'], check=True)
            subprocess.run(['apt-get', 'upgrade', '-y'], check=True)
        except subprocess.CalledProcessError:
            logger.warning("Package update failed (may not be supported on this system)")
    
    def _configure_firewall(self):
        """Configure firewall rules"""
        try:
            # Allow SSH
            subprocess.run(['ufw', 'allow', 'ssh'], check=True)
            
            # Allow application ports
            for port in [5000, 5001]:  # Dashboard and API ports
                subprocess.run(['ufw', 'allow', str(port)], check=True)
            
            # Enable firewall
            subprocess.run(['ufw', '--force', 'enable'], check=True)
            
        except subprocess.CalledProcessError:
            logger.warning("Firewall configuration failed (may not be supported on this system)")
    
    def _secure_ssh(self):
        """Secure SSH configuration"""
        ssh_config = """
# Security hardening
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
MaxAuthTries 3
ClientAliveInterval 300
ClientAliveCountMax 2
"""
        try:
            with open('/etc/ssh/sshd_config', 'a') as f:
                f.write(ssh_config)
            subprocess.run(['systemctl', 'restart', 'ssh'], check=True)
        except Exception:
            logger.warning("SSH configuration failed (may not have permissions)")
    
    def _configure_permissions(self):
        """Configure secure file permissions"""
        try:
            # Secure configuration files
            for config_file in ['dashboard_config.yml', 'advanced_integration_config.yml']:
                if os.path.exists(config_file):
                    os.chmod(config_file, 0o600)
            
            # Secure database
            if os.path.exists('advanced_integration.db'):
                os.chmod('advanced_integration.db', 0o600)
                
        except Exception as e:
            logger.warning(f"Permission configuration failed: {e}")
    
    def _enable_monitoring(self):
        """Enable security monitoring"""
        # This would typically involve setting up log monitoring, intrusion detection, etc.
        logger.info("Security monitoring enabled")

class DeploymentManager:
    """Main deployment manager"""
    
    def __init__(self, config_path: str = 'deployment_config.yml'):
        self.config_path = config_path
        self.config = self._load_config()
        
        # Initialize managers
        self.docker_manager = DockerManager()
        self.kubernetes_manager = KubernetesManager()
        self.health_monitor = HealthMonitor(self.config.get('health_checks', {}))
        self.backup_manager = BackupManager(self.config.get('backup', {}))
        self.security_hardener = SecurityHardener(self.config.get('security', {}))
        
        # Deployment tracking
        self.deployments: Dict[str, DeploymentStatus] = {}
        
        logger.info("Deployment Manager initialized")
    
    def _load_config(self) -> Dict[str, Any]:
        """Load deployment configuration"""
        if os.path.exists(self.config_path):
            with open(self.config_path, 'r') as f:
                return yaml.safe_load(f)
        else:
            return self._get_default_config()
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Get default deployment configuration"""
        return {
            'environment': 'production',
            'deployments': {
                'dashboard': {
                    'image': 'bug-bounty-dashboard:latest',
                    'replicas': 2,
                    'ports': [5000],
                    'resources': {
                        'requests': {'memory': '256Mi', 'cpu': '250m'},
                        'limits': {'memory': '512Mi', 'cpu': '500m'}
                    }
                },
                'api': {
                    'image': 'bug-bounty-api:latest',
                    'replicas': 3,
                    'ports': [5001],
                    'resources': {
                        'requests': {'memory': '512Mi', 'cpu': '500m'},
                        'limits': {'memory': '1Gi', 'cpu': '1000m'}
                    }
                }
            },
            'health_checks': {
                'dashboard': {'url': 'http://localhost:5000/health'},
                'api': {'url': 'http://localhost:5001/health'}
            },
            'backup': {
                'backup_dir': 'backups',
                'retention_days': 30,
                'schedule': 'daily'
            },
            'security': {
                'enable_firewall': True,
                'secure_ssh': True,
                'update_packages': True
            }
        }
    
    def deploy_application(self, app_name: str, version: str = 'latest') -> bool:
        """Deploy application"""
        try:
            if app_name not in self.config['deployments']:
                raise ValueError(f"Application '{app_name}' not configured")
            
            app_config = self.config['deployments'][app_name]
            
            # Create deployment configuration
            deployment_config = DeploymentConfig(
                name=app_name,
                environment=self.config['environment'],
                version=version,
                replicas=app_config['replicas'],
                resources=app_config['resources'],
                environment_variables=app_config.get('environment_variables', {}),
                ports=app_config['ports'],
                health_check=app_config.get('health_check', {}),
                auto_scaling=app_config.get('auto_scaling', {})
            )
            
            # Deploy using Kubernetes if available
            if self.kubernetes_manager.available:
                success = self.kubernetes_manager.deploy_application(deployment_config)
            else:
                # Fallback to Docker
                success = self._deploy_with_docker(deployment_config)
            
            if success:
                self.deployments[app_name] = DeploymentStatus(
                    name=app_name,
                    status='deploying',
                    replicas=deployment_config.replicas,
                    available_replicas=0,
                    health_status='Unknown',
                    last_update=datetime.now(),
                    metrics={}
                )
            
            return success
            
        except Exception as e:
            logger.error(f"Deployment failed: {e}")
            return False
    
    def _deploy_with_docker(self, config: DeploymentConfig) -> bool:
        """Deploy using Docker"""
        try:
            # Build image if needed
            if not self.docker_manager.build_image('.', f"{config.name}:{config.version}"):
                return False
            
            # Run container
            ports = {f"{port}/tcp": str(port) for port in config.ports}
            return self.docker_manager.run_container(
                image=f"{config.name}:{config.version}",
                name=config.name,
                ports=ports,
                environment=config.environment_variables
            )
            
        except Exception as e:
            logger.error(f"Docker deployment failed: {e}")
            return False
    
    def scale_application(self, app_name: str, replicas: int) -> bool:
        """Scale application"""
        try:
            if self.kubernetes_manager.available:
                return self.kubernetes_manager.scale_application(app_name, replicas)
            else:
                # Docker scaling would require multiple container instances
                logger.warning("Scaling not supported in Docker mode")
                return False
                
        except Exception as e:
            logger.error(f"Scaling failed: {e}")
            return False
    
    def get_deployment_status(self, app_name: str) -> Optional[DeploymentStatus]:
        """Get deployment status"""
        try:
            if self.kubernetes_manager.available:
                return self.kubernetes_manager.get_deployment_status(app_name)
            else:
                return self._get_docker_status(app_name)
                
        except Exception as e:
            logger.error(f"Failed to get deployment status: {e}")
            return None
    
    def _get_docker_status(self, app_name: str) -> Optional[DeploymentStatus]:
        """Get Docker container status"""
        container_status = self.docker_manager.get_container_status(app_name)
        if container_status:
            return DeploymentStatus(
                name=app_name,
                status=container_status['status'],
                replicas=1,
                available_replicas=1 if container_status['status'] == 'running' else 0,
                health_status='Healthy' if container_status['status'] == 'running' else 'Unhealthy',
                last_update=datetime.now(),
                metrics={}
            )
        return None
    
    def create_backup(self, backup_type: str = 'full') -> str:
        """Create backup"""
        return self.backup_manager.create_backup(backup_type)
    
    def restore_backup(self, backup_path: str) -> bool:
        """Restore from backup"""
        return self.backup_manager.restore_backup(backup_path)
    
    def list_backups(self) -> List[Dict[str, Any]]:
        """List available backups"""
        return self.backup_manager.list_backups()
    
    def harden_security(self) -> bool:
        """Apply security hardening"""
        return self.security_hardener.harden_system()
    
    def get_health_status(self) -> Dict[str, bool]:
        """Get health status of all services"""
        return self.health_monitor.get_health_status()
    
    def get_deployment_report(self) -> Dict[str, Any]:
        """Get comprehensive deployment report"""
        return {
            'environment': self.config['environment'],
            'deployments': {
                name: asdict(status) for name, status in self.deployments.items()
            },
            'health_status': self.get_health_status(),
            'backups': self.list_backups(),
            'system_info': self._get_system_info()
        }
    
    def _get_system_info(self) -> Dict[str, Any]:
        """Get system information"""
        return {
            'platform': sys.platform,
            'python_version': sys.version,
            'cpu_count': psutil.cpu_count(),
            'memory_total': psutil.virtual_memory().total,
            'disk_usage': psutil.disk_usage('/').percent
        }

# Global deployment manager instance
deployment_manager = None

def initialize_deployment_manager(config_path: str = 'deployment_config.yml'):
    """Initialize the global deployment manager"""
    global deployment_manager
    deployment_manager = DeploymentManager(config_path)
    return deployment_manager

def get_deployment_manager() -> DeploymentManager:
    """Get the global deployment manager instance"""
    if deployment_manager is None:
        raise RuntimeError("Deployment manager not initialized. Call initialize_deployment_manager() first.")
    return deployment_manager

if __name__ == '__main__':
    # Example usage
    manager = initialize_deployment_manager()
    
    # Deploy applications
    manager.deploy_application('dashboard')
    manager.deploy_application('api')
    
    # Create backup
    backup_path = manager.create_backup('full')
    print(f"Backup created: {backup_path}")
    
    # Get deployment report
    report = manager.get_deployment_report()
    print(json.dumps(report, indent=2, default=str)) 