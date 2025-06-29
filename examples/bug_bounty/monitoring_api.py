#!/usr/bin/env python3
"""
🔄 Monitoring API Endpoints
API endpoints for automated monitoring and scheduling
"""

from flask import Blueprint, request, jsonify
from simple_monitoring import get_simple_monitoring
import json
import logging

logger = logging.getLogger(__name__)

# Create Blueprint
monitoring_bp = Blueprint('monitoring', __name__)

@monitoring_bp.route('/tasks', methods=['GET', 'POST'])
def manage_tasks():
    """Manage scan tasks"""
    monitoring = get_simple_monitoring()
    
    if request.method == 'POST':
        data = request.get_json()
        if not data or 'target_domain' not in data:
            return jsonify({'error': 'Target domain is required'}), 400
        
        target_domain = data['target_domain']
        scan_type = data.get('scan_type', 'full')
        schedule_hours = data.get('schedule_hours', 24)
        
        try:
            task_id = monitoring.add_scan_task(target_domain, scan_type, schedule_hours)
            return jsonify({
                'success': True,
                'task_id': task_id,
                'message': f'Scan task created for {target_domain}'
            })
        except Exception as e:
            logger.error(f"Failed to create task: {e}")
            return jsonify({'error': f'Failed to create task: {str(e)}'}), 500
    
    else:
        # Get all tasks
        try:
            tasks = []
            for task_id, task in monitoring.scan_tasks.items():
                tasks.append({
                    'id': task.id,
                    'target_domain': task.target_domain,
                    'scan_type': task.scan_type,
                    'schedule_hours': task.schedule_hours,
                    'last_run': task.last_run.isoformat() if task.last_run else None,
                    'next_run': task.next_run.isoformat(),
                    'status': task.status,
                    'enabled': task.enabled
                })
            
            return jsonify({
                'success': True,
                'tasks': tasks
            })
        except Exception as e:
            logger.error(f"Failed to get tasks: {e}")
            return jsonify({'error': f'Failed to get tasks: {str(e)}'}), 500

@monitoring_bp.route('/start', methods=['POST'])
def start_monitoring():
    """Start the monitoring system"""
    try:
        monitoring = get_simple_monitoring()
        monitoring.start_monitoring()
        
        return jsonify({
            'success': True,
            'message': 'Monitoring system started'
        })
    except Exception as e:
        logger.error(f"Failed to start monitoring: {e}")
        return jsonify({'error': f'Failed to start monitoring: {str(e)}'}), 500

@monitoring_bp.route('/stop', methods=['POST'])
def stop_monitoring():
    """Stop the monitoring system"""
    try:
        monitoring = get_simple_monitoring()
        monitoring.stop_monitoring()
        
        return jsonify({
            'success': True,
            'message': 'Monitoring system stopped'
        })
    except Exception as e:
        logger.error(f"Failed to stop monitoring: {e}")
        return jsonify({'error': f'Failed to stop monitoring: {str(e)}'}), 500

@monitoring_bp.route('/stats', methods=['GET'])
def get_monitoring_stats():
    """Get monitoring statistics"""
    try:
        monitoring = get_simple_monitoring()
        stats = monitoring.get_statistics()
        
        return jsonify({
            'success': True,
            'statistics': stats
        })
    except Exception as e:
        logger.error(f"Failed to get stats: {e}")
        return jsonify({'error': f'Failed to get stats: {str(e)}'}), 500

@monitoring_bp.route('/alerts', methods=['GET'])
def get_alerts():
    """Get recent alerts"""
    try:
        monitoring = get_simple_monitoring()
        limit = request.args.get('limit', 10, type=int)
        alerts = monitoring.get_recent_alerts(limit)
        
        return jsonify({
            'success': True,
            'alerts': alerts
        })
    except Exception as e:
        logger.error(f"Failed to get alerts: {e}")
        return jsonify({'error': f'Failed to get alerts: {str(e)}'}), 500

@monitoring_bp.route('/status', methods=['GET'])
def get_monitoring_status():
    """Get monitoring system status"""
    try:
        monitoring = get_simple_monitoring()
        
        return jsonify({
            'success': True,
            'status': {
                'monitoring_active': monitoring.monitoring_active,
                'active_tasks': len([t for t in monitoring.scan_tasks.values() if t.enabled]),
                'running_tasks': len([t for t in monitoring.scan_tasks.values() if t.status == 'running']),
                'total_alerts': len(monitoring.alerts)
            }
        })
    except Exception as e:
        logger.error(f"Failed to get status: {e}")
        return jsonify({'error': f'Failed to get status: {str(e)}'}), 500 