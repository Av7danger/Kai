#!/usr/bin/env python3
"""
🤖 AI API Endpoints
Simple API endpoints for AI-powered analysis integration
"""

from flask import Blueprint, request, jsonify
from ai_integration import get_ai_integration
import json
import logging

logger = logging.getLogger(__name__)

# Create Blueprint
ai_bp = Blueprint('ai', __name__)

@ai_bp.route('/analyze', methods=['POST'])
def analyze_recon_data():
    """Analyze reconnaissance data using AI"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        ai_integration = get_ai_integration()
        analysis_result = ai_integration.analyze_recon_data(data)
        
        # Generate custom payloads
        custom_payloads = ai_integration.generate_custom_payloads(analysis_result)
        
        return jsonify({
            'success': True,
            'analysis': analysis_result,
            'custom_payloads': custom_payloads,
            'message': 'AI analysis completed successfully'
        })
        
    except Exception as e:
        logger.error(f"AI analysis failed: {e}")
        return jsonify({'error': f'Analysis failed: {str(e)}'}), 500

@ai_bp.route('/generate-report', methods=['POST'])
def generate_bug_report():
    """Generate AI-powered bug report"""
    try:
        data = request.get_json()
        if not data or 'vulnerability_data' not in data:
            return jsonify({'error': 'Vulnerability data is required'}), 400
        
        ai_integration = get_ai_integration()
        bug_report = ai_integration.generate_bug_report(data['vulnerability_data'])
        
        return jsonify({
            'success': True,
            'report': bug_report,
            'message': 'Bug report generated successfully'
        })
        
    except Exception as e:
        logger.error(f"Bug report generation failed: {e}")
        return jsonify({'error': f'Report generation failed: {str(e)}'}), 500

@ai_bp.route('/payloads', methods=['POST'])
def generate_payloads():
    """Generate custom payloads"""
    try:
        data = request.get_json() or {}
        categories = data.get('categories', ['all'])
        count = data.get('count', 10)
        
        ai_integration = get_ai_integration()
        payloads = ai_integration.generate_custom_payloads({})
        
        # Filter by categories if specified
        if categories != ['all']:
            # Simple filtering - in a real implementation, you'd have categorized payloads
            payloads = payloads[:count]
        else:
            payloads = payloads[:count]
        
        return jsonify({
            'success': True,
            'payloads': payloads,
            'count': len(payloads),
            'message': f'Generated {len(payloads)} payloads'
        })
        
    except Exception as e:
        logger.error(f"Payload generation failed: {e}")
        return jsonify({'error': f'Payload generation failed: {str(e)}'}), 500

@ai_bp.route('/stats', methods=['GET'])
def get_ai_stats():
    """Get AI integration statistics"""
    try:
        ai_integration = get_ai_integration()
        stats = ai_integration.get_statistics()
        
        return jsonify({
            'success': True,
            'statistics': stats
        })
        
    except Exception as e:
        logger.error(f"Failed to get AI stats: {e}")
        return jsonify({'error': f'Failed to get statistics: {str(e)}'}), 500

@ai_bp.route('/suggestions', methods=['POST'])
def get_attack_suggestions():
    """Get attack suggestions based on reconnaissance data"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No reconnaissance data provided'}), 400
        
        ai_integration = get_ai_integration()
        analysis_result = ai_integration.analyze_recon_data(data)
        
        return jsonify({
            'success': True,
            'suggestions': analysis_result.get('suggestions', []),
            'priority_targets': analysis_result.get('priority_targets', []),
            'risk_score': analysis_result.get('risk_score', 0.0)
        })
        
    except Exception as e:
        logger.error(f"Failed to get suggestions: {e}")
        return jsonify({'error': f'Failed to get suggestions: {str(e)}'}), 500 