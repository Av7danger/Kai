#!/usr/bin/env python3
"""
💰 Submission API Endpoints
API endpoints for bug submission and payout tracking
"""

from flask import Blueprint, request, jsonify
from bug_submission import get_submission_manager
import json
import logging

logger = logging.getLogger(__name__)

# Create Blueprint
submission_bp = Blueprint('submission', __name__)

@submission_bp.route('/reports', methods=['GET', 'POST'])
def manage_reports():
    """Manage bug reports"""
    submission_manager = get_submission_manager()
    
    if request.method == 'POST':
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        required_fields = ['title', 'description', 'severity', 'target_domain', 'vulnerability_type', 'steps_to_reproduce']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing required field: {field}'}), 400
        
        try:
            report_id = submission_manager.create_bug_report(
                title=data['title'],
                description=data['description'],
                severity=data['severity'],
                target_domain=data['target_domain'],
                vulnerability_type=data['vulnerability_type'],
                steps_to_reproduce=data['steps_to_reproduce'],
                proof_of_concept=data.get('proof_of_concept', ''),
                impact=data.get('impact', ''),
                affected_components=data.get('affected_components', []),
                recommendations=data.get('recommendations', []),
                references=data.get('references', [])
            )
            
            return jsonify({
                'success': True,
                'report_id': report_id,
                'message': 'Bug report created successfully'
            })
            
        except Exception as e:
            logger.error(f"Failed to create report: {e}")
            return jsonify({'error': f'Failed to create report: {str(e)}'}), 500
    
    else:
        # Get all reports
        try:
            reports = []
            for report_id, report in submission_manager.bug_reports.items():
                reports.append({
                    'id': report.id,
                    'title': report.title,
                    'severity': report.severity,
                    'target_domain': report.target_domain,
                    'vulnerability_type': report.vulnerability_type,
                    'status': report.status,
                    'created_at': report.created_at.isoformat(),
                    'quality_score': submission_manager.get_quality_score(report_id)
                })
            
            return jsonify({
                'success': True,
                'reports': reports
            })
            
        except Exception as e:
            logger.error(f"Failed to get reports: {e}")
            return jsonify({'error': f'Failed to get reports: {str(e)}'}), 500

@submission_bp.route('/reports/<report_id>', methods=['GET'])
def get_report(report_id):
    """Get specific bug report"""
    try:
        submission_manager = get_submission_manager()
        
        if report_id not in submission_manager.bug_reports:
            return jsonify({'error': 'Report not found'}), 404
        
        report = submission_manager.bug_reports[report_id]
        quality_score = submission_manager.get_quality_score(report_id)
        
        return jsonify({
            'success': True,
            'report': {
                'id': report.id,
                'title': report.title,
                'description': report.description,
                'severity': report.severity,
                'impact': report.impact,
                'steps_to_reproduce': report.steps_to_reproduce,
                'proof_of_concept': report.proof_of_concept,
                'affected_components': report.affected_components,
                'recommendations': report.recommendations,
                'references': report.references,
                'target_domain': report.target_domain,
                'vulnerability_type': report.vulnerability_type,
                'status': report.status,
                'created_at': report.created_at.isoformat(),
                'quality_score': quality_score
            }
        })
        
    except Exception as e:
        logger.error(f"Failed to get report: {e}")
        return jsonify({'error': f'Failed to get report: {str(e)}'}), 500

@submission_bp.route('/submit', methods=['POST'])
def submit_report():
    """Submit bug report to platform"""
    data = request.get_json()
    if not data or 'report_id' not in data or 'platform' not in data:
        return jsonify({'error': 'Report ID and platform are required'}), 400
    
    report_id = data['report_id']
    platform = data['platform']
    
    try:
        submission_manager = get_submission_manager()
        result = submission_manager.submit_bug_report(report_id, platform)
        
        return jsonify({
            'success': result['success'],
            'submission_id': result['submission_id'],
            'status': result['status'],
            'message': result['message']
        })
        
    except Exception as e:
        logger.error(f"Failed to submit report: {e}")
        return jsonify({'error': f'Failed to submit report: {str(e)}'}), 500

@submission_bp.route('/auto-submit', methods=['POST'])
def auto_submit_reports():
    """Automatically submit high-quality reports"""
    try:
        submission_manager = get_submission_manager()
        results = submission_manager.auto_submit_high_quality_reports()
        
        return jsonify({
            'success': True,
            'results': results,
            'message': f'Auto-submitted {len(results)} reports'
        })
        
    except Exception as e:
        logger.error(f"Failed to auto-submit reports: {e}")
        return jsonify({'error': f'Failed to auto-submit reports: {str(e)}'}), 500

@submission_bp.route('/payouts', methods=['GET', 'POST'])
def manage_payouts():
    """Manage payout tracking"""
    submission_manager = get_submission_manager()
    
    if request.method == 'POST':
        data = request.get_json()
        if not data or 'submission_id' not in data or 'amount' not in data:
            return jsonify({'error': 'Submission ID and amount are required'}), 400
        
        submission_id = data['submission_id']
        amount = data['amount']
        currency = data.get('currency', 'USD')
        transaction_id = data.get('transaction_id')
        
        try:
            payout_id = submission_manager.track_payout(
                submission_id, amount, currency, transaction_id
            )
            
            return jsonify({
                'success': True,
                'payout_id': payout_id,
                'message': f'Payout tracked: ${amount} {currency}'
            })
            
        except Exception as e:
            logger.error(f"Failed to track payout: {e}")
            return jsonify({'error': f'Failed to track payout: {str(e)}'}), 500
    
    else:
        # Get all payouts
        try:
            payouts = []
            for payout_id, payout in submission_manager.payouts.items():
                payouts.append({
                    'id': payout.id,
                    'platform': payout.platform,
                    'report_id': payout.report_id,
                    'amount': payout.amount,
                    'currency': payout.currency,
                    'payout_date': payout.payout_date.isoformat(),
                    'status': payout.status,
                    'transaction_id': payout.transaction_id
                })
            
            return jsonify({
                'success': True,
                'payouts': payouts
            })
            
        except Exception as e:
            logger.error(f"Failed to get payouts: {e}")
            return jsonify({'error': f'Failed to get payouts: {str(e)}'}), 500

@submission_bp.route('/statistics', methods=['GET'])
def get_submission_stats():
    """Get submission statistics"""
    try:
        submission_manager = get_submission_manager()
        stats = submission_manager.get_submission_statistics()
        
        return jsonify({
            'success': True,
            'statistics': stats
        })
        
    except Exception as e:
        logger.error(f"Failed to get statistics: {e}")
        return jsonify({'error': f'Failed to get statistics: {str(e)}'}), 500

@submission_bp.route('/quality-score/<report_id>', methods=['GET'])
def get_quality_score(report_id):
    """Get quality score for a report"""
    try:
        submission_manager = get_submission_manager()
        score = submission_manager.get_quality_score(report_id)
        
        return jsonify({
            'success': True,
            'report_id': report_id,
            'quality_score': score
        })
        
    except Exception as e:
        logger.error(f"Failed to get quality score: {e}")
        return jsonify({'error': f'Failed to get quality score: {str(e)}'}), 500

@submission_bp.route('/submissions', methods=['GET'])
def get_submissions():
    """Get all submissions"""
    try:
        submission_manager = get_submission_manager()
        submissions = []
        
        for submission_id, submission in submission_manager.submissions.items():
            submissions.append({
                'id': submission.id,
                'bug_report_id': submission.bug_report_id,
                'platform': submission.platform,
                'platform_report_id': submission.platform_report_id,
                'submission_status': submission.submission_status,
                'submission_date': submission.submission_date.isoformat(),
                'response_date': submission.response_date.isoformat() if submission.response_date else None,
                'payout_amount': submission.payout_amount,
                'payout_currency': submission.payout_currency,
                'platform_response': submission.platform_response
            })
        
        return jsonify({
            'success': True,
            'submissions': submissions
        })
        
    except Exception as e:
        logger.error(f"Failed to get submissions: {e}")
        return jsonify({'error': f'Failed to get submissions: {str(e)}'}), 500

@submission_bp.route('/platforms', methods=['GET'])
def get_platforms():
    """Get available platforms"""
    try:
        submission_manager = get_submission_manager()
        platforms = list(submission_manager.platform_clients.keys())
        
        return jsonify({
            'success': True,
            'platforms': platforms
        })
        
    except Exception as e:
        logger.error(f"Failed to get platforms: {e}")
        return jsonify({'error': f'Failed to get platforms: {str(e)}'}), 500 