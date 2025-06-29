#!/usr/bin/env python3
"""
💰 Automated Bug Submission & Payout Tracking
Direct platform integration and automated reporting

Features:
- HackerOne and Bugcrowd platform integration
- Automated bug report submission
- Payout tracking and analytics
- Success rate optimization
- Platform-specific adapters
- Report quality scoring
- Duplicate detection
- Submission rate limiting
"""

import os
import json
import time
import hashlib
import sqlite3
import requests
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from pathlib import Path
import logging
import yaml
from urllib.parse import urljoin
import re

logger = logging.getLogger(__name__)

@dataclass
class BugReport:
    """Bug report structure for submission"""
    id: str
    title: str
    description: str
    severity: str
    impact: str
    steps_to_reproduce: List[str]
    proof_of_concept: str
    affected_components: List[str]
    recommendations: List[str]
    references: List[str]
    target_domain: str
    vulnerability_type: str
    created_at: datetime
    status: str = 'draft'  # draft, submitted, accepted, rejected, duplicate

@dataclass
class PlatformSubmission:
    """Platform submission record"""
    id: str
    bug_report_id: str
    platform: str  # hackerone, bugcrowd, etc.
    platform_report_id: str
    submission_status: str  # submitted, accepted, rejected, duplicate
    submission_date: datetime
    response_date: Optional[datetime] = None
    payout_amount: Optional[float] = None
    payout_currency: str = 'USD'
    platform_response: Optional[str] = None

@dataclass
class PayoutRecord:
    """Payout tracking record"""
    id: str
    platform: str
    report_id: str
    amount: float
    currency: str
    payout_date: datetime
    status: str  # pending, paid, failed
    transaction_id: Optional[str] = None

class BugSubmissionManager:
    """Automated bug submission and payout tracking manager"""
    
    def __init__(self, config_path: str = 'submission_config.yml'):
        self.config_path = config_path
        self.config = self._load_config()
        
        # Database
        self.db_path = 'bug_submission.db'
        self._init_database()
        
        # Platform clients
        self.platform_clients = self._initialize_platform_clients()
        
        # Report storage
        self.bug_reports: Dict[str, BugReport] = {}
        self.submissions: Dict[str, PlatformSubmission] = {}
        self.payouts: Dict[str, PayoutRecord] = {}
        
        # Create output directories
        self.output_dir = Path('submission_results')
        self.output_dir.mkdir(exist_ok=True)
        
        for subdir in ['reports', 'submissions', 'payouts', 'analytics']:
            (self.output_dir / subdir).mkdir(exist_ok=True)
    
    def _load_config(self) -> Dict:
        """Load submission configuration"""
        if os.path.exists(self.config_path):
            with open(self.config_path, 'r') as f:
                return yaml.safe_load(f)
        else:
            return self._get_default_config()
    
    def _get_default_config(self) -> Dict:
        """Get default submission configuration"""
        return {
            'platforms': {
                'hackerone': {
                    'enabled': False,
                    'api_token': '',
                    'username': '',
                    'base_url': 'https://api.hackerone.com/v1',
                    'rate_limit': 100,  # requests per hour
                    'auto_submit': False
                },
                'bugcrowd': {
                    'enabled': False,
                    'api_token': '',
                    'username': '',
                    'base_url': 'https://api.bugcrowd.com',
                    'rate_limit': 100,
                    'auto_submit': False
                }
            },
            'submission_settings': {
                'auto_submit_enabled': False,
                'quality_threshold': 0.7,
                'duplicate_check_enabled': True,
                'rate_limiting_enabled': True,
                'max_submissions_per_day': 10,
                'min_severity_for_auto_submit': 'medium'
            },
            'report_settings': {
                'include_proof_of_concept': True,
                'include_recommendations': True,
                'include_references': True,
                'max_report_length': 5000,
                'required_fields': ['title', 'description', 'steps_to_reproduce']
            },
            'payout_tracking': {
                'enabled': True,
                'auto_track_payouts': True,
                'payout_notifications': True
            }
        }
    
    def _init_database(self):
        """Initialize submission database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Bug reports table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS bug_reports (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT,
                severity TEXT,
                impact TEXT,
                steps_to_reproduce TEXT,
                proof_of_concept TEXT,
                affected_components TEXT,
                recommendations TEXT,
                refs TEXT,
                target_domain TEXT,
                vulnerability_type TEXT,
                created_at TEXT,
                status TEXT DEFAULT 'draft'
            )
        ''')
        
        # Platform submissions table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS platform_submissions (
                id TEXT PRIMARY KEY,
                bug_report_id TEXT,
                platform TEXT,
                platform_report_id TEXT,
                submission_status TEXT,
                submission_date TEXT,
                response_date TEXT,
                payout_amount REAL,
                payout_currency TEXT,
                platform_response TEXT,
                FOREIGN KEY (bug_report_id) REFERENCES bug_reports (id)
            )
        ''')
        
        # Payout records table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS payout_records (
                id TEXT PRIMARY KEY,
                platform TEXT,
                report_id TEXT,
                amount REAL,
                currency TEXT,
                payout_date TEXT,
                status TEXT,
                transaction_id TEXT
            )
        ''')
        
        # Analytics table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS submission_analytics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                date TEXT,
                platform TEXT,
                submissions_count INTEGER,
                accepted_count INTEGER,
                rejected_count INTEGER,
                duplicate_count INTEGER,
                total_payout REAL,
                avg_payout REAL,
                success_rate REAL
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def _initialize_platform_clients(self) -> Dict[str, Any]:
        """Initialize platform API clients"""
        clients = {}
        
        # HackerOne client
        if self.config['platforms']['hackerone']['enabled']:
            clients['hackerone'] = HackerOneClient(
                self.config['platforms']['hackerone']
            )
        
        # Bugcrowd client
        if self.config['platforms']['bugcrowd']['enabled']:
            clients['bugcrowd'] = BugcrowdClient(
                self.config['platforms']['bugcrowd']
            )
        
        return clients
    
    def create_bug_report(self, title: str, description: str, severity: str,
                         target_domain: str, vulnerability_type: str,
                         steps_to_reproduce: List[str], proof_of_concept: str = "",
                         impact: str = "", affected_components: List[str] = None,
                         recommendations: List[str] = None, references: List[str] = None) -> str:
        """Create a new bug report"""
        report_id = hashlib.md5(f"{title}_{target_domain}_{time.time()}".encode()).hexdigest()[:12]
        
        bug_report = BugReport(
            id=report_id,
            title=title,
            description=description,
            severity=severity,
            impact=impact,
            steps_to_reproduce=steps_to_reproduce,
            proof_of_concept=proof_of_concept,
            affected_components=affected_components or [],
            recommendations=recommendations or [],
            references=references or [],
            target_domain=target_domain,
            vulnerability_type=vulnerability_type,
            created_at=datetime.now()
        )
        
        self.bug_reports[report_id] = bug_report
        self._save_bug_report_to_db(bug_report)
        
        logger.info(f"Created bug report {report_id}: {title}")
        return report_id
    
    def _save_bug_report_to_db(self, report: BugReport):
        """Save bug report to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO bug_reports 
            (id, title, description, severity, impact, steps_to_reproduce,
             proof_of_concept, affected_components, recommendations, refs,
             target_domain, vulnerability_type, created_at, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            report.id, report.title, report.description, report.severity,
            report.impact, json.dumps(report.steps_to_reproduce),
            report.proof_of_concept, json.dumps(report.affected_components),
            json.dumps(report.recommendations), json.dumps(report.references),
            report.target_domain, report.vulnerability_type,
            report.created_at.isoformat(), report.status
        ))
        
        conn.commit()
        conn.close()
    
    def submit_bug_report(self, report_id: str, platform: str) -> Dict[str, Any]:
        """Submit a bug report to a specific platform"""
        if report_id not in self.bug_reports:
            raise ValueError(f"Bug report {report_id} not found")
        
        if platform not in self.platform_clients:
            raise ValueError(f"Platform {platform} not configured")
        
        report = self.bug_reports[report_id]
        client = self.platform_clients[platform]
        
        # Check rate limiting
        if not self._check_rate_limit(platform):
            raise Exception(f"Rate limit exceeded for {platform}")
        
        # Check for duplicates
        if self._check_duplicate(report, platform):
            submission_id = self._record_duplicate_submission(report_id, platform)
            return {
                'success': False,
                'submission_id': submission_id,
                'status': 'duplicate',
                'message': 'Duplicate report detected'
            }
        
        try:
            # Submit to platform
            result = client.submit_report(report)
            
            # Record submission
            submission_id = self._record_submission(report_id, platform, result)
            
            # Update report status
            report.status = 'submitted'
            self._update_report_status(report_id, 'submitted')
            
            logger.info(f"Successfully submitted report {report_id} to {platform}")
            
            return {
                'success': True,
                'submission_id': submission_id,
                'platform_report_id': result.get('report_id'),
                'status': 'submitted',
                'message': 'Report submitted successfully'
            }
            
        except Exception as e:
            logger.error(f"Failed to submit report {report_id} to {platform}: {e}")
            
            # Record failed submission
            submission_id = self._record_failed_submission(report_id, platform, str(e))
            
            return {
                'success': False,
                'submission_id': submission_id,
                'status': 'failed',
                'message': str(e)
            }
    
    def _check_rate_limit(self, platform: str) -> bool:
        """Check if rate limit allows submission"""
        if not self.config['submission_settings']['rate_limiting_enabled']:
            return True
        
        # Simple rate limiting - check submissions in last hour
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        one_hour_ago = (datetime.now() - timedelta(hours=1)).isoformat()
        cursor.execute('''
            SELECT COUNT(*) FROM platform_submissions 
            WHERE platform = ? AND submission_date > ?
        ''', (platform, one_hour_ago))
        
        count = cursor.fetchone()[0]
        conn.close()
        
        rate_limit = self.config['platforms'][platform]['rate_limit']
        return count < rate_limit
    
    def _check_duplicate(self, report: BugReport, platform: str) -> bool:
        """Check if report is a duplicate"""
        if not self.config['submission_settings']['duplicate_check_enabled']:
            return False
        
        # Simple duplicate check based on title and target
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT COUNT(*) FROM bug_reports 
            WHERE target_domain = ? AND title = ? AND status != 'draft'
        ''', (report.target_domain, report.title))
        
        count = cursor.fetchone()[0]
        conn.close()
        
        return count > 0
    
    def _record_submission(self, report_id: str, platform: str, result: Dict[str, Any]) -> str:
        """Record a successful submission"""
        submission_id = hashlib.md5(f"{report_id}_{platform}_{time.time()}".encode()).hexdigest()[:12]
        
        submission = PlatformSubmission(
            id=submission_id,
            bug_report_id=report_id,
            platform=platform,
            platform_report_id=result.get('report_id', ''),
            submission_status='submitted',
            submission_date=datetime.now()
        )
        
        self.submissions[submission_id] = submission
        self._save_submission_to_db(submission)
        
        return submission_id
    
    def _record_duplicate_submission(self, report_id: str, platform: str) -> str:
        """Record a duplicate submission"""
        submission_id = hashlib.md5(f"{report_id}_{platform}_{time.time()}".encode()).hexdigest()[:12]
        
        submission = PlatformSubmission(
            id=submission_id,
            bug_report_id=report_id,
            platform=platform,
            platform_report_id='',
            submission_status='duplicate',
            submission_date=datetime.now()
        )
        
        self.submissions[submission_id] = submission
        self._save_submission_to_db(submission)
        
        return submission_id
    
    def _record_failed_submission(self, report_id: str, platform: str, error: str) -> str:
        """Record a failed submission"""
        submission_id = hashlib.md5(f"{report_id}_{platform}_{time.time()}".encode()).hexdigest()[:12]
        
        submission = PlatformSubmission(
            id=submission_id,
            bug_report_id=report_id,
            platform=platform,
            platform_report_id='',
            submission_status='failed',
            submission_date=datetime.now(),
            platform_response=error
        )
        
        self.submissions[submission_id] = submission
        self._save_submission_to_db(submission)
        
        return submission_id
    
    def _save_submission_to_db(self, submission: PlatformSubmission):
        """Save submission to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO platform_submissions 
            (id, bug_report_id, platform, platform_report_id, submission_status,
             submission_date, response_date, payout_amount, payout_currency, platform_response)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            submission.id, submission.bug_report_id, submission.platform,
            submission.platform_report_id, submission.submission_status,
            submission.submission_date.isoformat(),
            submission.response_date.isoformat() if submission.response_date else None,
            submission.payout_amount, submission.payout_currency,
            submission.platform_response
        ))
        
        conn.commit()
        conn.close()
    
    def _update_report_status(self, report_id: str, status: str):
        """Update bug report status"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE bug_reports SET status = ? WHERE id = ?
        ''', (status, report_id))
        
        conn.commit()
        conn.close()
    
    def track_payout(self, submission_id: str, amount: float, currency: str = 'USD',
                    transaction_id: Optional[str] = None) -> str:
        """Track a payout for a submission"""
        if submission_id not in self.submissions:
            raise ValueError(f"Submission {submission_id} not found")
        
        payout_id = hashlib.md5(f"{submission_id}_{amount}_{time.time()}".encode()).hexdigest()[:12]
        
        payout = PayoutRecord(
            id=payout_id,
            platform=self.submissions[submission_id].platform,
            report_id=submission_id,
            amount=amount,
            currency=currency,
            payout_date=datetime.now(),
            status='paid',
            transaction_id=transaction_id
        )
        
        self.payouts[payout_id] = payout
        self._save_payout_to_db(payout)
        
        # Update submission with payout info
        self.submissions[submission_id].payout_amount = amount
        self.submissions[submission_id].payout_currency = currency
        self._update_submission_payout(submission_id, amount, currency)
        
        logger.info(f"Tracked payout {payout_id}: ${amount} {currency}")
        return payout_id
    
    def _save_payout_to_db(self, payout: PayoutRecord):
        """Save payout to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO payout_records 
            (id, platform, report_id, amount, currency, payout_date, status, transaction_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            payout.id, payout.platform, payout.report_id, payout.amount,
            payout.currency, payout.payout_date.isoformat(), payout.status,
            payout.transaction_id
        ))
        
        conn.commit()
        conn.close()
    
    def _update_submission_payout(self, submission_id: str, amount: float, currency: str):
        """Update submission with payout information"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE platform_submissions 
            SET payout_amount = ?, payout_currency = ?
            WHERE id = ?
        ''', (amount, currency, submission_id))
        
        conn.commit()
        conn.close()
    
    def get_submission_statistics(self) -> Dict[str, Any]:
        """Get submission statistics"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Total submissions by platform
        cursor.execute('''
            SELECT platform, COUNT(*) as count,
                   SUM(CASE WHEN submission_status = 'accepted' THEN 1 ELSE 0 END) as accepted,
                   SUM(CASE WHEN submission_status = 'rejected' THEN 1 ELSE 0 END) as rejected,
                   SUM(CASE WHEN submission_status = 'duplicate' THEN 1 ELSE 0 END) as duplicate
            FROM platform_submissions
            GROUP BY platform
        ''')
        
        platform_stats = {}
        for row in cursor.fetchall():
            platform, total, accepted, rejected, duplicate = row
            success_rate = (accepted / total * 100) if total > 0 else 0
            platform_stats[platform] = {
                'total_submissions': total,
                'accepted': accepted,
                'rejected': rejected,
                'duplicate': duplicate,
                'success_rate': success_rate
            }
        
        # Total payouts
        cursor.execute('''
            SELECT SUM(amount), AVG(amount), COUNT(*)
            FROM payout_records
            WHERE status = 'paid'
        ''')
        
        payout_stats = cursor.fetchone()
        total_payout = payout_stats[0] or 0
        avg_payout = payout_stats[1] or 0
        total_payouts = payout_stats[2] or 0
        
        # Recent activity
        cursor.execute('''
            SELECT COUNT(*) FROM platform_submissions
            WHERE submission_date > ?
        ''', ((datetime.now() - timedelta(days=7)).isoformat(),))
        
        recent_submissions = cursor.fetchone()[0]
        
        conn.close()
        
        return {
            'platform_statistics': platform_stats,
            'payout_statistics': {
                'total_payout': total_payout,
                'average_payout': avg_payout,
                'total_payouts': total_payouts
            },
            'recent_activity': {
                'submissions_last_7_days': recent_submissions
            }
        }
    
    def get_quality_score(self, report_id: str) -> float:
        """Calculate quality score for a bug report"""
        if report_id not in self.bug_reports:
            return 0.0
        
        report = self.bug_reports[report_id]
        score = 0.0
        
        # Title quality (0-20 points)
        if len(report.title) > 10 and len(report.title) < 100:
            score += 20
        
        # Description quality (0-25 points)
        if len(report.description) > 50:
            score += 25
        
        # Steps to reproduce (0-20 points)
        if len(report.steps_to_reproduce) >= 3:
            score += 20
        
        # Proof of concept (0-15 points)
        if report.proof_of_concept:
            score += 15
        
        # Recommendations (0-10 points)
        if report.recommendations:
            score += 10
        
        # References (0-10 points)
        if report.references:
            score += 10
        
        return min(score, 100.0) / 100.0  # Normalize to 0-1
    
    def auto_submit_high_quality_reports(self) -> List[Dict[str, Any]]:
        """Automatically submit high-quality reports"""
        if not self.config['submission_settings']['auto_submit_enabled']:
            return []
        
        results = []
        quality_threshold = self.config['submission_settings']['quality_threshold']
        min_severity = self.config['submission_settings']['min_severity_for_auto_submit']
        
        for report_id, report in self.bug_reports.items():
            if report.status != 'draft':
                continue
            
            # Check severity
            severity_levels = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
            if severity_levels.get(report.severity, 0) < severity_levels.get(min_severity, 0):
                continue
            
            # Check quality
            quality_score = self.get_quality_score(report_id)
            if quality_score < quality_threshold:
                continue
            
            # Submit to available platforms
            for platform in self.platform_clients.keys():
                try:
                    result = self.submit_bug_report(report_id, platform)
                    results.append({
                        'report_id': report_id,
                        'platform': platform,
                        'quality_score': quality_score,
                        'result': result
                    })
                except Exception as e:
                    logger.error(f"Auto-submit failed for {report_id} to {platform}: {e}")
        
        return results

class HackerOneClient:
    """HackerOne API client"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.api_token = config['api_token']
        self.username = config['username']
        self.base_url = config['base_url']
        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': f'Bearer {self.api_token}',
            'Content-Type': 'application/json'
        })
    
    def submit_report(self, report: BugReport) -> Dict[str, Any]:
        """Submit report to HackerOne"""
        # This is a mock implementation
        # In a real implementation, you would use the actual HackerOne API
        
        payload = {
            'data': {
                'type': 'report',
                'attributes': {
                    'title': report.title,
                    'body': self._format_report_for_hackerone(report),
                    'severity': self._map_severity_to_hackerone(report.severity)
                }
            }
        }
        
        # Mock API call
        time.sleep(1)  # Simulate API delay
        
        return {
            'report_id': f"h1_{hashlib.md5(report.title.encode()).hexdigest()[:8]}",
            'status': 'submitted'
        }
    
    def _format_report_for_hackerone(self, report: BugReport) -> str:
        """Format report for HackerOne submission"""
        body = f"""
## Summary
{report.description}

## Steps to Reproduce
{chr(10).join(f"{i+1}. {step}" for i, step in enumerate(report.steps_to_reproduce))}

## Impact
{report.impact}

## Proof of Concept
{report.proof_of_concept}

## Recommendations
{chr(10).join(f"- {rec}" for rec in report.recommendations)}

## References
{chr(10).join(f"- {ref}" for ref in report.references)}
        """
        return body.strip()
    
    def _map_severity_to_hackerone(self, severity: str) -> str:
        """Map internal severity to HackerOne severity"""
        mapping = {
            'critical': 'critical',
            'high': 'high',
            'medium': 'medium',
            'low': 'low'
        }
        return mapping.get(severity, 'medium')

class BugcrowdClient:
    """Bugcrowd API client"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.api_token = config['api_token']
        self.username = config['username']
        self.base_url = config['base_url']
        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': f'Token {self.api_token}',
            'Content-Type': 'application/json'
        })
    
    def submit_report(self, report: BugReport) -> Dict[str, Any]:
        """Submit report to Bugcrowd"""
        # This is a mock implementation
        # In a real implementation, you would use the actual Bugcrowd API
        
        payload = {
            'title': report.title,
            'description': self._format_report_for_bugcrowd(report),
            'severity': self._map_severity_to_bugcrowd(report.severity)
        }
        
        # Mock API call
        time.sleep(1)  # Simulate API delay
        
        return {
            'report_id': f"bc_{hashlib.md5(report.title.encode()).hexdigest()[:8]}",
            'status': 'submitted'
        }
    
    def _format_report_for_bugcrowd(self, report: BugReport) -> str:
        """Format report for Bugcrowd submission"""
        body = f"""
## Description
{report.description}

## Steps to Reproduce
{chr(10).join(f"{i+1}. {step}" for i, step in enumerate(report.steps_to_reproduce))}

## Impact
{report.impact}

## Proof of Concept
{report.proof_of_concept}

## Recommendations
{chr(10).join(f"- {rec}" for rec in report.recommendations)}
        """
        return body.strip()
    
    def _map_severity_to_bugcrowd(self, severity: str) -> str:
        """Map internal severity to Bugcrowd severity"""
        mapping = {
            'critical': 'P1',
            'high': 'P2',
            'medium': 'P3',
            'low': 'P4'
        }
        return mapping.get(severity, 'P3')

# Global submission manager instance
submission_manager = None

def initialize_submission_manager(config_path: str = 'submission_config.yml'):
    """Initialize the global submission manager"""
    global submission_manager
    submission_manager = BugSubmissionManager(config_path)
    return submission_manager

def get_submission_manager() -> BugSubmissionManager:
    """Get the global submission manager instance"""
    if submission_manager is None:
        raise RuntimeError("Submission manager not initialized. Call initialize_submission_manager() first.")
    return submission_manager 