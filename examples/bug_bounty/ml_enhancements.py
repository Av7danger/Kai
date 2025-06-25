"""
Machine Learning Enhancement Module
Advanced ML capabilities for improved vulnerability detection and false positive reduction
"""

import asyncio
import json
import pickle
import numpy as np
import pandas as pd
from typing import Dict, List, Tuple, Optional
from datetime import datetime, timedelta
from pathlib import Path
import hashlib
import logging

try:
    from sklearn.ensemble import RandomForestClassifier, IsolationForest
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import accuracy_score, precision_score, recall_score
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    print("⚠️ scikit-learn not available. Install with: pip install scikit-learn")

from autonomous_agent import BugReport, Priority

class VulnerabilityPatternLearner:
    """Machine learning system for vulnerability pattern recognition"""
    
    def __init__(self, model_dir: Path = Path("./ml_models")):
        self.model_dir = model_dir
        self.model_dir.mkdir(exist_ok=True)
        
        # Initialize models
        self.vulnerability_classifier = None
        self.false_positive_detector = None
        self.payload_generator = None
        self.vectorizer = TfidfVectorizer(max_features=10000, stop_words='english')
        
        # Training data storage
        self.training_data = {
            "vulnerabilities": [],
            "false_positives": [],
            "payloads": [],
            "targets": []
        }
        
        self.logger = logging.getLogger('ml_enhancer')
        self._load_existing_models()
    
    def _load_existing_models(self):
        """Load pre-trained models if available"""
        try:
            if (self.model_dir / "vulnerability_classifier.pkl").exists():
                with open(self.model_dir / "vulnerability_classifier.pkl", 'rb') as f:
                    self.vulnerability_classifier = pickle.load(f)
                self.logger.info("✅ Loaded vulnerability classifier model")
            
            if (self.model_dir / "false_positive_detector.pkl").exists():
                with open(self.model_dir / "false_positive_detector.pkl", 'rb') as f:
                    self.false_positive_detector = pickle.load(f)
                self.logger.info("✅ Loaded false positive detector model")
                
            if (self.model_dir / "vectorizer.pkl").exists():
                with open(self.model_dir / "vectorizer.pkl", 'rb') as f:
                    self.vectorizer = pickle.load(f)
                self.logger.info("✅ Loaded text vectorizer")
                
        except Exception as e:
            self.logger.error(f"Error loading models: {e}")
    
    def add_vulnerability_data(self, bug_report: BugReport, is_confirmed: bool):
        """Add vulnerability data for training"""
        feature_data = self._extract_vulnerability_features(bug_report)
        
        self.training_data["vulnerabilities"].append({
            "features": feature_data,
            "confirmed": is_confirmed,
            "severity": bug_report.severity.value,
            "type": bug_report.vulnerability_type,
            "target": bug_report.target
        })
    
    def add_false_positive_data(self, finding_text: str, is_false_positive: bool):
        """Add false positive training data"""
        self.training_data["false_positives"].append({
            "text": finding_text,
            "is_false_positive": is_false_positive,
            "timestamp": datetime.now().isoformat()
        })
    
    def _extract_vulnerability_features(self, bug_report: BugReport) -> Dict:
        """Extract numerical features from vulnerability report"""
        features = {
            "title_length": len(bug_report.title),
            "description_length": len(bug_report.description),
            "poc_length": len(bug_report.proof_of_concept),
            "cvss_score": bug_report.cvss_score,
            "confidence": bug_report.confidence,
            "false_positive_prob": bug_report.false_positive_probability,
            "severity_numeric": self._severity_to_numeric(bug_report.severity),
            "has_references": len(bug_report.references),
            "endpoint_complexity": len(bug_report.endpoint.split('/')),
            "vuln_type_encoded": self._encode_vuln_type(bug_report.vulnerability_type)
        }
        
        # Text-based features
        text_features = self._extract_text_features(
            f"{bug_report.title} {bug_report.description} {bug_report.proof_of_concept}"
        )
        features.update(text_features)
        
        return features
    
    def _severity_to_numeric(self, severity: Priority) -> float:
        """Convert severity to numeric value"""
        mapping = {
            Priority.INFO: 0.0,
            Priority.LOW: 0.25,
            Priority.MEDIUM: 0.5,
            Priority.HIGH: 0.75,
            Priority.CRITICAL: 1.0
        }
        return mapping.get(severity, 0.5)
    
    def _encode_vuln_type(self, vuln_type: str) -> int:
        """Encode vulnerability type to numeric"""
        common_types = [
            "xss", "sqli", "csrf", "ssrf", "idor", "rce", "lfi", "rfi",
            "xxe", "deserialization", "authentication", "authorization"
        ]
        return common_types.index(vuln_type.lower()) if vuln_type.lower() in common_types else -1
    
    def _extract_text_features(self, text: str) -> Dict:
        """Extract features from text content"""
        text_lower = text.lower()
        
        # Keyword presence features
        vulnerability_keywords = [
            "exploit", "payload", "injection", "bypass", "escalation",
            "disclosure", "exposure", "vulnerability", "security", "flaw"
        ]
        
        features = {}
        for keyword in vulnerability_keywords:
            features[f"has_{keyword}"] = 1 if keyword in text_lower else 0
        
        # Text complexity features
        features["word_count"] = len(text.split())
        features["unique_words"] = len(set(text.split()))
        features["avg_word_length"] = np.mean([len(word) for word in text.split()]) if text.split() else 0
        
        return features
    
    async def train_models(self) -> Dict[str, float]:
        """Train ML models on collected data"""
        if not SKLEARN_AVAILABLE:
            return {"error": "scikit-learn not available"}
        
        results = {}
        
        # Train vulnerability classifier
        if len(self.training_data["vulnerabilities"]) > 50:
            vuln_results = await self._train_vulnerability_classifier()
            results.update(vuln_results)
        
        # Train false positive detector
        if len(self.training_data["false_positives"]) > 30:
            fp_results = await self._train_false_positive_detector()
            results.update(fp_results)
        
        # Save models
        await self._save_models()
        
        return results
    
    async def _train_vulnerability_classifier(self) -> Dict[str, float]:
        """Train vulnerability classification model"""
        vuln_data = self.training_data["vulnerabilities"]
        
        # Prepare features and labels
        features = []
        labels = []
        
        for item in vuln_data:
            feature_vector = list(item["features"].values())
            features.append(feature_vector)
            labels.append(1 if item["confirmed"] else 0)
        
        X = np.array(features)
        y = np.array(labels)
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        
        # Train model
        self.vulnerability_classifier = RandomForestClassifier(n_estimators=100, random_state=42)
        self.vulnerability_classifier.fit(X_train, y_train)
        
        # Evaluate model
        y_pred = self.vulnerability_classifier.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        precision = precision_score(y_test, y_pred, zero_division=0)
        recall = recall_score(y_test, y_pred, zero_division=0)
        
        self.logger.info(f"📊 Vulnerability classifier - Accuracy: {accuracy:.3f}, Precision: {precision:.3f}, Recall: {recall:.3f}")
        
        return {
            "vuln_classifier_accuracy": accuracy,
            "vuln_classifier_precision": precision,
            "vuln_classifier_recall": recall
        }
    
    async def _train_false_positive_detector(self) -> Dict[str, float]:
        """Train false positive detection model"""
        fp_data = self.training_data["false_positives"]
        
        # Prepare text data
        texts = [item["text"] for item in fp_data]
        labels = [1 if item["is_false_positive"] else 0 for item in fp_data]
        
        # Vectorize text
        X = self.vectorizer.fit_transform(texts)
        y = np.array(labels)
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        
        # Train model
        self.false_positive_detector = RandomForestClassifier(n_estimators=100, random_state=42)
        self.false_positive_detector.fit(X_train, y_train)
        
        # Evaluate model
        y_pred = self.false_positive_detector.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        precision = precision_score(y_test, y_pred, zero_division=0)
        recall = recall_score(y_test, y_pred, zero_division=0)
        
        self.logger.info(f"📊 False positive detector - Accuracy: {accuracy:.3f}, Precision: {precision:.3f}, Recall: {recall:.3f}")
        
        return {
            "fp_detector_accuracy": accuracy,
            "fp_detector_precision": precision,
            "fp_detector_recall": recall
        }
    
    async def _save_models(self):
        """Save trained models to disk"""
        try:
            if self.vulnerability_classifier:
                with open(self.model_dir / "vulnerability_classifier.pkl", 'wb') as f:
                    pickle.dump(self.vulnerability_classifier, f)
            
            if self.false_positive_detector:
                with open(self.model_dir / "false_positive_detector.pkl", 'wb') as f:
                    pickle.dump(self.false_positive_detector, f)
            
            with open(self.model_dir / "vectorizer.pkl", 'wb') as f:
                pickle.dump(self.vectorizer, f)
            
            # Save training data
            with open(self.model_dir / "training_data.json", 'w') as f:
                json.dump(self.training_data, f, indent=2, default=str)
            
            self.logger.info("✅ Models saved successfully")
            
        except Exception as e:
            self.logger.error(f"❌ Error saving models: {e}")
    
    async def predict_vulnerability_validity(self, bug_report: BugReport) -> float:
        """Predict if a vulnerability is valid (not false positive)"""
        if not self.vulnerability_classifier:
            return 0.5  # Default confidence
        
        features = self._extract_vulnerability_features(bug_report)
        feature_vector = np.array([list(features.values())])
        
        try:
            probability = self.vulnerability_classifier.predict_proba(feature_vector)[0][1]
            return probability
        except Exception as e:
            self.logger.error(f"Error predicting vulnerability validity: {e}")
            return 0.5
    
    async def detect_false_positive(self, finding_text: str) -> float:
        """Detect if a finding is likely a false positive"""
        if not self.false_positive_detector:
            return 0.5  # Default probability
        
        try:
            text_vector = self.vectorizer.transform([finding_text])
            probability = self.false_positive_detector.predict_proba(text_vector)[0][1]
            return probability
        except Exception as e:
            self.logger.error(f"Error detecting false positive: {e}")
            return 0.5
    
    async def generate_adaptive_payloads(self, target_info: Dict, vulnerability_type: str) -> List[str]:
        """Generate adaptive payloads based on target characteristics"""
        base_payloads = {
            "xss": [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "javascript:alert('XSS')",
                "\"><script>alert('XSS')</script>",
                "';alert('XSS');//"
            ],
            "sqli": [
                "' OR '1'='1",
                "'; DROP TABLE users; --",
                "' UNION SELECT NULL,NULL,NULL--",
                "1' AND (SELECT COUNT(*) FROM INFORMATION_SCHEMA.TABLES)>0--",
                "'; WAITFOR DELAY '00:00:05'; --"
            ],
            "ssrf": [
                "http://localhost:80",
                "http://127.0.0.1:22",
                "file:///etc/passwd",
                "http://169.254.169.254/latest/meta-data/",
                "gopher://127.0.0.1:25/_MAIL"
            ],
            "lfi": [
                "../../../etc/passwd",
                "....//....//....//etc/passwd",
                "/var/log/apache2/access.log",
                "php://filter/read=convert.base64-encode/resource=index.php",
                "/proc/self/environ"
            ]
        }
        
        payloads = base_payloads.get(vulnerability_type.lower(), [])
        
        # Adapt payloads based on target characteristics
        adapted_payloads = []
        
        for payload in payloads:
            # URL encoding variations
            adapted_payloads.append(payload)
            adapted_payloads.append(self._url_encode(payload))
            adapted_payloads.append(self._double_url_encode(payload))
            
            # Case variations for evasion
            if vulnerability_type.lower() == "xss":
                adapted_payloads.append(payload.upper())
                adapted_payloads.append(self._case_variation(payload))
        
        return adapted_payloads[:20]  # Limit to prevent excessive requests
    
    def _url_encode(self, payload: str) -> str:
        """URL encode payload"""
        import urllib.parse
        return urllib.parse.quote(payload)
    
    def _double_url_encode(self, payload: str) -> str:
        """Double URL encode payload"""
        import urllib.parse
        return urllib.parse.quote(urllib.parse.quote(payload))
    
    def _case_variation(self, payload: str) -> str:
        """Create case variation of payload"""
        result = ""
        for i, char in enumerate(payload):
            if i % 2 == 0:
                result += char.upper()
            else:
                result += char.lower()
        return result


class AnomalyDetector:
    """Detect anomalous patterns in scan results"""
    
    def __init__(self):
        self.isolation_forest = IsolationForest(contamination=0.1, random_state=42) if SKLEARN_AVAILABLE else None
        self.baseline_metrics = {}
        
    async def establish_baseline(self, scan_results: List[Dict]):
        """Establish baseline metrics for normal behavior"""
        if not self.isolation_forest or not scan_results:
            return
        
        # Extract numerical features from scan results
        features = []
        for result in scan_results:
            feature_vector = [
                result.get("response_time", 0),
                result.get("status_code", 200),
                len(result.get("content", "")),
                len(result.get("headers", {})),
                result.get("content_length", 0)
            ]
            features.append(feature_vector)
        
        X = np.array(features)
        self.isolation_forest.fit(X)
        
        # Calculate baseline metrics
        self.baseline_metrics = {
            "avg_response_time": np.mean([r.get("response_time", 0) for r in scan_results]),
            "common_status_codes": self._get_common_status_codes(scan_results),
            "avg_content_length": np.mean([len(r.get("content", "")) for r in scan_results])
        }
    
    def _get_common_status_codes(self, scan_results: List[Dict]) -> List[int]:
        """Get most common status codes"""
        status_codes = [r.get("status_code", 200) for r in scan_results]
        from collections import Counter
        common_codes = Counter(status_codes).most_common(5)
        return [code for code, _ in common_codes]
    
    async def detect_anomalies(self, new_results: List[Dict]) -> List[Dict]:
        """Detect anomalous results that might indicate vulnerabilities"""
        if not self.isolation_forest or not new_results:
            return []
        
        anomalies = []
        
        for result in new_results:
            feature_vector = np.array([[
                result.get("response_time", 0),
                result.get("status_code", 200),
                len(result.get("content", "")),
                len(result.get("headers", {})),
                result.get("content_length", 0)
            ]])
            
            anomaly_score = self.isolation_forest.decision_function(feature_vector)[0]
            is_anomaly = self.isolation_forest.predict(feature_vector)[0] == -1
            
            if is_anomaly:
                anomalies.append({
                    "result": result,
                    "anomaly_score": anomaly_score,
                    "anomaly_reasons": self._analyze_anomaly(result)
                })
        
        return anomalies
    
    def _analyze_anomaly(self, result: Dict) -> List[str]:
        """Analyze why a result is considered anomalous"""
        reasons = []
        
        # Check response time
        if result.get("response_time", 0) > self.baseline_metrics.get("avg_response_time", 0) * 3:
            reasons.append("Unusually slow response time")
        
        # Check status code
        if result.get("status_code") not in self.baseline_metrics.get("common_status_codes", []):
            reasons.append("Uncommon status code")
        
        # Check content length
        content_len = len(result.get("content", ""))
        avg_len = self.baseline_metrics.get("avg_content_length", 0)
        if content_len > avg_len * 5 or content_len < avg_len * 0.1:
            reasons.append("Unusual content length")
        
        # Check for error indicators
        content = result.get("content", "").lower()
        error_indicators = ["error", "exception", "stack trace", "sql", "database"]
        for indicator in error_indicators:
            if indicator in content:
                reasons.append(f"Contains '{indicator}' - potential error disclosure")
        
        return reasons


class PayloadOptimizer:
    """Optimize payloads based on success rates and target characteristics"""
    
    def __init__(self):
        self.payload_stats = {}
        self.target_characteristics = {}
        
    async def record_payload_result(self, payload: str, target: str, success: bool, vulnerability_type: str):
        """Record payload success/failure for optimization"""
        payload_hash = hashlib.md5(payload.encode()).hexdigest()
        
        if payload_hash not in self.payload_stats:
            self.payload_stats[payload_hash] = {
                "payload": payload,
                "vulnerability_type": vulnerability_type,
                "successes": 0,
                "failures": 0,
                "targets": set()
            }
        
        self.payload_stats[payload_hash]["targets"].add(target)
        
        if success:
            self.payload_stats[payload_hash]["successes"] += 1
        else:
            self.payload_stats[payload_hash]["failures"] += 1
    
    async def get_optimized_payloads(self, vulnerability_type: str, target: str, limit: int = 10) -> List[str]:
        """Get optimized payloads based on historical success rates"""
        relevant_payloads = []
        
        for payload_hash, stats in self.payload_stats.items():
            if stats["vulnerability_type"] == vulnerability_type:
                total_attempts = stats["successes"] + stats["failures"]
                success_rate = stats["successes"] / total_attempts if total_attempts > 0 else 0
                
                relevant_payloads.append({
                    "payload": stats["payload"],
                    "success_rate": success_rate,
                    "total_attempts": total_attempts
                })
        
        # Sort by success rate and number of attempts
        relevant_payloads.sort(key=lambda x: (x["success_rate"], x["total_attempts"]), reverse=True)
        
        return [p["payload"] for p in relevant_payloads[:limit]]
    
    async def analyze_target_characteristics(self, target: str, scan_results: List[Dict]) -> Dict:
        """Analyze target characteristics for payload optimization"""
        characteristics = {
            "technologies": [],
            "waf_detected": False,
            "cms": None,
            "server_software": None,
            "programming_language": None,
            "security_headers": []
        }
        
        for result in scan_results:
            headers = result.get("headers", {})
            content = result.get("content", "")
            
            # Detect technologies
            if "wp-content" in content or "wordpress" in content.lower():
                characteristics["cms"] = "WordPress"
            elif "joomla" in content.lower():
                characteristics["cms"] = "Joomla"
            elif "drupal" in content.lower():
                characteristics["cms"] = "Drupal"
            
            # Detect server software
            server_header = headers.get("Server", "").lower()
            if "apache" in server_header:
                characteristics["server_software"] = "Apache"
            elif "nginx" in server_header:
                characteristics["server_software"] = "Nginx"
            elif "iis" in server_header:
                characteristics["server_software"] = "IIS"
            
            # Detect programming language
            if ".php" in result.get("url", "") or "php" in headers.get("X-Powered-By", "").lower():
                characteristics["programming_language"] = "PHP"
            elif ".asp" in result.get("url", "") or "asp.net" in headers.get("X-Powered-By", "").lower():
                characteristics["programming_language"] = "ASP.NET"
            elif ".jsp" in result.get("url", ""):
                characteristics["programming_language"] = "Java"
            
            # Detect WAF
            waf_indicators = ["cloudflare", "akamai", "incapsula", "sucuri", "modsecurity"]
            for indicator in waf_indicators:
                if indicator in str(headers).lower() or indicator in content.lower():
                    characteristics["waf_detected"] = True
                    break
            
            # Security headers
            security_headers = ["Content-Security-Policy", "X-Frame-Options", "X-XSS-Protection", "Strict-Transport-Security"]
            for header in security_headers:
                if header in headers:
                    characteristics["security_headers"].append(header)
        
        self.target_characteristics[target] = characteristics
        return characteristics


# Example usage and integration
async def main():
    """Example usage of ML enhancements"""
    print("🤖 Machine Learning Bug Bounty Enhancements")
    print("=" * 50)
    
    # Initialize ML components
    pattern_learner = VulnerabilityPatternLearner()
    anomaly_detector = AnomalyDetector()
    payload_optimizer = PayloadOptimizer()
    
    print("✅ ML components initialized")
    
    # Simulate some training data
    from autonomous_agent import BugReport, Priority
    
    # Add sample vulnerability data
    sample_bug = BugReport(
        title="SQL Injection in login form",
        description="The login form is vulnerable to SQL injection attacks",
        vulnerability_type="sqli",
        severity=Priority.HIGH,
        target="https://example.com",
        endpoint="/login",
        proof_of_concept="username: admin' OR '1'='1' -- &password=test",
        cvss_score=7.5,
        confidence=0.9,
        false_positive_probability=0.1,
        references=["https://owasp.org/sql-injection"]
    )
    
    pattern_learner.add_vulnerability_data(sample_bug, is_confirmed=True)
    pattern_learner.add_false_positive_data("This looks like a vulnerability but it's not", True)
    
    print("📊 Sample training data added")
    
    # Train models (would need more data in practice)
    if len(pattern_learner.training_data["vulnerabilities"]) > 0:
        print("🎯 Training models...")
        results = await pattern_learner.train_models()
        print(f"📈 Training results: {results}")
    
    # Test predictions
    validity_score = await pattern_learner.predict_vulnerability_validity(sample_bug)
    print(f"🎯 Vulnerability validity prediction: {validity_score:.3f}")
    
    fp_score = await pattern_learner.detect_false_positive("This might be a false positive")
    print(f"🚫 False positive detection: {fp_score:.3f}")
    
    # Generate adaptive payloads
    payloads = await pattern_learner.generate_adaptive_payloads(
        {"technology": "PHP", "waf": False}, 
        "xss"
    )
    print(f"💉 Generated {len(payloads)} adaptive payloads")
    
    print("\n🎉 ML enhancements demonstration complete!")


if __name__ == "__main__":
    asyncio.run(main())
        
        # Evaluate
        y_pred = self.vulnerability_classifier.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        precision = precision_score(y_test, y_pred, average='weighted')
        recall = recall_score(y_test, y_pred, average='weighted')
        
        self.logger.info(f"Vulnerability classifier trained: accuracy={accuracy:.3f}")
        
        return {
            "vulnerability_classifier_accuracy": accuracy,
            "vulnerability_classifier_precision": precision,
            "vulnerability_classifier_recall": recall
        }
    
    async def _train_false_positive_detector(self) -> Dict[str, float]:
        """Train false positive detection model"""
        fp_data = self.training_data["false_positives"]
        
        # Prepare text data
        texts = [item["text"] for item in fp_data]
        labels = [1 if item["is_false_positive"] else 0 for item in fp_data]
        
        # Vectorize text
        X_text = self.vectorizer.fit_transform(texts)
        y = np.array(labels)
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(X_text, y, test_size=0.2, random_state=42)
        
        # Train model
        self.false_positive_detector = RandomForestClassifier(n_estimators=100, random_state=42)
        self.false_positive_detector.fit(X_train, y_train)
        
        # Evaluate
        y_pred = self.false_positive_detector.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        precision = precision_score(y_test, y_pred, average='weighted')
        recall = recall_score(y_test, y_pred, average='weighted')
        
        self.logger.info(f"False positive detector trained: accuracy={accuracy:.3f}")
        
        return {
            "false_positive_detector_accuracy": accuracy,
            "false_positive_detector_precision": precision,
            "false_positive_detector_recall": recall
        }
    
    async def _save_models(self):
        """Save trained models to disk"""
        try:
            if self.vulnerability_classifier:
                with open(self.model_dir / "vulnerability_classifier.pkl", 'wb') as f:
                    pickle.dump(self.vulnerability_classifier, f)
            
            if self.false_positive_detector:
                with open(self.model_dir / "false_positive_detector.pkl", 'wb') as f:
                    pickle.dump(self.false_positive_detector, f)
            
            with open(self.model_dir / "vectorizer.pkl", 'wb') as f:
                pickle.dump(self.vectorizer, f)
            
            # Save training data for future use
            with open(self.model_dir / "training_data.json", 'w') as f:
                json.dump(self.training_data, f, default=str, indent=2)
            
            self.logger.info("✅ Models saved successfully")
            
        except Exception as e:
            self.logger.error(f"Error saving models: {e}")
    
    def predict_vulnerability_validity(self, bug_report: BugReport) -> float:
        """Predict if a vulnerability is valid using ML"""
        if not self.vulnerability_classifier:
            return 0.5  # Default confidence if no model
        
        try:
            features = self._extract_vulnerability_features(bug_report)
            feature_vector = np.array([list(features.values())])
            
            # Get prediction probability
            probability = self.vulnerability_classifier.predict_proba(feature_vector)[0][1]
            return probability
            
        except Exception as e:
            self.logger.error(f"Error predicting vulnerability validity: {e}")
            return 0.5
    
    def predict_false_positive(self, finding_text: str) -> float:
        """Predict if a finding is a false positive"""
        if not self.false_positive_detector:
            return 0.3  # Default false positive probability
        
        try:
            # Vectorize text
            text_vector = self.vectorizer.transform([finding_text])
            
            # Get prediction probability
            probability = self.false_positive_detector.predict_proba(text_vector)[0][1]
            return probability
            
        except Exception as e:
            self.logger.error(f"Error predicting false positive: {e}")
            return 0.3
    
    def generate_smart_payloads(self, target_info: Dict, vulnerability_type: str) -> List[str]:
        """Generate smart payloads based on target characteristics"""
        base_payloads = {
            "xss": [
                "<script>alert('XSS')</script>",
                "'\"><script>alert('XSS')</script>",
                "javascript:alert('XSS')",
                "<img src=x onerror=alert('XSS')>",
                "<svg onload=alert('XSS')>"
            ],
            "sqli": [
                "' OR '1'='1",
                "' UNION SELECT NULL--",
                "'; DROP TABLE users--",
                "' AND (SELECT SUBSTRING(@@version,1,1))='5'--",
                "' OR 1=1#"
            ],
            "ssrf": [
                "http://localhost:80",
                "http://127.0.0.1:22",
                "http://169.254.169.254/",
                "file:///etc/passwd",
                "gopher://127.0.0.1:9000/"
            ]
        }
        
        payloads = base_payloads.get(vulnerability_type.lower(), ["test"])
        
        # Customize payloads based on target characteristics
        if target_info.get("technology") == "php":
            if vulnerability_type.lower() == "sqli":
                payloads.extend(["<?php echo 'test'; ?>", "'; phpinfo()--"])
        
        if target_info.get("framework") == "react":
            if vulnerability_type.lower() == "xss":
                payloads.extend(["{{alert('XSS')}}", "${alert('XSS')}"])
        
        return payloads

class AdaptiveDecisionEngine:
    """Enhanced decision engine with ML-powered optimization"""
    
    def __init__(self, ml_learner: VulnerabilityPatternLearner):
        self.ml_learner = ml_learner
        self.success_history = {}
        self.target_profiles = {}
        self.logger = logging.getLogger('decision_engine')
    
    async def optimize_testing_strategy(self, target: str, current_findings: List[BugReport]) -> Dict:
        """Optimize testing strategy based on ML insights"""
        
        # Analyze current findings with ML
        ml_insights = await self._analyze_findings_with_ml(current_findings)
        
        # Get target profile
        target_profile = self._get_target_profile(target)
        
        # Generate optimized strategy
        strategy = {
            "priority_areas": self._identify_priority_areas(ml_insights, target_profile),
            "recommended_tools": self._recommend_tools(target_profile),
            "payload_suggestions": self._get_payload_suggestions(target_profile, ml_insights),
            "testing_intensity": self._calculate_testing_intensity(target_profile, ml_insights),
            "estimated_completion": self._estimate_completion_time(target_profile, ml_insights)
        }
        
        return strategy
    
    async def _analyze_findings_with_ml(self, findings: List[BugReport]) -> Dict:
        """Analyze findings using ML models"""
        analysis = {
            "high_confidence_findings": [],
            "potential_false_positives": [],
            "vulnerability_patterns": {},
            "success_indicators": []
        }
        
        for finding in findings:
            # Check confidence with ML
            ml_confidence = self.ml_learner.predict_vulnerability_validity(finding)
            fp_probability = self.ml_learner.predict_false_positive(finding.description)
            
            if ml_confidence > 0.8 and fp_probability < 0.2:
                analysis["high_confidence_findings"].append(finding)
            elif fp_probability > 0.7:
                analysis["potential_false_positives"].append(finding)
            
            # Track patterns
            vuln_type = finding.vulnerability_type
            if vuln_type not in analysis["vulnerability_patterns"]:
                analysis["vulnerability_patterns"][vuln_type] = 0
            analysis["vulnerability_patterns"][vuln_type] += 1
        
        return analysis
    
    def _get_target_profile(self, target: str) -> Dict:
        """Get or create target profile with learned characteristics"""
        if target not in self.target_profiles:
            self.target_profiles[target] = {
                "technology_stack": [],
                "common_vulnerabilities": [],
                "response_patterns": {},
                "success_rate": 0.0,
                "last_updated": datetime.now()
            }
        
        return self.target_profiles[target]
    
    def _identify_priority_areas(self, ml_insights: Dict, target_profile: Dict) -> List[str]:
        """Identify priority testing areas based on ML analysis"""
        priority_areas = []
        
        # High success rate areas from target profile
        if target_profile.get("common_vulnerabilities"):
            priority_areas.extend(target_profile["common_vulnerabilities"][:3])
        
        # Areas where ML detected patterns
        patterns = ml_insights.get("vulnerability_patterns", {})
        for vuln_type, count in sorted(patterns.items(), key=lambda x: x[1], reverse=True):
            if vuln_type not in priority_areas:
                priority_areas.append(vuln_type)
        
        # Default priority areas if no patterns
        if not priority_areas:
            priority_areas = ["authentication", "input_validation", "authorization"]
        
        return priority_areas[:5]  # Top 5 priorities
    
    def _recommend_tools(self, target_profile: Dict) -> List[str]:
        """Recommend tools based on target characteristics"""
        tools = ["nuclei", "ffuf"]  # Default tools
        
        # Add tools based on technology stack
        tech_stack = target_profile.get("technology_stack", [])
        if "php" in tech_stack:
            tools.append("sqlmap")
        if "javascript" in tech_stack:
            tools.append("dalfox")
        if "api" in tech_stack:
            tools.extend(["postman", "burp_api"])
        
        return tools
    
    def _get_payload_suggestions(self, target_profile: Dict, ml_insights: Dict) -> Dict:
        """Get ML-optimized payload suggestions"""
        suggestions = {}
        
        for vuln_type in ml_insights.get("vulnerability_patterns", {}):
            payloads = self.ml_learner.generate_smart_payloads(target_profile, vuln_type)
            suggestions[vuln_type] = payloads
        
        return suggestions
    
    def _calculate_testing_intensity(self, target_profile: Dict, ml_insights: Dict) -> str:
        """Calculate optimal testing intensity"""
        success_rate = target_profile.get("success_rate", 0.0)
        high_confidence_count = len(ml_insights.get("high_confidence_findings", []))
        
        if success_rate > 0.7 or high_confidence_count > 5:
            return "high"
        elif success_rate > 0.3 or high_confidence_count > 2:
            return "medium"
        else:
            return "low"
    
    def _estimate_completion_time(self, target_profile: Dict, ml_insights: Dict) -> int:
        """Estimate testing completion time in minutes"""
        base_time = 60  # 1 hour base
        
        # Adjust based on success indicators
        success_rate = target_profile.get("success_rate", 0.0)
        if success_rate > 0.5:
            base_time *= 1.5  # Spend more time on promising targets
        
        # Adjust based on findings
        findings_count = len(ml_insights.get("high_confidence_findings", []))
        base_time += findings_count * 15  # 15 minutes per high-confidence finding
        
        return min(base_time, 300)  # Max 5 hours

# Example usage and integration
async def enhance_autonomous_agent_with_ml():
    """Example of integrating ML enhancements with autonomous agent"""
    
    # Initialize ML components
    ml_learner = VulnerabilityPatternLearner()
    decision_engine = AdaptiveDecisionEngine(ml_learner)
    
    # Simulate adding training data (in real implementation, this would come from actual findings)
    sample_bug_report = BugReport(
        id="test_001",
        title="SQL Injection in login form",
        description="The login form is vulnerable to SQL injection attacks",
        severity=Priority.HIGH,
        cvss_score=8.5,
        target="example.com",
        endpoint="/login",
        vulnerability_type="sqli",
        proof_of_concept="' OR '1'='1",
        impact="Data exposure",
        remediation="Use parameterized queries",
        references=["CWE-89"],
        discovered_at=datetime.now().isoformat(),
        confidence=0.9,
        false_positive_probability=0.1
    )
    
    # Add training data
    ml_learner.add_vulnerability_data(sample_bug_report, is_confirmed=True)
    ml_learner.add_false_positive_data("Potential XSS but filtered", is_false_positive=True)
    
    # Train models (requires sufficient data)
    if len(ml_learner.training_data["vulnerabilities"]) > 10:
        training_results = await ml_learner.train_models()
        print("📊 ML Training Results:", training_results)
    
    # Get optimized strategy
    strategy = await decision_engine.optimize_testing_strategy("example.com", [sample_bug_report])
    print("🎯 Optimized Testing Strategy:", json.dumps(strategy, indent=2, default=str))
    
    return ml_learner, decision_engine

if __name__ == "__main__":
    asyncio.run(enhance_autonomous_agent_with_ml())
