"""
Advanced ML Enhancements for Bug Bounty Framework
Comprehensive machine learning integration with rule-based optimization,
advanced error handling, data validation, and intelligent fallback mechanisms
"""

import asyncio
import json
import logging
import numpy as np
import pandas as pd
import pickle
import traceback
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple, Union, Callable
from dataclasses import dataclass, field
from enum import Enum
import hashlib
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
import yaml
from functools import wraps, lru_cache
import warnings
warnings.filterwarnings('ignore')

# Advanced imports for ML and optimization
try:
    from sklearn.ensemble import RandomForestClassifier, IsolationForest, GradientBoostingClassifier
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.preprocessing import StandardScaler, LabelEncoder
    from sklearn.model_selection import train_test_split, GridSearchCV
    from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
    from sklearn.pipeline import Pipeline
    from sklearn.decomposition import PCA
    from sklearn.cluster import DBSCAN, KMeans
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False
    # Create dummy classes for fallback
    class RandomForestClassifier:
        def __init__(self, **kwargs): pass
        def fit(self, X, y): return self
        def predict_proba(self, X): return [[0.5, 0.5]]
        def predict(self, X): return [0]
    
    class IsolationForest:
        def __init__(self, **kwargs): pass
        def fit(self, X): return self
        def predict(self, X): return [-1]
        def decision_function(self, X): return [-0.1]
    
    class TfidfVectorizer:
        def __init__(self, **kwargs): pass
        def fit_transform(self, X): return [[0.0]]
    
    logging.warning("Advanced ML libraries not available. Using fallback implementations.")

class MLErrorType(Enum):
    """Classification of ML-related errors"""
    DATA_VALIDATION = "data_validation"
    MODEL_LOADING = "model_loading"
    FEATURE_EXTRACTION = "feature_extraction"
    PREDICTION = "prediction"
    TRAINING = "training"
    MEMORY = "memory"
    TIMEOUT = "timeout"
    UNKNOWN = "unknown"

class ConfidenceLevel(Enum):
    """Confidence levels for predictions"""
    VERY_HIGH = 0.95
    HIGH = 0.85
    MEDIUM = 0.70
    LOW = 0.55
    VERY_LOW = 0.40

@dataclass
class MLMetrics:
    """Comprehensive metrics for ML model performance"""
    accuracy: float = 0.0
    precision: float = 0.0
    recall: float = 0.0
    f1_score: float = 0.0
    auc_score: float = 0.0
    processing_time: float = 0.0
    memory_usage: float = 0.0
    confidence: float = 0.0
    error_rate: float = 0.0
    false_positive_rate: float = 0.0
    sample_count: int = 0
    
class RuleEngine:
    """Advanced rule-based decision engine with optimization"""
    
    def __init__(self):
        self.rules: Dict[str, Dict] = {}
        self.rule_cache: Dict[str, Any] = {}
        self.rule_stats: Dict[str, Dict] = {}
        self.optimization_enabled = True
        
    def add_rule(self, name: str, condition: Callable, action: Callable, 
                 priority: int = 1, enabled: bool = True, 
                 cache_duration: int = 300) -> None:
        """Add optimized rule with caching and statistics"""
        self.rules[name] = {
            'condition': condition,
            'action': action,
            'priority': priority,
            'enabled': enabled,
            'cache_duration': cache_duration,
            'created_at': datetime.now(),
            'execution_count': 0,
            'success_count': 0,
            'failure_count': 0,
            'avg_execution_time': 0.0
        }
        self.rule_stats[name] = {
            'last_execution': None,
            'execution_times': [],
            'results': []
        }
    
    def execute_rules(self, data: Any, context: Optional[Dict] = None) -> List[Dict]:
        """Execute rules with optimization and error handling"""
        results = []
        context = context or {}
        
        # Sort rules by priority and success rate
        sorted_rules = sorted(
            [(name, rule) for name, rule in self.rules.items() if rule['enabled']],
            key=lambda x: (x[1]['priority'], x[1]['success_count'] / max(x[1]['execution_count'], 1)),
            reverse=True
        )
        
        for rule_name, rule in sorted_rules:
            try:
                start_time = time.time()
                
                # Check cache first
                cache_key = self._get_cache_key(rule_name, data)
                if cache_key in self.rule_cache:
                    cached_result = self.rule_cache[cache_key]
                    if time.time() - cached_result['timestamp'] < rule['cache_duration']:
                        results.append(cached_result['result'])
                        continue
                
                # Execute rule condition
                if rule['condition'](data, context):
                    action_result = rule['action'](data, context)
                    
                    execution_time = time.time() - start_time
                    self._update_rule_stats(rule_name, True, execution_time)
                    
                    result = {
                        'rule': rule_name,
                        'result': action_result,
                        'execution_time': execution_time,
                        'confidence': getattr(action_result, 'confidence', 1.0)
                    }
                    
                    # Cache result
                    self.rule_cache[cache_key] = {
                        'result': result,
                        'timestamp': time.time()
                    }
                    
                    results.append(result)
                else:
                    execution_time = time.time() - start_time
                    self._update_rule_stats(rule_name, False, execution_time)
                    
            except Exception as e:
                execution_time = time.time() - start_time
                self._update_rule_stats(rule_name, False, execution_time)
                logging.error(f"Rule execution error for {rule_name}: {e}")
                
        return results
    
    def _get_cache_key(self, rule_name: str, data: Any) -> str:
        """Generate cache key for rule and data combination"""
        data_hash = hashlib.md5(str(data).encode()).hexdigest()
        return f"{rule_name}_{data_hash}"
    
    def _update_rule_stats(self, rule_name: str, success: bool, execution_time: float):
        """Update rule execution statistics"""
        rule = self.rules[rule_name]
        stats = self.rule_stats[rule_name]
        
        rule['execution_count'] += 1
        if success:
            rule['success_count'] += 1
        else:
            rule['failure_count'] += 1
            
        # Update average execution time
        times = stats['execution_times']
        times.append(execution_time)
        if len(times) > 100:  # Keep only recent 100 executions
            times.pop(0)
        rule['avg_execution_time'] = sum(times) / len(times)
        
        stats['last_execution'] = datetime.now()

class AdvancedDataHandler:
    """Enhanced data handling with validation, cleaning, and optimization"""
    
    def __init__(self):
        self.validators: Dict[str, Callable] = {}
        self.cleaners: Dict[str, Callable] = {}
        self.transformers: Dict[str, Callable] = {}
        self.cache = {}
        self.validation_stats = {}
        
    def register_validator(self, data_type: str, validator: Callable):
        """Register data validator for specific type"""
        self.validators[data_type] = validator
        self.validation_stats[data_type] = {
            'total_validations': 0,
            'successful_validations': 0,
            'failed_validations': 0
        }
    
    def register_cleaner(self, data_type: str, cleaner: Callable):
        """Register data cleaner for specific type"""
        self.cleaners[data_type] = cleaner
    
    def register_transformer(self, data_type: str, transformer: Callable):
        """Register data transformer for specific type"""
        self.transformers[data_type] = transformer
    
    def process_data(self, data: Any, data_type: str, 
                    validate: bool = True, clean: bool = True, 
                    transform: bool = False) -> Tuple[Any, Dict]:
        """Process data with validation, cleaning, and transformation"""
        processing_info = {
            'original_size': len(str(data)),
            'validation_passed': False,
            'cleaning_applied': False,
            'transformation_applied': False,
            'errors': [],
            'warnings': []
        }
        
        try:
            # Validation
            if validate and data_type in self.validators:
                validation_result = self.validators[data_type](data)
                self.validation_stats[data_type]['total_validations'] += 1
                
                if validation_result.get('valid', False):
                    processing_info['validation_passed'] = True
                    self.validation_stats[data_type]['successful_validations'] += 1
                else:
                    self.validation_stats[data_type]['failed_validations'] += 1
                    processing_info['errors'].extend(validation_result.get('errors', []))
                    if not validation_result.get('can_proceed', False):
                        return data, processing_info
            
            # Cleaning
            if clean and data_type in self.cleaners:
                cleaned_data = self.cleaners[data_type](data)
                if cleaned_data != data:
                    processing_info['cleaning_applied'] = True
                    data = cleaned_data
            
            # Transformation
            if transform and data_type in self.transformers:
                transformed_data = self.transformers[data_type](data)
                if transformed_data != data:
                    processing_info['transformation_applied'] = True
                    data = transformed_data
                    
            processing_info['final_size'] = len(str(data))
            return data, processing_info
            
        except Exception as e:
            processing_info['errors'].append(f"Processing error: {str(e)}")
            return data, processing_info

class FallbackManager:
    """Advanced fallback mechanism manager"""
    
    def __init__(self):
        self.fallback_chains: Dict[str, List[Callable]] = {}
        self.fallback_stats: Dict[str, Dict] = {}
        self.circuit_breakers: Dict[str, Dict] = {}
        
    def register_fallback_chain(self, operation_name: str, fallbacks: List[Callable]):
        """Register fallback chain for operation"""
        self.fallback_chains[operation_name] = fallbacks
        self.fallback_stats[operation_name] = {
            'primary_successes': 0,
            'primary_failures': 0,
            'fallback_usages': [0] * len(fallbacks),
            'total_failures': 0
        }
        self.circuit_breakers[operation_name] = {
            'state': 'closed',  # closed, open, half-open
            'failure_count': 0,
            'last_failure_time': None,
            'failure_threshold': 5,
            'recovery_timeout': 60
        }
    
    async def execute_with_fallback(self, operation_name: str, primary_func: Callable, 
                                  *args, **kwargs) -> Tuple[Any, Dict]:
        """Execute operation with intelligent fallback"""
        execution_info = {
            'primary_attempted': False,
            'fallback_level': -1,
            'total_attempts': 0,
            'errors': [],
            'execution_time': 0
        }
        
        start_time = time.time()
        
        try:
            # Check circuit breaker
            if self._is_circuit_open(operation_name):
                execution_info['errors'].append("Circuit breaker open, skipping primary")
            else:
                # Try primary operation
                execution_info['primary_attempted'] = True
                execution_info['total_attempts'] = 1
                
                try:
                    result = await self._safe_execute(primary_func, *args, **kwargs)
                    self.fallback_stats[operation_name]['primary_successes'] += 1
                    self._reset_circuit_breaker(operation_name)
                    execution_info['execution_time'] = time.time() - start_time
                    return result, execution_info
                    
                except Exception as e:
                    self.fallback_stats[operation_name]['primary_failures'] += 1
                    self._update_circuit_breaker(operation_name)
                    execution_info['errors'].append(f"Primary failed: {str(e)}")
            
            # Execute fallback chain
            if operation_name in self.fallback_chains:
                for i, fallback_func in enumerate(self.fallback_chains[operation_name]):
                    execution_info['total_attempts'] += 1
                    execution_info['fallback_level'] = i
                    
                    try:
                        result = await self._safe_execute(fallback_func, *args, **kwargs)
                        self.fallback_stats[operation_name]['fallback_usages'][i] += 1
                        execution_info['execution_time'] = time.time() - start_time
                        return result, execution_info
                        
                    except Exception as e:
                        execution_info['errors'].append(f"Fallback {i} failed: {str(e)}")
                        continue
            
            # All fallbacks failed
            self.fallback_stats[operation_name]['total_failures'] += 1
            execution_info['execution_time'] = time.time() - start_time
            raise Exception(f"All fallbacks failed for {operation_name}")
            
        except Exception as e:
            execution_info['execution_time'] = time.time() - start_time
            execution_info['errors'].append(f"Fallback execution error: {str(e)}")
            raise
    
    async def _safe_execute(self, func: Callable, *args, **kwargs):
        """Safely execute function with timeout"""
        if asyncio.iscoroutinefunction(func):
            return await asyncio.wait_for(func(*args, **kwargs), timeout=30)
        else:
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(None, func, *args, **kwargs)
    
    def _is_circuit_open(self, operation_name: str) -> bool:
        """Check if circuit breaker is open"""
        breaker = self.circuit_breakers[operation_name]
        
        if breaker['state'] == 'open':
            if (time.time() - breaker['last_failure_time']) > breaker['recovery_timeout']:
                breaker['state'] = 'half-open'
                return False
            return True
        return False
    
    def _update_circuit_breaker(self, operation_name: str):
        """Update circuit breaker on failure"""
        breaker = self.circuit_breakers[operation_name]
        breaker['failure_count'] += 1
        breaker['last_failure_time'] = time.time()
        
        if breaker['failure_count'] >= breaker['failure_threshold']:
            breaker['state'] = 'open'
    
    def _reset_circuit_breaker(self, operation_name: str):
        """Reset circuit breaker on success"""
        breaker = self.circuit_breakers[operation_name]
        breaker['failure_count'] = 0
        breaker['state'] = 'closed'

class OptimizedMLEnhancer:
    """Advanced ML enhancer with comprehensive optimization and error handling"""
    
    def __init__(self):
        self.models: Dict[str, Any] = {}
        self.feature_extractors: Dict[str, Any] = {}
        self.data_handler = AdvancedDataHandler()
        self.rule_engine = RuleEngine()
        self.fallback_manager = FallbackManager()
        self.model_cache: Dict[str, Any] = {}
        self.performance_metrics: Dict[str, MLMetrics] = {}
        
        # Setup logging
        self.logger = logging.getLogger('ml_enhancer')
        self.logger.setLevel(logging.INFO)
        
        # Initialize components
        self._initialize_validators()
        self._initialize_rules()
        self._initialize_fallbacks()
        self._load_pretrained_models()
    
    def _initialize_validators(self):
        """Initialize data validators"""
        
        def validate_vulnerability_data(data):
            """Validate vulnerability data structure"""
            required_fields = ['url', 'method', 'description']
            errors = []
            
            if not isinstance(data, dict):
                errors.append("Data must be a dictionary")
                return {'valid': False, 'errors': errors, 'can_proceed': False}
            
            for field in required_fields:
                if field not in data:
                    errors.append(f"Missing required field: {field}")
            
            if 'url' in data and not isinstance(data['url'], str):
                errors.append("URL must be a string")
            
            return {
                'valid': len(errors) == 0,
                'errors': errors,
                'can_proceed': len(errors) < len(required_fields)
            }
        
        def validate_network_data(data):
            """Validate network scanning data"""
            errors = []
            
            if not isinstance(data, (dict, list)):
                errors.append("Network data must be dict or list")
                return {'valid': False, 'errors': errors, 'can_proceed': False}
            
            return {'valid': True, 'errors': [], 'can_proceed': True}
        
        self.data_handler.register_validator('vulnerability', validate_vulnerability_data)
        self.data_handler.register_validator('network', validate_network_data)
    
    def _initialize_rules(self):
        """Initialize rule-based decision engine"""
        
        # High-priority vulnerability detection rule
        def is_high_severity(data, context):
            """Check if vulnerability is high severity"""
            if isinstance(data, dict):
                severity_indicators = ['sqli', 'xss', 'rce', 'lfi', 'rfi', 'xxe']
                description = data.get('description', '').lower()
                return any(indicator in description for indicator in severity_indicators)
            return False
        
        def prioritize_vulnerability(data, context):
            """Prioritize high-severity vulnerability"""
            return {
                'priority': 'high',
                'immediate_action': True,
                'confidence': 0.9
            }
        
        # False positive detection rule
        def is_likely_false_positive(data, context):
            """Detect likely false positives"""
            if isinstance(data, dict):
                fp_indicators = ['test', 'example', 'demo', 'placeholder']
                url = data.get('url', '').lower()
                return any(indicator in url for indicator in fp_indicators)
            return False
        
        def mark_false_positive(data, context):
            """Mark as potential false positive"""
            return {
                'false_positive_probability': 0.8,
                'requires_manual_review': True,
                'confidence': 0.7
            }
        
        self.rule_engine.add_rule('high_severity_detection', is_high_severity, 
                                prioritize_vulnerability, priority=10)
        self.rule_engine.add_rule('false_positive_detection', is_likely_false_positive, 
                                mark_false_positive, priority=8)
    
    def _initialize_fallbacks(self):
        """Initialize fallback mechanisms"""
        
        # Primary ML prediction function
        async def ml_predict_primary(data):
            """Primary ML prediction using advanced models"""
            if not ML_AVAILABLE:
                raise Exception("Advanced ML libraries not available")
            
            # Simulate ML prediction with actual logic
            features = self._extract_features(data)
            if 'vulnerability_classifier' in self.models:
                model = self.models['vulnerability_classifier']
                prediction = model.predict_proba([features])[0]
                return {
                    'prediction': prediction[1] if len(prediction) > 1 else prediction[0],
                    'confidence': max(prediction),
                    'method': 'advanced_ml'
                }
            raise Exception("ML model not available")
        
        # Rule-based fallback
        async def rule_based_fallback(data):
            """Rule-based prediction fallback"""
            rules_result = self.rule_engine.execute_rules(data)
            if rules_result:
                avg_confidence = sum(r.get('confidence', 0.5) for r in rules_result) / len(rules_result)
                return {
                    'prediction': avg_confidence,
                    'confidence': avg_confidence,
                    'method': 'rule_based'
                }
            return {
                'prediction': 0.5,
                'confidence': 0.3,
                'method': 'rule_based_default'
            }
        
        # Heuristic fallback
        async def heuristic_fallback(data):
            """Simple heuristic fallback"""
            if isinstance(data, dict):
                score = 0.5
                if 'severity' in data:
                    severity_map = {'critical': 0.95, 'high': 0.8, 'medium': 0.6, 'low': 0.3}
                    score = severity_map.get(data['severity'].lower(), 0.5)
                return {
                    'prediction': score,
                    'confidence': 0.6,
                    'method': 'heuristic'
                }
            return {
                'prediction': 0.4,
                'confidence': 0.2,
                'method': 'heuristic_default'
            }
        
        self.fallback_manager.register_fallback_chain(
            'vulnerability_prediction',
            [rule_based_fallback, heuristic_fallback]
        )
    
    def _load_pretrained_models(self):
        """Load or create pretrained ML models"""
        try:
            if ML_AVAILABLE:
                # Create a simple vulnerability classifier
                self.models['vulnerability_classifier'] = self._create_vulnerability_classifier()
                self.models['anomaly_detector'] = self._create_anomaly_detector()
                self.feature_extractors['text'] = TfidfVectorizer(max_features=1000, stop_words='english')
                self.logger.info("✅ ML models loaded successfully")
            else:
                self.logger.warning("⚠️  Using fallback implementations due to missing ML libraries")
        except Exception as e:
            self.logger.error(f"❌ Error loading ML models: {e}")
    
    def _create_vulnerability_classifier(self):
        """Create vulnerability classification model"""
        if not ML_AVAILABLE:
            return None
        
        # Create a simple model for demonstration
        # In production, this would be trained on real vulnerability data
        model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42,
            n_jobs=-1
        )
        
        # Create dummy training data for initialization
        X_dummy = np.random.rand(100, 10)
        y_dummy = np.random.randint(0, 2, 100)
        model.fit(X_dummy, y_dummy)
        
        return model
    
    def _create_anomaly_detector(self):
        """Create anomaly detection model"""
        if not ML_AVAILABLE:
            return None
        
        return IsolationForest(
            contamination=0.1,
            random_state=42,
            n_jobs=-1
        )
    
    def _extract_features(self, data: Dict) -> List[float]:
        """Extract features from vulnerability data"""
        features = []
        
        try:
            # Basic features
            features.append(len(data.get('description', '')))
            features.append(len(data.get('url', '')))
            features.append(1 if data.get('method', '').upper() == 'POST' else 0)
            
            # Severity indicators
            severity_keywords = ['critical', 'high', 'medium', 'low']
            desc_lower = data.get('description', '').lower()
            for keyword in severity_keywords:
                features.append(1 if keyword in desc_lower else 0)
            
            # Vulnerability type indicators
            vuln_types = ['sqli', 'xss', 'csrf', 'lfi', 'rfi']
            for vuln_type in vuln_types:
                features.append(1 if vuln_type in desc_lower else 0)
            
            # Ensure we have exactly 10 features for the dummy model
            while len(features) < 10:
                features.append(0.0)
            
            return features[:10]
        
        except Exception as e:
            self.logger.error(f"Feature extraction error: {e}")
            return [0.0] * 10
    
    async def analyze_vulnerability(self, vulnerability_data: Dict) -> Dict:
        """Comprehensive vulnerability analysis with optimization"""
        start_time = time.time()
        
        try:
            # Validate and process data
            processed_data, processing_info = self.data_handler.process_data(
                vulnerability_data, 'vulnerability', validate=True, clean=True
            )
            
            if not processing_info['validation_passed']:
                return {
                    'error': 'Data validation failed',
                    'details': processing_info['errors'],
                    'confidence': 0.0
                }
            
            # Execute ML prediction with fallback
            prediction_result, execution_info = await self.fallback_manager.execute_with_fallback(
                'vulnerability_prediction',
                self._ml_predict_vulnerability,
                processed_data
            )
            
            # Apply rule-based enhancements
            rule_results = self.rule_engine.execute_rules(processed_data)
            
            # Combine results
            final_confidence = prediction_result.get('confidence', 0.5)
            if rule_results:
                rule_confidence = sum(r.get('confidence', 0.5) for r in rule_results) / len(rule_results)
                final_confidence = (final_confidence + rule_confidence) / 2
            
            # Calculate metrics
            processing_time = time.time() - start_time
            
            result = {
                'vulnerability_score': prediction_result.get('prediction', 0.5),
                'confidence': final_confidence,
                'method': prediction_result.get('method', 'unknown'),
                'rule_enhancements': rule_results,
                'processing_info': processing_info,
                'execution_info': execution_info,
                'processing_time': processing_time,
                'timestamp': datetime.now().isoformat()
            }
            
            # Update performance metrics
            self._update_metrics('vulnerability_analysis', result)
            
            return result
            
        except Exception as e:
            self.logger.error(f"Vulnerability analysis error: {e}")
            return {
                'error': str(e),
                'confidence': 0.0,
                'processing_time': time.time() - start_time,
                'timestamp': datetime.now().isoformat()
            }
    
    async def _ml_predict_vulnerability(self, data: Dict) -> Dict:
        """Primary ML vulnerability prediction"""
        if not ML_AVAILABLE or 'vulnerability_classifier' not in self.models:
            raise Exception("ML model not available")
        
        features = self._extract_features(data)
        model = self.models['vulnerability_classifier']
        
        prediction_proba = model.predict_proba([features])[0]
        prediction = prediction_proba[1] if len(prediction_proba) > 1 else prediction_proba[0]
        
        return {
            'prediction': float(prediction),
            'confidence': float(max(prediction_proba)),
            'method': 'advanced_ml'
        }
    
    def _update_metrics(self, operation: str, result: Dict):
        """Update performance metrics"""
        if operation not in self.performance_metrics:
            self.performance_metrics[operation] = MLMetrics()
        
        metrics = self.performance_metrics[operation]
        metrics.processing_time = result.get('processing_time', 0.0)
        metrics.confidence = result.get('confidence', 0.0)
        
        # Update averages (simple running average for demo)
        if metrics.sample_count > 0:
            metrics.sample_count += 1
        else:
            metrics.sample_count = 1
    
    async def detect_anomalies(self, network_data: List[Dict]) -> Dict:
        """Advanced anomaly detection with fallback"""
        try:
            # Validate data
            processed_data, processing_info = self.data_handler.process_data(
                network_data, 'network', validate=True
            )
            
            if not processing_info['validation_passed']:
                return {
                    'anomalies': [],
                    'error': 'Data validation failed',
                    'details': processing_info['errors']
                }
            
            # Use ML model if available
            if ML_AVAILABLE and 'anomaly_detector' in self.models:
                features_matrix = self._extract_network_features(processed_data)
                model = self.models['anomaly_detector']
                
                anomaly_scores = model.decision_function(features_matrix)
                predictions = model.predict(features_matrix)
                
                anomalies = []
                for i, (score, prediction) in enumerate(zip(anomaly_scores, predictions)):
                    if prediction == -1:  # Anomaly detected
                        anomalies.append({
                            'index': i,
                            'data': processed_data[i] if i < len(processed_data) else None,
                            'anomaly_score': float(score),
                            'confidence': abs(float(score))
                        })
                
                return {
                    'anomalies': anomalies,
                    'total_analyzed': len(processed_data),
                    'method': 'isolation_forest'
                }
            
            else:
                # Fallback to rule-based anomaly detection
                return await self._rule_based_anomaly_detection(processed_data)
                
        except Exception as e:
            self.logger.error(f"Anomaly detection error: {e}")
            return {
                'anomalies': [],
                'error': str(e),
                'method': 'error_fallback'
            }
    
    def _extract_network_features(self, network_data: List[Dict]) -> np.ndarray:
        """Extract features from network data"""
        if not ML_AVAILABLE:
            return np.array([])
        
        features_list = []
        
        for item in network_data:
            features = []
            
            # Basic features
            features.append(item.get('port', 0))
            features.append(len(item.get('service', '')))
            features.append(1 if item.get('state', '').lower() == 'open' else 0)
            features.append(item.get('response_time', 0))
            
            # Service type features
            common_services = ['http', 'https', 'ssh', 'ftp', 'smtp']
            service = item.get('service', '').lower()
            for svc in common_services:
                features.append(1 if svc in service else 0)
            
            features_list.append(features)
        
        return np.array(features_list) if features_list else np.array([]).reshape(0, -1)
    
    async def _rule_based_anomaly_detection(self, data: List[Dict]) -> Dict:
        """Fallback rule-based anomaly detection"""
        anomalies = []
        
        for i, item in enumerate(data):
            anomaly_score = 0
            reasons = []
            
            # Check for unusual ports
            port = item.get('port', 0)
            if port > 50000:
                anomaly_score += 0.3
                reasons.append('Unusual high port number')
            
            # Check for suspicious services
            service = item.get('service', '').lower()
            suspicious_services = ['backdoor', 'trojan', 'malware']
            if any(sus in service for sus in suspicious_services):
                anomaly_score += 0.8
                reasons.append('Suspicious service detected')
            
            # Check response times
            response_time = item.get('response_time', 0)
            if response_time > 10:
                anomaly_score += 0.2
                reasons.append('Slow response time')
            
            if anomaly_score > 0.5:
                anomalies.append({
                    'index': i,
                    'data': item,
                    'anomaly_score': anomaly_score,
                    'confidence': min(anomaly_score, 1.0),
                    'reasons': reasons
                })
        
        return {
            'anomalies': anomalies,
            'total_analyzed': len(data),
            'method': 'rule_based'
        }
    
    def get_system_stats(self) -> Dict:
        """Get comprehensive system statistics"""
        return {
            'model_stats': {
                'available_models': list(self.models.keys()),
                'ml_available': ML_AVAILABLE,
                'cache_size': len(self.model_cache)
            },
            'rule_engine_stats': {
                'total_rules': len(self.rule_engine.rules),
                'enabled_rules': sum(1 for r in self.rule_engine.rules.values() if r['enabled']),
                'cache_size': len(self.rule_engine.rule_cache)
            },
            'fallback_stats': dict(self.fallback_manager.fallback_stats),
            'circuit_breaker_states': {
                name: breaker['state'] 
                for name, breaker in self.fallback_manager.circuit_breakers.items()
            },
            'performance_metrics': {
                name: {
                    'processing_time': metrics.processing_time,
                    'confidence': metrics.confidence,
                    'sample_count': getattr(metrics, 'sample_count', 0)
                } 
                for name, metrics in self.performance_metrics.items()
            },
            'validation_stats': dict(self.data_handler.validation_stats)
        }

# Global instance for easy access
ml_enhancer = OptimizedMLEnhancer()

# Utility functions for backward compatibility
async def analyze_vulnerability(vulnerability_data: Dict) -> Dict:
    """Analyze vulnerability with ML enhancements"""
    return await ml_enhancer.analyze_vulnerability(vulnerability_data)

async def detect_anomalies(network_data: List[Dict]) -> Dict:
    """Detect anomalies in network data"""
    return await ml_enhancer.detect_anomalies(network_data)

def get_ml_stats() -> Dict:
    """Get ML system statistics"""
    return ml_enhancer.get_system_stats()

if __name__ == "__main__":
    # Demo functionality
    async def demo():
        print("🚀 ML Enhancements Demo")
        print("=" * 40)
        
        # Test vulnerability analysis
        test_vuln = {
            'url': 'https://example.com/admin',
            'method': 'POST',
            'description': 'SQL injection vulnerability in login form',
            'severity': 'high'
        }
        
        result = await analyze_vulnerability(test_vuln)
        print(f"Vulnerability Analysis Result: {json.dumps(result, indent=2)}")
        
        # Test anomaly detection
        test_network = [
            {'port': 80, 'service': 'http', 'state': 'open', 'response_time': 0.1},
            {'port': 65535, 'service': 'backdoor', 'state': 'open', 'response_time': 15.0},
            {'port': 443, 'service': 'https', 'state': 'open', 'response_time': 0.2}
        ]
        
        anomaly_result = await detect_anomalies(test_network)
        print(f"Anomaly Detection Result: {json.dumps(anomaly_result, indent=2)}")
        
        # Show system stats
        stats = get_ml_stats()
        print(f"System Statistics: {json.dumps(stats, indent=2)}")
    
    asyncio.run(demo())
