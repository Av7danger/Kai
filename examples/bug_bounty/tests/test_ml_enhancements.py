"""
Unit Tests for ML Enhancements Module
Testing ML capabilities, rule engine, data handling, and fallback mechanisms
"""

import pytest
import asyncio
from unittest.mock import Mock, AsyncMock, patch
from ml_enhancements import OptimizedMLEnhancer, RuleEngine, DataHandler, FallbackManager

class TestOptimizedMLEnhancer:
    """Test cases for the ML Enhancement system"""
    
    @pytest.mark.asyncio
    async def test_ml_enhancer_initialization(self):
        """Test ML enhancer initialization"""
        enhancer = OptimizedMLEnhancer()
        
        assert enhancer is not None
        assert hasattr(enhancer, 'rule_engine')
        assert hasattr(enhancer, 'data_handler')
        assert hasattr(enhancer, 'fallback_manager')
    
    @pytest.mark.asyncio
    async def test_vulnerability_analysis(self):
        """Test vulnerability analysis with ML enhancement"""
        enhancer = OptimizedMLEnhancer()
        
        vulnerability_data = {
            'url': 'https://demo.testfire.net/login.php',
            'method': 'POST',
            'description': 'SQL injection in login form',
            'parameters': ['username', 'password']
        }
        
        result = await enhancer.analyze_vulnerability(vulnerability_data)
        
        assert 'confidence' in result
        assert 'classification' in result
        assert 'risk_score' in result
        assert result['confidence'] >= 0.0
        assert result['confidence'] <= 1.0
    
    @pytest.mark.asyncio
    async def test_anomaly_detection(self):
        """Test anomaly detection capabilities"""
        enhancer = OptimizedMLEnhancer()
        
        # Normal request pattern
        normal_pattern = {
            'request_frequency': 10,
            'response_time': 200,
            'status_codes': [200, 301, 404],
            'user_agents': ['Mozilla/5.0', 'Chrome/96.0']
        }
        
        # Anomalous pattern
        anomaly_pattern = {
            'request_frequency': 1000,  # Very high frequency
            'response_time': 5000,      # Very slow response
            'status_codes': [500, 503], # Error codes
            'user_agents': ['sqlmap']   # Scanner user agent
        }
        
        normal_result = await enhancer.detect_anomaly(normal_pattern)
        anomaly_result = await enhancer.detect_anomaly(anomaly_pattern)
        
        assert normal_result['is_anomaly'] is False
        assert anomaly_result['is_anomaly'] is True
        assert anomaly_result['anomaly_score'] > normal_result['anomaly_score']
    
    @pytest.mark.asyncio
    async def test_false_positive_reduction(self):
        """Test false positive reduction mechanism"""
        enhancer = OptimizedMLEnhancer()
        
        # High confidence finding
        high_confidence_vuln = {
            'type': 'SQL Injection',
            'endpoint': 'https://demo.testfire.net/login.php',
            'payload': "' OR 1=1--",
            'response_indicators': ['MySQL error', 'database connection']
        }
        
        # Potential false positive
        false_positive_vuln = {
            'type': 'SQL Injection',
            'endpoint': 'https://demo.testfire.net/test.html',
            'payload': "' OR 1=1--",
            'response_indicators': ['test', 'demo', 'example']
        }
        
        high_conf_result = await enhancer.reduce_false_positives(high_confidence_vuln)
        false_pos_result = await enhancer.reduce_false_positives(false_positive_vuln)
        
        assert high_conf_result['confidence'] > false_pos_result['confidence']
        assert false_pos_result['false_positive_probability'] > 0.5
    
    @pytest.mark.ml
    @pytest.mark.asyncio
    async def test_ml_model_training_simulation(self):
        """Test ML model training simulation"""
        enhancer = OptimizedMLEnhancer()
        
        training_data = [
            {'features': [1, 0, 1, 0], 'label': 'vulnerable'},
            {'features': [0, 1, 0, 1], 'label': 'safe'},
            {'features': [1, 1, 0, 0], 'label': 'vulnerable'},
            {'features': [0, 0, 1, 1], 'label': 'safe'}
        ]
        
        result = await enhancer.train_model(training_data)
        
        assert result['training_completed'] is True
        assert 'model_accuracy' in result
        assert result['model_accuracy'] > 0.5

class TestRuleEngine:
    """Test cases for the Rule Engine"""
    
    def test_rule_engine_initialization(self):
        """Test rule engine initialization"""
        engine = RuleEngine()
        
        assert engine is not None
        assert hasattr(engine, 'rules')
        assert hasattr(engine, 'rule_cache')
    
    @pytest.mark.asyncio
    async def test_rule_execution(self):
        """Test rule execution with caching"""
        engine = RuleEngine()
        
        # Define a test rule
        test_rule = {
            'name': 'high_value_endpoint',
            'condition': lambda data: 'admin' in data.get('url', '').lower(),
            'action': lambda data: {'priority': 'high', 'score': 0.9}
        }
        
        engine.add_rule(test_rule)
        
        # Test data that should match the rule
        test_data = {'url': 'https://example.com/admin/login'}
        result = await engine.execute_rules(test_data)
        
        assert len(result) > 0
        assert result[0]['priority'] == 'high'
        assert result[0]['score'] == 0.9
    
    @pytest.mark.asyncio
    async def test_rule_performance_tracking(self):
        """Test rule performance tracking"""
        engine = RuleEngine()
        
        # Add multiple rules
        for i in range(5):
            rule = {
                'name': f'test_rule_{i}',
                'condition': lambda data, i=i: data.get('id', 0) == i,
                'action': lambda data, i=i: {'matched_rule': i}
            }
            engine.add_rule(rule)
        
        # Execute rules multiple times
        for i in range(10):
            test_data = {'id': i % 5}
            await engine.execute_rules(test_data)
        
        stats = engine.get_performance_stats()
        
        assert 'total_executions' in stats
        assert 'average_execution_time' in stats
        assert stats['total_executions'] == 10
    
    def test_rule_caching(self):
        """Test rule result caching"""
        engine = RuleEngine()
        
        # Add a rule
        test_rule = {
            'name': 'cache_test',
            'condition': lambda data: True,
            'action': lambda data: {'cached': True}
        }
        engine.add_rule(test_rule)
        
        # First execution (should cache)
        test_data = {'test': 'data'}
        result1 = asyncio.run(engine.execute_rules(test_data))
        
        # Second execution (should use cache)
        result2 = asyncio.run(engine.execute_rules(test_data))
        
        assert result1 == result2
        assert engine.rule_cache.get(str(test_data)) is not None

class TestDataHandler:
    """Test cases for the Data Handler"""
    
    def test_data_handler_initialization(self):
        """Test data handler initialization"""
        handler = DataHandler()
        
        assert handler is not None
        assert hasattr(handler, 'validation_rules')
        assert hasattr(handler, 'processing_stats')
    
    @pytest.mark.asyncio
    async def test_data_validation(self):
        """Test data validation pipeline"""
        handler = DataHandler()
        
        # Valid data
        valid_data = {
            'url': 'https://example.com',
            'method': 'GET',
            'status_code': 200,
            'response_time': 150
        }
        
        # Invalid data
        invalid_data = {
            'url': 'not-a-url',
            'method': 'INVALID',
            'status_code': 'not-a-number'
        }
        
        valid_result = await handler.validate_data(valid_data)
        invalid_result = await handler.validate_data(invalid_data)
        
        assert valid_result['is_valid'] is True
        assert invalid_result['is_valid'] is False
        assert len(invalid_result['errors']) > 0
    
    @pytest.mark.asyncio
    async def test_data_cleaning(self):
        """Test data cleaning and transformation"""
        handler = DataHandler()
        
        dirty_data = {
            'url': '  HTTPS://EXAMPLE.COM/PATH  ',
            'headers': {'Content-Type': 'text/html; charset=utf-8'},
            'response': '<html><body>Test</body></html>',
            'extra_field': None
        }
        
        cleaned_data = await handler.clean_data(dirty_data)
        
        assert cleaned_data['url'] == 'https://example.com/path'
        assert 'extra_field' not in cleaned_data
        assert isinstance(cleaned_data['headers'], dict)
    
    @pytest.mark.asyncio
    async def test_feature_extraction(self):
        """Test feature extraction for ML"""
        handler = DataHandler()
        
        raw_data = {
            'url': 'https://example.com/admin/login.php',
            'method': 'POST',
            'parameters': ['username', 'password'],
            'headers': {'Content-Type': 'application/x-www-form-urlencoded'},
            'response_size': 1024,
            'response_time': 200
        }
        
        features = await handler.extract_features(raw_data)
        
        assert 'url_features' in features
        assert 'method_features' in features
        assert 'parameter_features' in features
        assert isinstance(features['url_features']['has_admin'], bool)
        assert isinstance(features['parameter_features']['param_count'], int)
    
    @pytest.mark.asyncio
    async def test_batch_processing(self):
        """Test batch data processing"""
        handler = DataHandler()
        
        batch_data = []
        for i in range(100):
            batch_data.append({
                'id': i,
                'url': f'https://test{i}.example.com',
                'method': 'GET'
            })
        
        processed_batch = await handler.process_batch(batch_data)
        
        assert len(processed_batch) == 100
        assert all('processed' in item for item in processed_batch)

class TestFallbackManager:
    """Test cases for the Fallback Manager"""
    
    def test_fallback_manager_initialization(self):
        """Test fallback manager initialization"""
        manager = FallbackManager()
        
        assert manager is not None
        assert hasattr(manager, 'circuit_breakers')
        assert hasattr(manager, 'fallback_chains')
    
    @pytest.mark.asyncio
    async def test_circuit_breaker_pattern(self):
        """Test circuit breaker functionality"""
        manager = FallbackManager()
        
        # Register a failing operation
        failing_operation = AsyncMock(side_effect=Exception("Service unavailable"))
        fallback_operation = AsyncMock(return_value={'fallback': True})
        
        manager.register_fallback('test_operation', failing_operation, fallback_operation)
        
        # Execute multiple times to trigger circuit breaker
        results = []
        for _ in range(6):  # Exceed failure threshold
            try:
                result = await manager.execute_with_fallback('test_operation', {})
                results.append(result)
            except Exception:
                pass
        
        # Should have some fallback results
        fallback_results = [r for r in results if r and r.get('fallback')]
        assert len(fallback_results) > 0
    
    @pytest.mark.asyncio
    async def test_intelligent_retry(self):
        """Test intelligent retry mechanism"""
        manager = FallbackManager()
        
        # Create a mock operation that fails twice then succeeds
        call_count = 0
        def mock_operation(data):
            nonlocal call_count
            call_count += 1
            if call_count <= 2:
                raise Exception("Temporary failure")
            return {'success': True, 'attempts': call_count}
        
        result = await manager.retry_with_backoff(mock_operation, {}, max_retries=3)
        
        assert result['success'] is True
        assert result['attempts'] == 3
    
    @pytest.mark.asyncio
    async def test_fallback_chain_execution(self):
        """Test fallback chain execution"""
        manager = FallbackManager()
        
        # Create fallback chain: primary -> secondary -> tertiary
        primary = AsyncMock(side_effect=Exception("Primary failed"))
        secondary = AsyncMock(side_effect=Exception("Secondary failed"))
        tertiary = AsyncMock(return_value={'source': 'tertiary'})
        
        chain = [primary, secondary, tertiary]
        
        result = await manager.execute_fallback_chain(chain, {})
        
        assert result['source'] == 'tertiary'
        primary.assert_called_once()
        secondary.assert_called_once()
        tertiary.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_fallback_success_tracking(self):
        """Test fallback success rate tracking"""
        manager = FallbackManager()
        
        # Simulate multiple operations with different success rates
        successful_op = AsyncMock(return_value={'success': True})
        failing_op = AsyncMock(side_effect=Exception("Always fails"))
        
        # Execute successful operations
        for _ in range(7):
            await manager.execute_with_fallback('successful_op', {}, successful_op, successful_op)
        
        # Execute failing operations
        for _ in range(3):
            try:
                await manager.execute_with_fallback('failing_op', {}, failing_op, successful_op)
            except:
                pass
        
        stats = manager.get_fallback_stats()
        
        assert 'successful_op' in stats
        assert 'failing_op' in stats
        assert stats['successful_op']['success_rate'] > 0.8

class TestIntegrationML:
    """Integration tests for ML components working together"""
    
    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_end_to_end_ml_analysis(self):
        """Test complete ML analysis pipeline"""
        enhancer = OptimizedMLEnhancer()
        
        vulnerability_data = {
            'url': 'https://admin.example.com/login.php?debug=true',
            'method': 'POST',
            'parameters': ['username', 'password', 'debug'],
            'response_indicators': ['MySQL error', 'root@localhost'],
            'payload': "' UNION SELECT 1,2,3--"
        }
        
        # Full analysis pipeline
        result = await enhancer.analyze_vulnerability(vulnerability_data)
        
        # Should have high confidence due to multiple risk indicators
        assert result['confidence'] > 0.7
        assert result['classification'] in ['high_risk', 'critical']
        assert 'risk_factors' in result
    
    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_ml_with_fallback_integration(self):
        """Test ML enhancement with fallback mechanisms"""
        enhancer = OptimizedMLEnhancer()
        
        # Simulate ML service failure
        with patch.object(enhancer, '_run_ml_analysis', side_effect=Exception("ML service down")):
            vulnerability_data = {
                'url': 'https://example.com/test.php',
                'method': 'GET'
            }
            
            result = await enhancer.analyze_vulnerability(vulnerability_data)
            
            # Should fallback to rule-based analysis
            assert 'fallback_used' in result
            assert result['fallback_used'] is True
            assert 'confidence' in result
            assert result['confidence'] > 0  # Should still provide some confidence

if __name__ == "__main__":
    # Run tests with verbose output
    pytest.main([__file__, "-v"])
