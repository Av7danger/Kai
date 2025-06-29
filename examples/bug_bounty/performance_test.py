#!/usr/bin/env python3
"""
Performance Testing Script for Enhanced Bug Bounty Dashboard
Comprehensive load testing and performance monitoring
"""

import asyncio
import aiohttp
import time
import json
import statistics
import argparse
import sys
from datetime import datetime, timedelta
from typing import Dict, List, Any
import concurrent.futures
import threading
from dataclasses import dataclass
import matplotlib.pyplot as plt
import numpy as np

@dataclass
class TestResult:
    """Test result data structure"""
    endpoint: str
    method: str
    response_time: float
    status_code: int
    success: bool
    error_message: str = ""
    timestamp: datetime = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now()

class PerformanceTester:
    """Comprehensive performance testing for the dashboard"""
    
    def __init__(self, base_url: str = "http://localhost:5000"):
        self.base_url = base_url.rstrip('/')
        self.results: List[TestResult] = []
        self.session = None
        
    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    async def test_endpoint(self, endpoint: str, method: str = "GET", 
                          data: Dict = None, headers: Dict = None) -> TestResult:
        """Test a single endpoint"""
        url = f"{self.base_url}{endpoint}"
        start_time = time.time()
        
        try:
            if method.upper() == "GET":
                async with self.session.get(url, headers=headers) as response:
                    response_time = time.time() - start_time
                    return TestResult(
                        endpoint=endpoint,
                        method=method,
                        response_time=response_time,
                        status_code=response.status,
                        success=200 <= response.status < 300
                    )
            elif method.upper() == "POST":
                async with self.session.post(url, json=data, headers=headers) as response:
                    response_time = time.time() - start_time
                    return TestResult(
                        endpoint=endpoint,
                        method=method,
                        response_time=response_time,
                        status_code=response.status,
                        success=200 <= response.status < 300
                    )
        except Exception as e:
            response_time = time.time() - start_time
            return TestResult(
                endpoint=endpoint,
                method=method,
                response_time=response_time,
                status_code=0,
                success=False,
                error_message=str(e)
            )
    
    async def run_load_test(self, endpoint: str, method: str = "GET", 
                          concurrent_users: int = 10, duration_seconds: int = 60,
                          data: Dict = None) -> Dict:
        """Run load test for a specific endpoint"""
        print(f"Starting load test for {endpoint} with {concurrent_users} concurrent users for {duration_seconds}s")
        
        start_time = time.time()
        tasks = []
        results = []
        
        # Create tasks for concurrent users
        async def user_work():
            while time.time() - start_time < duration_seconds:
                result = await self.test_endpoint(endpoint, method, data)
                results.append(result)
                await asyncio.sleep(0.1)  # Small delay between requests
        
        # Start concurrent users
        for _ in range(concurrent_users):
            tasks.append(asyncio.create_task(user_work()))
        
        # Wait for all tasks to complete
        await asyncio.gather(*tasks)
        
        return self.analyze_results(results)
    
    def analyze_results(self, results: List[TestResult]) -> Dict:
        """Analyze test results and generate statistics"""
        if not results:
            return {"error": "No results to analyze"}
        
        response_times = [r.response_time for r in results]
        success_count = sum(1 for r in results if r.success)
        error_count = len(results) - success_count
        
        analysis = {
            "total_requests": len(results),
            "successful_requests": success_count,
            "failed_requests": error_count,
            "success_rate": success_count / len(results) * 100,
            "response_time_stats": {
                "min": min(response_times),
                "max": max(response_times),
                "mean": statistics.mean(response_times),
                "median": statistics.median(response_times),
                "p95": np.percentile(response_times, 95),
                "p99": np.percentile(response_times, 99)
            },
            "requests_per_second": len(results) / (max(r.timestamp for r in results) - min(r.timestamp for r in results)).total_seconds(),
            "errors": [r.error_message for r in results if r.error_message]
        }
        
        return analysis
    
    async def test_dashboard_endpoints(self) -> Dict:
        """Test all dashboard endpoints"""
        endpoints = [
            ("/", "GET"),
            ("/health", "GET"),
            ("/health/detailed", "GET"),
            ("/api/stats", "GET"),
            ("/api/optimization_stats", "GET"),
            ("/api/optimization/stats/detailed", "GET"),
            ("/api/optimization/settings", "GET"),
            ("/vulnerabilities", "GET"),
        ]
        
        results = {}
        for endpoint, method in endpoints:
            print(f"Testing {method} {endpoint}")
            result = await self.test_endpoint(endpoint, method)
            results[endpoint] = {
                "response_time": result.response_time,
                "status_code": result.status_code,
                "success": result.success,
                "error": result.error_message
            }
        
        return results
    
    async def test_optimization_endpoints(self) -> Dict:
        """Test optimization-specific endpoints"""
        optimization_tests = [
            ("/api/optimization/clear-cache", "POST"),
            ("/api/optimization/run", "POST"),
            ("/api/optimization/settings", "POST", {"cache_settings": {"max_size": 1000}}),
        ]
        
        results = {}
        for test in optimization_tests:
            endpoint = test[0]
            method = test[1]
            data = test[2] if len(test) > 2 else None
            
            print(f"Testing optimization endpoint: {method} {endpoint}")
            result = await self.test_endpoint(endpoint, method, data)
            results[endpoint] = {
                "response_time": result.response_time,
                "status_code": result.status_code,
                "success": result.success,
                "error": result.error_message
            }
        
        return results
    
    def generate_report(self, results: Dict, output_file: str = None) -> str:
        """Generate a comprehensive performance report"""
        report = []
        report.append("=" * 80)
        report.append("PERFORMANCE TEST REPORT")
        report.append("=" * 80)
        report.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"Base URL: {self.base_url}")
        report.append("")
        
        # Dashboard endpoints summary
        if "dashboard_endpoints" in results:
            report.append("DASHBOARD ENDPOINTS PERFORMANCE")
            report.append("-" * 40)
            for endpoint, data in results["dashboard_endpoints"].items():
                status = "✅" if data["success"] else "❌"
                report.append(f"{status} {endpoint}")
                report.append(f"   Response Time: {data['response_time']:.3f}s")
                report.append(f"   Status Code: {data['status_code']}")
                if data["error"]:
                    report.append(f"   Error: {data['error']}")
                report.append("")
        
        # Load test results
        if "load_tests" in results:
            report.append("LOAD TEST RESULTS")
            report.append("-" * 40)
            for test_name, data in results["load_tests"].items():
                report.append(f"Test: {test_name}")
                report.append(f"  Total Requests: {data['total_requests']}")
                report.append(f"  Success Rate: {data['success_rate']:.1f}%")
                report.append(f"  Requests/Second: {data['requests_per_second']:.1f}")
                report.append(f"  Response Times:")
                report.append(f"    Mean: {data['response_time_stats']['mean']:.3f}s")
                report.append(f"    Median: {data['response_time_stats']['median']:.3f}s")
                report.append(f"    P95: {data['response_time_stats']['p95']:.3f}s")
                report.append(f"    P99: {data['response_time_stats']['p99']:.3f}s")
                report.append("")
        
        # Optimization endpoints
        if "optimization_endpoints" in results:
            report.append("OPTIMIZATION ENDPOINTS")
            report.append("-" * 40)
            for endpoint, data in results["optimization_endpoints"].items():
                status = "✅" if data["success"] else "❌"
                report.append(f"{status} {endpoint}")
                report.append(f"   Response Time: {data['response_time']:.3f}s")
                report.append(f"   Status Code: {data['status_code']}")
                if data["error"]:
                    report.append(f"   Error: {data['error']}")
                report.append("")
        
        # Recommendations
        report.append("PERFORMANCE RECOMMENDATIONS")
        report.append("-" * 40)
        
        # Analyze response times
        all_response_times = []
        for section in results.values():
            if isinstance(section, dict):
                for endpoint_data in section.values():
                    if isinstance(endpoint_data, dict) and "response_time" in endpoint_data:
                        all_response_times.append(endpoint_data["response_time"])
        
        if all_response_times:
            avg_response_time = statistics.mean(all_response_times)
            if avg_response_time > 1.0:
                report.append("⚠️  Average response time is high (>1s). Consider:")
                report.append("   - Implementing caching for expensive operations")
                report.append("   - Optimizing database queries")
                report.append("   - Using background tasks for long-running operations")
            elif avg_response_time > 0.5:
                report.append("⚠️  Response time could be improved. Consider:")
                report.append("   - Adding response compression")
                report.append("   - Implementing request batching")
            else:
                report.append("✅ Response times are good")
        
        # Success rate analysis
        success_rates = []
        for section in results.values():
            if isinstance(section, dict):
                for endpoint_data in section.values():
                    if isinstance(endpoint_data, dict) and "success" in endpoint_data:
                        success_rates.append(endpoint_data["success"])
        
        if success_rates:
            overall_success_rate = sum(success_rates) / len(success_rates) * 100
            if overall_success_rate < 95:
                report.append(f"⚠️  Overall success rate is {overall_success_rate:.1f}%. Check error logs.")
            else:
                report.append(f"✅ Overall success rate is good ({overall_success_rate:.1f}%)")
        
        report.append("")
        report.append("=" * 80)
        
        report_text = "\n".join(report)
        
        if output_file:
            with open(output_file, 'w') as f:
                f.write(report_text)
            print(f"Report saved to {output_file}")
        
        return report_text
    
    def plot_results(self, results: Dict, output_file: str = None):
        """Generate performance charts"""
        try:
            fig, axes = plt.subplots(2, 2, figsize=(15, 10))
            fig.suptitle('Dashboard Performance Analysis', fontsize=16)
            
            # Response times by endpoint
            if "dashboard_endpoints" in results:
                endpoints = list(results["dashboard_endpoints"].keys())
                response_times = [results["dashboard_endpoints"][ep]["response_time"] for ep in endpoints]
                
                axes[0, 0].bar(range(len(endpoints)), response_times)
                axes[0, 0].set_title('Response Times by Endpoint')
                axes[0, 0].set_ylabel('Response Time (seconds)')
                axes[0, 0].set_xticks(range(len(endpoints)))
                axes[0, 0].set_xticklabels([ep.split('/')[-1] or 'root' for ep in endpoints], rotation=45)
            
            # Load test results
            if "load_tests" in results:
                test_names = list(results["load_tests"].keys())
                success_rates = [results["load_tests"][tn]["success_rate"] for tn in test_names]
                
                axes[0, 1].bar(test_names, success_rates)
                axes[0, 1].set_title('Success Rates by Load Test')
                axes[0, 1].set_ylabel('Success Rate (%)')
                axes[0, 1].tick_params(axis='x', rotation=45)
            
            # Response time distribution
            if "load_tests" in results:
                all_response_times = []
                for test_data in results["load_tests"].values():
                    if "response_time_stats" in test_data:
                        # Simulate distribution based on stats
                        mean = test_data["response_time_stats"]["mean"]
                        std = (test_data["response_time_stats"]["p95"] - mean) / 2
                        times = np.random.normal(mean, std, 1000)
                        all_response_times.extend(times)
                
                if all_response_times:
                    axes[1, 0].hist(all_response_times, bins=50, alpha=0.7)
                    axes[1, 0].set_title('Response Time Distribution')
                    axes[1, 0].set_xlabel('Response Time (seconds)')
                    axes[1, 0].set_ylabel('Frequency')
            
            # Performance trends
            if "load_tests" in results:
                test_names = list(results["load_tests"].keys())
                rps_values = [results["load_tests"][tn]["requests_per_second"] for tn in test_names]
                
                axes[1, 1].plot(test_names, rps_values, marker='o')
                axes[1, 1].set_title('Requests per Second')
                axes[1, 1].set_ylabel('RPS')
                axes[1, 1].tick_params(axis='x', rotation=45)
            
            plt.tight_layout()
            
            if output_file:
                plt.savefig(output_file, dpi=300, bbox_inches='tight')
                print(f"Chart saved to {output_file}")
            else:
                plt.show()
                
        except Exception as e:
            print(f"Error generating charts: {e}")

async def main():
    """Main performance testing function"""
    parser = argparse.ArgumentParser(description="Performance testing for Bug Bounty Dashboard")
    parser.add_argument("--url", default="http://localhost:5000", help="Base URL to test")
    parser.add_argument("--load-test", action="store_true", help="Run load tests")
    parser.add_argument("--concurrent", type=int, default=10, help="Number of concurrent users for load tests")
    parser.add_argument("--duration", type=int, default=60, help="Duration of load tests in seconds")
    parser.add_argument("--output", help="Output file for report")
    parser.add_argument("--chart", help="Output file for performance chart")
    
    args = parser.parse_args()
    
    print(f"Starting performance tests for {args.url}")
    print(f"Load testing: {args.load_test}")
    if args.load_test:
        print(f"Concurrent users: {args.concurrent}")
        print(f"Duration: {args.duration}s")
    
    async with PerformanceTester(args.url) as tester:
        results = {}
        
        # Test dashboard endpoints
        print("\n1. Testing dashboard endpoints...")
        results["dashboard_endpoints"] = await tester.test_dashboard_endpoints()
        
        # Test optimization endpoints
        print("\n2. Testing optimization endpoints...")
        results["optimization_endpoints"] = await tester.test_optimization_endpoints()
        
        # Run load tests if requested
        if args.load_test:
            print("\n3. Running load tests...")
            load_tests = {
                "dashboard_home": await tester.run_load_test("/", "GET", args.concurrent, args.duration),
                "optimization_stats": await tester.run_load_test("/api/optimization_stats", "GET", args.concurrent, args.duration),
                "health_check": await tester.run_load_test("/health", "GET", args.concurrent, args.duration),
            }
            results["load_tests"] = load_tests
        
        # Generate report
        print("\n4. Generating performance report...")
        report = tester.generate_report(results, args.output)
        print(report)
        
        # Generate charts
        if args.chart:
            print("\n5. Generating performance charts...")
            tester.plot_results(results, args.chart)
        
        print("\nPerformance testing completed!")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nPerformance testing interrupted by user")
    except Exception as e:
        print(f"Error during performance testing: {e}")
        sys.exit(1) 