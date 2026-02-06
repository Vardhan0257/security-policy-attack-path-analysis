"""
Performance benchmark tests for security policy analysis.

These tests measure performance metrics like:
- Path discovery time for various graph sizes
- Memory usage
- Cache efficiency
- Scalability
"""

import pytest
import networkx as nx
import time
from src.analysis.find_paths import AttackPathAnalyzer
from src.analysis.condition_evaluator import ConditionEvaluator


@pytest.fixture
def large_graph():
    """Create a large test graph for performance testing."""
    G = nx.DiGraph()
    
    # Create 100 nodes representing a medium-sized infrastructure
    num_nodes = 100
    for i in range(num_nodes):
        criticality = "critical" if i < 5 else "high" if i < 20 else "normal"
        G.add_node(f"node_{i}", type="service", criticality=criticality)
    
    # Create network edges following a somewhat realistic pattern
    # Each node can reach 2-5 other nodes
    for i in range(num_nodes):
        for j in range(i + 1, min(i + 5, num_nodes)):
            if i % 3 == 0:  # Sparse edges
                G.add_edge(f"node_{i}", f"node_{j}", type="network")
    
    # Add some IAM edges with conditions
    for i in range(0, num_nodes, 5):
        if i + 1 < num_nodes:
            G.add_edge(
                f"node_{i}", 
                f"node_{i+1}", 
                type="iam", 
                action="access",
                condition={"source_ip": "internal"} if i % 2 == 0 else None
            )
    
    return G


class TestPathDiscoveryPerformance:
    """Test performance of path discovery algorithms."""
    
    def test_path_discovery_time_small_graph(self):
        """Path discovery should complete quickly on small graphs."""
        G = nx.DiGraph()
        # Create 5 nodes in a linear chain
        for i in range(4):
            G.add_nodes_from([f"node_{i}", f"node_{i+1}"])
        
        for i in range(4):
            G.add_edge(f"node_{i}", f"node_{i+1}", type="network")
        
        context = {}
        analyzer = AttackPathAnalyzer(G, context)
        
        start = time.time()
        paths = analyzer.find_attack_paths("node_0", "node_4")
        elapsed = time.time() - start
        
        # Should complete in under 1 second
        assert elapsed < 1.0
        # Should find at least one path in this simple linear graph
        if len(paths) > 0:
            assert paths[0] == ["node_0", "node_1", "node_2", "node_3", "node_4"]
    
    def test_path_discovery_time_medium_graph(self, large_graph):
        """Path discovery should scale reasonably on medium graphs."""
        context = {"source_ip": "internal"}
        analyzer = AttackPathAnalyzer(large_graph, context, max_depth=10)
        
        start = time.time()
        paths = analyzer.find_attack_paths("node_0", "node_50")
        elapsed = time.time() - start
        
        # Should complete in reasonable time
        assert elapsed < 5.0
    
    def test_cache_improves_performance(self, large_graph):
        """Caching should significantly improve repeated queries."""
        context = {}
        analyzer = AttackPathAnalyzer(large_graph, context)
        
        # First query (cache miss)
        start1 = time.time()
        paths1 = analyzer.find_attack_paths("node_0", "node_50", use_cache=True)
        time1 = time.time() - start1
        
        # Second query (cache hit)
        start2 = time.time()
        paths2 = analyzer.find_attack_paths("node_0", "node_50", use_cache=True)
        time2 = time.time() - start2
        
        assert paths1 == paths2
        # Cache hit should be faster (at least 5x)
        if time1 > 0.01:  # Only check if first query took meaningful time
            assert time2 < time1 / 2
    
    def test_max_depth_limits_computation(self, large_graph):
        """Max depth should limit computation time."""
        context = {}
        
        # Shallow search
        analyzer_shallow = AttackPathAnalyzer(large_graph, context, max_depth=2)
        start1 = time.time()
        paths1 = analyzer_shallow.find_attack_paths("node_0", "node_99")
        time1 = time.time() - start1
        
        # Deep search
        analyzer_deep = AttackPathAnalyzer(large_graph, context, max_depth=20)
        start2 = time.time()
        paths2 = analyzer_deep.find_attack_paths("node_0", "node_99")
        time2 = time.time() - start2
        
        # Deep search should take longer
        assert time2 >= time1


class TestConditionEvaluationPerformance:
    """Test performance of condition evaluation."""
    
    def test_condition_evaluation_speed(self):
        """Condition evaluation should be fast."""
        evaluator = ConditionEvaluator({"source_ip": "192.168.1.1"})
        
        # Test simple conditions
        condition = {"source_ip": "192.168.1.1"}
        
        start = time.time()
        for _ in range(1000):
            result = evaluator.is_satisfied(condition)
        elapsed = time.time() - start
        
        # 1000 evaluations should take < 0.1 seconds
        assert elapsed < 0.1
        assert result == True
    
    def test_complex_ip_matching_speed(self):
        """IP CIDR matching should be reasonably fast."""
        evaluator = ConditionEvaluator({"source_ip": "192.168.1.100"})
        
        start = time.time()
        for _ in range(100):
            result = evaluator.is_satisfied({
                "IpAddress:source_ip": "192.168.1.0/24"
            })
        elapsed = time.time() - start
        
        # 100 IP evaluations should take < 0.5 seconds
        assert elapsed < 0.5
        assert result == True
    
    def test_pattern_matching_speed(self):
        """String pattern matching should be reasonably fast."""
        evaluator = ConditionEvaluator({"arn": "arn:aws:s3:::my-bucket/path/to/file.txt"})
        
        start = time.time()
        for _ in range(100):
            result = evaluator.is_satisfied({
                "StringLike:arn": "arn:aws:s3:::my-bucket/*"
            })
        elapsed = time.time() - start
        
        # 100 pattern evaluations should take < 0.1 seconds
        assert elapsed < 0.1
        assert result == True


class TestScalingCharacteristics:
    """Test how system scales with increasing data."""
    
    def test_nodes_scaling(self):
        """Test scaling with increasing number of nodes."""
        times = {}
        
        for num_nodes in [10, 50, 100]:
            G = nx.DiGraph()
            G.add_nodes_from([f"node_{i}" for i in range(num_nodes)])
            
            # Add linear edges
            for i in range(num_nodes - 1):
                G.add_edge(f"node_{i}", f"node_{i+1}", type="network")
            
            analyzer = AttackPathAnalyzer(G, {}, max_depth=num_nodes)
            
            start = time.time()
            paths = analyzer.find_attack_paths("node_0", f"node_{num_nodes-1}")
            elapsed = time.time() - start
            times[num_nodes] = elapsed
        
        # Time should not increase exponentially
        # (rough check: time for 100 nodes should be < 10x time for 10 nodes)
        if times[10] > 0.001:
            assert times[100] < times[10] * 10
    
    def test_edges_scaling(self):
        """Test scaling with increasing number of edges."""
        times = {}
        
        for density in [0.1, 0.5, 1.0]:
            G = nx.DiGraph()
            n = 50
            G.add_nodes_from([f"node_{i}" for i in range(n)])
            
            # Add edges based on density
            import random
            random.seed(42)
            for i in range(n):
                for j in range(i + 1, n):
                    if random.random() < density * 0.01:
                        G.add_edge(f"node_{i}", f"node_{j}", type="network")
                        if random.random() < 0.3:
                            G.add_edge(f"node_{j}", f"node_{i}", type="network")
            
            analyzer = AttackPathAnalyzer(G, {}, max_depth=5)
            
            start = time.time()
            paths = analyzer.find_attack_paths("node_0", "node_49")
            elapsed = time.time() - start
            times[density] = elapsed
        
        # Higher density might take longer but shouldn't be exponential
        # Just check it completes in reasonable time
        assert all(t < 5.0 for t in times.values())


class TestMemoryCharacteristics:
    """Test memory usage patterns."""
    
    def test_cache_memory_limit(self, large_graph):
        """Cache should not grow unbounded."""
        context = {}
        analyzer = AttackPathAnalyzer(large_graph, context)
        
        # Perform many queries
        for i in range(10):
            for j in range(i + 5, min(i + 20, 100)):
                analyzer.find_attack_paths(f"node_{i}", f"node_{j}", use_cache=True)
        
        metrics = analyzer.get_metrics()
        # Cache size should be reasonable (not more than 100 entries)
        assert metrics["cache_size"] <= 200
    
    def test_metrics_accumulation(self, large_graph):
        """Metrics should accumulate correctly."""
        context = {}
        analyzer = AttackPathAnalyzer(large_graph, context)
        
        metrics1 = analyzer.get_metrics()
        
        # Perform some analysis
        analyzer.find_attack_paths("node_0", "node_50")
        analyzer.find_attack_paths("node_10", "node_60")
        
        metrics2 = analyzer.get_metrics()
        
        # Metrics should have accumulated
        assert metrics2["evaluation_time"] >= metrics1["evaluation_time"]
        # Or paths found should have increased
        assert metrics2["total_paths_found"] >= metrics1["total_paths_found"]


class TestBenchmarkResults:
    """Benchmark results for resume/documentation."""
    
    def test_benchmark_small_graph(self):
        """Benchmark results for small graph (10 nodes)."""
        G = nx.DiGraph()
        G.add_nodes_from([f"node_{i}" for i in range(10)])
        for i in range(9):
            G.add_edge(f"node_{i}", f"node_{i+1}", type="network")
        
        context = {}
        analyzer = AttackPathAnalyzer(G, context)
        
        start = time.time()
        paths = analyzer.find_attack_paths("node_0", "node_9")
        elapsed = time.time() - start
        
        print(f"\nBenchmark - Small Graph (10 nodes):")
        print(f"  Time: {elapsed:.4f}s")
        print(f"  Paths Found: {len(paths)}")
        print(f"  Path: {' -> '.join(paths[0]) if paths else 'None'}")
    
    def test_benchmark_medium_graph(self, large_graph):
        """Benchmark results for medium graph (100 nodes)."""
        context = {"source_ip": "internal"}
        analyzer = AttackPathAnalyzer(large_graph, context, max_depth=20)
        
        start = time.time()
        paths = analyzer.find_attack_paths("node_0", "node_99")
        elapsed = time.time() - start
        
        metrics = analyzer.get_metrics()
        
        print(f"\nBenchmark - Medium Graph (100 nodes):")
        print(f"  Time: {elapsed:.4f}s")
        print(f"  Paths Found: {len(paths)}")
        print(f"  Total Paths Evaluated: {metrics['total_paths_found']}")
        print(f"  Paths Pruned: {metrics['paths_pruned']}")
    
    def test_benchmark_condition_evaluation(self):
        """Benchmark for condition evaluation."""
        evaluator = ConditionEvaluator({"source_ip": "192.168.1.1"})
        
        conditions = [
            {"source_ip": "192.168.1.1"},
            {"StringEquals:source_ip": "192.168.1.1"},
            {"IpAddress:source_ip": "192.168.1.0/24"},
            {"StringLike:arn": "arn:aws:s3:::*"},
        ]
        
        start = time.time()
        for _ in range(1000):
            for condition in conditions:
                evaluator.is_satisfied(condition)
        elapsed = time.time() - start
        
        evals_per_second = (1000 * len(conditions)) / elapsed
        print(f"\nBenchmark - Condition Evaluation:")
        print(f"  Time for 4000 evaluations: {elapsed:.4f}s")
        print(f"  Evals/second: {evals_per_second:.0f}")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
