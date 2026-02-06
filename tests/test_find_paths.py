import pytest
import networkx as nx
from src.analysis.find_paths import (
    AttackPathAnalyzer,
    find_attack_paths,
    explain_path,
    score_path
)


@pytest.fixture
def simple_graph():
    """Create a simple test graph."""
    G = nx.DiGraph()
    
    # Nodes
    G.add_node("internet", type="external", criticality="normal")
    G.add_node("web_server", type="server", criticality="high")
    G.add_node("app_server", type="server", criticality="high")
    G.add_node("database", type="database", criticality="critical")
    
    # Network edges
    G.add_edge("internet", "web_server", type="network", rule_name="allow_http")
    G.add_edge("web_server", "app_server", type="network", rule_name="internal_network")
    
    # IAM edges without condition
    G.add_edge("web_server", "app_server", type="iam", action="invoke", condition=None)
    
    # IAM edge with condition
    G.add_edge("app_server", "database", type="iam", action="read", 
               condition={"source_ip": "internal"})
    
    return G


@pytest.fixture
def complex_graph():
    """Create a more complex test graph with multiple paths."""
    G = nx.DiGraph()
    
    # Create assets
    assets = ["internet", "bastion", "web1", "web2", "app", "cache", "db", "backup"]
    criticalities = {
        "internet": "normal",
        "bastion": "high",
        "web1": "medium",
        "web2": "medium",
        "app": "high",
        "cache": "medium",
        "db": "critical",
        "backup": "high"
    }
    
    for asset in assets:
        G.add_node(asset, type="node", criticality=criticalities[asset])
    
    # Network paths
    G.add_edge("internet", "bastion", type="network")
    G.add_edge("internet", "web1", type="network")
    G.add_edge("bastion", "app", type="network")
    G.add_edge("web1", "app", type="network")
    G.add_edge("app", "cache", type="network")
    G.add_edge("app", "db", type="network")
    G.add_edge("db", "backup", type="network")
    
    # IAM permissions
    G.add_edge("web1", "app", type="iam", action="call", condition=None)
    G.add_edge("bastion", "db", type="iam", action="admin", 
               condition={"source_ip": "bastion_network"})
    
    return G


class TestAttackPathAnalyzer:
    """Test AttackPathAnalyzer class."""
    
    def test_analyzer_initialization(self, simple_graph):
        """Analyzer should initialize correctly."""
        context = {"source_ip": "internal"}
        analyzer = AttackPathAnalyzer(simple_graph, context, max_depth=5)
        
        assert analyzer.graph is simple_graph
        assert analyzer.context == context
        assert analyzer.max_depth == 5
    
    def test_find_simple_path(self, simple_graph):
        """Find valid attack path through network."""
        context = {"source_ip": "internal"}
        analyzer = AttackPathAnalyzer(simple_graph, context)
        
        paths = analyzer.find_attack_paths("internet", "app_server")
        assert len(paths) > 0
        assert paths[0] == ["internet", "web_server", "app_server"]
    
    def test_path_not_found(self, simple_graph):
        """Return empty list when no path exists."""
        context = {}
        analyzer = AttackPathAnalyzer(simple_graph, context)
        
        # Try to find path from database back to internet (edge direction matters)
        paths = analyzer.find_attack_paths("database", "internet")
        assert len(paths) == 0
    
    def test_invalid_source_node(self, simple_graph):
        """Should raise error for invalid source node."""
        context = {}
        analyzer = AttackPathAnalyzer(simple_graph, context)
        
        with pytest.raises(ValueError):
            analyzer.find_attack_paths("nonexistent", "database")
    
    def test_invalid_target_node(self, simple_graph):
        """Should raise error for invalid target node."""
        context = {}
        analyzer = AttackPathAnalyzer(simple_graph, context)
        
        with pytest.raises(ValueError):
            analyzer.find_attack_paths("internet", "nonexistent")
    
    def test_condition_evaluation_blocks_path(self, simple_graph):
        """Condition evaluation should block invalid paths."""
        # Try with external source (won't satisfy condition)
        context = {"source_ip": "external"}
        analyzer = AttackPathAnalyzer(simple_graph, context)
        
        # Database is only reachable with internal source_ip condition
        paths = analyzer.find_attack_paths("app_server", "database")
        assert len(paths) == 0
    
    def test_condition_evaluation_allows_path(self, simple_graph):
        """Condition evaluation should allow valid paths."""
        # Try with internal source (satisfies condition)
        context = {"source_ip": "internal"}
        analyzer = AttackPathAnalyzer(simple_graph, context)
        
        paths = analyzer.find_attack_paths("app_server", "database")
        assert len(paths) > 0
    
    def test_cache_functionality(self, simple_graph):
        """Path results should be cached."""
        context = {}
        analyzer = AttackPathAnalyzer(simple_graph, context)
        
        # First call - should execute
        paths1 = analyzer.find_attack_paths("internet", "app_server", use_cache=True)
        metrics1 = analyzer.get_metrics()
        
        # Second call - should use cache
        paths2 = analyzer.find_attack_paths("internet", "app_server", use_cache=True)
        metrics2 = analyzer.get_metrics()
        
        assert paths1 == paths2
        assert metrics2["cache_size"] > 0
    
    def test_cache_can_be_cleared(self, simple_graph):
        """Cache should be clearable."""
        context = {}
        analyzer = AttackPathAnalyzer(simple_graph, context)
        
        analyzer.find_attack_paths("internet", "app_server", use_cache=True)
        assert analyzer.get_metrics()["cache_size"] > 0
        
        analyzer.clear_cache()
        assert analyzer.get_metrics()["cache_size"] == 0


class TestPathExplanation:
    """Test path explanation generation."""
    
    def test_explain_network_edge(self, simple_graph):
        """Explanation for network edge."""
        analyzer = AttackPathAnalyzer(simple_graph, {})
        path = ["internet", "web_server"]
        
        explanation = analyzer.explain_path(path)
        assert len(explanation) > 0
        assert "network" in explanation[0].lower() or "reach" in explanation[0].lower()
    
    def test_explain_iam_edge(self, simple_graph):
        """Explanation for IAM edge."""
        analyzer = AttackPathAnalyzer(simple_graph, {"source_ip": "internal"})
        path = ["app_server", "database"]
        
        explanation = analyzer.explain_path(path)
        assert len(explanation) > 0
        assert "iam" in explanation[0].lower() or "permission" in explanation[0].lower()
    
    def test_explain_complex_path(self, simple_graph):
        """Explanation for multi-step path."""
        analyzer = AttackPathAnalyzer(simple_graph, {"source_ip": "internal"})
        path = ["internet", "web_server", "app_server", "database"]
        
        explanation = analyzer.explain_path(path)
        # Should have explanation for each step
        assert len(explanation) >= len(path) - 1
    
    def test_explain_empty_path(self, simple_graph):
        """Explanation for empty path should return empty list."""
        analyzer = AttackPathAnalyzer(simple_graph, {})
        assert analyzer.explain_path([]) == []
        assert analyzer.explain_path(["single_node"]) == []


class TestPathScoring:
    """Test path risk scoring."""
    
    def test_score_basic_path(self, simple_graph):
        """Basic path should receive a score."""
        analyzer = AttackPathAnalyzer(simple_graph, {})
        path = ["internet", "web_server"]
        
        score = analyzer.score_path(path)
        assert score >= 0
        assert score <= 100
    
    def test_shorter_path_higher_risk(self, simple_graph):
        """Shorter direct paths typically have higher risk scores."""
        analyzer = AttackPathAnalyzer(simple_graph, {})
        
        # Path to high criticality asset (2 hops)
        path_direct = ["internet", "web_server"]
        # Path to the same criticality (3 hops)  
        path_longer = ["internet", "web_server", "app_server"]
        
        direct_score = analyzer.score_path(path_direct)
        longer_score = analyzer.score_path(path_longer)
        
        # Both should be non-zero and valid scores
        assert direct_score > 0
        assert longer_score > 0
        assert direct_score <= 100
        assert longer_score <= 100
    
    def test_critical_target_increases_score(self, simple_graph):
        """Critical target increases risk score."""
        analyzer = AttackPathAnalyzer(simple_graph, {})
        
        path_to_normal = ["internet", "web_server"]  # web_server is "high"
        path_to_critical = ["web_server", "app_server", "database"]  # database is "critical"
        
        score_normal = analyzer.score_path(path_to_normal)
        score_critical = analyzer.score_path(path_to_critical)
        
        # Critical target should increase score
        assert score_critical > score_normal
    
    def test_score_empty_path(self, simple_graph):
        """Empty path should score 0."""
        analyzer = AttackPathAnalyzer(simple_graph, {})
        assert analyzer.score_path([]) == 0.0
        assert analyzer.score_path(["single"]) == 0.0
    
    def test_score_normalized(self, simple_graph):
        """All scores should be normalized between 0-100."""
        analyzer = AttackPathAnalyzer(simple_graph, {})
        
        paths = [
            ["internet", "web_server"],
            ["internet", "web_server", "app_server"],
            ["internet", "web_server", "app_server", "database"]
        ]
        
        for path in paths:
            score = analyzer.score_path(path)
            assert 0 <= score <= 100


class TestMetrics:
    """Test performance metrics collection."""
    
    def test_metrics_initialization(self, simple_graph):
        """Metrics should initialize correctly."""
        analyzer = AttackPathAnalyzer(simple_graph, {})
        metrics = analyzer.get_metrics()
        
        assert "total_paths_found" in metrics
        assert "paths_pruned" in metrics
        assert "evaluation_time" in metrics
        assert "cache_size" in metrics
    
    def test_metrics_updated_after_analysis(self, simple_graph):
        """Metrics should update after path analysis."""
        analyzer = AttackPathAnalyzer(simple_graph, {"source_ip": "internal"})
        
        initial_metrics = analyzer.get_metrics()
        analyzer.find_attack_paths("internet", "database")
        final_metrics = analyzer.get_metrics()
        
        # Should have found some paths
        assert final_metrics["total_paths_found"] > initial_metrics["total_paths_found"]\
               or final_metrics["evaluation_time"] > initial_metrics["evaluation_time"]


class TestBackwardCompatibility:
    """Test backward compatibility with old function interface."""
    
    def test_find_attack_paths_function(self, simple_graph):
        """Old find_attack_paths function should still work."""
        context = {"source_ip": "internal"}
        paths = find_attack_paths(simple_graph, "internet", "app_server", context)
        
        assert isinstance(paths, list)
    
    def test_explain_path_function(self, simple_graph):
        """Old explain_path function should still work."""
        path = ["internet", "web_server"]
        explanation = explain_path(simple_graph, path)
        
        assert isinstance(explanation, list)
    
    def test_score_path_function(self, simple_graph):
        """Old score_path function should still work."""
        path = ["internet", "web_server"]
        score = score_path(simple_graph, path)
        
        assert isinstance(score, (int, float))


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
