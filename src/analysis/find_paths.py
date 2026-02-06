import networkx as nx
from src.graph.build_graph import build_graph
from src.analysis.condition_evaluator import ConditionEvaluator
from src.visualization import visualize_graph
import argparse
import logging
import time
from functools import lru_cache
from typing import List, Tuple, Dict, Any
from concurrent.futures import ThreadPoolExecutor, as_completed


# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class AttackPathAnalyzer:
    """
    Discovers and analyzes security attack paths in a policy graph.
    Supports caching, performance metrics, and detailed explanations.
    """
    
    def __init__(self, graph: nx.DiGraph, context: Dict[str, Any], max_depth: int = 5):
        self.graph = graph
        self.context = context
        self.max_depth = max_depth
        self.evaluator = ConditionEvaluator(context)
        self._path_cache = {}
        self._metrics = {
            "total_paths_found": 0,
            "paths_pruned": 0,
            "evaluation_time": 0.0
        }

    def find_attack_paths(self, source: str, target: str, use_cache: bool = True) -> List[List[str]]:
        """
        Find all valid attack paths from source to target.
        
        Args:
            source: Starting node
            target: Destination node
            use_cache: Whether to cache results
            
        Returns:
            List of valid attack paths (list of node lists)
        """
        cache_key = (source, target)
        if use_cache and cache_key in self._path_cache:
            logger.info(f"Cache hit for {source} -> {target}")
            return self._path_cache[cache_key]

        start_time = time.time()
        valid_paths = []
        
        try:
            # Check if nodes exist
            if source not in self.graph:
                raise ValueError(f"Source node '{source}' not found in graph")
            if target not in self.graph:
                raise ValueError(f"Target node '{target}' not found in graph")
            
            # Find all simple paths up to max_depth
            try:
                all_paths = nx.all_simple_paths(
                    self.graph, 
                    source=source, 
                    target=target, 
                    cutoff=self.max_depth
                )
            except nx.NetworkXNoPath:
                logger.warning(f"No path exists from {source} to {target}")
                return []

            # Validate each path
            for path in all_paths:
                if self._is_path_valid(path):
                    valid_paths.append(path)
                else:
                    self._metrics["paths_pruned"] += 1

            self._metrics["total_paths_found"] += len(valid_paths)
            self._metrics["evaluation_time"] += time.time() - start_time
            
            if use_cache:
                self._path_cache[cache_key] = valid_paths
            
            return valid_paths
            
        except Exception as e:
            logger.error(f"Error finding attack paths: {e}")
            raise

    def _is_path_valid(self, path: List[str]) -> bool:
        """Check if a path is valid given execution context."""
        for i in range(len(path) - 1):
            src = path[i]
            dst = path[i + 1]
            edge_data = self.graph.get_edge_data(src, dst)
            
            if edge_data is None:
                return False
            
            # For IAM edges, check conditions
            if edge_data.get("type") == "iam":
                condition = edge_data.get("condition")
                if not self.evaluator.is_satisfied(condition):
                    return False
        
        return True

    def explain_path(self, path: List[str]) -> List[str]:
        """
        Generate human-readable explanation for a path.
        
        Args:
            path: List of nodes forming the attack path
            
        Returns:
            List of explanation strings
        """
        if not path or len(path) < 2:
            return []
        
        explanation = []
        
        for i in range(len(path) - 1):
            src = path[i]
            dst = path[i + 1]
            edge_data = self.graph.get_edge_data(src, dst)
            
            if edge_data is None:
                continue
            
            step_num = i + 1
            
            if edge_data.get("type") == "network":
                rule_name = edge_data.get("rule_name", "firewall rule")
                explanation.append(
                    f"Step {step_num}: [{src}] can reach [{dst}] via network "
                    f"({rule_name})"
                )
            
            elif edge_data.get("type") == "iam":
                action = edge_data.get("action", "access")
                condition_info = ""
                if edge_data.get("condition"):
                    condition_info = f" (conditions satisfied: {edge_data.get('condition')})"
                explanation.append(
                    f"Step {step_num}: [{src}] has IAM permission to [{dst}] "
                    f"({action}){condition_info}"
                )
        
        return explanation

    def score_path(self, path: List[str]) -> float:
        """
        Score attack path risk using multiple factors.
        
        Scoring factors:
        - Path length (more steps = lower risk, but still accessible)
        - Target criticality (high criticality = higher risk)
        - Edge types (IAM bypass = higher risk than network traversal)
        - Number of conditions bypassed (more conditions = higher difficulty)
        
        Args:
            path: List of nodes forming the attack path
            
        Returns:
            Risk score (0-100)
        """
        if not path or len(path) < 2:
            return 0.0
        
        score = 10.0  # Base score
        
        # Factor 1: Path length (inversely related - shorter = direct = higher risk)
        # Max 25 points
        path_length_score = max(0, 25 - (len(path) - 2) * 3)
        score += path_length_score
        
        # Factor 2: Target criticality
        target = path[-1]
        target_data = self.graph.nodes.get(target, {})
        criticality = target_data.get("criticality", "normal")
        if criticality == "critical":
            score += 40
        elif criticality == "high":
            score += 30
        elif criticality == "medium":
            score += 15
        
        # Factor 3: Edge types and conditions
        iam_count = 0
        network_count = 0
        conditions_bypassed = 0
        iam_complexity = 0
        
        for i in range(len(path) - 1):
            src = path[i]
            dst = path[i + 1]
            edge_data = self.graph.get_edge_data(src, dst)
            
            if edge_data.get("type") == "iam":
                iam_count += 1
                # Check if conditions were present
                if edge_data.get("condition"):
                    conditions_bypassed += 1
                    iam_complexity += 5  # More complex conditions = more risk to bypass
            elif edge_data.get("type") == "network":
                network_count += 1
        
        # IAM misconfigurations worth more risk points
        score += iam_count * 5
        score += conditions_bypassed * 3
        
        # Normalize to 0-100
        return min(100.0, score)

    def get_metrics(self) -> Dict[str, Any]:
        """Return performance metrics."""
        return {
            **self._metrics,
            "cache_size": len(self._path_cache)
        }

    def clear_cache(self):
        """Clear path cache."""
        self._path_cache.clear()


def find_attack_paths(graph, source, target, context, max_depth=5):
    """Convenience function for backward compatibility."""
    analyzer = AttackPathAnalyzer(graph, context, max_depth)
    return analyzer.find_attack_paths(source, target)


def explain_path(graph, path):
    """Convenience function for backward compatibility."""
    analyzer = AttackPathAnalyzer(graph, {})
    return analyzer.explain_path(path)


def score_path(graph, path):
    """Convenience function for backward compatibility."""
    analyzer = AttackPathAnalyzer(graph, {})
    return analyzer.score_path(path)


def main_cli():
    parser = argparse.ArgumentParser(
        description="Analyze attack paths with IAM conditions.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  attack-path-analyzer --source internet --target database
  attack-path-analyzer --source app-server --target database --visualize
  attack-path-analyzer --source internet --target database --time_of_day off_hours
        """
    )
    parser.add_argument("--source", default="internet", help="Source node")
    parser.add_argument("--target", default="database", help="Target node")
    parser.add_argument("--source_ip", default="external", help="Source IP context")
    parser.add_argument("--time_of_day", default="business_hours", help="Time of day context")
    parser.add_argument("--max_depth", type=int, default=5, help="Max path depth")
    parser.add_argument("--visualize", action="store_true", help="Generate graph visualization")
    parser.add_argument("--verbose", action="store_true", help="Verbose output with metrics")

    args = parser.parse_args()

    logger.info("Building security graph...")
    graph = build_graph()

    execution_context = {
        "source_ip": args.source_ip,
        "time_of_day": args.time_of_day
    }

    logger.info(f"Analyzing paths from {args.source} to {args.target}...")
    analyzer = AttackPathAnalyzer(graph, execution_context, args.max_depth)
    attack_paths = analyzer.find_attack_paths(args.source, args.target)

    print("\n" + "=" * 80)
    print("ATTACK PATH ANALYSIS RESULTS")
    print("=" * 80)
    print(f"Source: {args.source}")
    print(f"Target: {args.target}")
    print(f"Context: {execution_context}")
    print(f"Paths Found: {len(attack_paths)}\n")

    if not attack_paths:
        print("[OK] No viable attack paths discovered!")
    else:
        scored_paths = [
            (path, analyzer.score_path(path)) 
            for path in attack_paths
        ]
        scored_paths.sort(key=lambda x: x[1], reverse=True)

        for idx, (path, score) in enumerate(scored_paths, 1):
            print(f"\n[Attack Path #{idx}]")
            print(f"Risk Score: {score:.1f}/100")
            print(f"Path Length: {len(path)} nodes")
            print(f"Route: {' → '.join(path)}")
            
            reasons = analyzer.explain_path(path)
            print("Explanation:")
            for reason in reasons:
                print(f"  • {reason}")

    # Show metrics if verbose
    if args.verbose:
        metrics = analyzer.get_metrics()
        print("\n" + "=" * 80)
        print("PERFORMANCE METRICS")
        print("=" * 80)
        print(f"Total Paths Found: {metrics.get('total_paths_found')}")
        print(f"Paths Pruned (Invalid): {metrics.get('paths_pruned')}")
        print(f"Evaluation Time: {metrics.get('evaluation_time'):.4f}s")
        print(f"Cache Size: {metrics.get('cache_size')}")

    # Generate visualization if requested
    if args.visualize:
        logger.info("Generating visualization...")
        visualize_graph(graph, attack_paths)
        print("\nVisualization saved to: graph_visualization.html")

    print("=" * 80 + "\n")


if __name__ == "__main__":
    main_cli()

