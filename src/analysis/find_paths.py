import networkx as nx
from src.graph.build_graph import build_graph
from src.analysis.condition_evaluator import ConditionEvaluator
from src.visualization import visualize_graph
import argparse


def find_attack_paths(graph, source, target, context, max_depth=5):
    evaluator = ConditionEvaluator(context)
    valid_paths = []

    for path in nx.all_simple_paths(graph, source=source, target=target, cutoff=max_depth):
        path_valid = True

        for i in range(len(path) - 1):
            src = path[i]
            dst = path[i + 1]
            edge = graph.get_edge_data(src, dst)

            if edge["type"] == "iam":
                condition = edge.get("condition")
                if not evaluator.is_satisfied(condition):
                    path_valid = False
                    break

        if path_valid:
            valid_paths.append(path)

    return valid_paths

def explain_path(graph, path):
    explanation = []
    for i in range(len(path) - 1):
        src = path[i]
        dst = path[i + 1]
        edge_data = graph.get_edge_data(src, dst)

        if edge_data["type"] == "network":
            explanation.append(
                f"{src} can reach {dst} due to an allowed network rule"
            )
        elif edge_data["type"] == "iam":
            explanation.append(
                f"{src} has permission to access {dst} due to an IAM policy"
            )
    return explanation

def score_path(graph, path):
    score = 0

    # Longer paths = more steps = higher risk
    score += len(path)

    # If target is critical, add weight
    target = path[-1]
    if graph.nodes[target].get("criticality") == "high":
        score += 5

    return score

def main_cli():
    parser = argparse.ArgumentParser(description="Analyze attack paths with IAM conditions.")
    parser.add_argument("--source", default="internet", help="Source node")
    parser.add_argument("--target", default="database", help="Target node")
    parser.add_argument("--source_ip", default="external", help="Source IP context")
    parser.add_argument("--time_of_day", default="business_hours", help="Time of day context")
    parser.add_argument("--max_depth", type=int, default=5, help="Max path depth")
    parser.add_argument("--visualize", action="store_true", help="Generate graph visualization")

    args = parser.parse_args()

    graph = build_graph()

    execution_context = {
        "source_ip": args.source_ip,
        "time_of_day": args.time_of_day
    }

    attack_paths = find_attack_paths(graph, args.source, args.target, execution_context, args.max_depth)

    print("Discovered attack paths:\n")
    scored_paths = []

    for path in attack_paths:
        score = score_path(graph, path)
        scored_paths.append((path, score))

    scored_paths.sort(key=lambda x: x[1], reverse=True)

    for path, score in scored_paths:
        print(f"Attack Path (Risk Score: {score})")
        print(" -> ".join(path))
        reasons = explain_path(graph, path)
        for reason in reasons:
            print("  -", reason)
        print()

    # Generate visualization if requested
    if args.visualize:
        visualize_graph(graph, attack_paths)


if __name__ == "__main__":
    main_cli()

