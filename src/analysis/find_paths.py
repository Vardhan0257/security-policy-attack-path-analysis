import networkx as nx
from src.graph.build_graph import build_graph


def find_attack_paths(graph, source, target, max_depth=5):
    paths = []
    for path in nx.all_simple_paths(graph, source=source, target=target, cutoff=max_depth):
        paths.append(path)
    return paths

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

if __name__ == "__main__":
    graph = build_graph()

    source = "internet"
    target = "database"

    attack_paths = find_attack_paths(graph, source, target)

    print("Discovered attack paths:\n")
    for path in attack_paths:
        print(" -> ".join(path))
        reasons = explain_path(graph, path)
        for reason in reasons:
            print("  -", reason)
        print()
