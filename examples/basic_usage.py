#!/usr/bin/env python3
"""
Example usage of the Security Policy Attack Path Analysis framework.
"""

from src.analysis.find_paths import find_attack_paths
from src.graph.build_graph import build_graph

def main():
    # Build the graph
    graph = build_graph()

    # Define execution context
    context = {
        "source_ip": "internal",
        "time_of_day": "business_hours"
    }

    # Find attack paths
    paths = find_attack_paths(graph, "internet", "database", context)

    print(f"Found {len(paths)} attack paths:")
    for i, path in enumerate(paths, 1):
        print(f"{i}. {' -> '.join(path)}")

if __name__ == "__main__":
    main()