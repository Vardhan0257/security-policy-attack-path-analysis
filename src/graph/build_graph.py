import json
import csv
import networkx as nx
from pathlib import Path


def load_assets(path):
    with open(path, "r") as f:
        return json.load(f)["assets"]


def load_iam_policies(path):
    policies = []
    for file in Path(path).glob("*.json"):
        with open(file, "r") as f:
            policies.append(json.load(f))
    return policies


def load_firewall_rules(path):
    rules = []
    with open(path, "r") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rules.append(row)
    return rules


def build_graph():
    G = nx.DiGraph()

    assets = load_assets("data/assets.json")
    for asset in assets:
        G.add_node(
            asset["id"],
            type=asset["type"],
            criticality=asset.get("criticality", "normal")
        )
    return G

if __name__ == "__main__":
    graph = build_graph()
    print("Nodes in graph:")
    for node, data in graph.nodes(data=True):
        print(node, data)

