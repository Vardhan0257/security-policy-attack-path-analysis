import json
import csv
import networkx as nx
from pathlib import Path


def load_assets(path):
    try:
        with open(path, "r") as f:
            return json.load(f)["assets"]
    except FileNotFoundError:
        raise FileNotFoundError(f"Assets file not found: {path}")
    except json.JSONDecodeError:
        raise ValueError(f"Invalid JSON in assets file: {path}")


def load_iam_policies(path):
    policies = []
    try:
        for file in Path(path).glob("*.json"):
            with open(file, "r") as f:
                policies.append(json.load(f))
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON in IAM policy file: {e}")
    return policies


def load_firewall_rules(path):
    rules = []
    try:
        with open(path, "r") as f:
            reader = csv.DictReader(f)
            for row in reader:
                rules.append(row)
    except FileNotFoundError:
        raise FileNotFoundError(f"Firewall rules file not found: {path}")
    except csv.Error:
        raise ValueError(f"Invalid CSV in firewall rules file: {path}")
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
    
    firewall_rules = load_firewall_rules("data/firewall_rules/rules.csv")
    for rule in firewall_rules:
        if rule["action"] == "allow":
            G.add_edge(
                rule["source"],
                rule["destination"],
                type="network"
            )

    iam_policies = load_iam_policies("data/iam_policies")
    for policy in iam_policies:
        if policy["Effect"] == "Allow":
            G.add_edge(
                policy["Principal"],
                policy["Resource"],
                type="iam",
                action=",".join(policy["Action"]),
                condition=policy.get("Condition")
            )

    return G

if __name__ == "__main__":
    graph = build_graph()
    print("Nodes:")
    for node, data in graph.nodes(data=True):
        print(node, data)

    print("\nNetwork edges:")
    for src, dst, data in graph.edges(data=True):
        if data["type"] == "network":
            print(f"{src} -> {dst}")

    print("\nIAM edges:")
    for src, dst, data in graph.edges(data=True):
        if data["type"] == "iam":
            print(f"{src} -> {dst} ({data['action']})")



