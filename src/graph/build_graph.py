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
    return G


if __name__ == "__main__":
    print("Graph builder initialized")
