import json
import csv
import networkx as nx
import logging
from pathlib import Path
from typing import List, Dict, Any


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def load_assets(path: str) -> List[Dict[str, Any]]:
    """
    Load asset definitions from JSON file.
    
    Args:
        path: Relative path to assets file
        
    Returns:
        List of asset dictionaries
        
    Raises:
        FileNotFoundError: If file doesn't exist
        ValueError: If JSON is invalid
    """
    try:
        full_path = f"src/data/{path}"
        with open(full_path, "r") as f:
            data = json.load(f)
            assets = data.get("assets", [])
            logger.info(f"Loaded {len(assets)} assets from {path}")
            return assets
    except FileNotFoundError:
        logger.error(f"Assets file not found: {full_path}")
        raise FileNotFoundError(f"Assets file not found: {full_path}")
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in assets file: {e}")
        raise ValueError(f"Invalid JSON in assets file: {e}")


def load_iam_policies(path: str) -> List[Dict[str, Any]]:
    """
    Load IAM policy definitions from JSON files.
    
    Args:
        path: Relative path to directory containing policy files
        
    Returns:
        List of policy dictionaries
        
    Raises:
        ValueError: If JSON is invalid
    """
    policies = []
    try:
        policy_dir = Path(f"src/data/{path}")
        if not policy_dir.exists():
            logger.warning(f"Policy directory not found: {policy_dir}")
            return []
        
        for file in policy_dir.glob("*.json"):
            try:
                with open(file, "r") as f:
                    policy = json.load(f)
                    policies.append(policy)
                    logger.info(f"Loaded policy from {file.name}")
            except json.JSONDecodeError as e:
                logger.error(f"Invalid JSON in policy file {file.name}: {e}")
                raise ValueError(f"Invalid JSON in policy file {file.name}: {e}")
        
        logger.info(f"Loaded {len(policies)} policies from {path}")
        return policies
    except Exception as e:
        logger.error(f"Error loading IAM policies: {e}")
        raise


def load_firewall_rules(path: str) -> List[Dict[str, str]]:
    """
    Load firewall rules from CSV file.
    
    Args:
        path: Relative path to CSV file
        
    Returns:
        List of rule dictionaries
        
    Raises:
        FileNotFoundError: If file doesn't exist
        ValueError: If CSV is invalid
    """
    rules = []
    try:
        full_path = f"src/data/{path}"
        with open(full_path, "r") as f:
            reader = csv.DictReader(f)
            if not reader.fieldnames:
                raise ValueError("CSV file is empty or has no headers")
            
            for row in reader:
                rules.append(row)
            
            logger.info(f"Loaded {len(rules)} firewall rules from {path}")
            return rules
    except FileNotFoundError:
        logger.error(f"Firewall rules file not found: {full_path}")
        raise FileNotFoundError(f"Firewall rules file not found: {full_path}")
    except csv.Error as e:
        logger.error(f"Invalid CSV in firewall rules file: {e}")
        raise ValueError(f"Invalid CSV in firewall rules file: {e}")


def build_graph() -> nx.DiGraph:
    """
    Build security graph from policy and asset definitions.
    
    Graph contains:
    - Nodes: Assets (with type and criticality metadata)
    - Edges: Network rules (firewall) and IAM policies
    
    Returns:
        NetworkX DiGraph with security policies modeled as edges
    """
    logger.info("Building security graph...")
    G = nx.DiGraph()

    # Load and add assets as nodes
    try:
        assets = load_assets("assets.json")
        for asset in assets:
            G.add_node(
                asset["id"],
                type=asset["type"],
                criticality=asset.get("criticality", "normal"),
                description=asset.get("description", "")
            )
        logger.info(f"Added {len(assets)} asset nodes to graph")
    except Exception as e:
        logger.error(f"Error loading assets: {e}")
        raise
    
    # Load and add network edges (firewall rules)
    try:
        firewall_rules = load_firewall_rules("firewall_rules/rules.csv")
        network_edge_count = 0
        for rule in firewall_rules:
            if rule.get("action", "").lower() == "allow":
                source = rule.get("source")
                destination = rule.get("destination")
                if source and destination:
                    G.add_edge(
                        source,
                        destination,
                        type="network",
                        rule_name=rule.get("rule_name", "firewall_rule"),
                        protocol=rule.get("protocol", "any"),
                        port=rule.get("port", "any")
                    )
                    network_edge_count += 1
        logger.info(f"Added {network_edge_count} network edges to graph")
    except Exception as e:
        logger.error(f"Error loading firewall rules: {e}")
        raise
    
    # Load and add IAM edges (identity & access management policies)
    try:
        iam_policies = load_iam_policies("iam_policies")
        iam_edge_count = 0
        for policy in iam_policies:
            if policy.get("Effect", "").lower() == "allow":
                principal = policy.get("Principal")
                resource = policy.get("Resource")
                if principal and resource:
                    G.add_edge(
                        principal,
                        resource,
                        type="iam",
                        action=",".join(policy.get("Action", [])) if isinstance(policy.get("Action"), list) else policy.get("Action", ""),
                        condition=policy.get("Condition"),
                        policy_name=policy.get("PolicyName", "default")
                    )
                    iam_edge_count += 1
        logger.info(f"Added {iam_edge_count} IAM edges to graph")
    except Exception as e:
        logger.error(f"Error loading IAM policies: {e}")
        raise
    
    logger.info(f"Graph construction complete: {G.number_of_nodes()} nodes, {G.number_of_edges()} edges")
    return G


if __name__ == "__main__":
    graph = build_graph()
    print("\n" + "=" * 80)
    print("GRAPH STRUCTURE SUMMARY")
    print("=" * 80)
    print(f"Total Nodes: {graph.number_of_nodes()}")
    print(f"Total Edges: {graph.number_of_edges()}")
    
    print("\nAsset Nodes:")
    for node, data in graph.nodes(data=True):
        print(f"  • {node}: type={data.get('type')}, criticality={data.get('criticality')}")

    print("\nNetwork Edges (Firewall Rules):")
    network_edges = [(src, dst, data) for src, dst, data in graph.edges(data=True) if data.get("type") == "network"]
    for src, dst, data in network_edges[:5]:
        print(f"  • {src} → {dst} ({data.get('rule_name')})")
    if len(network_edges) > 5:
        print(f"  ... and {len(network_edges) - 5} more")

    print("\nIAM Edges (Permission Policies):")
    iam_edges = [(src, dst, data) for src, dst, data in graph.edges(data=True) if data.get("type") == "iam"]
    for src, dst, data in iam_edges[:5]:
        condition_str = f" [Condition: {data.get('condition')}]" if data.get('condition') else ""
        print(f"  • {src} → {dst} ({data.get('action')}){condition_str}")
    if len(iam_edges) > 5:
        print(f"  ... and {len(iam_edges) - 5} more")
    print("=" * 80 + "\n")



