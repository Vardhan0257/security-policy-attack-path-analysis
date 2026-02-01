# Unified Security Policy Conflict & Attack-Path Analysis Framework

## Overview
This project demonstrates how interactions between security policies—specifically identity permissions and network access rules—can unintentionally create hidden attack paths within an environment.

The system models a small, controlled environment and converts security policies into a graph representation to automatically discover and explain potential attack paths from an external entity to sensitive assets.

This project focuses on architectural security reasoning rather than enterprise-scale deployment or exploit execution.

---

## Key Features
- Graph-based modeling of assets, identities, and policies
- Automatic discovery of attack paths caused by policy interactions
- Human-readable explanations showing which policies enable each step
- Simple, transparent risk prioritization using heuristics

---

## System Scope
- Uses a controlled, synthetic environment
- Models snapshot-based policies only
- Focuses on policy interaction analysis, not live exploitation
- Intended as a reasoning prototype, not a production system

---

## How It Works
1. Assets are represented as graph nodes
2. Network firewall rules define movement edges
3. IAM policies define privilege edges
4. Graph traversal identifies attack paths
5. Each path is explained and risk-ranked

---

## Correctness-First Policy Semantics

This project intentionally prioritizes *semantic correctness* over scale.

Unlike topology-only attack graph models, access paths in this system are considered valid **only if policy conditions are satisfied under a given execution context**. Identity permissions may exist structurally but are pruned at analysis time if contextual constraints (e.g., source origin) are not met.

This design demonstrates how effective exploitability depends not just on connectivity, but on *policy semantics*, and highlights why many naive attack-path tools overestimate risk.

The controlled scope is a deliberate tradeoff to focus on reasoning accuracy rather than enterprise-scale data ingestion.

---

## Technologies Used
- Python
- NetworkX
- Git
- VS Code

---

## Disclaimer
This project is designed for academic and learning purposes. It demonstrates architectural reasoning under defined assumptions and limitations and does not claim enterprise completeness or real-world exploit accuracy.
