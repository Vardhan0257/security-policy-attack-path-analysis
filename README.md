# Unified Security Policy Conflict & Attack-Path Analysis Framework

This project explores how interactions between security policies (identity and network controls) can unintentionally create hidden attack paths.

The goal is to demonstrate architectural security reasoning using a controlled, synthetic environment — not to build an enterprise-scale system.

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

## Technologies Used
- Python
- NetworkX
- Git
- VS Code

---

## Disclaimer
This project is designed for academic and learning purposes. It demonstrates architectural reasoning under defined assumptions and limitations and does not claim enterprise completeness or real-world exploit accuracy.
