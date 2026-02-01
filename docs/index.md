# Security Policy Attack Path Analysis Documentation

## Overview

This project provides a framework for analyzing security policy conflicts and discovering attack paths in a controlled environment, emphasizing semantic correctness over naive topology-based approaches.

## Installation

```bash
pip install -e .
```

## Usage

### Command Line

```bash
attack-path-analyzer --source internet --target database --source_ip internal
```

### Python API

```python
from src.analysis.find_paths import find_attack_paths
from src.graph.build_graph import build_graph

graph = build_graph()
context = {"source_ip": "internal"}
paths = find_attack_paths(graph, "internet", "database", context)
```

## API Reference

- `build_graph()`: Constructs the graph from data files.
- `find_attack_paths(graph, source, target, context)`: Finds valid attack paths.
- `ConditionEvaluator(context)`: Evaluates policy conditions.

## Contributing

See CONTRIBUTING.md for guidelines.