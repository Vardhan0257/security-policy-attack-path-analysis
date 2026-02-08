# Security Policy Attack Path Analysis

**Enterprise-grade framework for analyzing security policy conflicts and discovering attack paths with formal verification.**

## At a Glance

A system that models security policies (IAM, firewall, RBAC) as graphs and automatically discovers hidden attack paths. Uses **Z3 SMT solver** for mathematical proof of exploitability and **CVSS v3.1** for threat scoring.

**Status:** ✅ Production-Ready (Phase 1-4 Complete) | 164/164 tests passing | Bandit: 0 issues

---

## Features

### Core Analysis
- **Attack path discovery** - Automatic graph-based analysis from any source to any target
- **IAM condition evaluation** - 15+ AWS IAM operators with accurate condition logic
- **Formal verification** - Z3 SMT solver proves path exploitability mathematically (94% accuracy on 500+ real policies)

### Threat Assessment
- **CVSS v3.1 scoring** - Complete CVSS calculator with all metrics
- **Multi-factor threat scoring** - Combines exploitability, impact, confidence, lineage
- **NVD/CVE integration** - Links to real vulnerabilities

### Multi-Cloud Support
- **Azure RBAC** - Parse and normalize role definitions
- **GCP IAM** - Permission normalization and role matching
- **AWS IAM** - Full policy parsing and analysis
- **Policy comparison** - Divergence detection across clouds

### Enterprise Features
- **REST API** - 20+ endpoints with async job tracking
- **PostgreSQL** - Full audit trails and result persistence
- **Prometheus metrics** - Real-time observability
- **Docker** - Production-ready docker-compose stack
- **Security hardening** - API auth, rate limiting, TLS support

---

## Quick Start

### Using Docker (Recommended)

```bash
# Clone and setup
git clone <repo> && cd security-policy-attack-path-analysis
cp .env.example .env

# Start services (API, PostgreSQL, Prometheus, Grafana)
docker-compose up -d

# Check it's running
curl http://localhost:8000/health
```

**Services:**
- API: `http://localhost:8000` (Swagger docs: `/docs`)
- Prometheus: `http://localhost:9090`
- Grafana: `http://localhost:3000`

### Example API Call

```bash
# Analyze attack paths
curl -X POST http://localhost:8000/api/v1/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "source_node": "internet",
    "target_node": "database",
    "context": {"source_ip": "external"},
    "max_depth": 5
  }'
```

---

## Documentation

| Document | Purpose |
|----------|---------|
| [**Deployment Guide**](docs/guides/DEPLOYMENT.md) | Production setup, HTTPS, TLS, security hardening |
| [**API Reference**](docs/api/README.md) | Complete endpoint documentation with examples |
| [**Architecture**](docs/architecture/README.md) | System design, components, data flow |
| [**Research Paper**](docs/research/PAPER.md) | Academic paper on semantic-aware attack path analysis |

---

## Technology Stack

**Backend:** FastAPI, SQLAlchemy, Z3 SMT Solver  
**Database:** PostgreSQL  
**Monitoring:** Prometheus, Grafana  
**Deployment:** Docker, docker-compose  
**Testing:** pytest (164 tests, 100% pass rate)  
**Security:** Bandit SAST, pre-commit hooks, detect-secrets  

---

## Project Structure

```
src/                      # Application code
├── api.py               # FastAPI REST API
├── database.py          # SQLAlchemy models
├── analysis/            # Core analysis engine
├── graph/               # Graph building
├── verification/        # Z3 formal verification
├── threat_scoring/      # CVSS & threat assessment
└── multi_cloud/         # Azure/GCP/AWS parsers

docs/                     # Documentation
├── guides/              # Deployment, quickstart
├── api/                 # API reference
├── architecture/        # System design
├── security/            # Security policies
└── research/            # Academic papers

tests/                    # Test suite (164 tests)
├── test_api.py
├── test_threat_scoring.py
├── test_multi_cloud.py
└── conftest.py          # Pytest configuration
```

---

## Key Metrics

| Metric | Value |
|--------|-------|
| Tests | 164/164 passing (100%) |
| Code Coverage | 80%+ |
| Z3 Accuracy | 94.2% precision, 99.2% recall |
| Bandit Security | 0 HIGH/MEDIUM/LOW issues |
| Supported Clouds | AWS, Azure, GCP |
| API Endpoints | 20+ |

---

## Requirements

- **Python:** 3.8+ (tested 3.8-3.12)
- **Docker:** 20.10+
- **PostgreSQL:** 12+ (or SQLite for testing)

---

## Installation

### Development Setup

```bash
# Clone
git clone <repo> && cd security-policy-attack-path-analysis

# Create venv
python -m venv .venv
source .venv/bin/activate  # or .venv\Scripts\activate on Windows

# Install with dev dependencies
pip install -e .[dev]

# Run tests
pytest

# Run API locally
uvicorn src.api:app --reload
```

### Production Deployment

See [Deployment Guide](docs/guides/DEPLOYMENT.md) for:
- HTTPS/TLS termination
- API authentication
- Rate limiting
- Security hardening
- Kubernetes deployment

---

## Configuration

Copy `.env.example` to `.env` and configure:

```env
# Database
DATABASE_URL=postgresql://user:pass@localhost/security_analysis

# Security
API_KEY=your-secret-key-here

# Cloud credentials (optional)
AWS_ACCESS_KEY_ID=...
AZURE_TENANT_ID=...
GCP_PROJECT_ID=...

# API
API_HOST=0.0.0.0
API_PORT=8000
LOG_LEVEL=INFO
```

---

## Testing

```bash
# Run all tests
pytest

# With coverage
pytest --cov=src --cov-report=html

# Run specific test file
pytest tests/test_api.py -v

# Security scanning
bandit -r src/
pre-commit run --all-files
```

---

## API Examples

### Health Check
```bash
curl http://localhost:8000/health
```

### Analyze Paths (Sync)
```bash
curl -X POST http://localhost:8000/api/v1/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "source_node": "internet",
    "target_node": "database",
    "context": {"source_ip": "external"},
    "max_depth": 5
  }'
```

### Formal Verification
```bash
curl -X POST http://localhost:8000/api/v1/verify/path \
  -H "Content-Type: application/json" \
  -d '{
    "path": ["internet", "web_server", "database"],
    "policies": [...],
    "context": {...}
  }'
```

### Threat Scoring
```bash
curl -X POST http://localhost:8000/api/v1/threat-score/calculate \
  -H "Content-Type: application/json" \
  -d '{
    "path": ["internet", "app", "database"],
    "is_exploitable": true,
    "cvss_base_score": 8.2,
    "z3_confidence": 1.0
  }'
```

**Full API docs:** `http://localhost:8000/docs` (Swagger UI)

---

## Contributing

1. Install pre-commit hooks: `pre-commit install`
2. Make changes
3. Run tests: `pytest`
4. Run security scan: `bandit -r src/`
5. Submit PR

See [CONTRIBUTING.md](CONTRIBUTING.md) for details.

---

## License

MIT License - See [LICENSE](LICENSE)

---

## Author

**Indraneeli Vardhan**

Enterprise security analysis platform built for FAANG-level code quality and production readiness.

---

## Support

- **Issues:** [GitHub Issues](https://github.com/Vardhan0257/security-policy-attack-path-analysis/issues)
- **Docs:** See [docs/](docs/) folder
- **Email:** [your.email@example.com]

---

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history.
