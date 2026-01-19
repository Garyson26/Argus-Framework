# Changelog

All notable changes to FuFuFaFa will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.2.0] - 2026-01-20

### Fixed
- **Critical**: Resolved test failures caused by missing `pydantic_settings` module import
- **Python 3.12+ Compatibility**: Replaced deprecated `datetime.utcnow()` with timezone-aware `datetime.now(timezone.utc)` in `base.py` and `iac/scanner.py`
- **Class Name Typo**: Renamed `IaCSCanner` to `IaCScanner` for consistency across all modules
- **Mutable Default Argument**: Fixed dataclass mutable default issue in `SecretPattern` class
- **Memory Leak Prevention**: Changed `ThreadPoolExecutor.shutdown(wait=False)` to `wait=True` in secret scanner
- **Pytest Configuration**: Updated deprecated `asyncio_mode` to `asyncio_default_fixture_loop_scope` for pytest-asyncio 0.23+

### Added
- MIT `LICENSE` file (as referenced in pyproject.toml)
- This `CHANGELOG.md` file to track project changes

### Changed
- Updated version from 0.1.0 to 0.2.0

---

## [0.1.0] - 2026-01-15

### Added
- **🔐 Secret Scanner**: Pattern-based detection with 50+ regex rules for AWS keys, GitHub tokens, private keys, API credentials, and more
- **☁️ AWS Cloud Scanner**: Parallel multi-region scanning for S3, EC2, IAM, RDS, Lambda, VPC misconfigurations
- **📜 IaC Scanner**: Checkov-powered scanning for Terraform, CloudFormation, Serverless, and Kubernetes
- **👤 IAM Analyzer**: Neo4j graph-based privilege escalation path detection
- **🔄 Parallel Processing**: Async/await architecture with concurrent region and file scanning
- **📊 Rich CLI**: Beautiful command-line interface using Typer and Rich
- **🗄️ Database Support**: PostgreSQL for persistence, Neo4j for IAM graphs, Redis for caching
- **📈 Progress Tracking**: Real-time progress bars with ETA estimation
- **🔧 Configuration**: Pydantic-based settings with environment variable support
- **🐳 Docker Support**: docker-compose.yaml for one-command infrastructure setup

### Technical Stack
- Python 3.9+ with full type hints
- Async/await throughout with asyncio
- boto3 for AWS API integration
- Checkov for IaC security scanning
- GitPython for repository history scanning
- Shannon entropy analysis for secret detection
- Rich progress bars and styled console output

---

## Timeline

| Date | Milestone |
|------|-----------|
| 2026-01-20 | v0.2.0 - Bug fixes and quality improvements |
| 2026-01-15 | v0.1.0 - Initial release with core scanning features |
| 2026-01-10 | Project structure and architecture design |
| 2026-01-05 | Project inception |
