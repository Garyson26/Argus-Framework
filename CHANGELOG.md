# Changelog

All notable changes to Argus will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Changed
- **Project renamed**: `FuFuFaFa Framework` is now **Argus** - Automated Risk &
  Governance Unified Scanner. The CLI command is `argus`, the PyPI distribution
  is `argus-cloud`, environment variables use the `ARGUS_` prefix, and Docker
  services, Celery task names, and the Postgres database are renamed to match.
- **License changed** from MIT to the Apache License, Version 2.0. The original
  MIT copyright and permission notice is preserved in `NOTICE`.
- Repository moved to https://github.com/Garyson26/Argus-Framework
- New project banner (`assets/banner.png`), now a true PNG at 1600x400.

### Migration notes
- Rename any `FUFUFAFA_*` environment variables to `ARGUS_*`; the old names are
  ignored and settings silently fall back to defaults.
- The Postgres database, user, and password default to `argus` / `argus_secret`.
  Existing volumes still hold the `fufufafa` database and need renaming or
  recreating.
- Queued Celery tasks named `fufufafa.tasks.*` will not route to the renamed
  `argus.tasks.*` handlers.

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
