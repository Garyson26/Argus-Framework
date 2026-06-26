# Contributing to Argus

First off, thank you for considering contributing to **Argus**! 🎉 Your contributions help make cloud security auditing accessible to everyone.

## 📋 Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [How to Contribute](#how-to-contribute)
- [Pull Request Process](#pull-request-process)
- [Coding Standards](#coding-standards)
- [Testing Guidelines](#testing-guidelines)

---

## 📜 Code of Conduct

This project adheres to the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code. Please report unacceptable behavior to the maintainers.

---

## 🚀 Getting Started

### Prerequisites

- **Python 3.9+** 
- **Docker & Docker Compose** (for running databases)
- **Git** for version control
- **AWS CLI** configured (for testing cloud scans)

### Development Setup

```bash
# 1. Fork and clone the repository
git clone https://github.com/Garyson26/Argus-Framework.git
cd Argus

# 2. Create a virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# 3. Install development dependencies
pip install -e ".[dev]"

# 4. Start required services
docker-compose up -d postgres redis neo4j

# 5. Initialize the database
argus init-db

# 6. Install pre-commit hooks
pre-commit install

# 7. Verify your setup
pytest
```

---

## 🤝 How to Contribute

### Reporting Bugs

Before creating a bug report, please check existing issues to avoid duplicates.

**When reporting a bug, include:**
- Your operating system and Python version
- Steps to reproduce the issue
- Expected vs actual behavior
- Error messages and stack traces
- Screenshots if applicable

### Suggesting Features

Feature requests are welcome! Please provide:
- A clear description of the feature
- The problem it solves
- Example use cases
- Any potential implementation ideas

### Contributing Code

1. **Find an issue** to work on, or create a new one
2. **Comment on the issue** to let others know you're working on it
3. **Fork the repository** and create your branch
4. **Make your changes** following our coding standards
5. **Write tests** for your changes
6. **Submit a pull request**

---

## 📤 Pull Request Process

### Before Submitting

- [ ] Update documentation if needed
- [ ] Add tests for new functionality
- [ ] Ensure all tests pass (`pytest`)
- [ ] Run code formatters (`black`, `isort`)
- [ ] Run type checker (`mypy src/`)
- [ ] Run linter (`flake8 src/`)

### PR Guidelines

1. **Use a clear, descriptive title**
2. **Reference related issues** using `Fixes #123` or `Closes #123`
3. **Provide a detailed description** of your changes
4. **Include screenshots** for UI changes
5. **Keep PRs focused** - one feature/fix per PR

### Review Process

1. Maintainers will review your PR
2. Address any requested changes
3. Once approved, your PR will be merged
4. Celebrate! 🎉

---

## 📝 Coding Standards

### Python Style

We use the following tools to maintain code quality:

| Tool | Purpose | Command |
|------|---------|---------|
| **Black** | Code formatting | `black src/ tests/` |
| **isort** | Import sorting | `isort src/ tests/` |
| **flake8** | Linting | `flake8 src/` |
| **mypy** | Type checking | `mypy src/` |

### Code Guidelines

```python
# ✅ Good - Type hints and docstrings
def scan_bucket(bucket_name: str, region: str = "us-east-1") -> dict:
    """
    Scan an S3 bucket for security misconfigurations.
    
    Args:
        bucket_name: Name of the S3 bucket to scan
        region: AWS region where the bucket is located
        
    Returns:
        Dictionary containing scan results with findings
    """
    ...

# ❌ Bad - No type hints or documentation
def scan_bucket(bucket_name, region="us-east-1"):
    ...
```

### Commit Messages

Use clear, descriptive commit messages:

```
feat: add support for CloudWatch Logs scanning
fix: resolve false positive in S3 public access detection
docs: update installation instructions for Windows
test: add unit tests for IAM analyzer module
refactor: simplify secret pattern matching logic
```

---

## 🧪 Testing Guidelines

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage report
pytest --cov=src --cov-report=html

# Run specific test file
pytest tests/unit/test_secret_scanner.py -v

# Run tests matching a pattern
pytest -k "test_s3" -v
```

### Writing Tests

```python
import pytest
from src.scanners.secrets import SecretScanner

class TestSecretScanner:
    """Tests for the secret scanning module."""
    
    def test_detect_aws_access_key(self):
        """Should detect AWS access key in code."""
        scanner = SecretScanner()
        content = 'AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"'
        
        findings = scanner.scan_content(content)
        
        assert len(findings) == 1
        assert findings[0].pattern_name == "aws_access_key"
```

### Test Categories

- `tests/unit/` - Unit tests for individual functions
- `tests/integration/` - Integration tests with mocked AWS
- `tests/e2e/` - End-to-end tests (requires Docker)

---

## 🏷️ Issue Labels

| Label | Description |
|-------|-------------|
| `bug` | Something isn't working |
| `enhancement` | New feature or request |
| `documentation` | Improvements to docs |
| `good first issue` | Good for newcomers |
| `help wanted` | Extra attention needed |
| `security` | Security-related issues |

---

## 💬 Getting Help

- **GitHub Issues** - For bugs and feature requests
- **Discussions** - For questions and ideas

---

<p align="center">
  <strong>Thank you for contributing to Argus! 🛡️</strong>
  <br>
  <sub>Together, we make cloud security accessible to everyone.</sub>
</p>
