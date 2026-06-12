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

