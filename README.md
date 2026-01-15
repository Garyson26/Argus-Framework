<p align="center">
  <img src="assets/banner.png" alt="FuFuFaFa Banner" width="100%"/>
</p>

# 🛡️ FuFuFaFa Framework

<p align="center">
  <a href="https://github.com/Masriyan/FuFuFaFa/blob/main/LICENSE">
    <img src="https://img.shields.io/github/license/Masriyan/FuFuFaFa?style=for-the-badge&color=blue" alt="License">
  </a>
  <a href="https://github.com/Masriyan/FuFuFaFa/commits/main">
    <img src="https://img.shields.io/github/last-commit/Masriyan/FuFuFaFa?style=for-the-badge&color=green" alt="Last Commit">
  </a>
  <a href="https://github.com/Masriyan/FuFuFaFa/issues">
    <img src="https://img.shields.io/github/issues/Masriyan/FuFuFaFa?style=for-the-badge&color=orange" alt="Issues">
  </a>
  <a href="https://pypi.org/project/fufufafa/">
    <img src="https://img.shields.io/pypi/v/fufufafa?style=for-the-badge&color=yellow" alt="PyPI">
  </a>
  <a href="https://www.python.org/">
    <img src="https://img.shields.io/badge/Python-3.9%2B-blue?style=for-the-badge&logo=python&logoColor=white" alt="Python">
  </a>
</p>

<p align="center">
  <strong>Framework for Unified Flaw & Fault Auditing</strong>
  <br>
  The ultimate AWS Cloud Security Audit Framework that makes security auditing <i>so easy, you can do it even when you're sleepy!</i> 😴
</p>

<p align="center">
  <a href="#-key-features">Key Features</a> •
  <a href="#-how-it-works">How It Works</a> •
  <a href="#-installation">Installation</a> •
  <a href="#-quick-start">Quick Start</a> •
  <a href="#-usage-guide">Usage Guide</a> •
  <a href="CONTRIBUTING.md">Contributing</a>
</p>

---

## 🌟 Key Features

<table>
  <tr>
    <td width="50%">
      <h3>🔐 Secret Leak Detection</h3>
      <p>Scan repositories for hardcoded credentials with over 50+ patterns including AWS keys, API tokens, and private keys. Includes Shannon entropy detection.</p>
    </td>
    <td width="50%">
      <h3>☁️ AWS Misconfiguration</h3>
      <p>Comprehensive checks for S3, EC2, IAM, RDS, Lambda, VPC, and CloudTrail to ensure your cloud infrastructure follows best practices.</p>
    </td>
  </tr>
  <tr>
    <td width="50%">
      <h3>📜 IaC Scanning</h3>
      <p>Analyze Terraform, CloudFormation, Serverless, and Kubernetes files for security flaws before deployment using the Checkov engine.</p>
    </td>
    <td width="50%">
      <h3>👤 IAM Permission Analysis</h3>
      <p>Visualize and analyze IAM permissions to detect privilege escalation paths and overly permissive policies using graph-based mapping.</p>
    </td>
  </tr>
</table>

---

## 🔄 How It Works

FuFuFaFa streamlines your security auditing workflow. Here is the process flow:

```mermaid
graph TD
    A[Start Scan] --> B{Select Scan Type}
    
    B -->|Secrets| C[Cloning Repository]
    C --> D[Regex & Entropy Analysis]
    D --> E[Git History Scan]
    
    B -->|Cloud| F[AWS API Calls]
    F --> G[Resource Enumeration]
    G --> H[Security Rule Check]
    
    B -->|IaC| I[Parse Infrastructure Code]
    I --> J[Checkov Policy Scan]
    
    B -->|IAM| K[Fetch IAM Policies]
    K --> L[Neo4j Graph Building]
    L --> M[Privilege Path Analysis]
    
    E --> N[Generate Report]
    H --> N
    J --> N
    M --> N
    
    N --> O((End))
    
    style A fill:#4F46E5,stroke:#333,stroke-width:2px,color:#fff
    style N fill:#10B981,stroke:#333,stroke-width:2px,color:#fff
    style O fill:#EF4444,stroke:#333,stroke-width:2px,color:#fff
```

---

## 🚀 Installation

### Prerequisites

- **Python 3.9+**
- **Docker & Docker Compose** (for persistent storage)
- **AWS CLI** configured (for cloud scanning)

### Quick Install

```bash
# 1. Clone the repository
git clone https://github.com/Masriyan/FuFuFaFa.git
cd FuFuFaFa

# 2. Set up virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# 3. Install dependencies
pip install -e ".[dev]"

# 4. Start database services
docker-compose up -d postgres redis neo4j

# 5. Initialize database
fufufafa init-db
```

---

## ⚡ Quick Start

Get up and running in seconds!

```bash
# 1. Verify installation
fufufafa --version

# 2. Run a secret scan on a local repo
fufufafa secret scan ./your-project

# 3. Scan your default AWS profile
fufufafa cloud scan

# 4. View help for more commands
fufufafa --help
```

---

## 📖 Usage Guide

### 🕵️ Secret Scanning
Find hidden secrets in your code, even deep in git history.

```bash
fufufafa secret scan ./target-repo --history
```
**Options:**
- `--history`: Scan full git history
- `--entropy 4.5`: Set custom entropy threshold
- `--json`: Output results in JSON format

### ☁️ Cloud Auditing
Audit your AWS environment for security gaps.

```bash
fufufafa cloud scan --profile production --regions us-east-1,us-west-2
```
**Options:**
- `--profile`: Specify AWS CLI profile
- `--services s3,ec2,iam`: Contextual scanning
- `--fix`: Attempt auto-remediation (Use with caution!)

### 🏗️ IaC Security
Shift left by scanning your infrastructure code.

```bash
fufufafa iac scan ./terraform-files
```

### 🕸️ IAM Analysis
Visualize permission paths and find dangerous roles.

```bash
fufufafa iam analyze --graph
```
*Note: Requires Neo4j service to be running.*

---

## 🏗️ Architecture

The FuFuFaFa framework is built for modularity and scalability.

```mermaid
C4Context
    title System Context Diagram for FuFuFaFa

    Person(user, "Security Auditor", "Uses FuFuFaFa to audit cloud security.")
    System(fufufafa, "FuFuFaFa Framework", "CLI tool for scanning secrets, cloud config, IaC, and IAM.")
    
    System_Ext(aws, "AWS Cloud", "Target environment for auditing.")
    System_Ext(neo4j, "Neo4j Database", "Stores IAM graph relationships.")
    System_Ext(postgres, "PostgreSQL", "Stores finding results and reports.")
    
    Rel(user, fufufafa, "Runs CLI commands")
    Rel(fufufafa, aws, "Reads configuration via API")
    Rel(fufufafa, neo4j, "Queries/Updates Graph")
    Rel(fufufafa, postgres, "Persists Audit Data")
```

---

## 🤝 Community & Support

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

- **Found a bug?** Open an [Issue](https://github.com/Masriyan/FuFuFaFa/issues)
- **Security concern?** See [SECURITY.md](SECURITY.md)
- **Code of Conduct?** See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)

---

<p align="center">
  Made with ❤️ and ☕ by the FuFuFaFa Team
</p>
