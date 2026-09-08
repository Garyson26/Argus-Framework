# Checkov Security Policy

## Supported Versions

We support the latest version of Argus. Please update to the most recent release to ensure you have the latest security patches.

| Version | Supported          |
| ------- | ------------------ |
| Latest  | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

We take security seriously. If you discover a security vulnerability within Argus, please follow these steps:

1.  **Do not open a public issue.** Security vulnerabilities should be handled discreetly to protect users.
2.  **Email us.** Send a detailed report to security@argus.example.com [Replace with actual email if available, or instruct to use GitHub Security Advisories].
    *   Include a description of the vulnerability.
    *   Provide steps to reproduce the issue.
    *   Attach any relevant proof-of-concept code or screenshots.
3.  **Wait for a response.** We will acknowledge your report within 48 hours and provide an estimated timeline for a fix.

## Security Best Practices for Users

When using Argus, we recommend the following best practices:

*   **Keep Argus updated:** regularly run `pip install --upgrade argus-cloud` or pull the latest Docker image.
*   **Secure your environment:** Ensure the machine running Argus is secure and has appropriate access controls.
*   **Review scan results:** Always verify findings before taking action, especially for automated remediation (if applicable).
*   **Protect your reports:** Scan reports may contain sensitive information about your infrastructure. Store them securely.

## License

This project is licensed under the Apache License, Version 2.0.
See [LICENSE](LICENSE) for details.
