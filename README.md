# SonarQube Security Assessment - Vulnerable Web Application

## Project Overview
This project demonstrates a **Static Application Security Testing (SAST) analysis** of a deliberately vulnerable web application using **SonarQube Community Edition**.  
The goal is to identify security vulnerabilities, code quality issues, and provide remediation recommendations.  

This work is part of my **Application Security portfolio** and was performed in a controlled lab environment.

---

## Tools Used
- **SonarQube Community Edition** – Static code analysis
- **Python / PHP / JS** – Vulnerable web application
- **VS Code** – Code editing and report preparation

---

## Findings Summary
The table below summarizes the vulnerabilities discovered, including severity, CVSS score, CWE reference, OWASP Top 10, ASVS, and OTG mappings.

| # | Title | Lang | Severity | CVSS | CWE | OWASP | ASVS | OTG |
|---|---|---|---|---|---|---|---|---|
| 1 | Hardcoded Password | PHP | 🔴 Critical | 9.8 | CWE-798 | A07:2021 | V2.10 | OTG-AUTHN-007 |
| 2 | 0.0.0.0 Binding (1) | Python | 🟠 High | 7.5 | CWE-668 | A05:2021 | V14.1 | OTG-CONFIG-006 |
| 3 | postMessage Wildcard | JS | 🟠 High | 7.4 | CWE-346 | A03:2021 | V5.2 | OTG-CLIENT-010 |
| 4 | No Origin Check | JS | 🟠 High | 7.4 | CWE-346 | A03:2021 | V5.2 | OTG-CLIENT-010 |
| 5 | 0.0.0.0 Binding (2) | Python | 🟠 High | 7.5 | CWE-668 | A05:2021 | V14.1 | OTG-CONFIG-006 |
| 6 | 0.0.0.0 Binding (3) | Python | 🟠 High | 7.5 | CWE-668 | A05:2021 | V14.1 | OTG-CONFIG-006 |
| 7 | XXE via loadXML | PHP | 🔴 Critical | 9.1 | CWE-611 | A05:2021 | V14.5 | OTG-INPVAL-007 |
| 8 | XXE via dom->loadXML | PHP | 🔴 Critical | 9.1 | CWE-611 | A05:2021 | V14.5 | OTG-INPVAL-007 |

> **Legend:**  
> 🔴 Critical – Severe vulnerability that could lead to data breach or code compromise  
> 🟠 High – High risk, requires prompt remediation  

---

## Key Takeaways
- Static analysis tools like SonarQube help quickly identify security and maintainability issues.
- Proper documentation of vulnerabilities is essential for remediation and reporting.
- Integrating SAST into CI/CD pipelines significantly improves application security.

---

## Recommendations
1. Integrate SonarQube scans into automated CI/CD workflows.
2. Replace hardcoded secrets with secure storage (environment variables or secret managers).
3. Educate developers on secure coding practices.
4. Perform regular code reviews and re-scan after remediation.

---

## Disclaimer
This project uses an **intentionally vulnerable application for educational purposes**. No real systems or sensitive data were used.
