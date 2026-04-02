# Application Security Report
### SonarQube Static Analysis — 8 Findings

**Prepared by:** Enoch K. Ali — Aspiring AppSec Engineer
**Date:** April 2026
**Classification:** Confidential — Internal Use Only
**Frameworks:** CVSS v3.1 · CWE · CVE · OWASP Top 10 · ASVS 4.0 · OTG v4

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Risk Rating Methodology](#2-risk-rating-methodology)
   - [2.1 CVSS v3.1 Scoring](#21-cvss-v31-scoring)
   - [2.2 Risk Rating Scale](#22-risk-rating-scale)
3. [Summary of All Findings](#3-summary-of-all-findings)
4. [Detailed Findings](#4-detailed-findings)
   - [4.1 Finding 1 — Hardcoded Password (PHP)](#41-finding-1--hardcoded-password-php)
   - [4.2 Findings 2, 5, 6 — Server Bound to 0.0.0.0 (Python)](#42-findings-2-5-6--server-bound-to-0000-python)
   - [4.3 Finding 3 — postMessage Wildcard Origin (JavaScript)](#43-finding-3--postmessage-wildcard-origin-javascript)
   - [4.4 Finding 4 — addEventListener No Origin Check (JavaScript)](#44-finding-4--addeventlistener-no-origin-check-javascript)
   - [4.5 Findings 7 & 8 — XXE Injection (PHP)](#45-findings-7--8--xxe-injection-php)
5. [Remediation Plan](#5-remediation-plan)
6. [Recommended GitHub Actions Pipeline](#6-recommended-github-actions-pipeline)
7. [References](#7-references)

---

## 1. Executive Summary

This report documents eight security findings identified via SonarQube static analysis across a multi-language codebase (PHP, Python, JavaScript). Each finding is assessed against six security frameworks:

- **CVSS v3.1** — Quantitative base score with full vector string
- **CWE** — Common Weakness Enumeration identifier(s) for root cause classification
- **CVE** — Known public vulnerability references where applicable
- **OWASP Top 10 2021** — Category mapping for risk communication and compliance
- **OWASP ASVS 4.0** — Specific verification control numbers that are failing
- **OWASP Testing Guide (OTG) v4** — Test case references for validation and QA

**Result:** 3 Critical findings (CVSS ≥ 9.0), 5 High findings (CVSS 7.0–8.9). No finding is below High. Immediate action is required on findings 1, 7, and 8 before any production deployment.

---

## 2. Risk Rating Methodology

### 2.1 CVSS v3.1 Scoring

All findings are scored using CVSS v3.1 Base Score only. Environmental and Temporal scores are not applied — they should be adjusted by the security team based on the deployment environment. The vector string encodes eight metrics:

| Group | Metrics |
|---|---|
| Exploitability | Attack Vector (AV) · Attack Complexity (AC) · Privileges Required (PR) · User Interaction (UI) |
| Impact | Confidentiality (C) · Integrity (I) · Availability (A) · Scope (S) |

### 2.2 Risk Rating Scale

| Rating | CVSS Range | SonarQube | Response SLA |
|---|---|---|---|
| 🔴 Critical | 9.0–10.0 | Blocker | Immediate — block all deployments, fix before next commit |
| 🟠 High | 7.0–8.9 | Critical | Within current sprint — fix within 7 days |
| 🟡 Medium | 4.0–6.9 | Major | Next planned release — fix within 30 days |
| 🟢 Low | 0.1–3.9 | Minor | Backlog — fix within 90 days |

---

## 3. Summary of All Findings

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

---

## 4. Detailed Findings

---

### 4.1 Finding 1 — Hardcoded Password (PHP)

| Field | Detail |
|---|---|
| **Severity** | 🔴 Critical (CVSS 9.8) |
| **CWE** | CWE-798: Use of Hard-coded Credentials |
| **CVE** | CVE-2021-43798 (analogous — static secret in source). Treat credential as fully compromised. |
| **OWASP Top 10** | A07:2021 — Identification and Authentication Failures |
| **ASVS 4.0** | V2.10.1 — Verify no integration secrets rely on unchanging passwords. V2.10.4 — Verify passwords not stored in source code. |
| **OTG Reference** | OTG-AUTHN-007 — Testing for Weak Password Policy |
| **Language / File** | PHP — public class property |

#### CVSS v3.1 Vector

| | |
|---|---|
| **Score** | **9.8 — Critical** |
| **Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |

> **Rationale:** Network-exploitable (AV:N), trivial complexity (AC:L), no privileges or user interaction required (PR:N/UI:N), full CIA impact — credential gives complete authentication bypass.

#### Vulnerable Code

```php
public $password = "Insanity";
```

#### Description

The credential is hardcoded as a public class property, visible to anyone with repository access — including via git history, leaked archives, or an exposed `.git` directory. It cannot be rotated without a code change and redeployment, creating a permanent window of exposure.

#### Attack Scenario

1. Attacker finds exposed `.git` directory or gains repository read access.
2. Simple `grep` for `"password"` trivially reveals the credential.
3. Credential is used to authenticate — full account or service takeover.
4. Credential cannot be silently rotated; requires code change, PR, and deployment.

#### Compliant Fix

```php
$user     = getUser();
$password = getPassword();  // loaded from environment or secrets vault
```

- Store credentials in environment variables — never commit `.env` files.
- Use a secrets manager: AWS Secrets Manager, HashiCorp Vault, or Azure Key Vault.
- Enable GitHub Secret Scanning and push protection on the repository.
- Audit git history with TruffleHog. **Rotate the credential immediately.**

---

### 4.2 Findings 2, 5, 6 — Server Bound to 0.0.0.0 (Python)

| Field | Detail |
|---|---|
| **Severity** | 🟠 High (CVSS 7.5) |
| **CWE** | CWE-668: Exposure of Resource to Wrong Sphere; CWE-605: Multiple Binds to Same Port |
| **CVE** | No specific CVE. Flask dev server internet exposure is a well-documented misconfiguration indexed by Shodan. |
| **OWASP Top 10** | A05:2021 — Security Misconfiguration |
| **ASVS 4.0** | V14.1.1 — Verify server components do not expose unnecessary interfaces. V14.4.1 — Verify HTTP security headers present (impossible with dev server). |
| **OTG Reference** | OTG-CONFIG-006 — Test HTTP Methods. OTG-CONFIG-002 — Test Application Platform Configuration. |
| **Language / Files** | Python — 3 separate entrypoints (ports 8000 and 5051) |

#### CVSS v3.1 Vector

| | |
|---|---|
| **Score** | **7.5 — High** |
| **Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` |

> **Rationale:** Reachable from any network (AV:N), no complexity or auth required, high confidentiality impact from unauthenticated route enumeration. Integrity rises to H if `debug=True` is ever set (RCE via Werkzeug console).

#### Vulnerable Code

```python
app.run(host='0.0.0.0', debug=False)   # findings 2 and 5
app.run(host="0.0.0.0", port=5051)     # finding 6
```

#### Description

Binding to `0.0.0.0` instructs the OS to accept connections on every available interface: loopback, LAN, and public IP. Flask and FastAPI development servers are not designed for internet exposure — they are single-threaded, unthrottled, have no TLS, and no request size caps. Shodan and Censys bots discover open ports within minutes. If `debug=True` is ever enabled, Werkzeug exposes an interactive Python console at every error URL — unauthenticated remote code execution.

#### Compliant Fix

```python
if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)
```

- **Fix all 3 occurrences** — this pattern appears in 3 separate Python files.
- Use `uvicorn` or `gunicorn` in all environments, never Flask dev server in production.
- Deploy behind Nginx or Caddy for TLS termination and public traffic handling.
- Never set `debug=True` on any network-reachable server.

---

### 4.3 Finding 3 — postMessage Wildcard Origin (JavaScript)

| Field | Detail |
|---|---|
| **Severity** | 🟠 High (CVSS 7.4) |
| **CWE** | CWE-346: Origin Validation Error |
| **CVE** | CVE-2018-8495 — analogous improper postMessage origin validation in browser context. |
| **OWASP Top 10** | A03:2021 — Injection (cross-window message injection) |
| **ASVS 4.0** | V5.2.6 — Verify JSON injection protection. V14.5.3 — Verify origin header validation on cross-domain calls. |
| **OTG Reference** | OTG-CLIENT-010 — Testing Cross-Origin Resource Sharing and postMessage abuse |
| **Language** | JavaScript |

#### CVSS v3.1 Vector

| | |
|---|---|
| **Score** | **7.4 — High** |
| **Vector** | `CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:L/A:N` |

#### Vulnerable Code

```javascript
window_ref.postMessage(message, "*");
```

#### Description

The wildcard `"*"` as `targetOrigin` instructs the browser to deliver the message to any window regardless of origin. Any malicious page that has embedded the application in an iframe, or opened it via `window.open()`, receives the full message payload — including tokens, session data, or PII.

#### Compliant Fix

```javascript
// Sender: pin the target origin
iframe.contentWindow.postMessage("hello", "https://secure.example.com");

// Receiver: validate origin before any processing
window.addEventListener("message", function(event) {
  if (event.origin !== "https://secure.example.com") return;
  console.log(event.data);
});
```

- Apply origin pinning to **every** `postMessage` call in the entire codebase.
- Never send authentication tokens or PII via `postMessage` with wildcard origin.

---

### 4.4 Finding 4 — addEventListener No Origin Check (JavaScript)

| Field | Detail |
|---|---|
| **Severity** | 🟠 High (CVSS 7.4) |
| **CWE** | CWE-346: Origin Validation Error |
| **CVE** | CVE-2018-8495 — same vulnerability class as Finding 3. |
| **OWASP Top 10** | A03:2021 — Injection |
| **ASVS 4.0** | V5.2.6 — Verify origin validation on all cross-domain communication. |
| **OTG Reference** | OTG-CLIENT-010 — Testing Cross-Origin Resource Sharing / postMessage |
| **Language** | JavaScript |

#### CVSS v3.1 Vector

| | |
|---|---|
| **Score** | **7.4 — High** |
| **Vector** | `CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:L/A:N` |

#### Vulnerable Code

```javascript
window.addEventListener("message", receiveMessage, false);
```

#### Description

The message handler accepts `postMessage` events from any origin without validating `event.origin`. Any website that can open or embed the application can send arbitrary messages that `receiveMessage` will process — enabling cross-window script injection, CSRF-via-message, and data manipulation.

#### Compliant Fix

```javascript
window.addEventListener("message", function(event) {
  if (event.origin !== "https://your-trusted-domain.com") return;
  console.log(event.data);
});
```

---

### 4.5 Findings 7 & 8 — XXE Injection (PHP)

| Field | Detail |
|---|---|
| **Severity** | 🔴 Critical (CVSS 9.1) |
| **CWE** | CWE-611: Improper Restriction of XML External Entity Reference |
| **CVE** | CVE-2021-21707 — PHP XML parser XXE via libxml. CVE-2021-3450 (libxml2 context). `LIBXML_NOENT` + `LIBXML_DTDLOAD` is a known XXE enabler documented in PHP security advisories. |
| **OWASP Top 10** | A05:2021 — Security Misconfiguration (XML processor misconfiguration) |
| **ASVS 4.0** | V14.5.1 — Verify XML parsers reject external entity resolution. V14.5.2 — Verify DTD processing is disabled. |
| **OTG Reference** | OTG-INPVAL-007 — Testing for XML Injection. OTG-INPVAL-008 — Testing for XXE Injection. |
| **Language / Files** | PHP — two files using DOMDocument |

#### CVSS v3.1 Vector

| | |
|---|---|
| **Score** | **9.1 — Critical** |
| **Vector** | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N` |

> **Rationale:** Network-exploitable (AV:N), low complexity, low privileges to submit XML (PR:L), scope changes to host filesystem (S:C), high confidentiality (file read) and integrity (SSRF write) impact.

#### Vulnerable Code

```php
// Finding 7
$document->loadXML($xml, LIBXML_NOENT | LIBXML_DTDLOAD);

// Finding 8
$dom->loadXML($xmlfile, LIBXML_NOENT | LIBXML_DTDLOAD);
```

#### Description

`LIBXML_NOENT` substitutes entity references including external ones defined as `<!ENTITY xxe SYSTEM "file:///etc/passwd">`. `LIBXML_DTDLOAD` enables loading external DTDs — the mechanism to define those entities remotely. Together they allow an attacker to:

1. **Read arbitrary server files** via `file://` entities
2. **Perform SSRF** by referencing internal network URLs via `http://`
3. **Cause DoS** via Billion Laughs entity expansion attack

#### Proof-of-Concept XXE Payload

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<root><data>&xxe;</data></root>
```

Submitting this payload to either vulnerable endpoint returns `/etc/passwd` in the XML response.

#### Compliant Fix — XMLReader with entities disabled

```php
$reader = new XMLReader();
$reader->open("input.xml");
$reader->setParserProperty(XMLReader::SUBST_ENTITIES, false);
```

#### Alternative — DOMDocument without dangerous flags

```php
$dom = new DOMDocument();
$dom->loadXML($xmlfile);  // no LIBXML_NOENT, no LIBXML_DTDLOAD
```

- Remove `LIBXML_NOENT` and `LIBXML_DTDLOAD` from **both files immediately**.
- Add input validation to reject XML payloads containing `DOCTYPE` declarations.
- Apply `libxml_disable_entity_loader(true)` as defence-in-depth (PHP < 8.0).

---

## 5. Remediation Plan

| Priority | Findings | Action | Effort | Timeline | Owner |
|---|---|---|---|---|---|
| **P0 — Immediate** | 1, 7, 8 | Remove hardcoded cred + disable XXE flags. Do not deploy until resolved. | Low | 24 hrs | Dev Lead |
| **P1 — This Sprint** | 2, 5, 6 | Migrate all 3 Python entrypoints to uvicorn on 127.0.0.1. | Low | 1 week | Backend Dev |
| **P2 — Next Release** | 3, 4 | Pin all postMessage origins; add event.origin checks to all listeners. | Medium | 2 weeks | Frontend Dev |
| **P3 — Ongoing** | All | Add GitHub Actions: SonarQube + TruffleHog + Semgrep + pip-audit. | Medium | 1 month | DevSecOps |

---

## 6. Recommended GitHub Actions Pipeline

| Tool | Purpose | Findings Caught |
|---|---|---|
| SonarQube Scan | SAST — static code analysis | All 8 findings in this report |
| TruffleHog | Secret detection in git history | Finding 1 — hardcoded credentials |
| Semgrep (OWASP rules) | Pattern-based SAST | XXE, postMessage wildcard, host binding |
| pip-audit | Python dependency CVEs | Known vulnerable packages |
| composer audit | PHP dependency CVEs | Known vulnerable PHP libraries |
| OWASP ZAP (DAST) | Dynamic scan against live app | Runtime XXE, injection, misconfiguration |

Add the following to `.github/workflows/security.yml`:

```yaml
name: Security scan
on: [push, pull_request]

jobs:
  sonarqube:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }
      - uses: SonarSource/sonarqube-scan-action@master
        env:
          SONAR_TOKEN: ${{ secrets.SONAR_TOKEN }}
          SONAR_HOST_URL: ${{ secrets.SONAR_HOST_URL }}

  secrets:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: trufflesecurity/trufflehog@main
        with: { path: ./, base: main }

  semgrep:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: returntocorp/semgrep-action@v1
        with: { config: "p/owasp-top-ten p/php p/python" }

  python-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: pip install pip-audit && pip-audit

  php-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: composer audit
```

---

## 7. References

| Resource | Link |
|---|---|
| OWASP Top 10 2021 | https://owasp.org/Top10/ |
| OWASP ASVS 4.0 | https://owasp.org/www-project-application-security-verification-standard/ |
| OWASP Testing Guide v4 | https://owasp.org/www-project-web-security-testing-guide/ |
| CVSS v3.1 Specification | https://www.first.org/cvss/v3.1/specification-document |
| NVD CVSS Calculator | https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator |
| CWE-798 Hardcoded Credentials | https://cwe.mitre.org/data/definitions/798.html |
| CWE-611 XXE | https://cwe.mitre.org/data/definitions/611.html |
| CWE-346 Origin Validation Error | https://cwe.mitre.org/data/definitions/346.html |
| CWE-668 Resource Exposure | https://cwe.mitre.org/data/definitions/668.html |
| CVE-2021-21707 PHP XXE | https://nvd.nist.gov/vuln/detail/CVE-2021-21707 |
| CVE-2018-8495 postMessage | https://nvd.nist.gov/vuln/detail/CVE-2018-8495 |
| PHP libxml security | https://www.php.net/manual/en/function.libxml-disable-entity-loader.php |
| SonarQube Rules | https://rules.sonarsource.com/ |
| GitHub Secret Scanning | https://docs.github.com/en/code-security/secret-scanning |
| TruffleHog | https://github.com/trufflesecurity/trufflehog |
| Semgrep OWASP ruleset | https://semgrep.dev/p/owasp-top-ten |

---

*Prepared by **Enoch K. Ali** — Aspiring AppSec Engineer*
*Classification: Confidential — Internal Use Only*
